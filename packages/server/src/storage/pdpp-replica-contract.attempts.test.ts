/**
 * Contract suite, S2b: attempt-scoped results, the coordinator's clock and
 * eligibility, and bounded hints, proven on the real transport worker.
 *
 * Each case is an adapter-level reproduction of a finding in the cross-family
 * review of dab96705 (S2-REVIEW-DOT-R1.md).
 */
import { afterEach, expect, it } from "vitest";
import type { ProgressReport } from "@opendatalabs/personal-server-ts-core/replication/coordinator";
import {
  clock,
  cleanupHarness,
  cycles,
  network,
  slotKey,
  transportDevice,
  workRecords,
  type TransportDevice,
} from "./pdpp-replica-contract.test-utils.js";

afterEach(cleanupHarness);

const B1 = 1000;
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const step = (d: TransportDevice, units = 50) =>
  d.step({ units }) as Promise<ProgressReport>;
const num = (d: TransportDevice, sql: string, ...params: unknown[]) =>
  (d.db.prepare(sql).get(...params) as { n: number }).n;
const phaseState = (d: TransportDevice, phase: string) =>
  d.db
    .prepare("SELECT * FROM pdpp_transport_phase_state WHERE phase=?")
    .get(phase) as
    | {
        outcome: string;
        reason: string;
        attempts: number;
        next_attempt: number;
      }
    | undefined;
async function within<T>(ms: number, work: Promise<T>, label: string) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label}: hung`)), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
/** A writer whose single batch is published and finalized. */
async function source(net: ReturnType<typeof network>) {
  const a = transportDevice(net, { preexisting: "record" });
  await cycles([a], 3);
  return a;
}

it("S2b-1 a late discover result after its deadline never commits, not even with a later attempt's Retry", async () => {
  const net = network();
  await source(net);
  const list = net.port.list;
  const held: (() => void)[] = [];
  const release = () => held.splice(0).forEach((go) => go());
  net.port.list = (cursor) =>
    new Promise((resolve, reject) => {
      held.push(() => void list(cursor).then(resolve, reject));
    });
  const b = transportDevice(net, { worker: { deadlineMs: 50 } });
  await within(2000, step(b), "first step");
  expect(phaseState(b, "discover")).toMatchObject({
    outcome: "retry",
    reason: "deadline_exceeded",
  });
  // The next attempt fails fast; then the abandoned listing resolves.
  net.port.list = async () => {
    throw new Error("listing down");
  };
  release();
  await sleep(20);
  clock.advance(10 * B1);
  await within(2000, step(b), "second step");
  expect(
    num(b, "SELECT count(*) AS n FROM pdpp_transport_manifests_in"),
    "late admissions",
  ).toBe(0);
  expect(
    (
      b.db.prepare("SELECT scan_cursor FROM pdpp_transport_state").get() as {
        scan_cursor: string | null;
      }
    ).scan_cursor,
  ).toBeNull();
  expect(phaseState(b, "discover")).toMatchObject({
    outcome: "retry",
    reason: "discovery_failed",
    attempts: 2,
  });
});

it("S2b-2 a late download result after its deadline never retains a manifest", async () => {
  const net = network();
  await source(net);
  const b = transportDevice(net, { worker: { deadlineMs: 50 } });
  const get = net.port.get;
  const held: (() => void)[] = [];
  const release = () => held.splice(0).forEach((go) => go());
  net.port.get = (scope, version) =>
    new Promise((resolve, reject) => {
      held.push(() => void get(scope, version).then(resolve, reject));
    });
  await within(2000, step(b), "first step");
  const timedOut = workRecords(b.db).filter(
    (r) =>
      r.table === "pdpp_transport_manifests_in" &&
      r.reason === "deadline_exceeded",
  );
  expect(timedOut.length).toBeGreaterThan(0);
  net.port.get = async () => {
    throw new Error("storage down");
  };
  release();
  await sleep(20);
  clock.advance(10 * B1);
  await within(2000, step(b), "second step");
  expect(
    num(
      b,
      "SELECT count(*) AS n FROM pdpp_transport_manifests_in WHERE manifest_json IS NOT NULL AND slot=?",
      timedOut[0]!.id,
    ),
    "the abandoned download committed its manifest",
  ).toBe(0);
});

it("S2b-3 a finality hint that never settles is bounded by the deadline and never gates progress", async () => {
  const net = network();
  const a = await source(net);
  net.port.finality = { head: () => new Promise<bigint>(() => undefined) };
  const b = transportDevice(net, { worker: { deadlineMs: 100 } });
  for (let i = 0; i < 6 && b.get() === undefined; i++) {
    clock.advance(10 * B1);
    await within(3000, step(b), `step ${i}`);
  }
  expect(b.get()).toEqual(a.get());
});

it("S2b-4 a slow failure keeps its full backoff from the settlement time", async () => {
  const net = network();
  net.port.list = async () => ({ points: [], cursor: null });
  const a = transportDevice(net, { preexisting: "record" });
  const evidence = net.port.evidence;
  net.port.evidence = async (scope, version) => {
    await evidence(scope, version);
    clock.advance(5 * B1); // the RPC took five seconds of wall time
    throw new Error("rpc failed slowly");
  };
  await step(a);
  // One manifest, one publication attempt: its settlement is the last clock read.
  const rows = workRecords(a.db).filter(
    (r) => r.table === "pdpp_transport_manifests_out",
  );
  expect(rows).toHaveLength(1);
  expect(rows[0]).toMatchObject({ outcome: "retry", attempts: 1 });
  expect(
    rows[0]!.nextEligible,
    "the deadline had already expired when written",
  ).toBe(clock.now() + B1);
});

it("S2b-5 a failed commit transaction persists none of the attempt's effects and a Retry from the settlement time", async () => {
  const net = network();
  await source(net);
  const b = transportDevice(net);
  b.db.exec(
    "CREATE TRIGGER fail_ack BEFORE INSERT ON pdpp_transport_imported BEGIN SELECT RAISE(ABORT,'ack failed'); END",
  );
  await cycles([b], 4);
  expect(num(b, "SELECT count(*) AS n FROM pdpp_transport_imported")).toBe(0);
  expect(num(b, "SELECT count(*) AS n FROM pdpp_replica_received")).toBe(0);
  const work = b.db
    .prepare(
      "SELECT outcome,reason,next_attempt,cause_json FROM pdpp_transport_import_work",
    )
    .all() as {
    outcome: string;
    reason: string;
    next_attempt: number;
    cause_json: string;
  }[];
  expect(work.length).toBeGreaterThan(0);
  for (const row of work) {
    expect(row).toMatchObject({ outcome: "retry", reason: "import_failed" });
    expect(row.next_attempt).toBeGreaterThan(clock.now());
    expect(row.cause_json).not.toContain("ack failed");
  }
});

it("S2b-6 nextWake follows eligibility: a hint-parked wait is not 'now', and an outstanding singleton retry is not idle", async () => {
  const net = network();
  net.port.list = async () => ({ points: [], cursor: null });
  net.port.finality = { head: async () => 100n }; // below the verified height
  const a = transportDevice(net, { preexisting: "record" });
  const put = net.port.put;
  net.port.put = async (manifest) => {
    net.pending.add(slotKey(manifest.scope, manifest.version));
    return put(manifest);
  };
  await step(a);
  const parked = workRecords(a.db).filter(
    (r) => r.table === "pdpp_transport_manifests_out",
  );
  expect(parked).toHaveLength(1);
  expect(
    parked.every((r) => r.outcome === "wait" && r.checkedBlock === "123"),
  ).toBe(true);
  // Past the durable deadline the hint keeps the wait parked: nothing is runnable.
  clock.advance(60 * B1);
  const report = await step(a);
  expect(report.receipts.filter((r) => r.phase === "publish")).toEqual([]);
  expect(
    report.nextWake,
    "a parked wait reported runnable now",
  ).toBeGreaterThan(clock.now());

  // A failing discovery is outstanding work with a deadline.
  const nb = network();
  nb.port.list = async () => {
    throw new Error("listing down");
  };
  const c = transportDevice(nb);
  const failed = await step(c);
  expect(failed.problems.some((p) => p.phase === "discover")).toBe(true);
  expect(
    failed.nextWake,
    "a discover retry left the device idle",
  ).toBeDefined();
  expect(failed.nextWake).toBe(phaseState(c, "discover")!.next_attempt);
});

it("S2b-7 revalidation with unavailable evidence is not reported as Progress", async () => {
  const net = network();
  await source(net);
  const b = transportDevice(net);
  await cycles([b], 4);
  expect(b.get()).toEqual({ id: "a", text: "record" });
  const evidence = net.port.evidence;
  net.port.evidence = async (scope, version) => ({
    ...(await evidence(scope, version)),
    chain: null,
  });
  clock.advance(10 * B1);
  const report = await step(b);
  expect(report.receipts.filter((r) => r.phase === "revalidate")).toEqual([]);
  const rows = workRecords(b.db).filter(
    (r) => r.table === "pdpp_transport_manifests_in" && r.state === "imported",
  );
  expect(rows.length).toBeGreaterThan(0);
  for (const row of rows)
    expect(row).toMatchObject({
      outcome: "retry",
      reason: "evidence_unavailable",
    });
});
