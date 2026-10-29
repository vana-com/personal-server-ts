/**
 * Replica contract suite, section A: typed outcomes and durable transitions
 * (cases 01-14). Red-first: describes the ReplicaCoordinator target API in
 * CONTRACT-API.md against the REAL transport worker + receiver, and for the
 * retained-import cases (01, 04, 11) also over the canonical adapters.
 */
import type Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import type { ProgressReport } from "@opendatalabs/personal-server-ts-core/replication/coordinator";
import type { ReplicaOperation } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import type { MergeContext } from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import { replicaFragmentKey } from "@opendatalabs/personal-server-ts-core/replication/transport";
import {
  authenticatedOwnFork,
  adapterFactories,
  at,
  batchOfPlaintext,
  binding,
  CrashController,
  clock,
  cleanupHarness,
  credential,
  envelope,
  expected,
  network,
  owner,
  slotKey,
  sourceId,
  transportDevice,
  transportInvariantViolations,
  workRecords,
  type CanonicalAdapter,
  type Network,
  type TransportDevice,
  unprovisionConnection,
} from "./pdpp-replica-contract.test-utils.js";

afterEach(cleanupHarness);

// ------------------------------------------------------------------ helpers

type Row = Record<string, unknown>;
type Db = Database.Database;

const LEAK = "LEAK-7c1e-secret-rpc-detail";

/** All rows of a table; [] when the table does not exist (yet). */
function tableRows(db: Db, table: string): Row[] {
  const exists = db
    .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?")
    .get(table);
  return exists
    ? (db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all() as Row[])
    : [];
}
const batchRows = (d: TransportDevice) =>
  tableRows(d.db, "pdpp_transport_batches");
/** Unregistered content-addressed uploads of the device's batches. */
const fragmentRows = (d: TransportDevice) =>
  tableRows(d.db, "pdpp_transport_fragments_out");
/** One manifest per batch: the batch's one registration. */
const manifestRows = (d: TransportDevice) =>
  tableRows(d.db, "pdpp_transport_manifests_out").map((r) => ({
    ...r,
    slot: slotKey(r.scope as string, r.version as number),
  }));
/** Batches whose manifest registration the network received. */
const registeredBatches = (d: TransportDevice, net: Network) =>
  manifestRows(d)
    .filter((r) => net.calls.registrations.includes(r.slot))
    .map((r) => r.batch as string);
const importWork = (d: TransportDevice) =>
  tableRows(d.db, "pdpp_transport_import_work");
const logical = (d: TransportDevice, table: string) =>
  workRecords(d.db).filter((r) => r.table === table);
const writerOf = (d: TransportDevice) =>
  (
    d.db
      .prepare("SELECT writer FROM pdpp_transport_state WHERE id=1")
      .get() as {
      writer: string;
    }
  ).writer;

/** Every string/number a transport table persisted, to prove no exception text leaks. */
function durableText(db: Db): string {
  const tables = db
    .prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'pdpp_transport_%'",
    )
    .all() as { name: string }[];
  const out: string[] = [];
  for (const { name } of tables)
    for (const row of tableRows(db, name))
      for (const value of Object.values(row))
        if (typeof value === "string") out.push(value);
  return out.join("\n");
}

async function step(
  d: TransportDevice,
  budget?: { units: number; bytes?: number },
) {
  return (await d.step(budget)) as ProgressReport | undefined;
}
/** Advance the shared clock, then step. */
async function at_(d: TransportDevice, ms: number) {
  clock.advance(ms);
  return step(d);
}

function wake(d: TransportDevice, key: string) {
  const f = (d.worker as { onDependencyChanged?: (key: string) => unknown })
    .onDependencyChanged;
  expect(typeof f, "worker.onDependencyChanged is part of the contract").toBe(
    "function",
  );
  return f!.call(d.worker, key);
}

/**
 * Wrap the port's uploads, fragments and manifests in call order: count
 * calls, record exact bytes, fail on demand. `pending` keeps each manifest
 * registration out of finalized evidence.
 */
function instrumentPut(
  net: Network,
  options: {
    fail?: (call: number) => Error | undefined;
    pending?: boolean;
  } = {},
) {
  const log = {
    calls: 0,
    parts: [] as { key: string; encrypted: Uint8Array }[],
  };
  const record = (key: string, encrypted: Uint8Array) => {
    log.calls++;
    log.parts.push({ key, encrypted: new Uint8Array(encrypted) });
    const error = options.fail?.(log.calls);
    if (error) throw error;
  };
  const putFragment = net.port.putFragment;
  net.port.putFragment = async (fragment) => {
    record(
      replicaFragmentKey(fragment.scope, fragment.digest),
      fragment.encrypted,
    );
    return putFragment(fragment);
  };
  const put = net.port.put;
  net.port.put = async (manifest) => {
    const slot = slotKey(manifest.scope, manifest.version);
    record(slot, manifest.encrypted);
    if (options.pending) net.pending.add(slot);
    return put(manifest);
  };
  return log;
}

/**
 * Wrap the port's evidence: fail on demand, count reads per slot. A
 * conflict is a finalized commitment at the slot other than the registered one.
 */
function instrumentEvidence(
  net: Network,
  local?: () => TransportDevice,
  authenticated = false,
) {
  const original = net.port.evidence;
  const state = {
    fail: false,
    error: () => new Error(LEAK) as unknown,
    calls: [] as string[],
    conflict: undefined as undefined | ((slot: string) => boolean),
  };
  net.port.evidence = async (scope, version) => {
    const slot = slotKey(scope, version);
    state.calls.push(slot);
    if (state.fail) throw state.error();
    const evidence = await original(scope, version);
    if (state.conflict?.(slot) && evidence.chain) {
      if (authenticated && local)
        return authenticatedOwnFork(net, local(), scope, version);
      if (local && !net.blobs.has(slot)) {
        const held = local()
          .db.prepare(
            "SELECT encrypted FROM pdpp_transport_manifests_out WHERE scope=? AND version=?",
          )
          .get(scope, version) as { encrypted: Buffer } | undefined;
        if (held) net.blobs.set(slot, held.encrypted);
      }
      return {
        ...evidence,
        chain: {
          ...evidence.chain,
          currentVersion: String(version),
          status: "Active",
          commitment: `0x${"f".repeat(64)}` as const,
        },
        pending: false,
      };
    }
    return evidence;
  };
  return state;
}

/** Make the first batch whose fragment is encrypted impossible to frame under the cap. */
function stickFirstBatch(net: Network, cap: number) {
  const encrypt = net.port.encrypt;
  const state = { batch: undefined as string | undefined };
  net.port.encrypt = async (scope, bytes) => {
    const batch = batchOfPlaintext(bytes);
    state.batch ??= batch;
    const out = await encrypt(scope, bytes);
    if (batch !== state.batch) return out;
    const padded = new Uint8Array(cap + 64);
    padded.set(out.subarray(0, Math.min(out.length, padded.length)));
    return padded;
  };
  return state;
}

/** A tiny cap: even one encrypted 1-byte fragment exceeds it. */
const TINY_CAP = 256;

// ======================================================================== 01

describe("01 Progress with retained custody, not premature availability", () => {
  it("01 [transport] retains the complete payload once, keeps a separate Wait(mapping), hides data, then materializes without local echo", async () => {
    const net = network();
    const a = transportDevice(net, { preexisting: "record" });
    await at_(a, 10000);
    await at_(a, 10000);
    const b = transportDevice(net);
    // Provisioning is a separate authority: transport must not invent the mapping.
    unprovisionConnection(b.db, "conn");
    const reports: (ProgressReport | undefined)[] = [];
    for (let i = 0; i < 4; i++) reports.push(await at_(b, 10000));

    expect(b.get()).toBeUndefined(); // hidden before mapping
    const aBatches = batchRows(a).length;
    // One retention/import receipt per complete retained batch of A (B also
    // imports its own registration batch).
    const writerA = writerOf(a);
    const workOfA = () => importWork(b).filter((w) => w.writer === writerA);
    const work = workOfA();
    expect(work).toHaveLength(aBatches);
    expect(work.every((w) => w.outcome === "progress")).toBe(true);
    expect(work.every((w) => w.attempts === 0)).toBe(true);
    // A separate materialization wait, reported with its dependency.
    const waits = reports.flatMap((r) => r?.waits ?? []);
    expect(waits.map((w) => w.dependency)).toContainEqual({
      kind: "mapping",
      key: "conn",
    });

    // Restart: the retention receipt and the wait are durable facts.
    b.reopen();
    expect(workOfA()).toEqual(work);
    expect(b.get()).toBeUndefined();
    let retries = 0;
    const receiver = b.receiver;
    const originalStep = receiver.reconcileStep.bind(receiver);
    receiver.reconcileStep = ((input) => {
      if (input.restart) retries++;
      return originalStep(input);
    }) as typeof receiver.reconcileStep;
    for (let i = 0; i < 5; i++) await at_(b, 1000); // inside the 60 s fallback
    // At most the one post-restart rebuild; never one retry per step.
    expect(
      retries,
      "a reconcile pass starts only when due",
    ).toBeLessThanOrEqual(1);
    const parked = retries;
    clock.advance(60000);
    const again = await step(b);
    expect(again?.waits.map((w) => w.dependency)).toContainEqual({
      kind: "mapping",
      key: "conn",
    });
    expect(retries).toBe(parked + 1); // the bounded fallback: exactly one reconcile unit

    // Provision, then signal the exact key.
    b.store.registerConnection({
      instance: "conn",
      sourceId,
      method: "export",
      label: "C",
    });
    const journal = tableRows(b.db, "pdpp_replica_own_writes");
    wake(b, "mapping:conn");
    const woken = await step(b);
    expect(b.get()).toEqual(a.get());
    expect(woken?.waits ?? []).toEqual([]);
    expect(tableRows(b.db, "pdpp_replica_own_writes")).toEqual(journal); // no local echo
    expect(workOfA()).toEqual(work); // visibility did not rewrite the import receipt
  });

  for (const [name, make] of Object.entries(adapterFactories))
    it(`01 [${name}] retained complete payload stays hidden until the mapping arrives, then appears exactly`, async () => {
      const context = adapterContext();
      const adapter = await make(context);
      await adapter.send([registration(), upsert(20)]);
      expect(
        visible(await adapter.point(CONN, "messages", "a")),
      ).toBeUndefined();
      adapter.reopen();
      expect(
        visible(await adapter.point(CONN, "messages", "a")),
      ).toBeUndefined();
      await adapter.provision(CONN, { sourceId, methodId: METHOD });
      await adapter.retry();
      expect(visible(await adapter.point(CONN, "messages", "a"))).toEqual({
        id: "a",
        text: "remote-20",
      });
    });
});

// ======================================================================== 02

describe("02 Progress to the next phase is atomic", () => {
  async function prepareRun(crashAt: number | undefined) {
    const crash = new CrashController();
    const net = network({ crash });
    const d = transportDevice(net, {
      preexisting: "x".repeat(9000),
      chunk: 2000,
      crash,
    });
    crash.arm(crashAt);
    try {
      await d.step();
    } catch {
      // process loss surfaces here; durable state is read after reopen
    }
    return { crash, net, d };
  }

  it("02 preparation receipt and publish work commit together at every crash point of the prepare transaction", async () => {
    const reference = await prepareRun(undefined);
    const trace = [...reference.crash.trace];
    const firstPreparing = trace.findIndex((l) =>
      l.includes("insert:pdpp_transport_staged_fragments"),
    );
    const firstOutbox = trace.findIndex((l) =>
      l.includes("insert:pdpp_transport_manifests_out"),
    );
    expect(firstPreparing).toBeGreaterThan(-1);
    expect(firstOutbox).toBeGreaterThan(firstPreparing);
    const commit = trace.findIndex((l, i) => i > firstOutbox && l === "commit");
    expect(commit).toBeGreaterThan(firstOutbox);
    const fragments = fragmentRows(reference.d).length;
    expect(fragments).toBeGreaterThan(1);
    expect(manifestRows(reference.d)).toHaveLength(1);
    reference.d.close();
    cleanupHarness();

    const points: number[] = [];
    for (let i = firstPreparing - 1; i <= commit + 2; i++)
      if (i >= 0 && i < trace.length) points.push(i);
    expect(points.length).toBeGreaterThan(6);

    for (const point of points) {
      const { crash, net, d } = await prepareRun(point);
      expect(crash.dead, `crash point ${point} ${trace[point]} reached`).toBe(
        true,
      );
      d.crashReopen();
      crash.dead = false; // the network outlives the crashed process
      const where = `crash point ${point} (${trace[point]})`;
      expect(transportInvariantViolations(d), where).toEqual([]);
      const afterCrash = fragmentRows(d);
      const manifestAfterCrash = manifestRows(d);
      const batches = batchRows(d);
      for (const batch of batches) {
        const mine = afterCrash.filter((o) => o.batch === batch.batch);
        const manifest = manifestAfterCrash.filter(
          (o) => o.batch === batch.batch,
        );
        if (batch.prepared === 1) {
          expect(mine, where).toHaveLength(fragments);
          expect(manifest, where).toHaveLength(1);
          expect(batch.outcome, `${where}: prepare receipt`).toBe("progress");
        } else {
          expect(mine, where).toHaveLength(0);
          expect(manifest, where).toHaveLength(0);
          expect(batch.prepared, where).toBe(0);
          expect(batch.outcome, where).not.toBe("progress");
        }
      }
      // Resume twice. Hashes stay stable and nothing duplicates.
      for (let i = 0; i < 2; i++) {
        clock.advance(5000);
        await d.step();
      }
      const final = fragmentRows(d);
      expect(final, where).toHaveLength(fragments);
      expect(new Set(final.map((o) => o.digest)).size, where).toBe(fragments);
      for (const before of afterCrash) {
        const now = final.find(
          (o) => o.batch === before.batch && o.position === before.position,
        );
        expect(now?.digest, where).toEqual(before.digest);
        expect(
          Buffer.compare(now?.encrypted as Buffer, before.encrypted as Buffer),
          where,
        ).toBe(0);
      }
      const finalManifests = manifestRows(d);
      expect(finalManifests, where).toHaveLength(1);
      for (const before of manifestAfterCrash) {
        const now = finalManifests.find((o) => o.batch === before.batch);
        expect(now?.version, where).toEqual(before.version);
        expect(now?.data_hash, where).toEqual(before.data_hash);
        expect(now?.metadata_hash, where).toEqual(before.metadata_hash);
        expect(
          Buffer.compare(now?.encrypted as Buffer, before.encrypted as Buffer),
          where,
        ).toBe(0);
      }
      const batchesAfter = batchRows(d);
      expect(batchesAfter, where).toHaveLength(1);
      expect(batchesAfter[0]!.prepared, where).toBe(1);
      expect(batchesAfter[0]!.outcome, where).toBe("progress");
      expect(net.calls.encrypts).toBeGreaterThan(0);
      d.close();
      cleanupHarness();
    }
  }, 60_000); // one full pipeline step per crash point

  it("02 a prepared batch makes no remote availability claim before finalized evidence", async () => {
    const net = network();
    const puts = instrumentPut(net, { pending: true });
    const d = transportDevice(net, { preexisting: "record" });
    await step(d);
    expect(batchRows(d)[0]!.outcome).toBe("progress");
    expect(d.get()).toEqual({ id: "a", text: "record" }); // local value unchanged
    const rows = logical(d, "pdpp_transport_manifests_out");
    expect(rows).toHaveLength(1);
    expect(rows.every((r) => r.outcome === "wait")).toBe(true);
    // Every fragment and the one manifest are stored, once each.
    expect(puts.calls).toBe(fragmentRows(d).length + rows.length);
  });
});

// ======================================================================== 03

describe("03 Due to Wait and Wait to Progress", () => {
  it("03 a successor without its predecessor is a stable Wait(predecessor) that never inflates attempts, then imports with original identity", async () => {
    const net = network();
    const a = transportDevice(net);
    a.put("tail record");
    for (let i = 0; i < 3; i++) await at_(a, 10000);
    const aBatches = batchRows(a);
    expect(aBatches.length).toBeGreaterThanOrEqual(2);
    const first = aBatches.find((r) => r.sequence === 1)!;
    const second = aBatches.find((r) => r.sequence === 2)!;
    // The predecessor's registration is not final for a while.
    const firstSlot = manifestRows(a).find(
      (r) => r.batch === first.batch,
    )!.slot;
    const finalized = net.chain.get(firstSlot)!;
    net.chain.delete(firstSlot);
    net.pending.add(firstSlot);
    const b = transportDevice(net);
    for (let i = 0; i < 8; i++) await at_(b, 10000);
    expect(b.get()).toBeUndefined();
    const dependency = `predecessor:${writerOf(a)}:1`;
    const waiting = () => importWork(b).find((r) => r.batch === second.batch);
    expect(waiting()).toMatchObject({
      outcome: "wait",
      dependency,
      attempts: 0,
    });
    b.reopen();
    for (let i = 0; i < 8; i++) await at_(b, 10000);
    expect(waiting()).toMatchObject({
      outcome: "wait",
      dependency,
      attempts: 0,
    });
    expect(b.get()).toBeUndefined();

    // The predecessor finalizes and its exact key is signalled.
    net.pending.delete(firstSlot);
    net.chain.set(firstSlot, finalized);
    for (let i = 0; i < 3; i++) {
      wake(b, `finality:${firstSlot}`);
      wake(b, dependency);
      await at_(b, 10000); // 30 s in total: inside the 60 s fallback rescan
    }
    expect(waiting()).toMatchObject({ outcome: "progress" });
    expect(importWork(b).every((r) => r.outcome === "progress")).toBe(true);
    expect(b.get()).toEqual(a.get());
    // Original operation identity survives the delay.
    const ids = (d: TransportDevice, table: string) =>
      tableRows(d.db, table)
        .map((r) => JSON.parse(r.operation_json as string) as ReplicaOperation)
        .filter((op) => op.kind === "upsert")
        .map((op) => op.revision.operationId)
        .sort();
    expect(ids(b, "pdpp_replica_received")).toEqual(
      ids(a, "pdpp_replica_operations"),
    );
  });
});

// ======================================================================== 04

describe("04 Wait to Wait with a new dependency", () => {
  it("04 [transport] reset predecessor then trusted declaration: the wait key changes, nothing orphaned, no failure charge", async () => {
    const net = network();
    const b = transportDevice(net);
    b.declarations([]);
    b.receiver.import({
      credential,
      envelope: envelope([upsert(20, 3, "conn", "export")], "direct-future"),
    });
    const first = await step(b);
    expect(first?.waits).toHaveLength(1);
    const wait = first!.waits[0]!.dependency;
    expect(wait.kind).toBe("reset");
    expect(first?.problems).toEqual([]);
    expect(b.get()).toBeUndefined();
    b.reopen();
    b.declarations([]);

    // Supply the reset chain only, then signal the key the report named.
    b.receiver.import({
      credential,
      envelope: envelope(
        [reset(2, "conn", "export"), reset(3, "conn", "export")],
        "direct-resets",
      ),
    });
    wake(b, `${wait.kind}:${wait.key}`);
    const second = await step(b);
    expect(second?.waits.map((w) => w.dependency)).toEqual([
      { kind: "declaration", key: `${sourceId}:messages` },
    ]);
    expect(second?.problems).toEqual([]);
    expect(b.get()).toBeUndefined(); // new value hidden until both conditions hold
    b.reopen();
    b.declarations([]);
    clock.advance(60000);
    const restarted = await step(b);
    expect(restarted?.waits.map((w) => w.dependency)).toEqual([
      { kind: "declaration", key: `${sourceId}:messages` },
    ]);

    b.declarations(expected.declarations);
    wake(b, `declaration:${sourceId}:messages`);
    const third = await step(b);
    expect(third?.waits ?? []).toEqual([]);
    expect(b.get()).toEqual({ id: "a", text: "remote-20" });
  });

  for (const [name, make] of Object.entries(adapterFactories))
    it(`04 [${name}] a future generation stays hidden through reset-only and appears only once the declaration is trusted`, async () => {
      const adapter = await make(adapterContext([]), {
        connectionId: CONN,
        sourceId,
        methodId: METHOD,
      });
      await adapter.send([registration(), upsert(20, 3)]);
      expect(
        visible(await adapter.point(CONN, "messages", "a")),
      ).toBeUndefined();
      adapter.reopen();
      await adapter.send([reset(2), reset(3)]);
      await adapter.retry();
      expect(
        visible(await adapter.point(CONN, "messages", "a")),
      ).toBeUndefined();
      adapter.reopen();
      adapter.declare(adapterContext());
      await adapter.retry();
      expect(visible(await adapter.point(CONN, "messages", "a"))).toEqual({
        id: "a",
        text: "remote-20",
      });
    });
});

// ================================================================== 05 / 06

describe("05 Due to Retry and Retry to Progress", () => {
  it("05 a failed PUT is Retry(publish_failed) at t+B(1); no early call; identical bytes at the deadline", async () => {
    const net = network();
    const puts = instrumentPut(net, {
      fail: (n) => (n === 1 ? new Error(LEAK) : undefined),
    });
    const d = transportDevice(net, { preexisting: "record" });
    const t = clock.now();
    await step(d);
    expect(puts.calls).toBe(1);
    const original = fragmentRows(d)[0]!;
    const row = logical(d, "pdpp_transport_fragments_out")[0]!;
    expect(row.outcome).toBe("retry");
    expect(row.reason).toBe("publish_failed");
    expect(row.attempts).toBe(1);
    expect(row.nextEligible).toBe(t + 1000);
    expect(row.cause).toMatchObject({ name: "Error" });
    expect(durableText(d.db)).not.toContain(LEAK);

    d.reopen();
    clock.advance(999);
    await step(d);
    expect(puts.calls, "no call before the deadline").toBe(1);
    clock.advance(1);
    await step(d);
    // The fragment again, then the manifest.
    expect(puts.calls).toBe(3);
    expect(puts.parts[1]!.key).toBe(puts.parts[0]!.key);
    expect(puts.parts[1]!.encrypted).toEqual(puts.parts[0]!.encrypted);
    expect(net.blobs.get(puts.parts[0]!.key)).toEqual(puts.parts[0]!.encrypted);
    const done = fragmentRows(d)[0]!;
    expect(
      Buffer.compare(done.encrypted as Buffer, original.encrypted as Buffer),
    ).toBe(0);
    expect(done.state).toBe("stored");
    expect(logical(d, "pdpp_transport_fragments_out")[0]).toMatchObject({
      outcome: "progress",
      attempts: 0,
    });
    expect(manifestRows(d)[0]!.state).toBe("published");
    expect(net.calls.registrations).toHaveLength(1);
    expect(d.get()).toEqual({ id: "a", text: "record" });
  });
});

describe("06 Retry to Retry preserves diagnostics and deadline", () => {
  it("06 a second failure is B(2), keeps the structured cause chain, and never stores the message text", async () => {
    const net = network();
    const failure = () =>
      new Error(LEAK, {
        cause: Object.assign(new TypeError(`inner ${LEAK}`), {
          code: "ECONNRESET",
        }),
      });
    const puts = instrumentPut(net, {
      fail: (n) => (n <= 2 ? failure() : undefined),
    });
    const d = transportDevice(net, { preexisting: "record" });
    const t = clock.now();
    await step(d);
    const checkpoint = fragmentRows(d)[0]!;
    d.reopen();
    expect(logical(d, "pdpp_transport_fragments_out")[0]).toMatchObject({
      outcome: "retry",
      reason: "publish_failed",
      attempts: 1,
      nextEligible: t + 1000,
    });
    clock.advance(1000);
    await step(d);
    d.reopen();
    const second = logical(d, "pdpp_transport_fragments_out")[0]!;
    expect(second).toMatchObject({
      outcome: "retry",
      reason: "publish_failed",
      attempts: 2,
      nextEligible: t + 1000 + 2000,
    });
    expect(second.cause).toMatchObject({
      name: "Error",
      cause: { name: "TypeError", code: "ECONNRESET" },
    });
    expect(durableText(d.db)).not.toContain(LEAK);
    clock.advance(1999);
    await step(d);
    expect(puts.calls).toBe(2);
    // Checkpoint unchanged and the item is pending, never quarantined.
    const now = fragmentRows(d)[0]!;
    expect(now.state).toBe("ready");
    expect(now.outcome).not.toBe("quarantine");
    expect(
      Buffer.compare(now.encrypted as Buffer, checkpoint.encrypted as Buffer),
    ).toBe(0);
    expect(now.digest).toBe(checkpoint.digest);
    clock.advance(1);
    await step(d);
    expect(puts.calls).toBe(4); // the fragment, then the manifest
    expect(logical(d, "pdpp_transport_fragments_out")[0]).toMatchObject({
      outcome: "progress",
      attempts: 0,
    });
  });
});

// ================================================================== 07 / 08

describe("07 Retry to Wait does not confuse attempts with waits", () => {
  it("07 a pending proof resets attempts, waits never count, and the next RPC error is B(1)", async () => {
    const net = network();
    const evidence = instrumentEvidence(net);
    const puts = instrumentPut(net, { pending: true });
    const d = transportDevice(net, { preexisting: "record" });
    const t0 = clock.now();
    evidence.fail = true;
    await step(d);
    expect(logical(d, "pdpp_transport_manifests_out")[0]).toMatchObject({
      outcome: "retry",
      attempts: 1,
      nextEligible: t0 + 1000,
    });
    evidence.fail = false;
    clock.advance(1000);
    await step(d);
    const slot = manifestRows(d)[0]!.slot;
    const wait = logical(d, "pdpp_transport_manifests_out")[0]!;
    expect(wait).toMatchObject({
      outcome: "wait",
      attempts: 0,
      dependency: `finality:${slot}`,
      checkedBlock: "123",
    });
    expect(typeof wait.waitSince).toBe("number");
    for (let i = 0; i < 16; i++) await at_(d, 2000);
    d.reopen();
    expect(logical(d, "pdpp_transport_manifests_out")[0]).toMatchObject({
      outcome: "wait",
      attempts: 0,
      checkedBlock: "123",
    });
    expect(puts.calls, "pending evidence never publishes again").toBe(
      fragmentRows(d).length + 1,
    );
    expect(net.calls.registrations).toHaveLength(1);
    expect(d.get()).toEqual({ id: "a", text: "record" });

    evidence.fail = true;
    const waitingAgain = logical(d, "pdpp_transport_manifests_out")[0]!;
    clock.advance(Math.max(0, waitingAgain.nextEligible - clock.now()));
    const t = clock.now();
    await step(d);
    expect(logical(d, "pdpp_transport_manifests_out")[0]).toMatchObject({
      outcome: "retry",
      attempts: 1,
      nextEligible: t + 1000,
      checkedBlock: "123",
    });
    evidence.fail = false;
    net.finalizeAll();
    clock.advance(1000);
    await step(d);
    expect(logical(d, "pdpp_transport_manifests_out")[0]).toMatchObject({
      outcome: "progress",
      attempts: 0,
    });
  });
});

describe("08 Wait to Retry on evidence transport failure", () => {
  it("08 a hint advance never replaces the verified checked height, and the failure is B(1)", async () => {
    const net = network();
    net.port.finality = { head: async () => 1000n };
    net.port.list = async () => ({ points: [], cursor: null }); // the writer must not read itself
    const evidence = instrumentEvidence(net);
    instrumentPut(net, { pending: true });
    const d = transportDevice(net, { preexisting: "record" });
    await step(d);
    const waiting = logical(d, "pdpp_transport_manifests_out")[0]!;
    expect(waiting).toMatchObject({ outcome: "wait", checkedBlock: "123" });
    const slot = manifestRows(d)[0]!.slot;
    // Park until the durable deadline, then fail the evidence read with the hint ahead.
    clock.advance((waiting.nextEligible as number) - clock.now());
    evidence.fail = true;
    const reads = evidence.calls.filter((s) => s === slot).length;
    const t = clock.now();
    await step(d);
    expect(evidence.calls.filter((s) => s === slot).length).toBe(reads + 1);
    const retry = logical(d, "pdpp_transport_manifests_out")[0]!;
    expect(retry).toMatchObject({
      outcome: "retry",
      attempts: 1,
      nextEligible: t + 1000,
      checkedBlock: "123", // never "1000"
    });
    expect(durableText(d.db)).not.toContain(LEAK);
    clock.advance(999);
    await step(d);
    expect(evidence.calls.filter((s) => s === slot).length).toBe(reads + 1);
    expect(d.get()).toEqual({ id: "a", text: "record" });
    expect(net.calls.registrations).toHaveLength(1); // no new live remote data
  });
});

// ======================================================================== 09

describe("09 Quarantine only with proof", () => {
  for (const source of ["fresh", "wait", "retry"] as const)
    it(`09 [outbox from ${source}] a holder commitment mismatch retries without retirement; no further put or register`, async () => {
      const net = network();
      const evidence = instrumentEvidence(net, () => d);
      const puts = instrumentPut(net, {
        pending: source === "wait",
        fail: (n) =>
          source === "retry" && n === 1 ? new Error(LEAK) : undefined,
      });
      const d = transportDevice(net, { preexisting: "immutable" });
      if (source === "fresh") evidence.conflict = () => true;
      await step(d);
      if (source === "wait") {
        expect(logical(d, "pdpp_transport_manifests_out")[0]!.outcome).toBe(
          "wait",
        );
        evidence.conflict = () => true;
        await at_(d, 2000);
      }
      if (source === "retry") {
        expect(logical(d, "pdpp_transport_fragments_out")[0]!.outcome).toBe(
          "retry",
        );
        evidence.conflict = () => true;
        await at_(d, 1000);
      }
      const row = logical(d, "pdpp_transport_manifests_out")[0]!;
      expect(row.outcome).toBe("retry");
      expect(row.reason).toBe("commitment_mismatch");
      const putCalls = puts.calls;
      const manifestPuts = () =>
        puts.parts.filter((p) => !p.key.includes("/fragments/")).length;
      const registrations = net.calls.registrations.length;
      // fresh: conflict seen before the manifest put. wait: put+register
      // happened once. retry: only a fragment put failed, then the conflict.
      expect(manifestPuts()).toBe(source === "wait" ? 1 : 0);
      expect(registrations).toBe(source === "wait" ? 1 : 0);
      // Restarts and wakes retry authentication without publishing unverified bytes.
      d.reopen();
      for (let i = 0; i < 4; i++) await at_(d, 3_600_000);
      expect(logical(d, "pdpp_transport_manifests_out")[0]).toMatchObject({
        outcome: "retry",
        reason: "commitment_mismatch",
      });
      expect(puts.calls).toBe(putCalls);
      expect(net.calls.registrations).toHaveLength(registrations);
      expect(d.get()).toEqual({ id: "a", text: "immutable" }); // local data stays
    });

  it("09 [inbox] a finalized conflict on an imported slot quarantines it with proof; replay changes nothing", async () => {
    const net = network();
    const a = transportDevice(net, { preexisting: "immutable" });
    await at_(a, 10000);
    await at_(a, 10000);
    const b = transportDevice(net);
    for (let i = 0; i < 3; i++) await at_(b, 10000);
    const slot = manifestRows(a)[0]!.slot;
    const received = () =>
      tableRows(b.db, "pdpp_transport_manifests_in").find(
        (r) => r.slot === slot,
      )!;
    expect(received().state).toBe("imported");
    expect(b.get()).toEqual({ id: "a", text: "immutable" });
    // The Gateway now finalizes another commitment at the imported slot.
    const evidence = instrumentEvidence(net);
    evidence.conflict = (s) => s === slot;
    const gets = net.calls.gets.length;
    for (let i = 0; i < 3; i++) await at_(b, 10000);
    expect(received()).toMatchObject({
      state: "quarantined",
      outcome: "quarantine",
      reason: "finalized_conflict",
    });
    expect(b.get(), "a disproved copy is withdrawn").toBeUndefined();
    expect(net.calls.gets, "proof needs no storage read").toHaveLength(gets);
    const settled = { row: received(), data: b.get() };
    b.reopen();
    for (let i = 0; i < 3; i++) await at_(b, 3_600_000);
    expect(received()).toEqual(settled.row);
    expect(b.get()).toEqual(settled.data);
    expect(net.calls.gets).toHaveLength(gets);
  });
});

// ======================================================================== 10

describe("10 Unsupported admission is not Quarantine", () => {
  async function waitsForUnsupported(
    d: TransportDevice,
  ): Promise<ReturnType<typeof logical>[number]> {
    await step(d);
    return logical(d, "pdpp_transport_batches")[0]!;
  }

  it("10 an impossible framing is Unsupported with a measured admission, never retried, local data intact", async () => {
    const net = network({ cap: TINY_CAP });
    const d = transportDevice(net, { preexisting: "record", cap: TINY_CAP });
    const batch = await waitsForUnsupported(d);
    expect(batch.prepared).toBe(-1);
    expect(batch.outcome).toBe("unsupported");
    expect(batch.reason).toBe("replica_framing_unsupported");
    const admission = batch.admission as {
      actual: number;
      limit: number;
      capability: string;
    };
    expect(admission.limit).toBe(TINY_CAP);
    expect(admission.actual).toBeGreaterThan(TINY_CAP);
    expect(admission.capability).toBe(`cap:${TINY_CAP}`);
    expect(fragmentRows(d)).toHaveLength(0);
    expect(manifestRows(d)).toHaveLength(0);
    expect(d.get()).toEqual({ id: "a", text: "record" });
    // No fabricated conflict and no fence.
    expect(batch.outcome).not.toBe("quarantine");

    // Restart, timer wakes and dependency wakes do not retry it.
    const frozen = batchRows(d)[0];
    d.reopen();
    const encrypts = net.calls.encrypts;
    for (let i = 0; i < 4; i++) await at_(d, 3_600_000);
    wake(d, `predecessor:${writerOf(d)}:0`);
    wake(d, "mapping:conn");
    wake(d, `declaration:${sourceId}:messages`);
    await at_(d, 1000);
    expect(net.calls.encrypts, "no hot or timer retry").toBe(encrypts);
    expect(batchRows(d)[0]).toEqual(frozen);
    expect(d.get()).toEqual({ id: "a", text: "record" });
  });

  it("10 a successor batch of the same writer still prepares and publishes; a remote importer records Wait(predecessor)", async () => {
    const net = network();
    stickFirstBatch(net, 8192);
    const a = transportDevice(net, { preexisting: "stuck" });
    await at_(a, 10000);
    expect(logical(a, "pdpp_transport_batches")[0]).toMatchObject({
      prepared: -1,
      outcome: "unsupported",
      reason: "replica_framing_unsupported",
    });
    a.put("next", "b");
    for (let i = 0; i < 3; i++) await at_(a, 10000);
    const batches = batchRows(a);
    expect(batches.length).toBeGreaterThanOrEqual(2);
    const stuck = batches.find((r) => r.sequence === 1)!;
    const next = batches.find((r) => r.sequence === 2)!;
    expect(stuck.prepared).toBe(-1);
    expect(next.prepared).toBe(1);
    expect(manifestRows(a).every((r) => r.state === "published")).toBe(true);
    expect(registeredBatches(a, net)).not.toContain(stuck.batch);
    expect(net.calls.registrations.length).toBeGreaterThan(0);

    const b = transportDevice(net);
    for (let i = 0; i < 4; i++) await at_(b, 10000);
    expect(importWork(b).find((r) => r.batch === next.batch)).toMatchObject({
      outcome: "wait",
      dependency: `predecessor:${writerOf(a)}:1`,
      attempts: 0,
    });
    expect(b.get("b")).toBeUndefined();
  });
});

// ======================================================================== 11

describe("11 Terminal outcome replay is inert", () => {
  it("11 [transport] a progressed, a terminal own-key wait and an unsupported item stay byte-identical under replay", async () => {
    const net = network();
    const evidence = instrumentEvidence(net, () => d, true);
    stickFirstBatch(net, 8192);
    const d = transportDevice(net, { preexisting: "one" });
    await at_(d, 10000); // batch 1: unsupported
    d.put("two", "b");
    for (let i = 0; i < 3; i++) await at_(d, 10000); // batch 2: progress
    d.put("three", "c");
    evidence.conflict = (slot) => {
      const third = batchRows(d).find((r) => r.sequence === 3);
      return (
        third !== undefined &&
        manifestRows(d).find((r) => r.batch === third.batch)?.slot === slot
      );
    };
    for (let i = 0; i < 3; i++) await at_(d, 10000); // batch 3: terminal own-key wait

    const batches = logical(d, "pdpp_transport_batches");
    expect(batches.map((r) => r.outcome)).toEqual([
      "unsupported",
      "progress",
      "progress",
    ]);
    const outbox = logical(d, "pdpp_transport_manifests_out");
    expect(outbox.some((r) => r.outcome === "progress")).toBe(true);
    expect(
      outbox.some(
        (r) => r.outcome === "wait" && r.reason === "own_key_conflict",
      ),
    ).toBe(true);

    const tables = [
      "pdpp_transport_batches",
      "pdpp_transport_fragments_out",
      "pdpp_transport_manifests_out",
    ];
    const snapshot = () =>
      tables.map((t) => tableRows(d.db, t).map((r) => ({ ...r })));
    const before = snapshot();
    const counts = {
      encrypts: net.calls.encrypts,
      puts: net.calls.puts.length,
      registrations: net.calls.registrations.length,
    };
    const keys = [
      ...manifestRows(d).map((r) => `finality:${r.slot}`),
      `predecessor:${writerOf(d)}:1`,
      "mapping:conn",
      `declaration:${sourceId}:messages`,
    ];
    for (let round = 0; round < 3; round++) {
      for (const key of keys) wake(d, key);
      await at_(d, 3_600_000);
      if (round === 1) d.reopen();
    }
    expect(snapshot()).toEqual(before);
    expect({
      encrypts: net.calls.encrypts,
      puts: net.calls.puts.length,
      registrations: net.calls.registrations.length,
    }).toEqual(counts);
    expect(d.get()).toEqual({ id: "a", text: "one" });
  });

  for (const [name, make] of Object.entries(adapterFactories))
    it(`11 [${name}] replaying a terminal equivocation changes nothing, before and after restart`, async () => {
      const adapter = await make(adapterContext(), {
        connectionId: CONN,
        sourceId,
        methodId: METHOD,
      });
      const first = upsert(20);
      await adapter.send([registration(), first]);
      await adapter.send([
        {
          ...first,
          data: { id: "a", text: "equivocated" },
        } as ReplicaOperation,
      ]);
      const settled = await observe(adapter);
      expect(settled.point).toBeUndefined(); // withdrawn, not silently replaced
      for (let i = 0; i < 3; i++) {
        await adapter.send([first]);
        await adapter.retry();
        adapter.reopen();
        await adapter.send([first]);
        expect(await observe(adapter)).toEqual(settled);
      }
    });
});

// ======================================================================== 12

describe("12 Explicit capability change re-admits Unsupported without falsifying history", () => {
  it("12a a plain reopen with a larger cap does not re-admit an Unsupported batch", async () => {
    const cap = { value: TINY_CAP };
    const net = network({ cap: 8192 });
    const d = transportDevice(net, {
      preexisting: "record",
      cap: TINY_CAP,
      worker: {
        get maxBlobBytes() {
          return cap.value;
        },
      },
    });
    await step(d);
    expect(logical(d, "pdpp_transport_batches")[0]).toMatchObject({
      prepared: -1,
      outcome: "unsupported",
    });
    cap.value = 8192;
    d.reopen();
    const encrypts = net.calls.encrypts;
    for (let i = 0; i < 3; i++) await at_(d, 3_600_000);
    expect(logical(d, "pdpp_transport_batches")[0]).toMatchObject({
      prepared: -1,
      outcome: "unsupported",
      reason: "replica_framing_unsupported",
    });
    expect(net.calls.encrypts).toBe(encrypts);
    expect(manifestRows(d)).toHaveLength(0);
  });

  it("12b the worker exposes an explicit readmitUnsupported event that re-admits under the new capability", async () => {
    const cap = { value: TINY_CAP };
    const net = network({ cap: 8192 });
    const d = transportDevice(net, {
      preexisting: "record",
      cap: TINY_CAP,
      worker: {
        get maxBlobBytes() {
          return cap.value;
        },
      },
    });
    await step(d);
    const digest = batchRows(d)[0]!.digest;
    cap.value = 8192;
    d.reopen();
    const readmit = (d.worker as { readmitUnsupported?: () => unknown })
      .readmitUnsupported;
    expect(typeof readmit, "contract gap: no explicit re-admission event").toBe(
      "function",
    );
    await readmit!.call(d.worker);
    for (let i = 0; i < 3; i++) await at_(d, 10000);
    const batch = batchRows(d)[0]!;
    expect(batch.prepared).toBe(1);
    expect(batch.digest).toBe(digest); // same original operations
    expect(manifestRows(d)).toHaveLength(1);
    expect(d.get()).toEqual({ id: "a", text: "record" });
  });
});

// ======================================================================== 13

describe("13 Transient RangeError", () => {
  it("13 a generic RangeError from encrypt is Retry(B(1)) with prepared=0; successors progress; recovery at the deadline", async () => {
    const net = network();
    let failed = false;
    net.faults.encrypt = () => {
      if (failed) return undefined;
      failed = true;
      return new RangeError(LEAK);
    };
    const encrypted: string[] = [];
    const encrypt = net.port.encrypt;
    net.port.encrypt = async (scope, bytes) => {
      encrypted.push(batchOfPlaintext(bytes));
      return encrypt(scope, bytes);
    };
    const d = transportDevice(net, { preexisting: "first" });
    const t = clock.now();
    await step(d);
    const stuck = logical(d, "pdpp_transport_batches")[0]!;
    expect(stuck.prepared, "RangeError must not become permanent").toBe(0);
    expect(stuck).toMatchObject({
      outcome: "retry",
      reason: "prepare_failed",
      attempts: 1,
      nextEligible: t + 1000,
    });
    expect(stuck.cause).toMatchObject({ name: "RangeError" });
    expect(durableText(d.db)).not.toContain(LEAK);
    const stuckBatch = batchRows(d)[0]!.batch as string;
    d.reopen();
    expect(net.calls.encrypts).toBe(1);

    d.put("second", "b");
    clock.advance(500);
    await step(d); // before the deadline: the claimed slot blocks its successor
    expect(encrypted.filter((b) => b === stuckBatch)).toHaveLength(1);
    expect(net.calls.registrations).toHaveLength(0);
    expect(registeredBatches(d, net)).not.toContain(stuckBatch);
    expect(batchRows(d)).toHaveLength(1);
    expect(logical(d, "pdpp_transport_manifests_out")).toHaveLength(0);
    expect(
      logical(d, "pdpp_transport_batches").find((r) => r.id === stuckBatch)
        ?.prepared,
    ).toBe(0);

    clock.advance(499);
    await step(d);
    expect(encrypted.filter((b) => b === stuckBatch)).toHaveLength(1);
    clock.advance(1);
    await step(d);
    const recovered = logical(d, "pdpp_transport_batches").find(
      (r) => r.id === stuckBatch,
    )!;
    expect(recovered.prepared).toBe(1);
    expect(recovered.outcome).toBe("progress");
    expect(registeredBatches(d, net)).toContain(stuckBatch);
    await step(d); // the waiting source operation may claim the next slot now
    expect(net.calls.registrations).toHaveLength(2);
    expect(d.get()).toEqual({ id: "a", text: "first" });
  });
});

// ======================================================================== 14

describe("14 Similar error strings cannot choose disposition", () => {
  const imitation = "encrypted fragment exceeds storage cap";
  const variants: [string, () => Error][] = [
    ["generic Error", () => new Error(imitation)],
    ["generic RangeError", () => new RangeError(imitation)],
  ];
  for (const [label, make] of variants)
    it(`14 ${label} imitating framing wording is Retry, prepared=0, with a single encrypt call and no data withdrawal`, async () => {
      const net = network();
      net.faults.encrypt = () => make();
      const d = transportDevice(net, { preexisting: "record" });
      const t = clock.now();
      await step(d);
      const batch = logical(d, "pdpp_transport_batches")[0]!;
      expect(batch.prepared).toBe(0);
      expect(batch).toMatchObject({
        outcome: "retry",
        reason: "prepare_failed",
        attempts: 1,
        nextEligible: t + 1000,
      });
      expect(net.calls.encrypts, "no chunk halving on an untyped error").toBe(
        1,
      );
      expect(batch.admission ?? null).toBeNull();
      expect(manifestRows(d)).toHaveLength(0);
      expect(d.get()).toEqual({ id: "a", text: "record" });
      d.reopen();
      clock.advance(1000);
      await step(d);
      expect(logical(d, "pdpp_transport_batches")[0]).toMatchObject({
        outcome: "retry",
        attempts: 2,
        nextEligible: clock.now() + 2000,
        prepared: 0,
      });
      expect(
        logical(d, "pdpp_transport_batches").every(
          (r) => r.outcome !== "quarantine" && r.outcome !== "unsupported",
        ),
      ).toBe(true);
      expect(d.get()).toEqual({ id: "a", text: "record" });
    });

  it("14 only the typed domain error yields Unsupported", async () => {
    const outcome = "@opendatalabs/personal-server-ts-core/replication/outcome";
    const module = (await import(/* @vite-ignore */ outcome)) as {
      ReplicaFramingUnsupported?: unknown;
    };
    expect(typeof module.ReplicaFramingUnsupported).toBe("function");
    const net = network({ cap: TINY_CAP });
    const d = transportDevice(net, { preexisting: "record", cap: TINY_CAP });
    await step(d);
    expect(logical(d, "pdpp_transport_batches")[0]).toMatchObject({
      prepared: -1,
      outcome: "unsupported",
      reason: "replica_framing_unsupported",
    });
    expect(d.get()).toEqual({ id: "a", text: "record" });
  });
});

// -------------------------------------------------------- adapter fixtures

const CONN = "conn_a";
const METHOD = "collector";

function adapterContext(
  entries: MergeContext["declarations"] = [
    { sourceId, binding, validateData: (data) => typeof data.id === "string" },
  ],
): MergeContext {
  return { owner, declarations: entries };
}

function upsert(
  counter = 20,
  generation = 1,
  connectionId = CONN,
  methodId = METHOD,
): ReplicaOperation {
  return {
    kind: "upsert",
    owner,
    sourceId,
    connectionId,
    methodId,
    generation,
    revision: { counter, writerId: "remote", operationId: `op-${counter}` },
    declaration: binding,
    recordKey: "a",
    emittedAt: at,
    data: { id: "a", text: `remote-${counter}` },
    blobs: [],
  };
}
function registration(
  connectionId = CONN,
  methodId = METHOD,
): ReplicaOperation {
  return {
    kind: "connection-register",
    owner,
    sourceId,
    connectionId,
    methodId,
    generation: 1,
    revision: { counter: 1, writerId: "remote", operationId: "register" },
  };
}
function reset(
  generation: number,
  connectionId = CONN,
  methodId = METHOD,
): ReplicaOperation {
  return {
    kind: "connection-reset",
    owner,
    sourceId,
    connectionId,
    methodId,
    generation,
    previousGeneration: generation - 1,
    revision: {
      counter: generation,
      writerId: "remote",
      operationId: `reset-${generation}`,
    },
  };
}
const visible = (row: { deleted: boolean; data?: unknown } | undefined) =>
  row && !row.deleted ? row.data : undefined;

/** Public reads of one adapter; unsupported surfaces assert their absence. */
async function observe(adapter: CanonicalAdapter) {
  const point = visible(await adapter.point(CONN, "messages", "a"));
  if (adapter.surfaces.list === "supported" && adapter.list)
    // Reading a changes page mints a new horizon token; compare its content only.
    return {
      point,
      list: (await adapter.list(CONN, "messages")).data,
      changes: (await adapter.changes?.(CONN, "messages"))?.data,
    };
  expect(adapter.surfaces.list).toBe("unsupported");
  expect(adapter.list).toBeUndefined();
  expect(adapter.changes).toBeUndefined();
  return { point };
}

// ================================================== g (#429 F1): authority

describe("g One validated authority context precedes every phase", () => {
  const traffic = (net: ReturnType<typeof network>) =>
    JSON.stringify({
      puts: net.calls.puts.length,
      gets: net.calls.gets.length,
      registrations: net.calls.registrations.length,
      evidence: net.calls.evidence.length,
      lists: net.calls.lists,
      encrypts: net.calls.encrypts,
    });
  const durable = (d: TransportDevice) =>
    JSON.stringify([
      batchRows(d),
      fragmentRows(d),
      manifestRows(d),
      tableRows(d.db, "pdpp_transport_manifests_in"),
      tableRows(d.db, "pdpp_transport_fragments_in"),
      importWork(d),
    ]);
  async function rejectsBeforeAnyPhase(d: TransportDevice, net: Network) {
    const calls = { retry: 0, stage: 0, import: 0 };
    const receiver = d.receiver;
    for (const name of ["retry", "stage", "import"] as const) {
      const original = receiver[name].bind(receiver) as (input: never) => never;
      (receiver as unknown as Record<string, unknown>)[name] = (
        input: never,
      ) => {
        calls[name]++;
        return original(input);
      };
    }
    const before = { traffic: traffic(net), durable: durable(d) };
    await expect(step(d)).rejects.toMatchObject({
      code: "replica_authority_mismatch",
    });
    expect(traffic(net), "no network or encryption call").toBe(before.traffic);
    expect(durable(d), "no phase state").toBe(before.durable);
    expect(calls).toEqual({ retry: 0, stage: 0, import: 0 });
  }
  it("g.1 a transport port for another owner is refused before any phase", async () => {
    const net = network();
    const other = "0x0000000000000000000000000000000000000002";
    const d = transportDevice(net, {
      preexisting: "record",
      worker: { transport: { ...net.port, owner: other } },
    });
    await rejectsBeforeAnyPhase(d, net);
  });
  it("g.2 a persisted binding to another owner is refused before any phase", async () => {
    const net = network();
    const d = transportDevice(net, { preexisting: "record" });
    await step(d);
    d.db
      .prepare("UPDATE pdpp_transport_state SET owner=? WHERE id=1")
      .run("0x0000000000000000000000000000000000000002");
    d.reopen();
    await rejectsBeforeAnyPhase(d, net);
  });
});
