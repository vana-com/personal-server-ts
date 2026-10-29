import Database from "better-sqlite3";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import { createTestReplicaSigner } from "@opendatalabs/personal-server-ts-core/replication/writer-identity.test-utils";
import { REPLICA_ATTEMPT_TIMEOUT_MS } from "@opendatalabs/personal-server-ts-core/replication/coordinator";
import {
  REPLICA_LOCAL_WRITE_DEBOUNCE_MS,
  type ReplicationTimers,
} from "@opendatalabs/personal-server-ts-core/replication/host-driver";
import {
  at,
  clock,
  network,
  owner,
  scratchDirectory,
} from "./pdpp-replica-contract.test-utils.js";
import { REPLICA_TEST_CHAIN_ID } from "./pdpp-replica-writer-identity.test-utils.js";
import { createNodeReplication } from "./pdpp-replication-host.js";

const SOURCE = "https://registry.pdpp.dev/connectors/host-test";
const declaration: DeclarationSnapshot = {
  source_id: SOURCE,
  source_kind: "connector" as DeclarationSnapshot["source_kind"],
  version: "1",
  digest: "c".repeat(64),
  streams: [
    {
      name: "messages",
      fields: ["id", "text"],
      required_fields: ["id"],
      primary_key: ["id"],
      schema: {
        type: "object",
        properties: { id: { type: "string" }, text: { type: "string" } },
        required: ["id"],
      },
    },
  ],
};
const logger = { info: () => {}, warn: () => {} };
/** The driver's own timer stays unarmed: the test steps by trigger. */
const manualTimers: ReplicationTimers = {
  now: clock.now,
  setTimeout: () => undefined,
  clearTimeout: () => {},
};

/** Timers on the shared test clock; the test runs the due ones. */
function clockTimers() {
  let next = 1;
  const pending = new Map<
    number,
    { at: number; ms: number; run: () => void }
  >();
  const timers: ReplicationTimers = {
    now: clock.now,
    setTimeout(run, ms) {
      pending.set(next, { at: clock.now() + ms, ms, run });
      return next++;
    },
    clearTimeout: (handle) => pending.delete(handle as number),
  };
  return {
    timers,
    /** Delays of the timers armed since the last call. */
    armedSince: (() => {
      let seen = 0;
      return () => {
        const fresh = [...pending.entries()]
          .filter(([id]) => id > seen)
          .map(([, t]) => t.ms);
        seen = next - 1;
        return fresh;
      };
    })(),
    runDue() {
      for (const [id, t] of [...pending])
        if (t.at <= clock.now()) {
          pending.delete(id);
          t.run();
        }
    },
  };
}

async function settled(driver: { status(): { stepping: boolean } }) {
  while (driver.status().stepping)
    await new Promise((resolve) => setImmediate(resolve));
}

function host(
  net: ReturnType<typeof network>,
  opts: {
    chainId?: number;
    declarations?: DeclarationSnapshot[];
    timers?: ReplicationTimers;
  } = {},
) {
  const db = new Database(join(scratchDirectory("replica-host"), "db.sqlite"));
  const signer = createTestReplicaSigner();
  net.roster.register(signer.address, owner);
  const runtime = createNodeReplication({
    db,
    owner,
    chainId: opts.chainId ?? REPLICA_TEST_CHAIN_ID,
    declarations: opts.declarations ?? [declaration],
    serverAccount: signer,
    ports: () => ({ transport: net.port, roster: net.roster.port }),
    logger,
    timers: opts.timers ?? manualTimers,
    worker: { now: clock.now, targetChunkBytes: 4000, maxBlobBytes: 8192 },
  });
  return { db, runtime };
}

function started(h: ReturnType<typeof host>) {
  if (h.runtime.state !== "started") throw new Error(h.runtime.reason);
  const { store, driver } = h.runtime;
  store.registerConnection({
    instance: "conn",
    sourceId: SOURCE,
    method: "export",
    label: "C",
  });
  return {
    ...h.runtime,
    /** A committed local write, with no explicit trigger. */
    write(text: string) {
      store.ingestBatch(
        [
          {
            instance: "conn",
            stream: "messages",
            key: "a",
            data: { id: "a", text },
            emitted_at: at,
          },
        ],
        () => "mutable_state",
        () => ["id"],
        { method: "export", generation: 1 },
      );
    },
    put(text: string) {
      this.write(text);
      void driver.trigger();
    },
    get: () => store.getRecord("conn", "messages", "a")?.data,
  };
}

it("two Node hosts built from retained declarations converge through their drivers", async () => {
  const net = network();
  const a = started(host(net));
  const b = started(host(net));
  a.driver.start();
  b.driver.start();
  a.put("from A");
  for (let i = 0; i < 12 && b.get()?.text !== "from A"; i++) {
    clock.advance(10_000);
    await a.driver.trigger();
    await b.driver.trigger();
  }
  expect(b.get()).toEqual({ id: "a", text: "from A" });
  // The owner reader sees the record through the receiver's reader port.
  expect(
    a.reads("owner").getRecord("conn", "messages", "a")?.data,
  ).toMatchObject({ text: "from A" });
  expect(b.driver.status()).toMatchObject({ state: "running" });
  expect(await a.driver.stop(1_000)).toBe(true);
  expect(await b.driver.stop(1_000)).toBe(true);
  expect(a.driver.status().state).toBe("stopped");
}, 60_000);

it("a committed local write steps within the debounce window; an import does not", async () => {
  const net = network();
  const timersA = clockTimers();
  const a = started(host(net, { timers: timersA.timers }));
  const b = started(host(net));
  a.driver.start();
  b.driver.start();
  await settled(a.driver);
  await settled(b.driver);
  // The first baseline journals operations: drain the step it scheduled.
  clock.advance(REPLICA_LOCAL_WRITE_DEBOUNCE_MS);
  timersA.runDue();
  await settled(a.driver);
  const wroteA = vi.spyOn(a.driver, "localWrite");
  const wroteB = vi.spyOn(b.driver, "localWrite");
  timersA.armedSince();
  a.write("from A");
  expect(wroteA).toHaveBeenCalled();
  // Only the debounced step: the idle wake is still 15 min away.
  expect(timersA.armedSince()).toEqual([REPLICA_LOCAL_WRITE_DEBOUNCE_MS]);
  clock.advance(REPLICA_LOCAL_WRITE_DEBOUNCE_MS);
  // A steps only on its own timers from here.
  for (let i = 0; i < 12 && b.get()?.text !== "from A"; i++) {
    timersA.runDue();
    await settled(a.driver);
    await b.driver.trigger();
    clock.advance(10_000);
  }
  expect(b.get()).toEqual({ id: "a", text: "from A" });
  // Imports never append to the journal, so they never schedule a step.
  expect(wroteB).not.toHaveBeenCalled();
  expect(await a.driver.stop(1_000)).toBe(true);
  expect(await b.driver.stop(1_000)).toBe(true);
}, 60_000);

/** Step a started host once: its writer identity, then its first baseline. */
async function baselineOnce(h: ReturnType<typeof host>) {
  const { driver } = started(h);
  const settings = () =>
    h.db.prepare("SELECT 1 FROM pdpp_replica_settings WHERE id = 1").get();
  expect(settings()).toBeUndefined();
  driver.start();
  await driver.trigger();
  expect(await driver.stop(1_000)).toBe(true);
  expect(settings()).toBeDefined();
}

it("a restart with the same declarations reuses the baseline", async () => {
  const net = network();
  const first = host(net);
  await baselineOnce(first);
  const again = createNodeReplication({
    db: first.db,
    owner,
    chainId: REPLICA_TEST_CHAIN_ID,
    declarations: [declaration],
    serverAccount: createTestReplicaSigner(),
    ports: () => ({ transport: net.port, roster: net.roster.port }),
    logger,
    timers: manualTimers,
  });
  expect(again.state).toBe("started");
});

it("waits for the roster before the first baseline", async () => {
  const net = network();
  const db = new Database(join(scratchDirectory("replica-host"), "db.sqlite"));
  // Not registered under the owner: the identity cannot be established yet.
  const runtime = createNodeReplication({
    db,
    owner,
    chainId: REPLICA_TEST_CHAIN_ID,
    declarations: [declaration],
    serverAccount: createTestReplicaSigner(),
    ports: () => ({ transport: net.port, roster: net.roster.port }),
    logger,
    timers: manualTimers,
  });
  if (runtime.state !== "started") throw new Error(runtime.reason);
  runtime.driver.start();
  const report = await runtime.driver.trigger();
  expect(report?.waits).toEqual([
    expect.objectContaining({ id: "writer-identity" }),
  ]);
  expect(
    db.prepare("SELECT 1 FROM pdpp_replica_settings WHERE id = 1").get(),
  ).toBeUndefined();
  expect(await runtime.driver.stop(1_000)).toBe(true);
});

it("a roster that hangs on the first enable waits and is read again", async () => {
  const net = network();
  const db = new Database(join(scratchDirectory("replica-host"), "db.sqlite"));
  const signer = createTestReplicaSigner();
  net.roster.register(signer.address, owner);
  let hang = true;
  const lookups: AbortSignal[] = [];
  // Timers the test fires by hand, so the roster deadline is observable.
  const pending = new Map<number, { ms: number; run: () => void }>();
  let nextTimer = 0;
  const timers: ReplicationTimers = {
    now: clock.now,
    setTimeout: (run, ms) => {
      pending.set(++nextTimer, { ms, run });
      return nextTimer;
    },
    clearTimeout: (handle) => pending.delete(handle as number),
  };
  const runtime = createNodeReplication({
    db,
    owner,
    chainId: REPLICA_TEST_CHAIN_ID,
    declarations: [declaration],
    serverAccount: signer,
    ports: () => ({
      transport: net.port,
      roster: {
        server: (address, call) => {
          if (!hang) return net.roster.port.server(address, call);
          lookups.push(call!.signal!);
          return new Promise(() => {});
        },
      },
    }),
    logger,
    timers,
    worker: { now: clock.now },
  });
  if (runtime.state !== "started") throw new Error(runtime.reason);
  runtime.driver.start();
  const first = runtime.driver.trigger();
  await new Promise((resolve) => setImmediate(resolve));
  expect(runtime.driver.status().stepping).toBe(true);
  const deadline = [...pending.values()].find(
    (timer) => timer.ms === REPLICA_ATTEMPT_TIMEOUT_MS,
  );
  expect(deadline).toBeDefined();
  deadline!.run();
  // `trigger` joined the first step, so one more runs right after it; by
  // then the gateway answers again.
  hang = false;
  const report = await first;
  expect(report?.waits).toEqual([
    expect.objectContaining({ id: "writer-identity" }),
  ]);
  expect(lookups).toHaveLength(1);
  expect(lookups[0]!.aborted).toBe(true);
  await new Promise((resolve) => setTimeout(resolve, 50));
  // The next step read the roster again and went on to the baseline.
  expect(runtime.driver.status().stepping).toBe(false);
  expect(
    db.prepare("SELECT 1 FROM pdpp_replica_settings WHERE id = 1").get(),
  ).toBeDefined();
  expect(await runtime.driver.stop(1_000)).toBe(true);
});

it("blocks without persisting anything it cannot keep", () => {
  const net = network();
  const unsupported = host(net, { chainId: 1 });
  expect(unsupported.runtime).toEqual({
    state: "blocked",
    reason: "unsupported_chain:1",
  });
  const empty = host(net, { declarations: [] });
  expect(empty.runtime).toEqual({
    state: "blocked",
    reason: "no_retained_declarations",
  });
  for (const { db } of [unsupported, empty])
    expect(
      db
        .prepare(
          "SELECT name FROM sqlite_master WHERE name = 'pdpp_replica_settings'",
        )
        .get(),
    ).toBeUndefined();
});

it("refuses a later, different declaration set on a baselined database", async () => {
  const net = network();
  const first = host(net);
  await baselineOnce(first);
  const upgraded = createNodeReplication({
    db: first.db,
    owner,
    chainId: REPLICA_TEST_CHAIN_ID,
    declarations: [{ ...declaration, version: "2" }],
    serverAccount: createTestReplicaSigner(),
    ports: () => ({ transport: net.port, roster: net.roster.port }),
    logger,
    timers: manualTimers,
  });
  expect(upgraded).toEqual({
    state: "blocked",
    reason: "replication binding is immutable",
  });
});
