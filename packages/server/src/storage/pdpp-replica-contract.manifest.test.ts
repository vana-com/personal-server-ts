/**
 * Replica contract suite, manifest carrier: one registration per device sync.
 * A sync stores its fragments unregistered at content addresses and registers
 * one manifest at the next version of the writer's single scope. A receiver
 * trusts a fragment only through the finalized manifest that names its digest.
 * Runs the REAL transport worker and receiver over the fake Gateway, chain and
 * storage of the contract harness, which count every registration.
 */
import { afterEach, describe, expect, it } from "vitest";
import { replicaScope } from "@opendatalabs/personal-server-ts-core/replication/transport";
import {
  CrashController,
  checkpoint,
  clock,
  cleanupHarness,
  network,
  slotKey,
  transportDevice,
  transportInvariantViolations,
  type Network,
  type TransportDevice,
} from "./pdpp-replica-contract.test-utils.js";

afterEach(cleanupHarness);

const NIGHTLY = process.env.REPLICA_ORACLE_NIGHTLY === "1";

const writerOf = (d: TransportDevice) =>
  (
    d.db
      .prepare("SELECT writer FROM pdpp_transport_state WHERE id=1")
      .get() as {
      writer: string;
    }
  ).writer;
const scopeOf = (d: TransportDevice) => replicaScope(writerOf(d));
/** Fragment objects stored since the last `forget`, without repeats. */
const fragmentKeys = (net: Network) => [
  ...new Set(net.calls.puts.filter((k) => k.includes("/fragments/"))),
];
/** Registrations of this device's scope since the last `forget`. */
const registrationsBy = (net: Network, d: TransportDevice) =>
  net.calls.registrations.filter((k) => k.startsWith(`${scopeOf(d)}/`));
/** Clear call logs, so a test counts only the sync it makes. */
function forget(net: Network) {
  for (const log of [net.calls.puts, net.calls.gets, net.calls.registrations])
    log.length = 0;
}
const slotRow = (d: TransportDevice, slot: string) =>
  d.db
    .prepare(
      "SELECT state,reason FROM pdpp_transport_manifests_in WHERE slot=?",
    )
    .get(slot) as { state: string; reason: string | null } | undefined;
async function steps(devices: TransportDevice[], n = 4) {
  for (let i = 0; i < n; i++) {
    clock.advance(10_000);
    for (const d of devices) await d.step();
  }
}
/** One sync of `records` records of about `size` bytes each, before any step. */
function write(d: TransportDevice, records: number, size = 600, tag = "") {
  for (let i = 0; i < records; i++)
    d.put(`${tag}${i}:${"r".repeat(size)}`, `${tag}${i}`);
}
/**
 * A sender past its first publication. A new device first publishes its
 * baseline batch (version 1); baseline and tail never share a batch. Its tail
 * syncs then take versions 2, 3, ... The target chunk is small, so one sync of
 * a few records spans several fragments under the harness storage cap.
 */
async function sender(
  net: Network,
  opts: Parameters<typeof transportDevice>[1] = {},
) {
  const d = transportDevice(net, { chunk: 1000, ...opts });
  await d.step();
  expect(net.registrationsOf(scopeOf(d)), "baseline published").toBe(1);
  forget(net);
  return d;
}

describe("one registration per device sync", () => {
  it("a sync of N fragments costs exactly one registration", async () => {
    const net = network();
    const a = await sender(net);
    write(a, 12);
    await a.step();
    const fragments = fragmentKeys(net);
    expect(
      fragments.length,
      "the sync spans several fragments",
    ).toBeGreaterThan(5);
    expect(net.calls.registrations).toEqual([slotKey(scopeOf(a), 2)]);
    // Fragments are content-addressed and never registered.
    expect([...net.head.keys()]).toEqual(
      [1, 2].map((v) => slotKey(scopeOf(a), v)),
    );

    const b = transportDevice(net);
    await steps([b]);
    for (let i = 0; i < 12; i++)
      expect(b.get(String(i))).toEqual({
        id: String(i),
        text: `${i}:${"r".repeat(600)}`,
      });
    expect(registrationsBy(net, a), "receiving never registers").toHaveLength(
      1,
    );
  });

  it("each later sync appends one version to the same scope, and the receiver imports them in order", async () => {
    const net = network();
    const a = await sender(net);
    const b = transportDevice(net);
    for (let sync = 1; sync <= 3; sync++) {
      write(a, 4, 600, `s${sync}-`);
      await a.step();
      await steps([b], 2);
      expect(b.get(`s${sync}-3`)).toBeDefined();
    }
    expect(registrationsBy(net, a)).toEqual(
      [2, 3, 4].map((v) => slotKey(scopeOf(a), v)),
    );
  });

  it("two devices use separate scopes, so their versions never contend", async () => {
    const net = network();
    const a = await sender(net);
    const c = await sender(net, { instance: "conn" });
    write(a, 3, 600, "a");
    write(c, 3, 600, "c");
    await a.step();
    await c.step();
    expect(scopeOf(a)).not.toBe(scopeOf(c));
    expect([...net.calls.registrations].sort()).toEqual(
      [slotKey(scopeOf(a), 2), slotKey(scopeOf(c), 2)].sort(),
    );
    const b = transportDevice(net);
    await steps([b]);
    expect(b.get("a2")).toBeDefined();
    expect(b.get("c2")).toBeDefined();
  });

  it("operations retained while a registration awaits finality join one later batch", async () => {
    const net = network();
    const a = await sender(net);
    const pend = net.port.register;
    net.port.register = async (manifest) => {
      net.pending.add(slotKey(manifest.scope, manifest.version));
      return pend(manifest);
    };
    write(a, 2, 100, "first");
    await a.step();
    expect(net.calls.registrations).toHaveLength(1);
    // Three more local syncs while the first registration is not final.
    for (let i = 0; i < 3; i++) {
      write(a, 2, 100, `later${i}-`);
      await steps([a], 1);
    }
    expect(
      net.calls.registrations,
      "no batch is cut while one is in flight",
    ).toHaveLength(1);
    net.port.register = pend;
    net.finalizeAll();
    await steps([a], 2);
    expect(net.calls.registrations).toEqual([
      slotKey(scopeOf(a), 2),
      slotKey(scopeOf(a), 3),
    ]);
    const b = transportDevice(net);
    await steps([b]);
    for (let i = 0; i < 3; i++) expect(b.get(`later${i}-1`)).toBeDefined();
  });

  it("bounds the operations and bytes one batch covers", async () => {
    const net = network();
    const a = await sender(net, { worker: { maxBatchOperations: 3 } });
    write(a, 7, 50);
    await steps([a], 4);
    expect(net.calls.registrations).toHaveLength(3);
    const net2 = network();
    const c = await sender(net2, { worker: { maxBatchBytes: 2500 } });
    write(c, 6, 600);
    await steps([c], 6);
    // About 4 records fit 2500 bytes; never fewer than one per batch.
    expect(net2.calls.registrations.length).toBeGreaterThanOrEqual(2);
    expect(net2.calls.registrations.length).toBeLessThanOrEqual(6);
    for (const d of [transportDevice(net), transportDevice(net2)]) {
      await steps([d], 5);
      expect(d.get("5")).toBeDefined();
    }
  });
});

describe("a fragment is trusted only through its finalized manifest", () => {
  async function published() {
    const net = network();
    const a = await sender(net);
    write(a, 8);
    await a.step();
    const fragments = fragmentKeys(net);
    expect(fragments.length).toBeGreaterThan(2);
    return { net, a, slot: slotKey(scopeOf(a), 2), fragments };
  }

  it("a tampered fragment is quarantined and nothing of its batch becomes visible", async () => {
    const { net, a, slot, fragments } = await published();
    const target = fragments[1]!;
    const original = net.blobs.get(target)!;
    // Storage PUT overwrites without checks: another object at this address.
    net.blobs.set(target, net.blobs.get(fragments[0]!)!);
    const b = transportDevice(net);
    await steps([b]);
    expect(slotRow(b, slot)).toEqual({
      state: "quarantined",
      reason: "fragment_mismatch",
    });
    for (let i = 0; i < 8; i++) expect(b.get(String(i))).toBeUndefined();
    // Quarantine is terminal until the owner re-admits after a repair.
    await steps([b], 3);
    expect(slotRow(b, slot)?.state).toBe("quarantined");
    net.blobs.set(target, original);
    expect(b.worker.readmitFragments()).toBe(1);
    await steps([b]);
    expect(b.get("7")).toBeDefined();
    expect(registrationsBy(net, a)).toHaveLength(1);
    expect(a.get("7")).toBeDefined();
  });

  it("flipped bytes of the right length are a mismatch, never decrypted", async () => {
    const { net, slot, fragments } = await published();
    const bytes = new Uint8Array(net.blobs.get(fragments[0]!)!);
    bytes[20] ^= 1;
    net.blobs.set(fragments[0]!, bytes);
    const decrypt = net.port.decrypt;
    const decrypted: number[] = [];
    net.port.decrypt = async (scope, data) => {
      decrypted.push(data.length);
      return decrypt(scope, data);
    };
    const b = transportDevice(net);
    await steps([b]);
    expect(slotRow(b, slot)?.reason).toBe("fragment_mismatch");
    expect(decrypted).not.toContain(bytes.length);
    expect(b.get("0")).toBeUndefined();
  });

  it("a missing fragment is quarantined and nothing of its batch becomes visible", async () => {
    const { net, slot, fragments } = await published();
    net.blobs.delete(fragments.at(-1)!);
    const b = transportDevice(net);
    await steps([b]);
    expect(slotRow(b, slot)).toEqual({
      state: "quarantined",
      reason: "fragment_missing",
    });
    for (let i = 0; i < 8; i++) expect(b.get(String(i))).toBeUndefined();
  });

  it("a transient storage failure is a retry, never a quarantine", async () => {
    const { net, slot, fragments } = await published();
    let failures = 2;
    net.faults.get = (key) =>
      key === fragments[0] && failures-- > 0 ? new Error("503") : undefined;
    const b = transportDevice(net);
    await steps([b], 1);
    expect(slotRow(b, slot)?.state).toBe("ready");
    await steps([b], 4);
    expect(b.get("7")).toBeDefined();
  });

  it("a manifest whose bytes are not the finalized commitment is refetched, never trusted", async () => {
    const { net, slot } = await published();
    const original = net.blobs.get(slot)!;
    net.blobs.set(slot, new Uint8Array(original.length).fill(7));
    const b = transportDevice(net);
    await steps([b], 2);
    expect(slotRow(b, slot)?.state).toBe("ready");
    expect(b.get("0")).toBeUndefined();
    net.blobs.set(slot, original);
    await steps([b], 4);
    expect(b.get("7")).toBeDefined();
  });

  it("nothing is fetched before the manifest registration is finalized", async () => {
    const net = network();
    const a = await sender(net);
    const register = net.port.register;
    net.port.register = async (manifest) => {
      net.pending.add(slotKey(manifest.scope, manifest.version));
      return register(manifest);
    };
    write(a, 4);
    await a.step();
    const b = transportDevice(net);
    await steps([b], 3);
    const synced = new Set([slotKey(scopeOf(a), 2), ...fragmentKeys(net)]);
    expect(net.calls.gets.filter((k) => synced.has(k))).toEqual([]);
    expect(b.get("0")).toBeUndefined();
    net.finalizeAll();
    await steps([b], 3);
    expect(b.get("3")).toBeDefined();
  });
});

describe("retries and crashes never register twice", () => {
  it("a lost registration acknowledgement and its retry register once", async () => {
    const net = network();
    const a = await sender(net);
    write(a, 6);
    net.faults.loseRegistrationResponse = true;
    await a.step();
    expect(net.calls.registrations).toHaveLength(1);
    await steps([a], 3);
    expect(net.calls.registrations).toHaveLength(1);
    const manifest = a.db
      .prepare(
        "SELECT state,version FROM pdpp_transport_manifests_out WHERE version=2",
      )
      .get();
    expect(manifest).toEqual({ state: "published", version: 2 });
    const b = transportDevice(net);
    await steps([b]);
    expect(b.get("5")).toBeDefined();
  });

  /**
   * A sender with one unpublished sync of six records, and a receiver that
   * already holds the sender's baseline. `run` puts both devices and the
   * network back to that state, kills the sender at trace point `crashAt` of
   * one step, and restarts it as a new process.
   */
  async function crashWorld() {
    const crash = new CrashController();
    const net = network({ crash });
    const a = await sender(net, {
      crash,
      worker: { registrationIntentTimeoutMs: 5_000 },
    });
    const r = transportDevice(net);
    await steps([a, r], 2);
    forget(net);
    write(a, 6);
    const restore = checkpoint(net, [a, r], crash);
    async function run(crashAt: number | undefined) {
      restore();
      crash.arm(crashAt);
      try {
        await a.step();
      } catch {
        // process loss; only durable state survives the restart
      }
      const died = crash.dead;
      a.crashReopen();
      return { died, trace: [...crash.trace] };
    }
    return { net, a, r, run };
  }
  type World = Awaited<ReturnType<typeof crashWorld>>;

  async function provesCrashPoint(world: World, point: number, label: string) {
    const { net, a, r } = world;
    const where = `crash point ${point} (${label})`;
    expect((await world.run(point)).died, where).toBe(true);
    expect(transportInvariantViolations(a), where).toEqual([]);
    // Before the sender recovers, the receiver sees none or all of the sync.
    await steps([r], 2);
    const seen = [0, 1, 2, 3, 4, 5].filter((i) => r.get(String(i))).length;
    expect([0, 6], `${where}: ${seen} of 6 records visible`).toContain(seen);
    await steps([a], 3);
    expect(registrationsBy(net, a), where).toEqual([slotKey(scopeOf(a), 2)]);
    await steps([r], 3);
    expect(r.get("5"), where).toBeDefined();
  }

  const lastIndex = (trace: string[], test: (label: string) => boolean) =>
    trace.reduce((last, label, i) => (test(label) ? i : last), -1);

  it("a crash between fragment upload and manifest registration leaves no visible batch and the retry registers once", async () => {
    const world = await crashWorld();
    const { trace } = await world.run(undefined);
    const lastFragment = lastIndex(
      trace,
      (l) => l.startsWith("net-after-put:") && l.includes("/fragments/"),
    );
    const register = trace.findIndex((l) =>
      l.startsWith("net-before-register:"),
    );
    expect(lastFragment).toBeGreaterThan(-1);
    expect(register).toBeGreaterThan(lastFragment);
    for (const point of [lastFragment, register - 1, register])
      await provesCrashPoint(world, point, trace[point]!);
  }, 30_000);

  it("a crash just after the registration commits does not register again", async () => {
    const world = await crashWorld();
    const { trace } = await world.run(undefined);
    const after = trace.findIndex((l) => l.startsWith("net-after-register:"));
    expect(after).toBeGreaterThan(-1);
    await provesCrashPoint(world, after, trace[after]!);
  }, 30_000);

  // Nightly (REPLICA_ORACLE_NIGHTLY=1): every crash point of one step, the
  // sender's own receive phases included. Pull requests run the points above.
  it.runIf(NIGHTLY)(
    "every crash point of a multi-fragment sync",
    async () => {
      const world = await crashWorld();
      const { trace } = await world.run(undefined);
      expect(trace.length).toBeGreaterThan(100);
      for (let point = 0; point < trace.length; point++)
        await provesCrashPoint(world, point, trace[point]!);
    },
    900_000,
  );
});
