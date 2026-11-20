// Erasure of a deleted connection's log objects against a log the real
// publisher wrote: real segments, a real compaction into snapshot parts, and a
// record whose body is stored out of line in pieces. The registry is the
// fake gateway the publisher commits to; storage is its in-memory store.
import { afterEach, describe, expect, it, vi } from "vitest";
import { logScope } from "@opendatalabs/personal-server-ts-stream-sync";
import { createConnectionDeleter } from "../../../core/src/localdb/index.js";
import {
  eraseDeletedConnectionLogs,
  type LogErasureDeps,
  type LogErasurePorts,
} from "../../../core/src/localdb/log-erase.js";
import {
  CONNECTOR,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const LOG = logScope(CONNECTOR, "");
const OTHER = "other";
const OTHER_LOG = logScope(OTHER, "");
// Compaction fires once a catch-up through a snapshot repays building it. A
// small part target makes the snapshot many parts, each a costly PUT, so the
// rule would never fire; this is large enough for it to, and a record three
// targets long is stored out of line, in pieces.
const PART_TARGET = 65536;

/**
 * A log that has compacted once and holds an out-of-line body, a second
 * connector's log beside it, and the delete of the first connector (fence
 * landed).
 */
async function deletedCompactedLog() {
  const w = await world({ streams: 1, partTargetBytes: PART_TARGET });
  const a = await w.device("a");
  await a.run(
    "run-1",
    [
      // Over the part target: its body goes out of line, in pieces.
      { stream: sName(0), id: "big", pad: PART_TARGET * 2 + 1000 },
      { stream: sName(0), id: "x", v: 0 },
    ],
    { observedAt: 1100 },
  );
  await a.cycle();
  await a.run(
    "other-1",
    [{ stream: sName(0), id: "o", pad: PART_TARGET * 2 + 1000 }],
    {
      connector: OTHER,
      observedAt: 1100,
    },
  );
  await a.cycle();
  for (let i = 0; i < 400; i++) {
    const segments = await w.segments();
    const head = segments.get(Math.max(...segments.keys()))!;
    if (head.snapshot !== null) break;
    await a.run(`grow-${i}`, [{ stream: sName(0), id: "x", v: i + 1 }], {
      full: false,
      covered: [sName(0)],
      observedAt: 2000 + i,
    });
    await a.cycle();
  }
  const keys = (prefix: string) =>
    w.innerBlobs.keys().filter((key) => key.startsWith(`${prefix}/`));
  const before = keys(LOG);
  expect(before.some((k) => k.includes("/s-"))).toBe(true);
  expect(before.some((k) => k.includes("/q-"))).toBe(true);
  expect(before.some((k) => k.includes("/v-"))).toBe(true);

  const answer = await a.sync.deleter.requestConnectionDelete(CONNECTOR);
  expect(answer.fenced).toBe(true);

  const calls: string[][] = [];
  const deps = (overrides: Partial<LogErasureDeps> = {}): LogErasureDeps => ({
    registry: a.deps.registry,
    versions: {
      list: async (scope) => ({
        complete: true,
        versions: (w.gateway.versions.get(scope) ?? []).map((v, i) => ({
          expectedVersion: String(i + 1),
          dataHash: v.dataHash,
          isTombstone: false,
        })),
      }),
    },
    finality: {
      tombstoneState: async () => ({ finalized: "99", rolledBack: null }),
    },
    blobs: a.deps.blobs,
    keys: a.deps.keys,
    objects: {
      deleteBlobVersions: async (scope, names) => {
        calls.push([...names]);
        const out = {
          deleted: [] as string[],
          missing: [] as string[],
          failed: [] as { version: string; error: string }[],
        };
        for (const name of names)
          (w.innerBlobs.delete(`${scope}/${name}`)
            ? out.deleted
            : out.missing
          ).push(name);
        return out;
      },
    },
    logger: { info() {}, warn() {} },
    ...overrides,
  });
  return { w, a, keys, before, deps, calls };
}

describe("erasing a log the real publisher wrote", () => {
  it("removes every segment, snapshot part and body piece of the deleted connection and none of another", async () => {
    const { keys, before, deps, calls } = await deletedCompactedLog();
    const otherBefore = keys(OTHER_LOG);
    expect(otherBefore.length).toBeGreaterThan(0);

    const report = await eraseDeletedConnectionLogs(deps(), {
      connector: CONNECTOR,
    });

    expect(report.pending).toBe(false);
    expect(report.connections).toHaveLength(1);
    expect(report.connections[0]!.outcome).toEqual({
      kind: "erased",
      deleted: before.length,
      unenumerated: 0,
    });
    expect(keys(LOG)).toEqual([]);
    expect(keys(OTHER_LOG)).toEqual(otherBefore);
    // Pieces, then parts, then segments; the newest segment is the last call.
    const order = calls.flat().map((name) => name[0]);
    expect(order).toEqual(
      [...order].sort((x, y) => "vqs".indexOf(x!) - "vqs".indexOf(y!)),
    );
  });

  it("finishes after a storage failure part-way, with nothing remembered between the passes", async () => {
    const { w, keys, before, deps } = await deletedCompactedLog();
    let failures = 0;
    const flaky = deps();
    const delegate = flaky.objects;
    const failing: LogErasureDeps = {
      ...flaky,
      objects: {
        deleteBlobVersions: async (scope, names) => {
          // The second request of the pass fails for every name in it.
          if (++failures === 2)
            return {
              deleted: [],
              missing: [],
              failed: names.map((version) => ({ version, error: "503" })),
            };
          return delegate.deleteBlobVersions(scope, names);
        },
      },
    };

    const first = await eraseDeletedConnectionLogs(failing);
    expect(first.pending).toBe(true);
    const left = keys(LOG);
    expect(left.length).toBeGreaterThan(0);
    expect(left.length).toBeLessThan(before.length);
    // Every segment is still there: they name what is left.
    expect(left.filter((k) => k.includes("/s-")).length).toBe(
      before.filter((k) => k.includes("/s-")).length,
    );

    // A restart: a fresh pass over the same registry and storage.
    const second = await eraseDeletedConnectionLogs(deps());
    expect(second.pending).toBe(false);
    expect(keys(LOG)).toEqual([]);
    void w;
  });

  it("leaves the log alone before the control tombstone is final", async () => {
    const { keys, before, deps, calls } = await deletedCompactedLog();
    const report = await eraseDeletedConnectionLogs(
      deps({
        finality: {
          tombstoneState: async () => ({ finalized: null, rolledBack: null }),
        },
      }),
    );
    expect(report.pending).toBe(true);
    expect(calls).toEqual([]);
    expect(keys(LOG)).toEqual(before);
  });
});

describe("erasure wired into the connection delete", () => {
  const RETRY = { first: 5, max: 20 };
  type World = Awaited<ReturnType<typeof world>>;

  /** The host's erasure ports over a world: its gateway inventory and its storage. */
  function ports(w: World, state: { finalized: string | null }) {
    const deleted: string[] = [];
    const erasure: LogErasurePorts = {
      versions: {
        list: async (scope) => ({
          complete: true,
          versions: (w.gateway.versions.get(scope) ?? []).map((v, i) => ({
            expectedVersion: String(i + 1),
            dataHash: v.dataHash,
            isTombstone: false,
          })),
        }),
      },
      finality: {
        tombstoneState: async () => ({
          finalized: state.finalized,
          rolledBack: null,
        }),
      },
      objects: {
        deleteBlobVersions: async (scope, names) => {
          deleted.push(...names);
          const out = {
            deleted: [] as string[],
            missing: [] as string[],
            failed: [] as { version: string; error: string }[],
          };
          for (const name of names)
            (w.innerBlobs.delete(`${scope}/${name}`)
              ? out.deleted
              : out.missing
            ).push(name);
          return out;
        },
      },
    };
    return { erasure, deleted };
  }
  const logKeys = (w: World, scope: string) =>
    w.innerBlobs.keys().filter((key) => key.startsWith(`${scope}/`));
  const big = { stream: sName(0), id: "big", pad: PART_TARGET * 2 + 1000 };

  /** A device that collected `big` for two connectors, published, and the world. */
  async function collected(state: { finalized: string | null }) {
    const w = await world({ streams: 1, partTargetBytes: PART_TARGET });
    const { erasure, deleted } = ports(w, state);
    const a = await w.device("a", {
      erasure: () => erasure,
      deleteRetryMs: RETRY,
    });
    await a.run("run-1", [big], { observedAt: 1100 });
    await a.cycle();
    await a.run("other-1", [{ ...big, id: "o" }], {
      connector: OTHER,
      observedAt: 1100,
    });
    await a.cycle();
    expect(logKeys(w, LOG).some((k) => k.includes("/v-"))).toBe(true);
    return { w, a, deleted, erasure };
  }
  const intents = (a: Awaited<ReturnType<World["device"]>>) =>
    a.db.query("SELECT 1 FROM delete_intents");

  it("erases the deleted connection's log objects once its delete settles, and no other connection's", async () => {
    const { w, a } = await collected({ finalized: "99" });
    const otherBefore = logKeys(w, OTHER_LOG);
    expect(otherBefore.length).toBeGreaterThan(0);

    expect(
      (await a.sync.deleter.requestConnectionDelete(CONNECTOR)).fenced,
    ).toBe(true);

    await vi.waitFor(() => expect(logKeys(w, LOG)).toEqual([]));
    expect(logKeys(w, OTHER_LOG)).toEqual(otherBefore);
    expect(await intents(a)).toEqual([]);
  });

  it("erases nothing while the control tombstone is not final, and finishes once it is", async () => {
    const state: { finalized: string | null } = { finalized: null };
    const { w, a, deleted } = await collected(state);
    const before = logKeys(w, LOG);

    await a.sync.deleter.requestConnectionDelete(CONNECTOR);
    await vi.waitFor(async () => expect(await intents(a)).toEqual([]));
    // The retry loop asks again and again; each time the tombstone is not final.
    await new Promise((resolve) => setTimeout(resolve, 80));
    expect(deleted).toEqual([]);
    expect(logKeys(w, LOG)).toEqual(before);

    state.finalized = "99";
    await vi.waitFor(() => expect(logKeys(w, LOG)).toEqual([]));
  });

  it("never erases a connection added again after its delete, though the old tombstone is final", async () => {
    const state: { finalized: string | null } = { finalized: null };
    const { w, a, deleted } = await collected(state);

    await a.sync.deleter.requestConnectionDelete(CONNECTOR);
    await vi.waitFor(async () => expect(await intents(a)).toEqual([]));
    await a.run("run-2", [big], { connect: true, observedAt: 1200 });
    await a.cycle();
    const readded = logKeys(w, LOG);

    state.finalized = "99";
    await new Promise((resolve) => setTimeout(resolve, 80));

    expect(deleted).toEqual([]);
    expect(logKeys(w, LOG)).toEqual(readded);
    const b = await w.device("b");
    await b.cycle();
    expect(await b.records()).toEqual(await a.records());
  });

  it("erases a delete another device wrote once this device has adopted it", async () => {
    const state = { finalized: "99" };
    const w = await world({ streams: 1, partTargetBytes: PART_TARGET });
    const { erasure } = ports(w, state);
    // The deleting device cannot erase from storage (a phone); the adopting one can.
    const phone = await w.device("phone");
    const desktop = await w.device("desktop", {
      erasure: () => erasure,
      deleteRetryMs: RETRY,
    });
    await phone.run("run-1", [big], { observedAt: 1100 });
    await phone.cycle();
    await desktop.cycle();
    expect(await desktop.records()).not.toEqual([]);
    expect(logKeys(w, LOG).length).toBeGreaterThan(0);

    await phone.sync.deleter.requestConnectionDelete(CONNECTOR);
    await vi.waitFor(async () => expect(await intents(phone)).toEqual([]));
    expect(logKeys(w, LOG).length).toBeGreaterThan(0);

    await desktop.cycle();
    await vi.waitFor(() => expect(logKeys(w, LOG)).toEqual([]));
  });

  it("does nothing for a delete this device has not adopted yet", async () => {
    const state = { finalized: "99" };
    const w = await world({ streams: 1, partTargetBytes: PART_TARGET });
    const { erasure, deleted } = ports(w, state);
    const phone = await w.device("phone");
    const desktop = await w.device("desktop", {
      erasure: () => erasure,
      deleteRetryMs: RETRY,
    });
    await phone.run("run-1", [big], { observedAt: 1100 });
    await phone.cycle();
    await desktop.cycle();
    await phone.sync.deleter.requestConnectionDelete(CONNECTOR);
    await vi.waitFor(async () => expect(await intents(phone)).toEqual([]));

    // The desktop has not looked at the registry since: its connection is live.
    await desktop.sync.deleter.resumeDeletes();
    await new Promise((resolve) => setTimeout(resolve, 80));
    expect(deleted).toEqual([]);
    expect(logKeys(w, LOG).length).toBeGreaterThan(0);
  });

  describe("the gate on a delete that has not settled here", () => {
    const owed = async (a: Awaited<ReturnType<World["device"]>>) => {
      const eraseLogs = vi.fn(async () => ({
        connections: [],
        pending: false,
      }));
      const deleter = createConnectionDeleter(a.deps, { eraseLogs });
      // The sweep that runs first once per process, then the owed connector.
      await deleter.resumeErasures();
      eraseLogs.mockClear();
      deleter.noteSettled(CONNECTOR);
      await deleter.resumeErasures();
      return eraseLogs;
    };

    it("does not erase while a local connection of the connector is live", async () => {
      const { a } = await collected({ finalized: "99" });
      expect(await owed(a)).not.toHaveBeenCalled();
    });

    it("does not erase while a delete of the connector is in flight", async () => {
      const { a } = await collected({ finalized: "99" });
      await a.sync.deleter.requestConnectionDelete(CONNECTOR);
      await vi.waitFor(async () => expect(await intents(a)).toEqual([]));
      await a.db.batch([
        {
          sql: "INSERT INTO delete_intents(connector,delete_id,intent) VALUES (?,?,?)",
          params: [CONNECTOR, "again", JSON.stringify({ pins: [] })],
        },
      ]);
      expect(await owed(a)).not.toHaveBeenCalled();
    });

    it("erases once the delete is settled: every local connection purged and no intent", async () => {
      const { a } = await collected({ finalized: "99" });
      await a.sync.deleter.requestConnectionDelete(CONNECTOR);
      await vi.waitFor(async () => expect(await intents(a)).toEqual([]));
      expect(await owed(a)).toHaveBeenCalledTimes(1);
    });
  });
});
