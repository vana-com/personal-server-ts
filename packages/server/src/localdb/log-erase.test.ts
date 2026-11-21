// Erasure of a deleted connection's log objects against a log the real
// publisher wrote: real segments, a real compaction into snapshot parts, and a
// record whose body is stored out of line in pieces. The registry is the
// fake gateway the publisher commits to; storage is its in-memory store.
import { afterEach, describe, expect, it, vi } from "vitest";
import { logScope } from "@opendatalabs/personal-server-ts-stream-sync";
import { createConnectionDeleter } from "../../../core/src/localdb/index.js";
import {
  onConnectionPurged,
  purgeConnection,
} from "../../../core/src/localdb/purge.js";
import {
  eraseDeletedConnectionLogs,
  retainedPiecesIn,
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
    retained: retainedPiecesIn(a.db),
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
  /** The body pieces of a log, as storage holds them. */
  const pieces = (prefix: string) =>
    keys(prefix).filter((key) => key.includes("/v-"));
  /** The piece names the erasure wrote down, as `<scope>/<name>`. */
  const recorded = async () =>
    (
      await a.db.query<{ scope: string; name: string }>(
        "SELECT scope, name FROM retained_log_pieces ORDER BY scope, name",
      )
    ).map((row) => `${row.scope}/${row.name}`);
  return { w, a, keys, pieces, recorded, before, deps, calls };
}

describe("erasing a log the real publisher wrote", () => {
  it("removes every segment and snapshot part of the deleted connection, leaves its body pieces and writes their names down, and touches none of another", async () => {
    const { keys, pieces, recorded, before, deps, calls } =
      await deletedCompactedLog();
    const otherBefore = keys(OTHER_LOG);
    expect(otherBefore.length).toBeGreaterThan(0);
    const bodyPieces = pieces(LOG);
    expect(bodyPieces.length).toBeGreaterThan(0);

    const report = await eraseDeletedConnectionLogs(deps(), {
      connector: CONNECTOR,
    });

    expect(report.pending).toBe(false);
    expect(report.connections).toHaveLength(1);
    expect(report.connections[0]!.outcome).toEqual({
      kind: "erased",
      deleted: before.length - bodyPieces.length,
      retained: bodyPieces.length,
      unenumerated: 0,
    });
    // Only the body pieces are left, and every one of them is on record.
    expect(keys(LOG)).toEqual(bodyPieces);
    expect(await recorded()).toEqual([...bodyPieces].sort());
    expect(keys(OTHER_LOG)).toEqual(otherBefore);
    // Parts, then segments; no piece is ever sent to storage's DELETE.
    const order = calls.flat().map((name) => name[0]);
    expect(order).toEqual(
      [...order].sort((x, y) => "qs".indexOf(x!) - "qs".indexOf(y!)),
    );
    expect(order).not.toContain("v");
  });

  it("finishes after a storage failure part-way, with nothing remembered between the passes", async () => {
    const { w, keys, pieces, before, deps } = await deletedCompactedLog();
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
    expect(keys(LOG)).toEqual(pieces(LOG));
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
  function ports(
    w: World,
    state: { finalized: string | null },
    hooks: { beforeFirstDelete?: () => Promise<void> } = {},
  ) {
    const deleted: string[] = [];
    let first = true;
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
          // The storage DELETE is slow: whatever happens "meanwhile" lands
          // after the pass's last look at the registry and before the DELETE.
          if (first) {
            first = false;
            await hooks.beforeFirstDelete?.();
          }
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
  /** What is left of a log once its segments and parts are gone: body pieces. */
  const erasable = (w: World, scope: string) =>
    logKeys(w, scope).filter((key) => !key.includes("/v-"));
  const big = { stream: sName(0), id: "big", pad: PART_TARGET * 2 + 1000 };

  /** A device that collected `big` for two connectors, published, and the world. */
  async function collected(
    state: { finalized: string | null },
    hooks: { beforeFirstDelete?: () => Promise<void> } = {},
  ) {
    const w = await world({ streams: 1, partTargetBytes: PART_TARGET });
    const { erasure, deleted } = ports(w, state, hooks);
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

    await vi.waitFor(() => expect(erasable(w, LOG)).toEqual([]));
    expect(logKeys(w, OTHER_LOG)).toEqual(otherBefore);
    expect(await intents(a)).toEqual([]);
    // What storage still holds of the log is on record, in the device's database.
    const left = logKeys(w, LOG).map((key) => key.slice(LOG.length + 1));
    expect(left.length).toBeGreaterThan(0);
    expect(
      (
        await a.db.query<{ name: string }>(
          "SELECT name FROM retained_log_pieces WHERE scope = ? ORDER BY name",
          [LOG],
        )
      ).map((row) => row.name),
    ).toEqual(left.sort());
  });

  it("never deletes a piece a connection added again re-collects, even when its commit lands after the pass's last tombstone check", async () => {
    // The re-add collects the same large record: its body pieces carry the
    // names of the deleted lifetime's, and storage keeps the first bytes of a
    // name, so its upload is answered by the old copies.
    let readd: () => Promise<void> = async () => {};
    const { w, a, deleted } = await collected(
      { finalized: "99" },
      { beforeFirstDelete: () => readd() },
    );
    readd = async () => {
      await a.run("run-2", [big], { connect: true, observedAt: 1200 });
      await a.cycle();
    };

    await a.sync.deleter.requestConnectionDelete(CONNECTOR);
    await vi.waitFor(() => expect(deleted.length).toBeGreaterThan(0));
    await new Promise((resolve) => setTimeout(resolve, 80));

    // No body piece is ever sent to storage's DELETE.
    expect(deleted.filter((name) => name.startsWith("v-"))).toEqual([]);
    // The new lifetime's log still reads on a device that never saw the old one.
    const b = await w.device("b");
    await b.cycle();
    expect(await b.records()).toEqual(await a.records());
    expect(await b.records()).not.toEqual([]);
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
    await vi.waitFor(() => expect(erasable(w, LOG)).toEqual([]));
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
    await vi.waitFor(() => expect(erasable(w, LOG)).toEqual([]));
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

  describe("the erasure's own bookkeeping", () => {
    const settled = async () => {
      const c = await collected({ finalized: "99" });
      await c.a.sync.deleter.requestConnectionDelete(CONNECTOR);
      await vi.waitFor(async () => expect(await intents(c.a)).toEqual([]));
      return c.a;
    };
    const none = { connections: [], pending: false } as const;

    it("a delete noted while an erasure runs is erased by a pass that starts after it", async () => {
      const a = await settled();
      let release: () => void = () => {};
      const eraseLogs = vi
        .fn()
        .mockImplementationOnce(
          () => new Promise((resolve) => (release = () => resolve(none))),
        )
        .mockResolvedValue(none);
      const deleter = createConnectionDeleter(a.deps, { eraseLogs });
      deleter.noteSettled(CONNECTOR);
      const first = deleter.resumeErasures();
      await vi.waitFor(() => expect(eraseLogs).toHaveBeenCalledTimes(1));

      // The connection is added again and deleted again: the second delete is
      // purged here while the first pass runs, and the retry loop looks at it.
      deleter.noteSettled(CONNECTOR);
      const second = deleter.resumeErasures();
      // The first pass ends as it would for a tombstone that moved: not pending.
      release();
      await Promise.all([first, second]);

      expect(eraseLogs).toHaveBeenCalledTimes(2);
      expect(deleter.erasureOwed()).toBe(false);
    });

    it("a retry that finds a pass running waits for it and reports what it leaves unfinished", async () => {
      const a = await settled();
      let release: () => void = () => {};
      const eraseLogs = vi.fn().mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            release = () => resolve({ connections: [], pending: true });
          }),
      );
      const deleter = createConnectionDeleter(a.deps, { eraseLogs });
      deleter.noteSettled(CONNECTOR);
      const first = deleter.resumeErasures();
      await vi.waitFor(() => expect(eraseLogs).toHaveBeenCalledTimes(1));
      // The running pass has taken the queue entry: the retry loop sees none.
      const second = deleter.resumeErasures();
      release();
      // Both answer true: the pass ended pending, and the loop must run again.
      expect(await Promise.all([first, second])).toEqual([true, true]);
      expect(eraseLogs).toHaveBeenCalledTimes(1);
    });

    it("a failed first sweep query is tried again, not skipped", async () => {
      const a = await settled();
      let failing = true;
      const db = {
        ...a.db,
        query: ((sql: string, params?: readonly unknown[]) => {
          if (failing && sql.includes("control_state='deleted'")) {
            failing = false;
            return Promise.reject(new Error("database is locked"));
          }
          return a.db.query(sql, params as never);
        }) as typeof a.db.query,
      };
      const eraseLogs = vi.fn().mockResolvedValue(none);
      const deleter = createConnectionDeleter({ ...a.deps, db }, { eraseLogs });

      await expect(deleter.resumeErasures()).rejects.toThrow("locked");
      expect(deleter.erasureOwed()).toBe(true);
      await deleter.resumeErasures();

      // The connector that was deleted before this process started is swept.
      expect(eraseLogs).toHaveBeenCalledWith(CONNECTOR, expect.anything());
    });

    it("a purge that cannot look up the connector still commits, with or without a listener", async () => {
      const { a } = await collected({ finalized: "99" });
      const [row] = await a.db.query<{ connection_id: string }>(
        "SELECT connection_id FROM connections WHERE connector = ?",
        [CONNECTOR],
      );
      const lookups: string[] = [];
      const db = {
        ...a.db,
        query: ((sql: string, params?: readonly unknown[]) => {
          if (sql.includes("SELECT connector FROM connections")) {
            lookups.push(sql);
            return Promise.reject(new Error("database is locked"));
          }
          return a.db.query(sql, params as never);
        }) as typeof a.db.query,
      };
      const flaky = { ...a.deps, db };

      await purgeConnection(flaky, row!.connection_id, { controlVersion: 2 });
      expect(
        await a.db.query(
          "SELECT control_state FROM connections WHERE connection_id = ?",
          [row!.connection_id],
        ),
      ).toEqual([{ control_state: "deleted" }]);

      // With a listener the lookup is made and its failure is only logged.
      const heard: string[] = [];
      const stop = onConnectionPurged(db, (connector) => heard.push(connector));
      await purgeConnection(flaky, row!.connection_id, { controlVersion: 2 });
      stop();
      expect(heard).toEqual([]);
    });
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
