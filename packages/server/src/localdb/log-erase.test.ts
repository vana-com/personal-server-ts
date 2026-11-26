// Erasure of a deleted connection's log objects against a log the real
// publisher wrote: real segments, a real compaction into snapshot parts, and a
// record whose body is stored out of line in pieces. The registry is the
// fake gateway the publisher commits to; storage is its in-memory store.
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  controlScope,
  logScope,
  segmentBlobName,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  createConnectionDeleter,
  type DeletePart,
} from "../../../core/src/localdb/index.js";
import {
  ConnectionLifetimeChanged,
  formatLifetime,
} from "../../../core/src/localdb/delete-lifetime.js";
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
  tempDbFile,
  sName,
  world,
} from "./log-world.test-utils.js";

import {
  createCanonicalImportSource,
  type CanonicalImportPageReader,
} from "./canonical-import-source.js";

afterEach(closeWorldDrivers);

describe("canonical import source page bounds", () => {
  async function candidate(page: CanonicalImportPageReader["page"]) {
    type Options = Parameters<typeof createCanonicalImportSource>[0];
    const reader: CanonicalImportPageReader = {
      declarations: [
        {
          source_id: "fixture-source",
          streams: [{ name: "items", primary_key: ["id"] }],
        },
      ] as unknown as CanonicalImportPageReader["declarations"],
      async *inventory() {
        yield {
          sourceId: "fixture-source",
          instance: "fixture-instance",
          stream: "items",
          rows: 1,
        };
      },
      assertRevision: async () => {},
      connections: async () => [
        { instance: "fixture-instance", deleted: false, lastActive: 1 },
      ],
      page,
    };
    const entries = createCanonicalImportSource({
      owner: "fixture-owner",
      network: "fixture-network",
      revision: "fixture-revision",
      reader,
      bindings: new Map([
        ["fixture", { connector: "fixture", streams: ["items"] }],
      ]) as unknown as Options["bindings"],
      resolveTarget: async () =>
        ({
          connectionId: "fixture-connection",
          connector: "fixture",
          stream: "items",
        }) as NonNullable<Awaited<ReturnType<Options["resolveTarget"]>>>,
    });
    const first = await entries[Symbol.asyncIterator]().next();
    if (first.done || !("records" in first.value))
      throw new Error("fixture lacked a candidate");
    return first.value;
  }

  it("does not yield any record from a page exceeding its requested row limit", async () => {
    const page = vi.fn(async () => ({
      rows: Array.from({ length: 129 }, (_, id) => ({ id })),
      next: null,
    }));
    const item = await candidate(page);
    await expect(item.records()[Symbol.asyncIterator]().next()).rejects.toThrow(
      "invalid_page_size",
    );
    expect(page).toHaveBeenCalledWith(
      "fixture-instance",
      "items",
      null,
      128,
      4 * 1024 * 1024,
      "fixture-revision",
    );
  });

  it("refuses a cursor on an empty page instead of looping to a second page", async () => {
    const page = vi.fn(async () => ({ rows: [], next: "would-repeat" }));
    const item = await candidate(page);
    await expect(item.records()[Symbol.asyncIterator]().next()).rejects.toThrow(
      "invalid_page_cursor",
    );
    expect(page).toHaveBeenCalledTimes(1);
  });
});

/** A database file of one test, on disk (a device can restart). */
const dbFile = tempDbFile;

const LOG = logScope(CONNECTOR, "");
const OTHER = "other";
/** The control tombstone of the delete these tests adopt. */
const TOMBSTONE = { ns: "", version: 2 };
/** The tombstone of the connection's next delete, after it was added again. */
const NEXT_TOMBSTONE = { ns: "", version: 4 };
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
      witnessed: true,
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

  it("reports the body pieces it left on a later pass, after the log objects are gone", async () => {
    const { pieces, deps } = await deletedCompactedLog();
    const bodyPieces = pieces(LOG);
    expect(bodyPieces.length).toBeGreaterThan(0);

    const first = await eraseDeletedConnectionLogs(deps(), {
      connector: CONNECTOR,
    });
    expect(first.connections[0]!.outcome).toMatchObject({
      kind: "erased",
      retained: bodyPieces.length,
    });

    // A later pass, or one after a restart, finds the head gone. The pieces
    // are still in storage and the record of them is still in the database.
    const again = await eraseDeletedConnectionLogs(deps(), {
      connector: CONNECTOR,
    });
    expect(again.connections[0]!.outcome).toEqual({
      kind: "erased",
      deleted: 0,
      retained: bodyPieces.length,
      unenumerated: 0,
      witnessed: true,
    });
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

  it("finishes under a per-owner delete quota smaller than the log: names storage already lacks are not sent again", async () => {
    const { keys, deps, before } = await deletedCompactedLog();
    const QUOTA = 3;
    const objects = before.filter(
      (key) => key.includes("/s-") || key.includes("/q-"),
    ).length;
    expect(objects).toBeGreaterThan(QUOTA * 2);
    const base = deps();
    let used = 0;
    const limited = deps({
      objects: {
        // vana-storage rate-limits DELETE per owner: every name sent costs one,
        // one storage already lacks included.
        deleteBlobVersions: async (scope, names) => {
          const allowed = names.slice(0, Math.max(0, QUOTA - used));
          used += allowed.length;
          const out = await base.objects.deleteBlobVersions(scope, allowed);
          return {
            ...out,
            failed: [
              ...out.failed,
              ...names
                .slice(allowed.length)
                .map((version) => ({ version, error: "429 rate limited" })),
            ],
          };
        },
      },
    });
    let report: Awaited<ReturnType<typeof eraseDeletedConnectionLogs>>;
    let passes = 0;
    do {
      used = 0; // each pass is a fresh quota window: the retry loop's wait
      report = await eraseDeletedConnectionLogs(limited, {
        connector: CONNECTOR,
      });
      passes += 1;
    } while (report.pending && passes < objects);

    expect(report.connections.map((c) => c.outcome.kind)).toEqual(["erased"]);
    expect(
      keys(LOG).filter((key) => key.includes("/s-") || key.includes("/q-")),
    ).toEqual([]);
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
    options: { dbFile?: string; twoSegments?: boolean } = {},
  ) {
    const w = await world({ streams: 1, partTargetBytes: PART_TARGET });
    const { erasure, deleted } = ports(w, state, hooks);
    const a = await w.device("a", {
      erasure: () => erasure,
      deleteRetryMs: RETRY,
      ...(options.dbFile && { dbFile: options.dbFile }),
    });
    await a.run("run-1", [big], { observedAt: 1100 });
    await a.cycle();
    if (options.twoSegments) {
      // A second commit: the log is two segments, the head and one it names.
      await a.run("run-1b", [{ stream: sName(0), id: "x", v: 0 }], {
        full: false,
        covered: [sName(0)],
        observedAt: 1150,
      });
      await a.cycle();
      expect(
        logKeys(w, LOG).filter((key) => key.includes("/s-")).length,
      ).toBeGreaterThan(1);
    }
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

    // The request answers `fenced: false` when the fence has not landed within
    // the retry loop's first wait (5 ms here); the loop then lands it. The
    // test waits on what the fence leaves behind, not on that answer.
    await a.sync.deleter.requestConnectionDelete(CONNECTOR);

    // The pass is over when the device judges the storage part: it deletes the
    // head last, then records its verdict. Wait for that, not for the retry
    // timer to have run a pass or for storage to look empty.
    await vi.waitFor(
      async () => {
        expect(erasable(w, LOG)).toEqual([]);
        expect(await intents(a)).toEqual([]);
        expect(
          (await a.sync.deleter.deleteStatusSnapshot(CONNECTOR)).storage,
        ).toEqual({ state: "blocked", reason: "body_pieces_retained" });
      },
      { timeout: 10_000 },
    );
    expect(logKeys(w, OTHER_LOG)).toEqual(otherBefore);
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

  it("retries one connector's unfinished erasure while another connector's storage request is still waiting", async () => {
    const w = await world({ streams: 1, partTargetBytes: PART_TARGET });
    const base = ports(w, { finalized: "99" }).erasure;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    // The other connector's finality read waits; this one's tombstone is not
    // final for its first five reads, so its erasure is unfinished each time.
    let asked = 0;
    const erasure: LogErasurePorts = {
      ...base,
      finality: {
        tombstoneState: async (scope) => {
          if (scope === controlScope(OTHER, "")) {
            await gate;
            return { finalized: "99", rolledBack: null };
          }
          asked += 1;
          return { finalized: asked > 5 ? "99" : null, rolledBack: null };
        },
      },
    };
    const a = await w.device("a", {
      erasure: () => erasure,
      deleteRetryMs: RETRY,
    });
    try {
      for (const connector of [CONNECTOR, OTHER]) {
        await a.run(`run-${connector}`, [{ stream: sName(0), id: "x", v: 0 }], {
          connector,
          observedAt: 1100,
        });
        await a.cycle();
      }
      await a.sync.deleter.requestConnectionDelete(OTHER);
      await a.sync.deleter.requestConnectionDelete(CONNECTOR);

      await vi.waitFor(() => expect(logKeys(w, LOG)).toEqual([]));
      // The other connector's erasure has not finished: it is still waiting.
      expect(logKeys(w, OTHER_LOG).length).toBeGreaterThan(0);
    } finally {
      release();
    }
    await vi.waitFor(() => expect(logKeys(w, OTHER_LOG)).toEqual([]));
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

  it("a delete adopted while the purge's connector lookup fails once is erased all the same, without a restart", async () => {
    const state = { finalized: "99" };
    const w = await world({ streams: 1, partTargetBytes: PART_TARGET });
    const { erasure } = ports(w, state);
    const phone = await w.device("phone");
    const desktop = await w.device("desktop", {
      erasure: () => erasure,
      deleteRetryMs: RETRY,
    });
    await phone.run("run-1", [big], { observedAt: 1100 });
    await phone.cycle();
    await desktop.cycle();
    // The start sweep has run (nothing was deleted yet): it will not run again.
    await desktop.sync.deleter.resumeDeletes();
    await phone.sync.deleter.requestConnectionDelete(CONNECTOR);
    await vi.waitFor(async () => expect(await intents(phone)).toEqual([]));
    expect(erasable(w, LOG).length).toBeGreaterThan(0);

    const query = desktop.db.query.bind(desktop.db);
    let lookups = 0;
    desktop.db.query = ((sql: string, params?: readonly unknown[]) => {
      if (sql.includes("SELECT connector, ns FROM connections WHERE")) {
        lookups += 1;
        if (lookups === 1)
          return Promise.reject(new Error("database is locked"));
      }
      return query(sql, params as never);
    }) as typeof desktop.db.query;
    await desktop.cycle();

    expect(lookups).toBeGreaterThan(0);
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

  describe("what the storage part of a delete says", () => {
    /** A deleter over a settled delete, whose eraser is the real one over `erasure`. */
    async function restarted(
      a: Awaited<ReturnType<World["device"]>>,
      erasure: LogErasurePorts,
      registry = a.deps.registry,
    ) {
      return createConnectionDeleter(a.deps, {
        eraseLogs: (connector, signal, gate) =>
          eraseDeletedConnectionLogs(
            {
              registry,
              blobs: a.deps.blobs,
              keys: a.deps.keys,
              logger: { info() {}, warn() {} },
              retained: retainedPiecesIn(a.db),
              ...erasure,
            },
            {
              connector,
              signal,
              ...(gate && { skipNamespaces: gate.skipNamespaces }),
            },
          ),
      });
    }
    const settledDelete = async () => {
      const c = await collected({ finalized: "99" });
      await c.a.sync.deleter.requestConnectionDelete(CONNECTOR);
      await vi.waitFor(async () => expect(await intents(c.a)).toEqual([]));
      await vi.waitFor(() => expect(erasable(c.w, LOG)).toEqual([]));
      return c;
    };

    it("still reads blocked(body_pieces_retained) on a second sweep after the log was erased", async () => {
      const { a, erasure } = await settledDelete();

      const deleter = await restarted(a, erasure);
      deleter.noteSettled(CONNECTOR, TOMBSTONE);
      await deleter.resumeErasures();

      expect((await deleter.deleteStatus(CONNECTOR)).storage).toEqual({
        state: "blocked",
        reason: "body_pieces_retained",
      });
    });

    it("reads storage as blocked(erased_elsewhere), never done, on a device that holds no record of the pieces another device kept", async () => {
      const state = { finalized: "99" };
      const w = await world({ streams: 1, partTargetBytes: PART_TARGET });
      const { erasure } = ports(w, state);
      const a = await w.device("a", {
        erasure: () => erasure,
        deleteRetryMs: RETRY,
      });
      const b = await w.device("b", {
        erasure: () => erasure,
        deleteRetryMs: RETRY,
      });
      await a.run("run-1", [big], { observedAt: 1100 });
      await a.cycle();
      await b.cycle();
      expect(await b.records()).not.toEqual([]);

      // Device a deletes and erases the log; the body pieces stay in storage
      // and only a's database names them.
      await a.sync.deleter.requestConnectionDelete(CONNECTOR);
      await vi.waitFor(async () => expect(await intents(a)).toEqual([]));
      await vi.waitFor(() => expect(erasable(w, LOG)).toEqual([]));
      await vi.waitFor(async () =>
        expect((await a.sync.deleter.deleteStatus(CONNECTOR)).storage).toEqual({
          state: "blocked",
          reason: "body_pieces_retained",
        }),
      );

      // Device b adopts the delete and finds the log gone. Its database has no
      // record of the pieces; storage cannot say what is left.
      await b.cycle();
      await vi.waitFor(async () =>
        expect(
          (await b.sync.deleter.deleteStatus(CONNECTOR)).storage,
        ).not.toEqual({ state: "pending" }),
      );
      expect((await b.sync.deleter.deleteStatus(CONNECTOR)).storage).toEqual({
        state: "blocked",
        reason: "erased_elsewhere",
      });
    });

    it("keeps reading storage done on the device that erased a log with no body pieces, after a restart", async () => {
      const state = { finalized: "99" };
      const w = await world({ streams: 1, partTargetBytes: PART_TARGET });
      const { erasure } = ports(w, state);
      const a = await w.device("a", {
        erasure: () => erasure,
        deleteRetryMs: RETRY,
      });
      await a.run("run-1", [{ stream: sName(0), id: "x", v: 0 }], {
        observedAt: 1100,
      });
      await a.cycle();
      await a.sync.deleter.requestConnectionDelete(CONNECTOR);
      await vi.waitFor(async () => expect(await intents(a)).toEqual([]));
      await vi.waitFor(() => expect(logKeys(w, LOG)).toEqual([]));

      const deleter = await restarted(a, erasure);
      deleter.noteSettled(CONNECTOR, TOMBSTONE);
      await deleter.resumeErasures();

      expect((await deleter.deleteStatus(CONNECTOR)).storage).toEqual({
        state: "done",
      });
    });

    it("reads blocked(re_added) for a deleted namespace a local connection still holds, and owes no further pass", async () => {
      const state: { finalized: string | null } = { finalized: null };
      const { w, a, deleted } = await collected(state);
      await a.sync.deleter.requestConnectionDelete(CONNECTOR);
      await vi.waitFor(async () => expect(await intents(a)).toEqual([]));
      const old = logKeys(w, LOG);
      // The connection is added again here, not published yet: the registry's
      // head is still the delete's tombstone, and a local connection is live.
      await a.db.batch([
        {
          sql: "UPDATE connections SET control_state = 'absent' WHERE connector = ?",
          params: [CONNECTOR],
        },
      ]);

      state.finalized = "99";
      await vi.waitFor(async () =>
        expect((await a.sync.deleter.deleteStatus(CONNECTOR)).storage).toEqual({
          state: "blocked",
          reason: "re_added",
        }),
      );
      await vi.waitFor(() => expect(a.sync.deleter.erasureOwed()).toBe(false));
      expect(deleted).toEqual([]);
      expect(logKeys(w, LOG)).toEqual(old);
    });

    /**
     * This device deleted the connector once (its tombstone is not final in
     * storage yet) and then connected again; another device deletes that second
     * lifetime. This device reads the new tombstone (a status read, or the
     * start sweep) before its own sync purges the old connection.
     */
    async function deletedAgainElsewhere() {
      const state: { finalized: string | null } = { finalized: null };
      const w = await world({ streams: 1, partTargetBytes: PART_TARGET });
      const { erasure } = ports(w, state);
      const phone = await w.device("phone");
      const desktop = await w.device("desktop", {
        erasure: () => erasure,
        deleteRetryMs: RETRY,
      });
      const record = { stream: sName(0), id: "x", v: 0 };
      await desktop.run("run-1", [record], { observedAt: 1100 });
      await desktop.cycle();
      await desktop.sync.deleter.requestConnectionDelete(CONNECTOR);
      await vi.waitFor(async () => expect(await intents(desktop)).toEqual([]));

      await desktop.run("run-2", [{ ...record, id: "y" }], {
        connect: true,
        observedAt: 1200,
      });
      await desktop.cycle();
      await phone.cycle();
      await phone.sync.deleter.requestConnectionDelete(CONNECTOR);
      await vi.waitFor(async () => expect(await intents(phone)).toEqual([]));
      return { w, desktop, phone, state };
    }

    it("erases a delete another device wrote though this device read its tombstone before purging its old connection", async () => {
      const { w, desktop, state } = await deletedAgainElsewhere();
      // The read adopts the newer tombstone; the old connection is still here,
      // registered at a lifetime that tombstone ended.
      await desktop.sync.deleter.deleteStatus(CONNECTOR);
      state.finalized = "99";
      // The pass that judges the adopted tombstone has run.
      await vi.waitFor(async () =>
        expect(
          (await desktop.sync.deleter.deleteStatus(CONNECTOR)).storage,
        ).not.toEqual({ state: "pending" }),
      );
      expect(
        await desktop.db.query(
          "SELECT control_state FROM connections WHERE connector = ?",
          [CONNECTOR],
        ),
      ).toEqual([{ control_state: "active" }]);
      // The local sync then purges it, naming the same tombstone.
      await desktop.cycle();

      await vi.waitFor(() => expect(logKeys(w, LOG)).toEqual([]));
      await vi.waitFor(async () =>
        expect(
          (await desktop.sync.deleter.deleteStatus(CONNECTOR)).storage,
        ).toEqual({ state: "done" }),
      );
    });

    it("never reads an old connection of an ended lifetime as a re-add while it waits for its purge", async () => {
      const { w, desktop, state } = await deletedAgainElsewhere();
      await desktop.sync.deleter.deleteStatus(CONNECTOR);
      state.finalized = "99";

      // Before any purge: the erasure needs no purge to proceed, and the
      // status never says the connection was added again.
      await vi.waitFor(() => expect(logKeys(w, LOG)).toEqual([]));
      expect(
        (await desktop.sync.deleter.deleteStatus(CONNECTOR)).storage,
      ).not.toEqual({ state: "blocked", reason: "re_added" });
    });

    it("erases once a connection that never registered, held back while it lived, is purged under the same tombstone", async () => {
      const { w, desktop, state } = await deletedAgainElsewhere();
      // The old connection never registered a lifetime the tombstone could have
      // ended (a local connection added again, not published yet): this device
      // cannot tell it from a re-add, so the namespace is held back.
      await desktop.db.batch([
        {
          sql: "UPDATE connections SET control_state = 'absent' WHERE connector = ?",
          params: [CONNECTOR],
        },
      ]);
      await desktop.sync.deleter.deleteStatus(CONNECTOR);
      state.finalized = "99";
      await vi.waitFor(async () =>
        expect(
          (await desktop.sync.deleter.deleteStatus(CONNECTOR)).storage,
        ).toEqual({ state: "blocked", reason: "re_added" }),
      );
      expect(logKeys(w, LOG).length).toBeGreaterThan(0);

      await desktop.cycle();

      await vi.waitFor(() => expect(logKeys(w, LOG)).toEqual([]));
      await vi.waitFor(async () =>
        expect(
          (await desktop.sync.deleter.deleteStatus(CONNECTOR)).storage,
        ).toEqual({ state: "done" }),
      );
    });

    it("reads storage as pending while the registry cannot list the deleted connections", async () => {
      const { a, erasure } = await settledDelete();
      const down = {
        ...a.deps.registry,
        listControlRows: async () => {
          throw new Error("registry unavailable");
        },
      };

      const deleter = await restarted(a, erasure, down);
      deleter.noteSettled(CONNECTOR, TOMBSTONE);
      await deleter.resumeErasures();

      expect((await deleter.deleteStatus(CONNECTOR)).storage).toEqual({
        state: "pending",
      });
      expect(deleter.erasureOwed()).toBe(true);
    });
  });

  describe("storage reads done only on this delete's own evidence", () => {
    const DONE: DeletePart = { state: "done" };
    type Device = Awaited<ReturnType<World["device"]>>;
    type Deleter = Device["sync"]["deleter"];
    /** A process over a database: its sync, and a way to restart it. */
    interface Subject {
      readonly sync: { readonly deleter: Deleter };
      readonly db: Device["db"];
      restart(): Promise<Subject>;
    }
    /** A process as a subject; restarting it gives the next one over the same file. */
    const subjectOf = (
      sync: { readonly deleter: Deleter },
      db: Device["db"],
      restart: () => Promise<{
        readonly sync: { readonly deleter: Deleter };
        readonly db: Device["db"];
      }>,
    ): Subject => ({
      sync,
      db,
      restart: async () => {
        const next = await restart();
        return subjectOf(next.sync, next.db, restart);
      },
    });
    /**
     * What a part that reads `pending` stands on: a delete still landing (its
     * intent row), or an erasure owed. A pending part with neither would read
     * pending for good.
     */
    async function pendingHasWork(subject: Subject) {
      const status = await subject.sync.deleter.deleteStatus(CONNECTOR);
      const landing =
        (await subject.db.query("SELECT 1 FROM delete_intents")).length > 0;
      for (const part of [status.fence, status.legacy, status.storage])
        if (part.state === "pending")
          expect(subject.sync.deleter.erasureOwed() || landing).toBe(true);
    }
    /** The storage part, once the erasure has judged it (not pending). */
    async function judged(deleter: Deleter) {
      let part: DeletePart = { state: "pending" };
      await vi.waitFor(async () => {
        part = (await deleter.deleteStatus(CONNECTOR)).storage;
        expect(part).not.toEqual({ state: "pending" });
      });
      return part;
    }
    const headOf = (w: World) =>
      segmentBlobName(w.gateway.versions.get(LOG)!.at(-1)!.dataHash);

    /** A log of one small record: this device enumerates it whole and deletes it. */
    async function completeAndAcknowledged() {
      const w = await world({ streams: 1, partTargetBytes: PART_TARGET });
      const { erasure } = ports(w, { finalized: "99" });
      const a = await w.device("a", {
        erasure: () => erasure,
        deleteRetryMs: RETRY,
        dbFile: dbFile(),
      });
      await a.run("run-1", [{ stream: sName(0), id: "x", v: 0 }], {
        observedAt: 1100,
      });
      await a.cycle();
      await a.sync.deleter.requestConnectionDelete(CONNECTOR);
      await vi.waitFor(() => expect(logKeys(w, LOG)).toEqual([]));
      return {
        storage: await judged(a.sync.deleter),
        subject: subjectOf(a.sync, a.db, a.restart),
      };
    }

    /** Another device erased the whole log; this one finds nothing it enumerated. */
    async function missingMetadata() {
      const w = await world({ streams: 1, partTargetBytes: PART_TARGET });
      const { erasure } = ports(w, { finalized: "99" });
      const a = await w.device("a", {
        erasure: () => erasure,
        deleteRetryMs: RETRY,
      });
      const b = await w.device("b", {
        erasure: () => erasure,
        deleteRetryMs: RETRY,
        dbFile: dbFile(),
      });
      await a.run("run-1", [big], { observedAt: 1100 });
      await a.cycle();
      await b.cycle();
      await a.sync.deleter.requestConnectionDelete(CONNECTOR);
      await vi.waitFor(() => expect(erasable(w, LOG)).toEqual([]));
      await vi.waitFor(async () =>
        expect((await a.sync.deleter.deleteStatus(CONNECTOR)).storage).toEqual({
          state: "blocked",
          reason: "body_pieces_retained",
        }),
      );
      await b.cycle();
      const part = await judged(b.sync.deleter);
      expect(await b.db.query("SELECT 1 FROM enumerated_logs")).toEqual([]);
      return { storage: part, subject: subjectOf(b.sync, b.db, b.restart) };
    }

    /**
     * Device a is cut off after the parts and segments but before the log
     * head: they are gone, the head stays. Device b finds the head and the
     * segments missing under it.
     */
    async function interrupted() {
      const w = await world({ streams: 1, partTargetBytes: PART_TARGET });
      const { erasure } = ports(w, { finalized: "99" });
      const cutOff: LogErasurePorts = {
        ...erasure,
        objects: {
          deleteBlobVersions: async (scope, names) =>
            names.includes(headOf(w))
              ? {
                  deleted: [],
                  missing: [],
                  failed: names.map((version) => ({ version, error: "503" })),
                }
              : erasure.objects.deleteBlobVersions(scope, names),
        },
      };
      const a = await w.device("a", {
        erasure: () => cutOff,
        deleteRetryMs: RETRY,
      });
      const b = await w.device("b", {
        erasure: () => erasure,
        deleteRetryMs: RETRY,
        dbFile: dbFile(),
      });
      await a.run("run-1", [big], { observedAt: 1100 });
      await a.cycle();
      await a.run("run-1b", [{ stream: sName(0), id: "x", v: 0 }], {
        full: false,
        covered: [sName(0)],
        observedAt: 1150,
      });
      await a.cycle();
      await b.cycle();
      const segments = () =>
        logKeys(w, LOG).filter((key) => key.includes("/s-"));
      expect(segments().length).toBeGreaterThan(1);

      await a.sync.deleter.requestConnectionDelete(CONNECTOR);
      // The segment the head names is gone; the head is not.
      await vi.waitFor(() =>
        expect(segments()).toEqual([`${LOG}/${headOf(w)}`]),
      );
      expect(
        (await a.sync.deleter.deleteStatus(CONNECTOR)).storage,
      ).not.toEqual(DONE);

      await b.cycle();
      const part = await judged(b.sync.deleter);
      expect(await b.db.query("SELECT 1 FROM enumerated_logs")).toEqual([]);
      return { storage: part, subject: subjectOf(b.sync, b.db, b.restart) };
    }

    /**
     * The connection is added again after its delete, before any erasure:
     * the old log objects stay, and so does the new lifetime's.
     */
    async function reconnectBefore() {
      const state: { finalized: string | null } = { finalized: null };
      const { w, a, deleted } = await collected(
        state,
        {},
        { dbFile: dbFile() },
      );
      const old = logKeys(w, LOG);
      await a.sync.deleter.requestConnectionDelete(CONNECTOR);
      await vi.waitFor(async () => expect(await intents(a)).toEqual([]));
      await a.run("run-2", [big], { connect: true, observedAt: 1200 });
      await a.cycle();

      state.finalized = "99";
      const part = await judged(a.sync.deleter);
      expect(deleted).toEqual([]);
      for (const key of old) expect(logKeys(w, LOG)).toContain(key);
      return { storage: part, subject: subjectOf(a.sync, a.db, a.restart) };
    }

    /** The connection is added again while the erasure is deleting. */
    async function reconnectDuring() {
      let readd: () => Promise<void> = async () => {};
      const { w, a, deleted } = await collected(
        { finalized: "99" },
        { beforeFirstDelete: () => readd() },
        { twoSegments: true, dbFile: dbFile() },
      );
      const oldHead = `${LOG}/${headOf(w)}`;
      readd = async () => {
        await a.run("run-2", [big], { connect: true, observedAt: 1200 });
        await a.cycle();
      };
      await a.sync.deleter.requestConnectionDelete(CONNECTOR);
      await vi.waitFor(() => expect(deleted.length).toBeGreaterThan(0));
      const part = await judged(a.sync.deleter);
      // The pass stopped before the head: the old head is still in storage.
      expect(logKeys(w, LOG)).toContain(oldHead);
      expect(deleted.filter((name) => name.startsWith("v-"))).toEqual([]);
      return { storage: part, subject: subjectOf(a.sync, a.db, a.restart) };
    }

    /** The eraser reports what a reconnect ended: unit mapping to the part. */
    async function eraserReports(outcome: {
      kind: "stopped";
      why: "re-added" | "rolled-back";
    }) {
      const c = await collected({ finalized: "99" }, {}, { dbFile: dbFile() });
      await c.a.sync.deleter.requestConnectionDelete(CONNECTOR);
      await vi.waitFor(async () => expect(await intents(c.a)).toEqual([]));
      const deleter = createConnectionDeleter(c.a.deps, {
        eraseLogs: async () => ({
          connections: [{ connector: CONNECTOR, ns: "", outcome }],
          pending: false,
          skipped: [],
        }),
      });
      deleter.noteSettled(CONNECTOR, TOMBSTONE);
      await deleter.resumeErasures();
      return {
        storage: (await deleter.deleteStatus(CONNECTOR)).storage,
        subject: subjectOf({ deleter }, c.a.db, c.a.restart),
      };
    }

    /**
     * A reconnect before the first pass and a restart: the new process holds
     * no verdict, and its first one is the same as the old process's would be.
     */
    async function restartedAfterReconnect() {
      const state: { finalized: string | null } = { finalized: null };
      const { w, a } = await collected(state, {}, { dbFile: dbFile() });
      const old = logKeys(w, LOG);
      await a.sync.deleter.requestConnectionDelete(CONNECTOR);
      await vi.waitFor(async () => expect(await intents(a)).toEqual([]));
      await a.run("run-2", [big], { connect: true, observedAt: 1200 });
      await a.cycle();

      const next = await a.restart();
      // Nothing is judged yet: pending, never done.
      expect((await next.sync.deleter.deleteStatus(CONNECTOR)).storage).toEqual(
        { state: "pending" },
      );
      state.finalized = "99";
      await next.sync.deleter.resumeDeletes();
      const part = await judged(next.sync.deleter);
      for (const key of old) expect(logKeys(w, LOG)).toContain(key);
      return {
        storage: part,
        subject: subjectOf(next.sync, next.db, a.restart),
      };
    }

    const rows: {
      name: string;
      expected: DeletePart;
      run: () => Promise<{ storage: DeletePart; subject: Subject }>;
    }[] = [
      {
        name: "complete and acknowledged",
        expected: DONE,
        run: completeAndAcknowledged,
      },
      {
        name: "missing metadata with no prior complete enumeration",
        expected: { state: "blocked", reason: "erased_elsewhere" },
        run: missingMetadata,
      },
      {
        name: "interrupted: another device stopped before the log head",
        expected: { state: "blocked", reason: "erased_elsewhere" },
        run: interrupted,
      },
      {
        name: "reconnect before erasure, old objects still present",
        expected: { state: "blocked", reason: "re_added" },
        run: reconnectBefore,
      },
      {
        name: "reconnect during erasure, old objects still present",
        expected: { state: "blocked", reason: "re_added" },
        run: reconnectDuring,
      },
      {
        name: "the eraser reports re-added",
        expected: { state: "blocked", reason: "re_added" },
        run: () => eraserReports({ kind: "stopped", why: "re-added" }),
      },
      {
        name: "rollback",
        expected: { state: "blocked", reason: "tombstone_rolled_back" },
        run: () => eraserReports({ kind: "stopped", why: "rolled-back" }),
      },
      {
        name: "restart after a reconnect",
        expected: { state: "blocked", reason: "re_added" },
        run: restartedAfterReconnect,
      },
    ];

    it.each(rows)("$name", async ({ expected, run }) => {
      const { storage, subject } = await run();
      expect(storage).toEqual(expected);
      // A part that reads pending has work queued behind it: as the scenario
      // ends, and again in the process that starts over the same database.
      await pendingHasWork(subject);
      const next = await subject.restart();
      await next.sync.deleter.resumeDeletes();
      await pendingHasWork(next);
    });

    it("lets only a complete, acknowledged enumeration read done", () => {
      expect(
        rows.filter((row) => row.expected.state === "done").map((r) => r.name),
      ).toEqual([rows[0]!.name]);
    });
  });

  describe("the erasure's own bookkeeping", () => {
    const settled = async () => {
      const c = await collected({ finalized: "99" });
      await c.a.sync.deleter.requestConnectionDelete(CONNECTOR);
      await vi.waitFor(async () => expect(await intents(c.a)).toEqual([]));
      return c.a;
    };
    const none = { connections: [], pending: false, skipped: [] } as const;
    /** A pass that erased the connector's log whole, on its own evidence. */
    const erased = {
      connections: [
        {
          connector: CONNECTOR,
          ns: "",
          outcome: {
            kind: "erased",
            deleted: 1,
            retained: 0,
            unenumerated: 0,
            witnessed: true,
          },
        },
      ],
      pending: false,
      skipped: [],
    } as const;

    it("a delete noted while an erasure runs is erased by a pass that starts after it", async () => {
      const a = await settled();
      let release: () => void = () => {};
      const eraseLogs = vi
        .fn()
        .mockImplementationOnce(
          () => new Promise((resolve) => (release = () => resolve(erased))),
        )
        .mockResolvedValue(erased);
      const deleter = createConnectionDeleter(a.deps, { eraseLogs });
      deleter.noteSettled(CONNECTOR, TOMBSTONE);
      const first = deleter.resumeErasures();
      await vi.waitFor(() => expect(eraseLogs).toHaveBeenCalledTimes(1));

      // The connection is added again and deleted again: the second delete is
      // purged here while the first pass runs, and the retry loop looks at it.
      deleter.noteSettled(CONNECTOR, NEXT_TOMBSTONE);
      const second = deleter.resumeErasures();
      // The first pass ends as it would for a tombstone that moved: not pending.
      release();
      await Promise.all([first, second]);

      expect(eraseLogs).toHaveBeenCalledTimes(2);
      expect(deleter.erasureOwed()).toBe(false);
    });

    /** A pass that ends with the erasure unfinished: a later one still owes it. */
    const unfinished = { ...none, pending: true } as const;

    it("a retry tick runs the connectors that are queued and never waits for one still in flight", async () => {
      const a = await settled();
      const OTHER_CONNECTOR = "other-source";
      let held = 0;
      const eraseLogs = vi.fn(async (connector: string) => {
        if (connector === OTHER_CONNECTOR) {
          held += 1;
          return new Promise<never>(() => {}); // storage never answers
        }
        return unfinished;
      });
      const deleter = createConnectionDeleter(a.deps, { eraseLogs });
      deleter.noteSettled(OTHER_CONNECTOR, TOMBSTONE);
      const stuck = deleter.resumeErasures();
      void stuck;
      await vi.waitFor(() => expect(held).toBe(1));

      // The retry loop ticks again and again; this connector is unfinished
      // each time. Every tick must end by itself while the other still waits:
      // a tick that joined it would stay pending, one more each time.
      deleter.noteSettled(CONNECTOR, TOMBSTONE);
      let ended = 0;
      for (let tick = 0; tick < 4; tick += 1)
        void deleter.resumeErasures().then(() => (ended += 1));
      await vi.waitFor(() => expect(ended).toBe(4));

      // The queued connector ran; the one in flight was not asked again.
      expect(
        eraseLogs.mock.calls.filter(([c]) => c === CONNECTOR).length,
      ).toBeGreaterThan(0);
      expect(held).toBe(1);
    });

    it("arms the retry only once the connector's pass is over: its verdict read done and its place in flight given up", async () => {
      const a = await settled();
      const eraseLogs = vi
        .fn()
        .mockResolvedValueOnce(unfinished)
        .mockResolvedValue(erased);
      // The verdict read at the end of a pass is the first registry read after
      // the pass's own work; hold it.
      let hold = false;
      let release!: () => void;
      const gate = new Promise<void>((resolve) => (release = resolve));
      const registry = {
        ...a.deps.registry,
        listControlRows: async () => {
          if (hold) await gate;
          return a.deps.registry.listControlRows();
        },
      };
      let armed = 0;
      let tick: Promise<boolean> | undefined;
      const deleter: ReturnType<typeof createConnectionDeleter> =
        createConnectionDeleter(
          { ...a.deps, registry },
          {
            eraseLogs: async (...args) => {
              const report = await eraseLogs(...args);
              hold = true;
              return report;
            },
            onRetryStateChange: () => {
              // What the host does: look at the work owed now, then decide.
              void deleter.retryOwed().then((owed) => {
                if (!owed) return;
                armed += 1;
                hold = false;
                // The retry timer firing at once.
                tick = deleter.resumeErasures();
              });
            },
          },
        );
      deleter.noteSettled(CONNECTOR, TOMBSTONE);
      const run = deleter.resumeErasures();
      await vi.waitFor(() => expect(eraseLogs).toHaveBeenCalledTimes(1));
      // The pass is over and its verdict read waits: not armed yet.
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(armed).toBe(0);

      release();
      await run;
      await vi.waitFor(() => expect(armed).toBe(1));
      // The tick found the connector queued, not in flight, and ran it.
      expect(await tick).toBe(false);
      expect(eraseLogs).toHaveBeenCalledTimes(2);
    });

    it("reads a newer delete of the connector as pending until its own pass has judged it, not done on the older delete's verdict", async () => {
      const a = await settled();
      let release: () => void = () => {};
      const eraseLogs = vi
        .fn()
        .mockResolvedValueOnce(erased)
        .mockImplementationOnce(
          () => new Promise((resolve) => (release = () => resolve(erased))),
        );
      const deleter = createConnectionDeleter(a.deps, { eraseLogs });
      // Delete 1 is adopted and judged done.
      deleter.noteSettled(CONNECTOR, TOMBSTONE);
      await deleter.resumeErasures();
      expect((await deleter.deleteStatus(CONNECTOR)).storage).toEqual({
        state: "done",
      });

      // The connection was added again and deleted again elsewhere; this
      // device adopts delete 2. Nothing has judged it yet.
      deleter.noteSettled(CONNECTOR, NEXT_TOMBSTONE);
      const second = deleter.resumeErasures();
      await vi.waitFor(() => expect(eraseLogs).toHaveBeenCalledTimes(2));
      expect((await deleter.deleteStatus(CONNECTOR)).storage).toEqual({
        state: "pending",
      });

      release();
      await second;
      expect((await deleter.deleteStatus(CONNECTOR)).storage).toEqual({
        state: "done",
      });
    });

    it("does not take a pass that began before a newer delete was adopted as that delete's verdict", async () => {
      const a = await settled();
      let releaseFirst: () => void = () => {};
      let releaseSecond: () => void = () => {};
      const eraseLogs = vi
        .fn()
        .mockImplementationOnce(
          () =>
            new Promise((resolve) => (releaseFirst = () => resolve(erased))),
        )
        .mockImplementationOnce(
          () =>
            new Promise((resolve) => (releaseSecond = () => resolve(erased))),
        );
      const deleter = createConnectionDeleter(a.deps, { eraseLogs });
      deleter.noteSettled(CONNECTOR, TOMBSTONE);
      const first = deleter.resumeErasures();
      await vi.waitFor(() => expect(eraseLogs).toHaveBeenCalledTimes(1));

      // Delete 2 is adopted while delete 1's pass runs; that pass then ends.
      deleter.noteSettled(CONNECTOR, NEXT_TOMBSTONE);
      const second = deleter.resumeErasures();
      releaseFirst();
      await vi.waitFor(() => expect(eraseLogs).toHaveBeenCalledTimes(2));
      expect((await deleter.deleteStatus(CONNECTOR)).storage).toEqual({
        state: "pending",
      });

      releaseSecond();
      await Promise.all([first, second]);
      expect((await deleter.deleteStatus(CONNECTOR)).storage).toEqual({
        state: "done",
      });
    });

    it("keeps the status of the last delete when a request for a stale lifetime is refused", async () => {
      const a = await settled();
      await vi.waitFor(async () =>
        expect((await a.sync.deleter.deleteStatus(CONNECTOR)).storage).toEqual({
          state: "blocked",
          reason: "body_pieces_retained",
        }),
      );
      const before = await a.sync.deleter.deleteStatus(CONNECTOR);

      // A request that names a connection this one never was: refused (409).
      await expect(
        a.sync.deleter.requestConnectionDelete(CONNECTOR, {
          lifetime: formatLifetime(CONNECTOR, new Map([["", 99]])),
        }),
      ).rejects.toBeInstanceOf(ConnectionLifetimeChanged);

      expect(await a.sync.deleter.deleteStatus(CONNECTOR)).toEqual(before);
    });

    it("a retry that finds a pass running does not wait for it: the pass arms the retry itself when it ends unfinished", async () => {
      const a = await settled();
      let release: () => void = () => {};
      const eraseLogs = vi.fn().mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            release = () =>
              resolve({ connections: [], pending: true, skipped: [] });
          }),
      );
      const onRetryStateChange = vi.fn();
      const deleter = createConnectionDeleter(a.deps, {
        eraseLogs,
        onRetryStateChange,
      });
      deleter.noteSettled(CONNECTOR, TOMBSTONE);
      const first = deleter.resumeErasures();
      await vi.waitFor(() => expect(eraseLogs).toHaveBeenCalledTimes(1));
      // The running pass has taken the queue entry: the retry loop sees none,
      // answers at once, and asks for nothing more.
      expect(await deleter.resumeErasures()).toBe(false);
      expect(onRetryStateChange).not.toHaveBeenCalled();

      release();
      // The pass ended pending: its caller is told, and the loop is armed.
      expect(await first).toBe(true);
      expect(onRetryStateChange).toHaveBeenCalledTimes(1);
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
      expect(eraseLogs).toHaveBeenCalledWith(
        CONNECTOR,
        expect.anything(),
        expect.anything(),
      );
    });

    it("works when its methods are taken off the deleter", async () => {
      const a = await settled();
      const eraseLogs = vi.fn().mockResolvedValue(erased);
      const { noteSettled, resumeErasures } = createConnectionDeleter(a.deps, {
        eraseLogs,
      });
      noteSettled(CONNECTOR, TOMBSTONE);
      expect(await resumeErasures()).toBe(false);
      expect(eraseLogs).toHaveBeenCalledTimes(1);
    });

    it("a purge that arrives while the start sweep reads is not lost: the sweep is owed again", async () => {
      const a = await settled();
      let release!: () => void;
      const gate = new Promise<void>((resolve) => (release = resolve));
      let reading = false;
      const db = {
        ...a.db,
        query: (async (sql: string, params?: readonly unknown[]) => {
          const rows = await a.db.query(sql, params as never);
          if (sql.includes("control_state='deleted'")) {
            reading = true;
            await gate;
          }
          return rows;
        }) as typeof a.db.query,
      };
      const deleter = createConnectionDeleter(
        { ...a.deps, db },
        { eraseLogs: vi.fn().mockResolvedValue(erased) },
      );
      const sweep = deleter.resumeErasures();
      await vi.waitFor(() => expect(reading).toBe(true));
      // A purge whose connector is unknown: its tombstone is written, and
      // only a new sweep finds it.
      deleter.noteSweepOwed();
      release();
      await sweep;
      expect(deleter.erasureOwed()).toBe(true);
    });

    it("the deprecated onUnfinished still fires, once the run has left the flight, when its erasure is still owed", async () => {
      const a = await settled();
      const eraseLogs = vi
        .fn()
        .mockResolvedValueOnce(unfinished)
        .mockResolvedValue(erased);
      const seen: boolean[] = [];
      const deleter: ReturnType<typeof createConnectionDeleter> =
        createConnectionDeleter(a.deps, {
          eraseLogs,
          onUnfinished: () => seen.push(deleter.erasureOwed()),
        });
      deleter.noteSettled(CONNECTOR, TOMBSTONE);
      expect(await deleter.resumeErasures()).toBe(true);
      // Fired once, and the erasure was queued again by then.
      expect(seen).toEqual([true]);
      expect(await deleter.resumeErasures()).toBe(false);
      // Finished: nothing more to report.
      expect(seen).toEqual([true]);
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
          if (sql.includes("SELECT connector, ns FROM connections")) {
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

      // With a listener the lookup is made; its failure is logged and the
      // listener hears of a purge with no connector, to sweep for it.
      const heard: (string | null)[] = [];
      const stop = onConnectionPurged(db, (connector) => heard.push(connector));
      await purgeConnection(flaky, row!.connection_id, { controlVersion: 2 });
      stop();
      expect(heard).toEqual([null]);
    });
  });

  describe("the gate on a delete that has not settled here", () => {
    const owed = async (a: Awaited<ReturnType<World["device"]>>) => {
      const eraseLogs = vi.fn(
        async (
          _connector: string,
          _signal: AbortSignal,
          _gate?: { skipNamespaces: ReadonlySet<string> },
        ) => ({ connections: [], pending: false, skipped: [] }),
      );
      const deleter = createConnectionDeleter(a.deps, { eraseLogs });
      // The sweep that runs first once per process, then the owed connector.
      await deleter.resumeErasures();
      eraseLogs.mockClear();
      deleter.noteSettled(CONNECTOR, TOMBSTONE);
      await deleter.resumeErasures();
      return eraseLogs;
    };

    it("does not erase a namespace while a local connection of it is live", async () => {
      const { a } = await collected({ finalized: "99" });
      // A lifetime registered after the tombstone (`TOMBSTONE.version`): a
      // connection of an earlier one is stale, and its namespace is erased.
      await a.db.batch([
        {
          sql: "UPDATE connections SET generation = ?, control_version = ? WHERE connector = ?",
          params: [TOMBSTONE.version + 1, TOMBSTONE.version + 1, CONNECTOR],
        },
      ]);
      const eraseLogs = await owed(a);
      // Every pass holds the live namespace back (the default one here).
      expect(eraseLogs).toHaveBeenCalled();
      for (const [, , gate] of eraseLogs.mock.calls)
        expect(gate?.skipNamespaces).toEqual(new Set([""]));
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

    it("erases a deleted namespace though a local connection of another namespace is not deleted", async () => {
      const { w, a } = await collected({ finalized: "99" });
      const otherBefore = logKeys(w, OTHER_LOG);
      // A local connection in a namespace the delete's lifetime does not name
      // (no control row): the delete leaves it, by design.
      await a.db.batch([
        {
          sql: "INSERT INTO connections(connection_id, connector, ns, generation, control_state) VALUES ('stray', ?, ?, 1, 'absent')",
          params: [CONNECTOR, "b".repeat(16)],
        },
      ]);
      const lifetime = await a.sync.deleter.readConnectionLifetime(CONNECTOR);
      await a.sync.deleter.requestConnectionDelete(CONNECTOR, { lifetime });

      await vi.waitFor(() => expect(erasable(w, LOG)).toEqual([]));
      expect(logKeys(w, OTHER_LOG)).toEqual(otherBefore);
      expect(
        await a.db.query(
          "SELECT control_state FROM connections WHERE connection_id = 'stray'",
        ),
      ).toEqual([{ control_state: "absent" }]);
    });

    it("erases once the delete is settled: every local connection purged and no intent", async () => {
      const { a } = await collected({ finalized: "99" });
      await a.sync.deleter.requestConnectionDelete(CONNECTOR);
      await vi.waitFor(async () => expect(await intents(a)).toEqual([]));
      expect(await owed(a)).toHaveBeenCalledTimes(1);
    });
  });
});
