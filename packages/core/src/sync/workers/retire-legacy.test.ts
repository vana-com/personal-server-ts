import { describe, it, expect, vi } from "vitest";

import {
  RETIRE_LEGACY_SCOPES_PER_CYCLE,
  countsOnlyLogger,
  liveRetireLegacy,
  retireLegacyScopes,
  type RetireCoverage,
} from "./retire-legacy.js";
import { deleteScope } from "./delete.js";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { createMemoryDataStorage } from "../../test-utils/memory-storage.js";
import { isEntryCoveredByTombstone } from "../scope-deletions.js";
import type { Logger } from "../../logger/index.js";
import type { DeleteDataPort, DataStoragePort } from "../../ports/index.js";
import { createMemoryPendingBlobDeletionStore } from "../pending-blob-deletions.js";
import {
  entityKeySets,
  type EntityKeySets,
} from "../../storage/legacy-entity-key-sets.js";
import { LEGACY_SCOPE_ENTITY_KEYS } from "../../storage/legacy-scope-entity-keys.js";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";

function logger() {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
    error: vi.fn(),
  } as unknown as Logger & { info: ReturnType<typeof vi.fn> };
}

interface Row {
  collectedAt: string;
  dataPointId: string | null;
}
const BEFORE = "2026-11-01T00:00:00.000Z";
const SWITCH = "2026-11-05T00:00:00.000Z";
const AFTER = "2026-11-06T00:00:00.000Z";

const entryFor = (scope: string, row: Partial<Row> = {}) => ({
  id: 1,
  fileId: null,
  schemaId: null,
  path: `${scope}/x.json`,
  scope,
  collectedAt: BEFORE,
  createdAt: BEFORE,
  sizeBytes: 1,
  version: 1,
  dataPointId: "0xdp" as string | null,
  ...row,
});

/** A legacy body holding one item per id, keyed as the reviewed table says. */
function keyedBody(scope: string, ids: readonly string[]) {
  const [path, fields] = Object.entries(LEGACY_SCOPE_ENTITY_KEYS[scope]!).find(
    ([p]) => /^\$\.\w+$/.test(p),
  )!;
  return {
    [path.slice(2)]: ids.map((id) =>
      Object.fromEntries(fields.map((f) => [f, id])),
    ),
  };
}

/** What the served view holds, as key sets. */
const viewOf = (scope: string, ids: readonly string[]): EntityKeySets | null =>
  entityKeySets(scope, keyedBody(scope, ids));

/** One device's local legacy storage. */
function deviceStorage(
  local: Set<string>,
  rows: Record<string, Partial<Row>> = {},
  bodies: Record<string, unknown> = {},
): DataStoragePort {
  return {
    listScopes: ({ limit = 100, offset = 0 }) => {
      const all = [...local].sort();
      return {
        total: all.length,
        scopes: all.slice(offset, offset + limit).map((scope) => ({
          scope,
          latestCollectedAt: "2026-11-01T00:00:00.000Z",
          versionCount: 1,
        })),
      };
    },
    listVersions: (scope: string) =>
      local.has(scope) ? [entryFor(scope, rows[scope])] : [],
    deleteVersion: async (scope: string) => local.delete(scope),
    markAfterTombstone: () => true,
    readEnvelope: async (scope: string) => ({
      data: scope in bodies ? bodies[scope] : keyedBody(scope, ["a"]),
    }),
  } as unknown as DataStoragePort;
}

/** A gateway shared by every device of the account. */
function gateway(remote: Set<string>) {
  const tombstones: string[] = [];
  const deleteData: DeleteDataPort = {
    async tombstone(scope) {
      tombstones.push(scope);
      const live = remote.delete(scope);
      return live
        ? {
            status: "tombstoned",
            dataPointId: "0x1",
            version: "2",
            deletedAt: "2026-11-02T00:00:00.000Z",
          }
        : {
            status: "already-deleted",
            dataPointId: "0x1",
            version: "2",
            deletedAt: "2026-11-02T00:00:00.000Z",
          };
    },
    // A second deleter finds the keys already gone: missing is success.
    async deleteBlobVersions(_scope, versions) {
      return { deleted: [], missing: versions, failed: [] };
    },
  };
  return { deleteData, tombstones };
}

function world(
  scopes: string[],
  rows: Record<string, Partial<Row>> = {},
  bodies: Record<string, unknown> = {},
) {
  const local = new Set(scopes);
  const remote = new Set(scopes);
  return {
    local,
    remote,
    storage: deviceStorage(local, rows, bodies),
    ...gateway(remote),
  };
}

const covered = (throughMs = Date.parse(SWITCH)): RetireCoverage => ({
  kind: "covered",
  throughMs,
});

interface RunOptions {
  coverage?: (scope: string) => RetireCoverage;
  switchedAt?: string | undefined;
  registeredAt?: (scope: string) => Promise<string | null>;
  viewKeys?: (scope: string) => Promise<EntityKeySets | null>;
  viewRevision?: (scope: string) => string;
  notHeldMemo?: Map<string, string>;
  stillOn?: () => boolean;
  log?: ReturnType<typeof logger>;
}

function run(w: ReturnType<typeof world>, o: RunOptions = {}) {
  const log = o.log ?? logger();
  return retireLegacyScopes({
    storage: w.storage,
    switchedAt: "switchedAt" in o ? o.switchedAt : SWITCH,
    coverage: o.coverage ?? (() => covered()),
    registeredAt: o.registeredAt ?? (async () => BEFORE),
    viewKeys: o.viewKeys ?? (async (scope) => viewOf(scope, ["a"])),
    ...(o.stillOn ? { stillOn: o.stillOn } : {}),
    ...(o.viewRevision ? { viewRevision: o.viewRevision } : {}),
    ...(o.notHeldMemo ? { notHeldMemo: o.notHeldMemo } : {}),
    deleteScope: (scope, entries) =>
      deleteScope(
        {
          storage: w.storage,
          serverOwner: OWNER,
          deleteData: w.deleteData,
          pendingBlobDeletions: createMemoryPendingBlobDeletionStore(),
          logger: logger(),
        },
        scope,
        { onlyEntries: entries },
      ),
    logger: log,
  });
}

describe("retireLegacyScopes", () => {
  it("deletes the legacy files, remote and local, of covered scopes only", async () => {
    const w = world(["github.events", "youtube.likes", "youtube.history"]);
    const result = await run(w, {
      coverage: (s) =>
        s === "youtube.likes"
          ? { kind: "skip", reason: "incomplete" }
          : covered(),
    });
    expect(result).toMatchObject({ considered: 3, deleted: 2 });
    expect(result.skipped.incomplete).toBe(1);
    expect([...w.local]).toEqual(["youtube.likes"]);
    expect([...w.remote]).toEqual(["youtube.likes"]);
  });

  it("keeps every file when no view covers", async () => {
    const w = world(["github.events", "youtube.likes"]);
    const result = await run(w, {
      coverage: () => ({ kind: "skip", reason: "incomplete" }),
    });
    expect(result.deleted).toBe(0);
    expect(w.tombstones).toEqual([]);
    expect(w.local.size).toBe(2);
  });

  it("counts an ambiguous scope (more than one connection) and keeps it", async () => {
    const w = world(["github.events"]);
    const result = await run(w, {
      coverage: () => ({ kind: "skip", reason: "ambiguous" }),
    });
    expect(result.skipped.ambiguous).toBe(1);
    expect(w.local.size).toBe(1);
  });

  describe("switchedAt", () => {
    it.each([
      ["absent", undefined],
      ["unparsable", "not a time"],
      ["empty", ""],
    ])("%s: nothing is deleted", async (_name, switchedAt) => {
      const w = world(["github.events"]);
      // No gateway row either: nothing but the cutoff itself can keep it.
      const result = await run(w, {
        switchedAt,
        registeredAt: async () => null,
      });
      expect(result.deleted).toBe(0);
      expect(w.tombstones).toEqual([]);
      expect(w.local.size).toBe(1);
    });

    it("a local row collected after the switch is this device's own: not counted, and the scope retires once membership holds", async () => {
      const w = world(["github.events", "youtube.likes"], {
        "github.events": { collectedAt: AFTER },
      });
      const result = await run(w, {
        coverage: () => covered(Date.parse(AFTER) + 1000),
      });
      expect(result.legacyWritesAfterSwitch).toBe(0);
      expect(result.deleted).toBe(2);
      expect(w.local.size).toBe(0);
    });

    it("a local row after the switch whose key the view lacks is kept, and still not counted", async () => {
      const w = world(
        ["github.events"],
        { "github.events": { collectedAt: AFTER } },
        { "github.events": keyedBody("github.events", ["a", "b"]) },
      );
      const result = await run(w, {
        coverage: () => covered(Date.parse(AFTER) + 1000),
      });
      expect(result.deleted).toBe(0);
      expect(result.skipped.notInView).toBe(1);
      expect(result.legacyWritesAfterSwitch).toBe(0);
    });

    it("a file registered at exactly the switch time is after it", async () => {
      const w = world(["github.events"]);
      const result = await run(w, { registeredAt: async () => SWITCH });
      expect(result.deleted).toBe(0);
      expect(result.legacyWritesAfterSwitch).toBe(1);
    });

    it("a gateway registration after the switch (another device) keeps the scope and counts 1", async () => {
      const w = world(["github.events"]);
      const result = await run(w, { registeredAt: async () => AFTER });
      expect(result.deleted).toBe(0);
      expect(result.skipped.afterSwitch).toBe(1);
      expect(result.legacyWritesAfterSwitch).toBe(1);
      expect(w.local.size).toBe(1);
    });

    it("an unreadable registry keeps the scope without counting a write", async () => {
      const w = world(["github.events"]);
      const result = await run(w, {
        registeredAt: async () => {
          throw new Error("gateway down");
        },
      });
      expect(result.deleted).toBe(0);
      expect(result.legacyWritesAfterSwitch).toBe(0);
    });

    it("a scope the gateway never saw is retired", async () => {
      const w = world(["github.events"]);
      const result = await run(w, { registeredAt: async () => null });
      expect(result.deleted).toBe(1);
    });

    it("all files before the switch and covered: retired", async () => {
      const w = world(["github.events"]);
      expect((await run(w)).deleted).toBe(1);
      expect(w.local.size).toBe(0);
      expect(w.remote.size).toBe(0);
    });
  });

  describe("coverage", () => {
    it("a local row collected after the oldest head is kept", async () => {
      const w = world(["github.events"], {
        "github.events": { collectedAt: "2026-11-03T00:00:00.000Z" },
      });
      const result = await run(w, {
        coverage: () => covered(Date.parse("2026-11-02T00:00:00.000Z")),
      });
      expect(result.deleted).toBe(0);
      expect(result.skipped.uncovered).toBe(1);
      expect(w.local.size).toBe(1);
    });

    it("a row with an unreadable time is kept", async () => {
      const w = world(["github.events"], {
        "github.events": { collectedAt: "garbage" },
      });
      const result = await run(w);
      expect(result.deleted).toBe(0);
    });

    it("a row on the boundary of the head (collected exactly at throughMs) is covered; one millisecond later is not", async () => {
      const at = "2026-11-03T00:00:00.000Z";
      const edge = Date.parse(at);
      const on = world(["github.events"], {
        "github.events": { collectedAt: at },
      });
      expect((await run(on, { coverage: () => covered(edge) })).deleted).toBe(
        1,
      );
      const late = world(["github.events"], {
        "github.events": { collectedAt: at },
      });
      const result = await run(late, { coverage: () => covered(edge - 1) });
      expect(result.deleted).toBe(0);
      expect(result.skipped.uncovered).toBe(1);
    });
  });

  describe("membership: a complete head is not proof the view holds the file", () => {
    it("head complete at T1 holds {a}; the local version at T0 < T1 holds {a, b}: kept", async () => {
      const w = world(
        ["github.events"],
        {},
        { "github.events": keyedBody("github.events", ["a", "b"]) },
      );
      const result = await run(w, {
        coverage: () => covered(Date.parse(SWITCH)),
        viewKeys: async (scope) => viewOf(scope, ["a"]),
      });
      expect(result.deleted).toBe(0);
      expect(result.skipped.notInView).toBe(1);
      expect(w.tombstones).toEqual([]);
      expect(w.local.size).toBe(1);
    });

    it("a row never uploaded is retired when the view holds every key (uploads stop at the switch)", async () => {
      const w = world(["github.events"], {
        "github.events": { dataPointId: null },
      });
      const result = await run(w, { registeredAt: async () => null });
      expect(result.deleted).toBe(1);
      expect(w.local.size).toBe(0);
    });

    it("a row never uploaded whose key the view lacks is kept", async () => {
      const w = world(
        ["github.events"],
        { "github.events": { dataPointId: null } },
        { "github.events": keyedBody("github.events", ["a", "z"]) },
      );
      const result = await run(w, { registeredAt: async () => null });
      expect(result.deleted).toBe(0);
      expect(w.local.size).toBe(1);
    });

    it.each([
      ["a view that cannot be read", async () => null],
      [
        "a view whose read throws",
        async () => {
          throw new Error("boom");
        },
      ],
    ])("%s: kept", async (_name, viewKeys) => {
      const w = world(["github.events"]);
      const result = await run(w, { viewKeys });
      expect(result.deleted).toBe(0);
      expect(result.skipped.notInView).toBe(1);
    });

    it("a scope with no reviewed key is kept (membership unknown)", async () => {
      const w = world(["acme.unkeyed"]);
      const result = await run(w);
      expect(result.deleted).toBe(0);
      expect(result.skipped.notInView).toBe(1);
    });

    it("a body that is not keyed, or an item without its key, is kept", async () => {
      for (const body of [
        { events: "nope" },
        { events: [{ noId: 1 }] },
        null,
      ]) {
        const w = world(["github.events"], {}, { "github.events": body });
        expect((await run(w)).deleted).toBe(0);
      }
    });

    /** Several local versions of one scope, each with its own key list. */
    function versioned(
      w: ReturnType<typeof world>,
      scope: string,
      byTime: Record<string, readonly string[]>,
    ) {
      const rows = Object.keys(byTime).map((collectedAt, i) =>
        entryFor(scope, { collectedAt, id: i + 1 } as Partial<Row>),
      );
      w.storage.listVersions = (() => rows) as never;
      w.storage.readEnvelope = (async (_s: string, at: string) => ({
        data: keyedBody(scope, byTime[at]!),
      })) as never;
      return rows;
    }

    // Mutant killed: compare only the newest local version. A windowed
    // connector drops old keys from later versions; the delete removes all.
    it("every local version must be held: an older version's key the view lacks keeps the scope", async () => {
      const w = world(["github.events"]);
      versioned(w, "github.events", {
        "2026-10-01T00:00:00.000Z": ["a", "b", "c"],
        "2026-10-15T00:00:00.000Z": ["c", "d"],
      });
      const result = await run(w, {
        viewKeys: async (s) => viewOf(s, ["c", "d"]),
      });
      expect(result.deleted).toBe(0);
      expect(result.skipped.notInView).toBe(1);
      expect(w.tombstones).toEqual([]);
      expect([...w.local]).toEqual(["github.events"]);
    });

    it("every local version held: the scope retires", async () => {
      const w = world(["github.events"]);
      versioned(w, "github.events", {
        "2026-10-01T00:00:00.000Z": ["a", "b", "c"],
        "2026-10-15T00:00:00.000Z": ["c", "d"],
      });
      const result = await run(w, {
        viewKeys: async (s) => viewOf(s, ["a", "b", "c", "d"]),
      });
      expect(result.deleted).toBe(1);
    });
  });

  describe("a version that lands during the delete (real storage, real deleteScope)", () => {
    const SCOPE = "github.events";
    async function seeded() {
      const storage = createMemoryDataStorage();
      const add = async (collectedAt: string, ids: readonly string[]) => {
        const envelope = createDataFileEnvelope(
          SCOPE,
          collectedAt,
          keyedBody(SCOPE, ids),
          "https://schemas.example/x.json",
          `0x${"12".repeat(32)}`,
        );
        const write = await storage.writeEnvelope(envelope);
        return storage.insertEntry({
          fileId: null,
          schemaId: null,
          path: write.relativePath,
          scope: SCOPE,
          collectedAt,
          sizeBytes: write.sizeBytes,
        });
      };
      await add(BEFORE, ["a"]);
      const deleteData: DeleteDataPort = {
        async tombstone() {
          // The file lands while the tombstone call is in flight.
          await add("2026-11-02T00:00:00.000Z", ["z"]);
          return {
            status: "tombstoned",
            dataPointId: "0x1",
            version: "5",
            deletedAt: "2026-11-02T01:00:00.000Z",
          };
        },
        async deleteBlobVersions(_scope, versions) {
          return { deleted: [...versions], missing: [], failed: [] };
        },
      };
      return { storage, deleteData };
    }

    // Mutant killed: erase by scope (ignore the checked ids). A version added
    // during the tombstone call was never checked and is erased unseen.
    it("is not erased, is kept as a re-add the upload guard will not drop", async () => {
      const w = await seeded();
      const result = await retireLegacyScopes({
        storage: w.storage,
        switchedAt: SWITCH,
        coverage: () => covered(),
        registeredAt: async () => BEFORE,
        viewKeys: async (s) => viewOf(s, ["a"]),
        deleteScope: (scope, entries) =>
          deleteScope(
            {
              storage: w.storage,
              serverOwner: OWNER,
              deleteData: w.deleteData,
              pendingBlobDeletions: createMemoryPendingBlobDeletionStore(),
              logger: logger(),
            },
            scope,
            { onlyEntries: entries },
          ),
        logger: logger(),
      });
      expect(result.deleted).toBe(1);
      const left = w.storage.listVersions(SCOPE, { limit: 10, offset: 0 });
      expect(left.map((e) => e.collectedAt)).toEqual([
        "2026-11-02T00:00:00.000Z",
      ]);
      const survivor = left[0]!;
      expect(survivor.dataPointId).toBeNull(); // still unsynced: it uploads
      expect(survivor.afterTombstoneVersion).toBe(5);
      expect(isEntryCoveredByTombstone(survivor, { version: "5" })).toBe(false);
    });

    it("a host without the stamp cannot retire", async () => {
      const w = await seeded();
      const storage = Object.create(w.storage);
      storage.markAfterTombstone = undefined;
      const result = await retireLegacyScopes({
        storage,
        switchedAt: SWITCH,
        coverage: () => covered(),
        registeredAt: async () => BEFORE,
        viewKeys: async (s) => viewOf(s, ["a"]),
        deleteScope: async () => {
          throw new Error("must not delete");
        },
        logger: logger(),
      });
      expect(result.deleted).toBe(0);
    });
  });

  describe("a scope that never retires is not re-read each cycle", () => {
    // Mutant killed: no memo (or a token that ignores the view revision or
    // the local versions).
    it("recomputes only when the view revision or the local versions change", async () => {
      const w = world(["github.events"]);
      const rows = [entryFor("github.events", { id: 1 } as Partial<Row>)];
      w.storage.listVersions = (() => rows) as never;
      let reads = 0;
      w.storage.readEnvelope = (async () => {
        reads += 1;
        return { data: keyedBody("github.events", ["a", "b"]) };
      }) as never;
      const viewKeys = vi.fn(async (s: string) => viewOf(s, ["a"]));
      let revision = "r1";
      const memo = new Map<string, string>();
      const go = () =>
        run(w, { viewKeys, viewRevision: () => revision, notHeldMemo: memo });
      expect((await go()).skipped.notInView).toBe(1);
      expect((await go()).skipped.notInView).toBe(1);
      expect(reads).toBe(1);
      expect(viewKeys).toHaveBeenCalledTimes(1);
      revision = "r2"; // the view changed
      await go();
      expect(reads).toBe(2);
      rows.push(
        entryFor("github.events", {
          id: 2,
          collectedAt: "2026-11-02T00:00:00.000Z",
        } as Partial<Row>),
      ); // a new local version
      await go();
      expect(reads).toBe(3); // read again (stops at the first unheld version)
    });

    // Mutant killed: cache any not-held answer. A file that could not be read
    // is not a fact about the data; a quiet scope must retry and retire.
    it("a read error is not remembered; a real mismatch is", async () => {
      const w = world(["github.events"]);
      const memo = new Map<string, string>();
      let broken = true;
      w.storage.readEnvelope = (async () => {
        if (broken) throw new Error("disk hiccup");
        return { data: keyedBody("github.events", ["a"]) };
      }) as never;
      const go = () =>
        run(w, {
          viewKeys: async (s) => viewOf(s, ["a"]),
          viewRevision: () => "r1",
          notHeldMemo: memo,
        });
      expect((await go()).deleted).toBe(0);
      expect(memo.size).toBe(0);
      broken = false;
      expect((await go()).deleted).toBe(1);
    });

    it("a transient view failure is not remembered", async () => {
      const w = world(["github.events"]);
      const memo = new Map<string, string>();
      let fail = true;
      const go = () =>
        run(w, {
          viewKeys: async (s) => {
            if (fail) throw new Error("read failed");
            return viewOf(s, ["a"]);
          },
          viewRevision: () => "r1",
          notHeldMemo: memo,
        });
      expect((await go()).deleted).toBe(0);
      fail = false;
      expect((await go()).deleted).toBe(1);
    });
  });

  describe("the switch is re-read before each delete", () => {
    it("turning it off mid-pass stops further deletes", async () => {
      const w = world(["github.events", "youtube.likes", "youtube.history"]);
      let on = true;
      const original = w.deleteData.tombstone.bind(w.deleteData);
      w.deleteData.tombstone = async (scope, fence) => {
        on = false; // the account switches off while the first delete runs
        return original(scope, fence);
      };
      const result = await run(w, { stillOn: () => on });
      expect(result.deleted).toBe(1);
      expect(w.tombstones.length).toBe(1);
      expect(w.local.size).toBe(2);
    });
  });

  it("is idempotent: a second pass finds nothing to do", async () => {
    const w = world(["github.events"]);
    await run(w);
    const again = await run(w);
    expect(again.considered).toBe(0);
    expect(w.tombstones).toEqual(["github.events"]);
  });

  it("two devices deleting at the same time both succeed", async () => {
    const w = world(["github.events", "youtube.likes"]);
    const localB = new Set(w.local);
    const b = { ...w, local: localB, storage: deviceStorage(localB) };
    const [ra, rb] = await Promise.all([run(w), run(b)]);
    expect(ra.deleted).toBe(2);
    expect(rb.deleted).toBe(2);
    expect(w.local.size).toBe(0);
    expect(localB.size).toBe(0);
    expect(w.remote.size).toBe(0);
  });

  it("never touches stream-sync or reserved names", async () => {
    const w = world([
      "github.events",
      "pdpp.acme~0123456789abcdef.items",
      "pdpp.acme~0123456789abcdef",
      "vana.system.keys",
    ]);
    const asked: string[] = [];
    await run(w, { coverage: (s) => (asked.push(s), covered()) });
    expect(asked).toEqual(["github.events"]);
    expect(w.tombstones).toEqual(["github.events"]);
    expect(w.local.has("pdpp.acme~0123456789abcdef.items")).toBe(true);
    expect(w.local.has("pdpp.acme~0123456789abcdef")).toBe(true);
    expect(w.local.has("vana.system.keys")).toBe(true);
  });

  it("keeps the local copy when the gateway delete fails, and retries later", async () => {
    const w = world(["github.events"]);
    let fail = true;
    const original = w.deleteData.tombstone.bind(w.deleteData);
    w.deleteData.tombstone = async (scope, fence) => {
      if (fail) throw new Error("gateway down");
      return original(scope, fence);
    };
    const first = await run(w);
    expect(first.deleted).toBe(0);
    expect(first.skipped.failed).toBe(1);
    expect(w.local.has("github.events")).toBe(true);
    fail = false;
    expect((await run(w)).deleted).toBe(1);
    expect(w.local.size).toBe(0);
  });

  it("limits the scopes deleted per cycle", async () => {
    const names = [
      "github.events",
      "youtube.likes",
      "youtube.history",
      "youtube.subscriptions",
      "youtube.watchLater",
      "youtube.playlists",
      "strava.activities",
      "shop.orders",
      "amazon.orders",
      "chatgpt.memories",
      "claude.projects",
      "icloud_notes.notes",
      "icloud_notes.folders",
    ].slice(0, RETIRE_LEGACY_SCOPES_PER_CYCLE + 3);
    const w = world(names);
    const result = await run(w);
    expect(result.deleted).toBe(RETIRE_LEGACY_SCOPES_PER_CYCLE);
    expect(w.local.size).toBe(3);
  });

  it("its own log carries counts only", async () => {
    const w = world(["youtube.subscriptions"]);
    const log = logger();
    await run(w, { log });
    expect(JSON.stringify(log.info.mock.calls)).not.toContain("youtube");
  });
});

describe("countsOnlyLogger", () => {
  it("passes counts and statuses and drops every identifying field", () => {
    const sink = logger();
    const log = countsOnlyLogger(sink);
    log.info(
      {
        scope: "secret.scope",
        dataPointId: "0xsecret",
        version: "7",
        tombstoneVersion: "9",
        keys: ["secret-key"],
        error: "secret message",
        marker: { scope: "secret.scope" },
        durable: true,
        gateway: "ok",
        storage: "deferred",
        blobsDeleted: 3,
        pending: 2,
        local: "secret-status-text",
      },
      "Scope deletion finished",
    );
    expect(sink.info).toHaveBeenCalledWith(
      {
        durable: true,
        gateway: "ok",
        storage: "deferred",
        blobsDeleted: 3,
        pending: 2,
      },
      "Scope deletion finished",
    );
    expect(JSON.stringify(sink.info.mock.calls)).not.toContain("secret");
  });

  it("drops an error object passed as the payload", () => {
    const sink = logger();
    countsOnlyLogger(sink).warn(new Error("secret message"), "failed");
    expect(JSON.stringify(sink.warn.mock.calls)).not.toContain("secret");
  });
});

describe("liveRetireLegacy", () => {
  const reader = { viewCoverage: () => covered() };
  const config = (write: boolean, switchedAt?: string) => ({
    streamSync: { write, switchedAt },
  });

  it("is off without the writer, without the reader, or with write off", () => {
    expect(
      liveRetireLegacy({ config: config(true), writer: null, reader })(),
    ).toBeNull();
    expect(
      liveRetireLegacy({ config: config(true), writer: {}, reader: null })(),
    ).toBeNull();
    expect(
      liveRetireLegacy({ config: config(false), writer: {}, reader })(),
    ).toBeNull();
  });

  it("reads the config each call: turning write off turns it off", () => {
    const c = config(true, SWITCH);
    const live = liveRetireLegacy({ config: c, writer: {}, reader });
    expect(live()?.switchedAt).toBe(SWITCH);
    c.streamSync.write = false;
    expect(live()).toBeNull();
    c.streamSync.write = true;
    c.streamSync.switchedAt = AFTER;
    expect(live()?.switchedAt).toBe(AFTER);
  });
});
