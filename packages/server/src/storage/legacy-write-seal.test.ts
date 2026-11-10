/**
 * Node storage seals every legacy file and index row it makes durable.
 *
 * Every test runs over a REAL mode authority (the module's own lock and
 * records), never a stub of its answer. The authority is wrapped twice:
 *
 * - its early courtesy answers (`admit`, `read`) always say "legacy", so a
 *   sink that only trusted an early check would write on a switched account;
 *   only the durable record read inside the lock can refuse;
 * - `commitLegacy` can pause inside the lock, which lets a test hold a write
 *   in flight while an On answer is submitted behind it.
 *
 * Per sink, the three properties are: a write in flight before On lands
 * before On is answered; a write started after On is refused and leaves
 * nothing; and the durable record decides (per mode, with a lying courtesy).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname, join, relative } from "node:path";
import { tmpdir } from "node:os";
import { pino } from "pino";
import type Database from "better-sqlite3";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/node";
import { buildDataFilePath } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import {
  createLegacyWriteSeal,
  LegacyWriteRefusedError,
  type LegacyWriteSeal,
} from "@opendatalabs/personal-server-ts-core/storage/legacy-write-seal";
import {
  createMemoryModeRecordStore,
  createModeAuthority,
  type ModeAuthority,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import {
  HOLD_FOR_TESTS,
  authorityHearing,
  fixedOwnedAccountStorageMode,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { initializeDatabase } from "./index-schema.js";
import { createIndexManager, type IndexManager } from "./index-manager.js";
import {
  createNodeDataStorage,
  recoverImportOperations,
  recoverStagedDataFiles,
  reindexLegacyDataFiles,
  type NodeDataStorageDeps,
} from "./node-data-storage.js";
import { dataRoutes } from "../routes/data.js";
import { SCOPE_IMPORT_CHUNK_BYTES } from "../routes/chunked-scope-import.js";

const owner = "0x1111111111111111111111111111111111111111";
const scope = "instagram.profile";
const collectedAt = "2026-11-09T00:00:00Z";
const bearer = { Authorization: "Bearer seal-test" };

type Mode = "off" | "on" | "unknown";

interface Deferred {
  promise: Promise<void>;
  resolve: () => void;
}
function deferred(): Deferred {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 5));

/** Fail a hang (a deadlock) as a test failure, not a suite timeout. */
function within<T>(promise: Promise<T>, ms = 3000): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error(`still pending after ${ms}ms`)), ms),
    ),
  ]);
}

/** Every file below `dir`, relative to it. */
async function filesUnder(dir: string): Promise<string[]> {
  try {
    const entries = await readdir(dir, {
      recursive: true,
      withFileTypes: true,
    });
    return entries
      .filter((entry) => entry.isFile())
      .map((entry) => relative(dir, join(entry.parentPath, entry.name)));
  } catch {
    return [];
  }
}

const envelope = (value = "v", at = collectedAt) =>
  createDataFileEnvelope(scope, at, { value });
const intent = (value: string) => ({
  authority: "local",
  owner: "owner",
  operation: value.repeat(64),
  bodySha256: value.repeat(64),
});

interface Harness {
  root: string;
  dataDir: string;
  db: Database.Database;
  index: IndexManager;
  /** The real authority: submit evidence here. */
  authority: ModeAuthority;
  seal: LegacyWriteSeal;
  deps: NodeDataStorageDeps;
  storage: ReturnType<typeof createNodeDataStorage>;
  /** Pause the next sealed write inside the lock until `release()`. */
  pauseNextWrite(): { entered: Promise<void>; release: () => void };
  turnOn(): Promise<unknown>;
}

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0)) await cleanup();
});

async function realAuthority(mode: Mode): Promise<ModeAuthority> {
  if (mode !== "unknown") return authorityHearing(owner, mode);
  const authority = createModeAuthority({
    store: createMemoryModeRecordStore(),
  });
  await authority.ready;
  return authority;
}

async function harness(mode: Mode): Promise<Harness> {
  const root = await mkdtemp(join(tmpdir(), "legacy-write-seal-"));
  const dataDir = join(root, "data");
  const db = initializeDatabase(join(root, "index.db"));
  const index = createIndexManager(db);
  const authority = await realAuthority(mode);
  let pause: { entered: Deferred; release: Deferred } | undefined;
  const wrapped: ModeAuthority = {
    ...authority,
    // A stale early answer: only the record read inside the lock refuses.
    read: () => ({ kind: "legacy" }),
    commitLegacy: (who, write) =>
      authority.commitLegacy(who, async () => {
        const mine = pause;
        if (mine) {
          pause = undefined;
          mine.entered.resolve();
          await mine.release.promise;
        }
        return write();
      }),
  };
  const seal = createLegacyWriteSeal({ authority: wrapped, owner });
  const deps: NodeDataStorageDeps = {
    indexManager: index,
    hierarchyOptions: { dataDir },
    legacyWriteSeal: seal,
  };
  cleanups.push(async () => {
    index.close();
    await authority.close();
    await rm(root, { recursive: true, force: true });
  });
  return {
    root,
    dataDir,
    db,
    index,
    authority,
    seal,
    deps,
    storage: createNodeDataStorage(deps),
    pauseNextWrite() {
      pause = { entered: deferred(), release: deferred() };
      return { entered: pause.entered.promise, release: pause.release.resolve };
    },
    turnOn: () =>
      authority.submitEvidence({
        owner,
        state: "on",
      }),
  };
}

/** What the disk and the index hold, whichever sink wrote it. */
async function state(h: Harness) {
  const files = (await filesUnder(h.dataDir)).filter(
    (file) => !file.startsWith(".scope-imports"),
  );
  return {
    published: files.filter(
      (file) => file.endsWith(".json") && !file.includes(".pending."),
    ),
    stages: files.filter((file) => file.includes(".pending.")),
    files,
    rows: h.index.countByScope(scope),
    ops: (
      h.db
        .prepare("SELECT COUNT(*) AS n FROM owner_import_operations")
        .get() as { n: number }
    ).n,
  };
}

/** Run a write; a seal refusal becomes its HTTP status, success is 200. */
async function statusOf(action: () => unknown): Promise<number> {
  try {
    const result = await action();
    if (result instanceof Response)
      return result.status === 201 ? 200 : result.status;
    return 200;
  } catch (error) {
    if (error instanceof LegacyWriteRefusedError) return error.response.status;
    throw error;
  }
}

interface Sink {
  name: string;
  /**
   * A boot recovery swallows a refusal (it drops or keeps what it found), so
   * it never answers 426 or 503; the state it leaves is the evidence.
   */
  silent?: true;
  /** Put the world in the state the sink starts from (before any pause). */
  prepare?(h: Harness): Promise<void>;
  run(h: Harness): Promise<unknown>;
  /** The write became durable. */
  landed(h: Harness): Promise<boolean>;
  /** The refused write left nothing of its own behind. */
  leftNothing(h: Harness): Promise<boolean>;
  /** What a refusal under an unknown mode leaves for a later boot. */
  keptOnUnknown?(h: Harness): Promise<boolean>;
}

const routeSession = new WeakMap<
  Harness,
  { app: ReturnType<typeof dataRoutes>; id: string }
>();

function routeApp(h: Harness) {
  return dataRoutes({
    legacyWriteSeal: h.seal,
    // A stale courtesy answer, as in the harness: the sink must still refuse.
    accountStorageMode: fixedOwnedAccountStorageMode("unswitched", owner),
    indexManager: h.index,
    hierarchyOptions: h.deps.hierarchyOptions,
    logger: pino({ level: "silent" }),
    serverOrigin: "http://localhost:8080",
    serverOwner: owner,
    devToken: "seal-test",
    gateway: {} as GatewayClient,
    accessLogWriter: { write: async () => undefined },
  });
}

async function openImport(h: Harness): Promise<string> {
  const chunk = new Uint8Array(SCOPE_IMPORT_CHUNK_BYTES).fill(0x20);
  chunk.set(new TextEncoder().encode('{"data":[]}'));
  const sha = createHash("sha256").update(chunk).digest("hex");
  const app = routeApp(h);
  const opened = await app.request(`/${scope}/imports`, {
    method: "POST",
    headers: { ...bearer, "Content-Type": "application/json" },
    body: JSON.stringify({
      totalBytes: chunk.byteLength,
      totalChunks: 1,
      sha256: sha,
    }),
  });
  expect(opened.status).toBe(201);
  const { importId } = (await opened.json()) as { importId: string };
  const sent = await app.request(`/${scope}/imports/${importId}/chunks/0`, {
    method: "PUT",
    headers: {
      ...bearer,
      "Content-Type": "application/octet-stream",
      "x-chunk-sha256": sha,
    },
    body: chunk,
  });
  expect(sent.status).toBe(200);
  routeSession.set(h, { app, id: importId });
  return importId;
}

const finalizeRequest = async (h: Harness): Promise<Response> => {
  const session = routeSession.get(h)!;
  return session.app.request(`/${scope}/imports/${session.id}/finalize`, {
    method: "POST",
    headers: bearer,
  });
};

const finalPathOf = (h: Harness, at = collectedAt) =>
  buildDataFilePath(h.dataDir, scope, at);

const SINKS: Sink[] = [
  {
    name: "writeEnvelope",
    run: (h) => h.storage.writeEnvelope(envelope()),
    landed: async (h) => (await state(h)).published.length === 1,
    leftNothing: async (h) => (await state(h)).files.length === 0,
  },
  {
    name: "writeEnvelopeAndIndex",
    run: (h) =>
      h.storage.writeEnvelopeAndIndex!(envelope(), {
        fileId: null,
        scope,
        collectedAt,
      }),
    landed: async (h) => {
      const s = await state(h);
      return s.published.length === 1 && s.rows === 1;
    },
    leftNothing: async (h) => {
      const s = await state(h);
      return s.files.length === 0 && s.rows === 0;
    },
  },
  {
    name: "commitEnvelope",
    run: (h) =>
      h.storage.commitEnvelope!(envelope(), {
        fileId: null,
        scope,
        collectedAt,
      }),
    landed: async (h) => {
      const s = await state(h);
      return s.published.length === 1 && s.rows === 1;
    },
    leftNothing: async (h) => {
      const s = await state(h);
      return s.files.length === 0 && s.rows === 0;
    },
  },
  {
    name: "insertEntry",
    run: async (h) =>
      h.storage.insertEntry({
        fileId: null,
        path: `instagram/profile/${collectedAt}.json`,
        scope,
        collectedAt,
        sizeBytes: 1,
      }),
    landed: async (h) => (await state(h)).rows === 1,
    leftNothing: async (h) => (await state(h)).rows === 0,
  },
  {
    name: "commitVersion with an import intent",
    run: (h) =>
      h.storage.commitVersion!({
        kind: "append",
        envelope: envelope(),
        metadata: {},
        import: intent("a"),
      }),
    landed: async (h) => {
      const s = await state(h);
      return s.published.length === 1 && s.rows === 1 && s.ops === 1;
    },
    leftNothing: async (h) => {
      const s = await state(h);
      return s.files.length === 0 && s.rows === 0 && s.ops === 0;
    },
  },
  {
    name: "commitVersion without an intent",
    run: (h) =>
      h.storage.commitVersion!({
        kind: "append",
        envelope: envelope(),
        metadata: {},
      }),
    landed: async (h) => {
      const s = await state(h);
      return s.published.length === 1 && s.rows === 1;
    },
    leftNothing: async (h) => {
      const s = await state(h);
      return s.files.length === 0 && s.rows === 0 && s.ops === 0;
    },
  },
  {
    name: "commitVersion replica",
    run: (h) =>
      h.storage.commitVersion!({
        kind: "replica",
        envelope: envelope(),
        metadata: { schemaId: null, dataPointId: "dp-1", version: 1 },
      }),
    landed: async (h) => {
      const s = await state(h);
      return s.published.length === 1 && s.rows === 1;
    },
    leftNothing: async (h) => {
      const s = await state(h);
      return s.files.length === 0 && s.rows === 0;
    },
  },
  {
    name: "chunked finalize (new publication)",
    prepare: async (h) => {
      await openImport(h);
    },
    run: async (h) => finalizeRequest(h),
    landed: async (h) => {
      const s = await state(h);
      return s.published.length === 1 && s.rows === 1;
    },
    leftNothing: async (h) => {
      const s = await state(h);
      return s.files.length === 0 && s.rows === 0;
    },
  },
  {
    name: "chunked finalize (resumed stage)",
    prepare: async (h) => {
      const id = await openImport(h);
      const metadata = JSON.parse(
        await readFile(
          join(h.dataDir, ".scope-imports", id, "metadata.json"),
          "utf8",
        ),
      ) as { collectedAt: string };
      const finalPath = finalPathOf(h, metadata.collectedAt);
      await mkdir(dirname(finalPath), { recursive: true });
      await writeFile(
        `${finalPath}.pending.${id}`,
        JSON.stringify(envelope("staged", metadata.collectedAt)),
      );
      h.index.insert(HOLD_FOR_TESTS, {
        fileId: null,
        path: relative(h.dataDir, finalPath),
        scope,
        collectedAt: metadata.collectedAt,
        sizeBytes: 1,
      });
    },
    run: async (h) => finalizeRequest(h),
    landed: async (h) => (await state(h)).published.length === 1,
    leftNothing: async (h) => {
      const s = await state(h);
      return s.files.length === 0 && s.rows === 0;
    },
    keptOnUnknown: async (h) => {
      const s = await state(h);
      return s.stages.length === 1 && s.rows === 1;
    },
  },
  {
    name: "recoverStagedDataFiles",
    silent: true,
    prepare: async (h) => {
      const finalPath = finalPathOf(h);
      await mkdir(dirname(finalPath), { recursive: true });
      await writeFile(`${finalPath}.pending.boot`, JSON.stringify(envelope()));
      h.index.insert(HOLD_FOR_TESTS, {
        fileId: null,
        path: relative(h.dataDir, finalPath),
        scope,
        collectedAt,
        sizeBytes: 1,
      });
    },
    run: (h) => recoverStagedDataFiles(h.deps),
    landed: async (h) => {
      const s = await state(h);
      return s.published.length === 1 && s.stages.length === 0 && s.rows === 1;
    },
    leftNothing: async (h) => {
      const s = await state(h);
      return s.files.length === 0 && s.rows === 0;
    },
    keptOnUnknown: async (h) => {
      const s = await state(h);
      return s.stages.length === 1 && s.rows === 1;
    },
  },
  {
    name: "reindexLegacyDataFiles",
    silent: true,
    prepare: async (h) => {
      const finalPath = finalPathOf(h);
      await mkdir(dirname(finalPath), { recursive: true });
      await writeFile(finalPath, JSON.stringify(envelope()));
    },
    run: (h) => reindexLegacyDataFiles(h.deps),
    landed: async (h) => (await state(h)).rows === 1,
    // The file stays on disk, unindexed: only the row is a legacy commit.
    leftNothing: async (h) => (await state(h)).rows === 0,
    keptOnUnknown: async (h) => {
      const s = await state(h);
      return s.rows === 0 && s.published.length === 1;
    },
  },
  {
    name: "recoverImportOperations (a prepared import)",
    silent: true,
    prepare: async (h) => {
      const finalPath = finalPathOf(h);
      h.db
        .prepare(
          `INSERT INTO owner_import_operations (authority, owner, scope, operation, body_sha256, state, collected_at, path, envelope_bytes, metadata_json)
           VALUES ('local', 'owner', @scope, @operation, @sha, 'prepared', @collectedAt, @path, @bytes, '{}')`,
        )
        .run({
          scope,
          operation: "p".repeat(64),
          sha: "p".repeat(64),
          collectedAt,
          path: relative(h.dataDir, finalPath),
          bytes: Buffer.from(JSON.stringify(envelope())),
        });
    },
    run: (h) => recoverImportOperations(h.deps),
    landed: async (h) => {
      const s = await state(h);
      return s.published.length === 1 && s.rows === 1;
    },
    leftNothing: async (h) => {
      const s = await state(h);
      return s.files.length === 0 && s.rows === 0 && s.ops === 0;
    },
    keptOnUnknown: async (h) => {
      const s = await state(h);
      return s.ops === 1 && s.files.length === 0 && s.rows === 0;
    },
  },
];

/** The status a refused write answers; a silent recovery always resolves. */
const refusedWith = (sink: Sink, status: number) =>
  sink.silent ? 200 : status;

describe.each(SINKS)("$name", (sink) => {
  it("a write in flight before On lands before On is answered", async () => {
    const h = await harness("off");
    await sink.prepare?.(h);
    const pause = h.pauseNextWrite();
    const write = sink.run(h);
    await within(pause.entered);

    let answered = false;
    let landedWhenAnswered: boolean | undefined;
    const on = h.turnOn().then(async () => {
      answered = true;
      landedWhenAnswered = await sink.landed(h);
    });
    await tick();
    // The write holds the lock: On is not answered and nothing is durable yet.
    expect(answered).toBe(false);
    expect(await sink.landed(h)).toBe(false);

    pause.release();
    expect(await statusOf(() => within(write))).toBe(200);
    await within(on);
    expect(landedWhenAnswered).toBe(true);
  });

  it("a write started after On is refused with the 426 and leaves nothing", async () => {
    const h = await harness("off");
    await sink.prepare?.(h);
    await h.turnOn();
    expect(await statusOf(() => sink.run(h))).toBe(refusedWith(sink, 426));
    expect(await sink.leftNothing(h)).toBe(true);
  });

  it("the record decides: an Off record writes, an On record refuses, an unknown one answers 503", async () => {
    const open = await harness("off");
    await sink.prepare?.(open);
    expect(await statusOf(() => sink.run(open))).toBe(200);
    expect(await sink.landed(open)).toBe(true);

    const switched = await harness("on");
    await sink.prepare?.(switched);
    expect(await statusOf(() => sink.run(switched))).toBe(
      refusedWith(sink, 426),
    );
    expect(await sink.leftNothing(switched)).toBe(true);

    const unknown = await harness("unknown");
    await sink.prepare?.(unknown);
    expect(await statusOf(() => sink.run(unknown))).toBe(
      refusedWith(sink, 503),
    );
    if (sink.keptOnUnknown) {
      expect(await sink.keptOnUnknown(unknown)).toBe(true);
    } else {
      expect(await sink.leftNothing(unknown)).toBe(true);
    }
  });
});

describe("a sealed write never nests the lock", () => {
  it("an On queued behind an in-flight write, and a second write behind it, finish without deadlock", async () => {
    const h = await harness("off");
    const pause = h.pauseNextWrite();
    const first = statusOf(() =>
      h.storage.writeEnvelopeAndIndex!(envelope("a"), {
        fileId: null,
        scope,
        collectedAt,
      }),
    );
    await within(pause.entered);
    const on = h.turnOn();
    // On is queued behind the in-flight write before the next write starts.
    await tick();
    const second = statusOf(() =>
      h.storage.writeEnvelopeAndIndex!(envelope("b", "2026-11-09T00:00:01Z"), {
        fileId: null,
        scope,
        collectedAt: "2026-11-09T00:00:01Z",
      }),
    );
    await tick();
    pause.release();

    expect(await within(first)).toBe(200);
    await within(on);
    expect(await within(second)).toBe(426);
    const s = await state(h);
    expect(s.published).toHaveLength(1);
    expect(s.rows).toBe(1);
  });

  it("a chunked-import commit and an owner import in flight together do not deadlock behind an On", async () => {
    const h = await harness("off");
    await openImport(h);
    const pause = h.pauseNextWrite();
    const finalize = finalizeRequest(h);
    await within(pause.entered);
    const on = h.turnOn();
    await tick();
    const owner2 = statusOf(() =>
      h.storage.commitVersion!({
        kind: "append",
        envelope: envelope("o", "2026-11-09T00:00:02Z"),
        metadata: {},
        import: intent("b"),
      }),
    );
    await tick();
    pause.release();
    expect((await within(finalize)).status).toBe(201);
    await within(on);
    expect(await within(owner2)).toBe(426);
  });
});

describe("the lock order is the seal, then the scope lock", () => {
  it("a deleteScope that holds the seal, a queued On and a concurrent writer of the same scope settle without deadlock", async () => {
    const h = await harness("off");
    await h.storage.writeEnvelopeAndIndex!(envelope(), {
      fileId: null,
      scope,
      collectedAt,
    });
    const pause = h.pauseNextWrite();
    // A caller inside the seal (the client delete route) erases the scope with
    // its hold, which takes the scope's lock inside the hold.
    const erased = h.seal.commit((hold) => h.storage.deleteScope(scope, hold));
    await within(pause.entered);
    // The On queues behind the delete, then a writer of the same scope queues
    // behind the On. If the writer took the scope lock first it would hold it
    // while waiting for the seal, and the delete would wait for that lock: a
    // deadlock. The seal comes first, so the writer holds nothing while it waits.
    const on = h.turnOn();
    await tick();
    const writer = statusOf(() =>
      h.storage.writeEnvelopeAndIndex!(envelope("w", "2026-11-09T00:00:05Z"), {
        fileId: null,
        scope,
        collectedAt: "2026-11-09T00:00:05Z",
      }),
    );
    await tick();
    pause.release();

    expect(await within(erased)).toBe(1);
    await within(on);
    expect(await within(writer)).toBe(426);
    const s = await state(h);
    expect(s.rows).toBe(0);
    expect(s.files).toEqual([]);
  });
});

describe("removal is admitted in every mode", () => {
  /** Every mode, over a storage with and without the import journal. */
  const CASES = (["off", "on", "unknown"] as const).flatMap((mode) =>
    [true, false].map((journal) => [mode, journal] as const),
  );
  async function seeded(mode: Mode, journal: boolean) {
    // Seed the data through an open storage, then judge removals over the
    // storage built on the mode under test.
    const open = await harness("off");
    await open.storage.writeEnvelopeAndIndex!(envelope(), {
      fileId: "file-1",
      scope,
      collectedAt,
    });
    await open.storage.writeEnvelopeAndIndex!(
      envelope("w", "2026-11-09T00:00:09Z"),
      {
        fileId: "file-2",
        scope,
        collectedAt: "2026-11-09T00:00:09Z",
      },
    );
    // The mode under test decides over the SAME data and index.
    const authority = await realAuthority(mode);
    const seal = createLegacyWriteSeal({ authority, owner });
    cleanups.push(() => authority.close());
    // An index manager the journal does not know has no import operations:
    // the storage then removes through its own sealed path.
    const storage = createNodeDataStorage({
      ...open.deps,
      indexManager: journal ? open.index : { ...open.index },
      legacyWriteSeal: seal,
    });
    return { open, storage };
  }

  it.each(CASES)(
    "deleteByFileId in %s (import journal: %s)",
    async (mode, journal) => {
      const { open, storage } = await seeded(mode, journal);
      expect(await storage.deleteByFileId("file-1")).toBe(true);
      expect((await state(open)).rows).toBe(1);
    },
  );

  it.each(CASES)(
    "deleteVersion in %s (import journal: %s)",
    async (mode, journal) => {
      const { open, storage } = await seeded(mode, journal);
      await storage.deleteVersion!(scope, collectedAt);
      expect((await state(open)).rows).toBe(1);
    },
  );

  it.each(CASES)(
    "deleteScope in %s (import journal: %s)",
    async (mode, journal) => {
      const { open, storage } = await seeded(mode, journal);
      expect(await storage.deleteScope(scope)).toBe(2);
      const s = await state(open);
      expect(s.rows).toBe(0);
      expect(s.published).toEqual([]);
    },
  );

  it.each(CASES)(
    "dropUnsyncedEntry in %s (import journal: %s)",
    async (mode, journal) => {
      const { open, storage } = await seeded(mode, journal);
      const row = open.index.findByScope({ scope })[0]!;
      await storage.dropUnsyncedEntry!(row.path);
      expect((await state(open)).rows).toBe(1);
    },
  );

  type Storage = ReturnType<typeof createNodeDataStorage>;
  const REMOVALS: ReadonlyArray<
    readonly [
      string,
      number,
      (storage: Storage, row: string) => Promise<unknown>,
    ]
  > = [
    ["deleteByFileId", 1, (st) => st.deleteByFileId("file-1")],
    ["deleteVersion", 1, (st) => st.deleteVersion!(scope, collectedAt)],
    ["deleteScope", 0, (st) => st.deleteScope(scope)],
    ["dropUnsyncedEntry", 1, (st, row) => st.dropUnsyncedEntry!(row)],
  ];

  it.each(
    REMOVALS.flatMap(([name, rowsLeft, run]) =>
      [true, false].map((journal) => [name, rowsLeft, run, journal] as const),
    ),
  )(
    "%s runs under the shared lock: an On waits for a removal in flight (import journal: %s)",
    async (_name, rowsLeft, run, journal) => {
      const open = await harness("off");
      await open.storage.writeEnvelopeAndIndex!(envelope(), {
        fileId: "file-1",
        scope,
        collectedAt,
      });
      await open.storage.writeEnvelopeAndIndex!(
        envelope("w", "2026-11-09T00:00:09Z"),
        { fileId: "file-2", scope, collectedAt: "2026-11-09T00:00:09Z" },
      );
      const row = open.index.findByScope({ scope })[0]!.path;
      const authority = await realAuthority("off");
      cleanups.push(() => authority.close());
      // Pause inside the removal's own lock, where the module runs it.
      const inside = deferred();
      const proceed = deferred();
      const gated: ModeAuthority = {
        ...authority,
        commitRemoval: (work) =>
          authority.commitRemoval(async () => {
            inside.resolve();
            await proceed.promise;
            return work();
          }),
      };
      const storage = createNodeDataStorage({
        ...open.deps,
        // An index manager the journal does not know has no import operations.
        indexManager: journal ? open.index : { ...open.index },
        legacyWriteSeal: createLegacyWriteSeal({ authority: gated, owner }),
      });

      const removing = run(storage, row);
      await within(inside.promise);
      let rowsWhenAnswered = -1;
      const on = authority
        .submitEvidence({
          owner,
          state: "on",
        })
        .then(async () => {
          rowsWhenAnswered = (await state(open)).rows;
        });
      await tick();
      expect(rowsWhenAnswered).toBe(-1);

      proceed.resolve();
      await within(removing);
      await within(on);
      expect(rowsWhenAnswered).toBe(rowsLeft);
    },
  );

  it("a removal given a hold runs inside the caller's commit, without taking the lock again", async () => {
    const h = await harness("off");
    await h.storage.writeEnvelopeAndIndex!(envelope(), {
      fileId: null,
      scope,
      collectedAt,
    });
    // A caller holding the lock (the route's delete) passes its hold; taking
    // the lock again here would hang.
    const deleted = await within(
      h.seal.commit((hold) => h.storage.deleteScope(scope, hold)),
    );
    expect(deleted).toBe(1);
    expect((await state(h)).rows).toBe(0);
  });

  const owe = (h: Harness) =>
    h.db
      .prepare(
        `INSERT INTO owner_import_operations (authority, owner, scope, operation, body_sha256, state, collected_at, path, envelope_bytes, metadata_json)
         VALUES ('local', 'owner', @scope, @operation, @sha, 'prepared', @collectedAt, @path, @bytes, '{}')`,
      )
      .run({
        scope,
        operation: "q".repeat(64),
        sha: "q".repeat(64),
        collectedAt,
        path: relative(h.dataDir, finalPathOf(h)),
        bytes: Buffer.from(JSON.stringify(envelope())),
      });

  it("a delete never publishes an owed import under a switched account", async () => {
    const h = await harness("on");
    owe(h);
    const indexed = vi.spyOn(h.index, "insertIfCurrent");
    await h.storage.deleteScope(scope);
    // Not even for a moment: a removal never installs a row.
    expect(indexed).not.toHaveBeenCalled();
    const s = await state(h);
    expect(s.published).toEqual([]);
    expect(s.rows).toBe(0);
  });

  it("a delete on an unswitched account finishes an owed import as its own commit, then removes", async () => {
    const h = await harness("off");
    owe(h);
    const indexed = vi.spyOn(h.index, "insertIfCurrent");
    await h.storage.deleteScope(scope);
    expect(indexed).toHaveBeenCalledTimes(1);
    const s = await state(h);
    expect(s.published).toEqual([]);
    expect(s.rows).toBe(0);
  });
});

describe("boot recovery by mode", () => {
  async function bootWorld(mode: Mode) {
    const h = await harness(mode);
    const finalPath = finalPathOf(h);
    await mkdir(dirname(finalPath), { recursive: true });
    await writeFile(`${finalPath}.pending.boot`, JSON.stringify(envelope()));
    h.index.insert(HOLD_FOR_TESTS, {
      fileId: null,
      path: relative(h.dataDir, finalPath),
      scope,
      collectedAt,
      sizeBytes: 1,
    });
    return h;
  }

  it("an unswitched account publishes the acknowledged stage", async () => {
    const h = await bootWorld("off");
    await recoverStagedDataFiles(h.deps);
    const s = await state(h);
    expect(s.published).toHaveLength(1);
    expect(s.stages).toEqual([]);
    expect(s.rows).toBe(1);
  });

  it("a switched account drops the stage and its row", async () => {
    const h = await bootWorld("on");
    await recoverStagedDataFiles(h.deps);
    const s = await state(h);
    expect(s.files).toEqual([]);
    expect(s.rows).toBe(0);
  });

  it("an unknown mode leaves the stage and its row for a later boot, then a later boot decides", async () => {
    const h = await bootWorld("unknown");
    await recoverStagedDataFiles(h.deps);
    let s = await state(h);
    expect(s.stages).toHaveLength(1);
    expect(s.rows).toBe(1);

    // The Account answers Off: the same files, a later boot, now published.
    await h.authority.submitEvidence({
      owner,
      state: "off",
    });
    await recoverStagedDataFiles(h.deps);
    s = await state(h);
    expect(s.published).toHaveLength(1);
    expect(s.stages).toEqual([]);
  });

  it("a stage that lost its index race is removed in every mode", async () => {
    for (const mode of ["off", "on", "unknown"] as const) {
      const h = await harness(mode);
      const finalPath = finalPathOf(h);
      await mkdir(dirname(finalPath), { recursive: true });
      await writeFile(`${finalPath}.pending.lost`, JSON.stringify(envelope()));
      await recoverStagedDataFiles(h.deps);
      expect((await state(h)).files, mode).toEqual([]);
    }
  });

  it("a retired import operation is cleaned in every mode, even unknown", async () => {
    for (const mode of ["off", "on", "unknown"] as const) {
      const h = await harness(mode);
      const finalPath = finalPathOf(h);
      h.db
        .prepare(
          `INSERT INTO owner_import_operations (authority, owner, scope, operation, body_sha256, state, collected_at, path, envelope_bytes, metadata_json)
           VALUES ('local', 'owner', @scope, @operation, @sha, 'deleted', @collectedAt, @path, @bytes, '{}')`,
        )
        .run({
          scope,
          operation: "r".repeat(64),
          sha: "r".repeat(64),
          collectedAt,
          path: relative(h.dataDir, finalPath),
          bytes: Buffer.from(JSON.stringify(envelope())),
        });
      await mkdir(dirname(finalPath), { recursive: true });
      await writeFile(finalPath, JSON.stringify(envelope()));
      await recoverImportOperations(h.deps);
      expect((await state(h)).files, mode).toEqual([]);
      expect(
        h.db
          .prepare(
            "SELECT COUNT(*) AS n FROM owner_import_operations WHERE metadata_json IS NOT NULL",
          )
          .get(),
        mode,
      ).toEqual({ n: 0 });
    }
  });
});
