import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/node";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { buildDataBlocksAsync } from "@opendatalabs/personal-server-ts-core/storage/blocks";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import type { IndexEntry } from "@opendatalabs/personal-server-ts-core/storage/index";
import { initializeDatabase } from "./index-schema.js";
import { createIndexManager } from "./index-manager.js";
import * as nodeStorage from "./node-data-storage.js";
import {
  createLegacyPublicationPolicy,
  type LegacyRestorationAdapter,
} from "./legacy-publication-policy.js";
import { retainLegacyVersions } from "./legacy-publication-fence.js";
import * as hierarchy from "./hierarchy.js";

const scope = "spotify.profile";
const owner = "0xowner";
const cleanups: (() => void)[] = [];
afterEach(() => {
  for (const cleanup of cleanups.splice(0).reverse()) cleanup();
});

/**
 * A root whose data directory is `<root>/spotify/profile`, so a caller that
 * passes `<root>` as its data directory and this scope names the protected
 * data root itself.
 */
function fixture() {
  const root = mkdtempSync(join(tmpdir(), "retained-version-files-"));
  cleanups.push(() => rmSync(root, { recursive: true, force: true }));
  const dbPath = join(root, "index.db");
  const db = initializeDatabase(dbPath);
  cleanups.push(() => db.open && db.close());
  const index = createIndexManager(db);
  const dataDir = join(root, "spotify", "profile");
  mkdirSync(dataDir, { recursive: true });
  const hierarchyOptions = { dataDir };
  const storage = nodeStorage.createNodeDataStorage({
    indexManager: index,
    hierarchyOptions,
  });
  db.prepare(
    "INSERT INTO legacy_publication_policy VALUES (?, 'generation-1', ?, 'mirroring', 2, 1, NULL)",
  ).run(owner, scope);
  const adapter: LegacyRestorationAdapter = {
    prepare: async (context) => ({
      ...context,
      contractVersion: 1,
      canonicalRevision: "current-1",
      canonicalIdentity: {
        declaration: "decl",
        artifact: "artifact",
        binding: "binding",
        projection: "projection",
        servingGeneration: "generation-1",
      },
      completeCurrentProjection: true,
      blobsHydrated: true,
      historyRecoveryQualified: true,
      envelope: {
        ...createDataFileEnvelope(scope, "2026-10-01T00:00:00Z", {
          full: "current canonical projection",
        }),
        producer: "pdpp-projector",
      },
    }),
    assertCurrent: () => true,
    confirmRemote: async (commit) => ({
      owner,
      serverGeneration: "generation-1",
      scope,
      epoch: commit.epoch,
      canonicalRevision: commit.projection.canonicalRevision,
      operation: commit.receipt.operation,
      bodySha256: commit.receipt.bodySha256,
      headGeneration: commit.headGeneration,
      remoteRevision: "registered-final",
      visible: true,
      historyRecoveryQualified: true,
    }),
    commitReopen: vi.fn(() => true),
  };
  const policy = createLegacyPublicationPolicy(db, {
    owner,
    serverGeneration: "generation-1",
    enabled: () => false,
    storage: { indexManager: index, hierarchyOptions },
    restoration: adapter,
    now: () => Date.parse("2026-11-01T00:00:00Z"),
  });
  /** Seal every version as the stop barrier does, in `state`. */
  function seal(state: "stopped" | "restoring") {
    for (const entry of index.findByScope({ scope }))
      if (entry.dataPointId === null)
        index.updateDataPointId(entry.path, `remote-${entry.id}`);
    db.transaction(() => {
      retainLegacyVersions(db, hierarchyOptions, { scope });
      db.prepare("UPDATE legacy_publication_policy SET state=?").run(state);
    }).immediate();
  }
  async function stopAndRollBack() {
    seal("stopped");
    expect(await policy.rollback(scope, { expectedEpoch: 2 })).toMatchObject({
      state: "mirroring",
      epoch: 4,
    });
  }
  return {
    root,
    dbPath,
    db,
    index,
    storage,
    hierarchyOptions,
    seal,
    stopAndRollBack,
  };
}
type Fixture = ReturnType<typeof fixture>;

async function seedWithBlocks(f: Fixture) {
  await f.storage.commitVersion!({
    kind: "append",
    envelope: createDataFileEnvelope(scope, "2026-10-24T00:00:00Z", {
      name: "original",
    }),
    metadata: {},
  });
  const entry = f.index.findLatestByScope(scope)!;
  const stored = await f.storage.readEnvelope(scope, entry.collectedAt);
  const built = await buildDataBlocksAsync({
    scope,
    collectedAt: entry.collectedAt,
    content: stored,
  });
  await f.storage.writeBlockManifest!(
    scope,
    entry.collectedAt,
    built.manifest,
    built.blocks,
  );
  const forged = await buildDataBlocksAsync({
    scope,
    collectedAt: entry.collectedAt,
    content: { ...stored, data: { name: "forged" } },
  });
  return { entry, stored, built, forged };
}

const readBlocks = (storage: DataStoragePort, collectedAt: string) =>
  storage.readScopeBlocks!(scope, collectedAt, { maxBytes: 1_000_000 });

it("refuses replacing a retained block sidecar through storage after an actual rollback", async () => {
  const f = fixture();
  const { entry, forged } = await seedWithBlocks(f);
  const before = await readBlocks(f.storage, entry.collectedAt);
  await f.stopAndRollBack();
  const row = f.index.findByPath(entry.path);

  await expect(
    f.storage.writeBlockManifest!(
      scope,
      entry.collectedAt,
      forged.manifest,
      forged.blocks,
    ),
  ).rejects.toMatchObject({ errorCode: "legacy_history_retained" });
  expect(await readBlocks(f.storage, entry.collectedAt)).toEqual(before);
  expect(f.index.findByPath(entry.path)).toEqual(row);
});

it("refuses replacing a retained block sidecar through a direct lower-layer call with fresh options", async () => {
  const f = fixture();
  const { entry, forged } = await seedWithBlocks(f);
  const before = await readBlocks(f.storage, entry.collectedAt);
  await f.stopAndRollBack();

  await expect(
    hierarchy.writeBlockManifest(
      { dataDir: f.hierarchyOptions.dataDir },
      scope,
      entry.collectedAt,
      forged.manifest,
      forged.blocks,
    ),
  ).rejects.toMatchObject({ errorCode: "legacy_history_retained" });
  expect(await readBlocks(f.storage, entry.collectedAt)).toEqual(before);
});

it("never seals missing or changed history", async () => {
  const f = fixture();
  const { entry } = await seedWithBlocks(f);
  const file = join(f.hierarchyOptions.dataDir, entry.path);
  const bytes = readFileSync(file);
  writeFileSync(file, bytes.toString("utf8").replace("original", "changed!"));
  expect(() => f.seal("stopped")).toThrow("is not its indexed generation");
  rmSync(file);
  expect(() => f.seal("stopped")).toThrow("file is missing");
  expect(
    f.db.prepare("SELECT * FROM legacy_publication_retained_versions").all(),
  ).toEqual([]);
  expect(
    f.db.prepare("SELECT state FROM legacy_publication_policy").get(),
  ).toEqual({
    state: "mirroring",
  });
});

it("restores a lost retained file only from its recorded bytes, never from equal content in other bytes", async () => {
  const f = fixture();
  const { entry } = await seedWithBlocks(f);
  await f.stopAndRollBack();
  const file = join(f.hierarchyOptions.dataDir, entry.path);
  const bytes = readFileSync(file);
  const envelope = JSON.parse(bytes.toString("utf8")) as DataFileEnvelope;
  rmSync(file);
  // Same envelope, other bytes: same generation, not the retained file.
  expect(() =>
    hierarchy.publishDataFile(
      { dataDir: f.hierarchyOptions.dataDir },
      envelope,
      Buffer.from(JSON.stringify(envelope)),
    ),
  ).toThrow(expect.objectContaining({ errorCode: "legacy_history_retained" }));
  expect(existsSync(file)).toBe(false);
  hierarchy.publishDataFile(
    { dataDir: f.hierarchyOptions.dataDir },
    envelope,
    bytes,
  );
  expect(readFileSync(file)).toEqual(bytes);
});

it("records of versions retained before byte records existed fail closed", async () => {
  const f = fixture();
  const { entry } = await seedWithBlocks(f);
  // Experimental retention metadata: a retained row with no file records.
  for (const e of f.index.findByScope({ scope }))
    f.index.updateDataPointId(e.path, `remote-${e.id}`);
  f.db
    .prepare(
      "INSERT INTO legacy_publication_retained_versions SELECT id FROM data_files",
    )
    .run();
  // Opening storage records unknown identities; none is read from the bytes.
  nodeStorage.createNodeDataStorage({
    indexManager: f.index,
    hierarchyOptions: f.hierarchyOptions,
  });
  const file = join(f.hierarchyOptions.dataDir, entry.path);
  const bytes = readFileSync(file);
  const envelope = JSON.parse(bytes.toString("utf8")) as DataFileEnvelope;
  const opts = { dataDir: f.hierarchyOptions.dataDir };
  // Existing identical bytes are a no-op; anything else is refused.
  expect(hierarchy.publishDataFile(opts, envelope, bytes)).toMatchObject({
    relativePath: entry.path,
  });
  expect(() =>
    hierarchy.deleteDataFileSync(opts, scope, entry.collectedAt),
  ).toThrow(expect.objectContaining({ errorCode: "legacy_history_retained" }));
  rmSync(file);
  // Lost: even the exact old bytes cannot be proven, so it stays missing.
  expect(() => hierarchy.publishDataFile(opts, envelope, bytes)).toThrow(
    expect.objectContaining({ errorCode: "legacy_history_retained" }),
  );
  expect(existsSync(file)).toBe(false);
});

// --- Exhaustive mutation matrix ------------------------------------------

type State =
  | "stopped"
  | "restoring"
  | "mirroring after rollback"
  | "flag off after restart";
const states: State[] = [
  "stopped",
  "restoring",
  "mirroring after rollback",
  "flag off after restart",
];

interface Ctx {
  state: State;
  f: Fixture;
  storage: DataStoragePort;
  /** Fresh options for every call: no shared object carries authority. */
  opts: () => { dataDir: string };
  entry: IndexEntry;
  file: string;
  bytes: Buffer;
  envelope: DataFileEnvelope;
  changed: DataFileEnvelope;
  blockDir: string;
  built: Awaited<ReturnType<typeof buildDataBlocksAsync>>;
  forged: Awaited<ReturnType<typeof buildDataBlocksAsync>>;
  /** Taken before the seal, as a caller holding an old snapshot would. */
  preSealSnapshot: ReturnType<typeof hierarchy.snapshotScopeFiles>;
  /** Outside every data root. */
  outside: string;
  /** A data directory whose first-seen dir resolves inside the retained sidecar. */
  aliasDataDir: string;
  /** A data directory whose scope dir resolves inside the retained sidecar. */
  stageAliasDataDir: string;
}

async function context(state: State): Promise<Ctx> {
  const f = fixture();
  const { entry, built, forged } = await seedWithBlocks(f);
  f.index.updateFileId(entry.path, "file-a");
  await f.storage.writeFirstSeenLedger!(scope, { seen: 1 });
  const preSealSnapshot = hierarchy.snapshotScopeFiles(
    { dataDir: f.hierarchyOptions.dataDir },
    scope,
  );
  let storage = f.storage;
  let index = f.index;
  if (state === "stopped" || state === "restoring") f.seal(state);
  else await f.stopAndRollBack();
  if (state === "flag off after restart") {
    f.db.close();
    const db = initializeDatabase(f.dbPath);
    cleanups.push(() => db.open && db.close());
    index = createIndexManager(db);
    storage = nodeStorage.createNodeDataStorage({
      indexManager: index,
      hierarchyOptions: { dataDir: f.hierarchyOptions.dataDir },
    });
  }
  const dataDir = f.hierarchyOptions.dataDir;
  const file = join(dataDir, entry.path);
  const bytes = readFileSync(file);
  const envelope = JSON.parse(bytes.toString("utf8")) as DataFileEnvelope;
  const blockDir = join(
    dataDir,
    "blocks",
    "spotify",
    "profile",
    entry.collectedAt,
  );
  const outside = join(f.root, "outside");
  mkdirSync(outside);
  const aliasDataDir = join(f.root, "alias");
  mkdirSync(aliasDataDir);
  symlinkSync(blockDir, join(aliasDataDir, "first-seen"));
  const stageAliasDataDir = join(f.root, "stage-alias");
  mkdirSync(stageAliasDataDir);
  symlinkSync(blockDir, join(stageAliasDataDir, "spotify"));
  return {
    state,
    f: { ...f, index },
    storage,
    opts: () => ({ dataDir }),
    entry: index.findByPath(entry.path)!,
    file,
    bytes,
    envelope,
    changed: { ...envelope, data: { name: "changed" } },
    blockDir,
    built,
    forged,
    preSealSnapshot,
    outside,
    aliasDataDir,
    stageAliasDataDir,
  };
}

function sha(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function files(dir: string, base = dir, out: Record<string, string> = {}) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) files(path, base, out);
    else out[relative(base, path)] = sha(readFileSync(path));
  }
  return out;
}

async function observe(c: Ctx) {
  return {
    // The data root and an outside directory; the index is compared by rows.
    files: {
      ...files(c.f.hierarchyOptions.dataDir),
      ...files(c.outside, c.f.root),
    },
    rows: c.f.index.findByScope({ scope }),
    retained: c.f.index
      .findByScope({ scope })
      .map((row) => row.id)
      .filter((id) => retainedIds(c).includes(id)),
    blocks: await readBlocks(c.storage, c.entry.collectedAt),
    envelope: Buffer.from(
      await c.storage.readEnvelopeBytes!(scope, c.entry.collectedAt),
    ),
  };
}

function retainedIds(c: Ctx): number[] {
  const db = initializeDatabase(c.f.dbPath);
  try {
    return (
      db
        .prepare("SELECT version_id FROM legacy_publication_retained_versions")
        .all() as {
        version_id: number;
      }[]
    ).map((row) => row.version_id);
  } finally {
    db.close();
  }
}

const RETAINED = { errorCode: "legacy_history_retained" };
/** A storage-port refusal: the fence wins while the scope is fenced. */
const REFUSED = {
  errorCode: expect.stringMatching(/^legacy_(history_retained|scope_retired)$/),
};

const throwsRetained = (run: () => unknown) =>
  expect(run).toThrow(expect.objectContaining(RETAINED));

interface Case {
  name: string;
  run: (c: Ctx) => Promise<void>;
  /** Files this case may add or change, never a version file or record. */
  ignore?: RegExp;
}

const STAGES = /(^|\/)[^/]*\.pending\.[^/]*$/;
const LEDGER = /(^|\/)first-seen\/[^/]*$/;

/**
 * Every exported function of the version-file owner, classified. A new
 * export fails the test until it is classified here; every mutation has
 * cases below.
 */
const hierarchyExports: Record<string, "read" | "error-type" | "mutation"> = {
  PublishedDataFileError: "error-type",
  recordRetainedVersionFiles: "mutation",
  hasRetainedVersionFiles: "read",
  publishDataFile: "mutation",
  deleteDataFileSync: "mutation",
  deleteFirstSeenLedgerSync: "mutation",
  snapshotScopeFiles: "read",
  deleteScopeFilesSync: "mutation",
  writeDataFile: "mutation",
  stageDataFile: "mutation",
  createStreamedStage: "mutation",
  assertPublishable: "read",
  publishStagedDataFile: "mutation",
  publishStagedDataFileSync: "mutation",
  publishStageBytesSync: "mutation",
  discardDataFile: "mutation",
  readDataFile: "read",
  readDataFileBytes: "read",
  readDataFileStream: "read",
  readDataFilePreview: "read",
  readFirstSeenLedger: "read",
  writeFirstSeenLedger: "mutation",
  deleteFirstSeenLedger: "mutation",
  writeBlockManifest: "mutation",
  readScopeBlocks: "read",
  readScopeBlockManifest: "read",
  hasScopeBlocks: "read",
  listVersions: "read",
  deleteDataFile: "mutation",
  deleteAllForScope: "mutation",
};

const nodeStorageExports: Record<string, "mutation" | "composition"> = {
  publishIndexedStage: "mutation",
  recoverStagedDataFiles: "mutation",
  reindexLegacyDataFiles: "mutation",
  createNodeDataStorage: "composition",
};

/** Storage port methods. Index metadata is owned by SQLite triggers. */
const portMethods: Record<string, "read" | "index-metadata" | "mutation"> = {
  listScopes: "read",
  listVersions: "read",
  countVersions: "read",
  findEntry: "read",
  findByFileId: "read",
  findByDataPointId: "read",
  findUnsynced: "read",
  readEnvelope: "read",
  readEnvelopeBytes: "read",
  readEnvelopeStream: "read",
  readEnvelopePreview: "read",
  readScopeBlocks: "read",
  hasScopeBlocks: "read",
  readBlockManifest: "read",
  findLatestVersionByScope: "read",
  readFirstSeenLedger: "read",
  insertEntry: "index-metadata",
  backfillGeneration: "index-metadata",
  updateFileId: "index-metadata",
  updateDataPointId: "index-metadata",
  updateEntryVersion: "index-metadata",
  commitVersion: "mutation",
  writeEnvelope: "mutation",
  commitEnvelope: "mutation",
  writeBlockManifest: "mutation",
  writeFirstSeenLedger: "mutation",
  deleteFirstSeenLedger: "mutation",
  deleteScope: "mutation",
  deleteByFileId: "mutation",
  deleteVersion: "mutation",
  dropUnsyncedEntry: "mutation",
};

const stage = (c: Ctx, name: string, bytes: Buffer) => {
  const path = join(c.outside, name);
  writeFileSync(path, bytes);
  return path;
};

const sealAt = (dataDir: string) =>
  hierarchy.recordRetainedVersionFiles(
    { dataDir },
    [
      {
        scope,
        collectedAt: "2026-10-24T00:00:00Z",
        path: "manifest.json",
        generation: null,
      },
    ],
    "observed",
  );

const cases: Record<string, Case[]> = {
  recordRetainedVersionFiles: [
    {
      name: "sealing again replaces no record and changes no file",
      run: async (c) =>
        hierarchy.recordRetainedVersionFiles(
          c.opts(),
          [
            {
              scope,
              collectedAt: c.entry.collectedAt,
              path: c.entry.path,
              generation: c.entry.generation ?? null,
            },
          ],
          "observed",
        ),
    },
    {
      name: "never roots records inside a retained set",
      run: async (c) => throwsRetained(() => sealAt(c.blockDir)),
    },
    {
      name: "never roots records inside a retained set through a linked data directory",
      run: async (c) => {
        const link = join(c.outside, "linked-root");
        symlinkSync(c.blockDir, link);
        throwsRetained(() => sealAt(link));
        rmSync(link);
      },
    },
  ],
  publishDataFile: [
    {
      name: "changed bytes at the retained path are refused",
      run: async (c) =>
        throwsRetained(() =>
          hierarchy.publishDataFile(
            c.opts(),
            c.changed,
            Buffer.from(JSON.stringify(c.changed, null, 2)),
          ),
        ),
    },
    {
      name: "identical bytes are a no-op",
      run: async (c) => {
        expect(
          hierarchy.publishDataFile(c.opts(), c.envelope, c.bytes),
        ).toMatchObject({ relativePath: c.entry.path });
      },
    },
  ],
  deleteDataFileSync: [
    {
      name: "is refused",
      run: async (c) =>
        throwsRetained(() =>
          hierarchy.deleteDataFileSync(c.opts(), scope, c.entry.collectedAt),
        ),
    },
  ],
  deleteFirstSeenLedgerSync: [
    {
      name: "removes the scope-level ledger only",
      ignore: LEDGER,
      run: async (c) => hierarchy.deleteFirstSeenLedgerSync(c.opts(), scope),
    },
    {
      name: "never removes inside a retained set that its path resolves to",
      run: async (c) =>
        hierarchy.deleteFirstSeenLedgerSync({ dataDir: c.aliasDataDir }, scope),
    },
  ],
  deleteScopeFilesSync: [
    {
      name: "refuses a snapshot taken before the seal",
      run: async (c) =>
        throwsRetained(() => hierarchy.deleteScopeFilesSync(c.preSealSnapshot)),
    },
    {
      name: "refuses a snapshot from a parent data directory",
      run: async (c) =>
        throwsRetained(() =>
          hierarchy.deleteScopeFilesSync(
            hierarchy.snapshotScopeFiles({ dataDir: c.f.root }, scope),
          ),
        ),
    },
  ],
  writeDataFile: [
    {
      name: "a changed envelope is refused",
      ignore: STAGES,
      run: async (c) => {
        await expect(
          hierarchy.writeDataFile(c.opts(), c.changed),
        ).rejects.toMatchObject(RETAINED);
      },
    },
    {
      name: "the identical envelope is a no-op",
      run: async (c) => {
        await expect(
          hierarchy.writeDataFile(c.opts(), c.envelope),
        ).resolves.toMatchObject({ relativePath: c.entry.path });
      },
    },
  ],
  stageDataFile: [
    {
      name: "creates only a new stage beside the retained file",
      ignore: STAGES,
      run: async (c) => {
        await hierarchy.stageDataFile(c.opts(), c.changed);
      },
    },
    {
      name: "creates nothing inside a retained set its path resolves to",
      run: async (c) => {
        await expect(
          hierarchy.stageDataFile({ dataDir: c.stageAliasDataDir }, c.changed),
        ).rejects.toMatchObject(RETAINED);
      },
    },
  ],
  createStreamedStage: [
    {
      name: "creates only a private stage in a dot directory of the data directory",
      ignore: /(^|\/)\.scope-imports\//,
      run: async (c) => {
        const stage = await hierarchy.createStreamedStage(
          c.opts(),
          join(c.opts().dataDir, ".scope-imports", "import", "envelope.stage"),
        );
        await stage.write(Buffer.from("first"));
        await stage.write(Buffer.from(" second"));
        await stage.sync();
        await stage.close();
      },
    },
    {
      name: "creates nothing inside a retained set a scope directory link resolves to",
      run: async (c) => {
        await expect(
          hierarchy.createStreamedStage(
            { dataDir: c.stageAliasDataDir },
            join(c.stageAliasDataDir, "spotify", "envelope.stage"),
          ),
        ).rejects.toThrow("private file in a dot directory");
      },
    },
    {
      name: "creates nothing when the data directory is a link to a retained set",
      run: async (c) => {
        const alias = join(c.f.root, "root-alias");
        symlinkSync(c.blockDir, alias);
        await expect(
          hierarchy.createStreamedStage(
            { dataDir: alias },
            join(alias, ".scope-imports", "import", "envelope.stage"),
          ),
        ).rejects.toMatchObject(RETAINED);
      },
    },
  ],
  publishStagedDataFile: [
    {
      name: "a changed stage at the retained path is refused",
      run: async (c) => {
        const s = stage(c, "changed", Buffer.from("changed"));
        await expect(
          hierarchy.publishStagedDataFile(s, c.file),
        ).rejects.toMatchObject(RETAINED);
        rmSync(s);
      },
    },
    {
      name: "an identical stage is a no-op that consumes the stage",
      run: async (c) => {
        const s = stage(c, "same", c.bytes);
        await hierarchy.publishStagedDataFile(s, c.file);
        expect(existsSync(s)).toBe(false);
      },
    },
    {
      name: "a retained file is never consumed as the stage",
      run: async (c) => {
        await expect(
          hierarchy.publishStagedDataFile(
            c.file,
            join(c.outside, "moved.json"),
          ),
        ).rejects.toMatchObject(RETAINED);
        expect(existsSync(join(c.outside, "moved.json"))).toBe(false);
      },
    },
  ],
  publishStagedDataFileSync: [
    {
      name: "a changed stage at the retained path is refused",
      run: async (c) => {
        const s = stage(c, "changed", Buffer.from("changed"));
        throwsRetained(() => hierarchy.publishStagedDataFileSync(s, c.file));
        rmSync(s);
      },
    },
    {
      name: "an identical stage is a no-op that consumes the stage",
      run: async (c) => {
        const s = stage(c, "same", c.bytes);
        hierarchy.publishStagedDataFileSync(s, c.file);
        expect(existsSync(s)).toBe(false);
      },
    },
    {
      name: "a retained file is never consumed as the stage",
      run: async (c) =>
        throwsRetained(() =>
          hierarchy.publishStagedDataFileSync(
            c.file,
            join(c.outside, "moved.json"),
          ),
        ),
    },
  ],
  publishStageBytesSync: [
    {
      name: "a retained file is never consumed as the stage",
      run: async (c) =>
        throwsRetained(() =>
          hierarchy.publishStageBytesSync(
            c.file,
            c.bytes,
            join(c.outside, "moved.json"),
          ),
        ),
    },
    {
      name: "changed bytes at the retained path are not published",
      run: async (c) => {
        const s = stage(c, "changed", Buffer.from("changed"));
        expect(
          hierarchy.publishStageBytesSync(s, Buffer.from("changed"), c.file),
        ).toBe(false);
        rmSync(s);
      },
    },
  ],
  discardDataFile: [
    {
      name: "a retained envelope is refused",
      run: async (c) => {
        await expect(hierarchy.discardDataFile(c.file)).rejects.toMatchObject(
          RETAINED,
        );
      },
    },
    {
      name: "a retained sidecar file is refused",
      run: async (c) => {
        await expect(
          hierarchy.discardDataFile(join(c.blockDir, "manifest.json")),
        ).rejects.toMatchObject(RETAINED);
      },
    },
  ],
  writeFirstSeenLedger: [
    {
      name: "writes the scope-level ledger only",
      ignore: LEDGER,
      run: async (c) => {
        await hierarchy.writeFirstSeenLedger(c.opts(), scope, { seen: 2 });
      },
    },
    {
      name: "creates nothing inside a retained set its path resolves to",
      run: async (c) => {
        await expect(
          hierarchy.writeFirstSeenLedger(
            { dataDir: c.aliasDataDir },
            scope,
            {},
          ),
        ).rejects.toMatchObject(RETAINED);
      },
    },
  ],
  deleteFirstSeenLedger: [
    {
      name: "removes the scope-level ledger only",
      ignore: LEDGER,
      run: async (c) => {
        await hierarchy.deleteFirstSeenLedger(c.opts(), scope);
      },
    },
    {
      name: "removes nothing inside a retained set its path resolves to",
      run: async (c) => {
        await expect(
          hierarchy.deleteFirstSeenLedger({ dataDir: c.aliasDataDir }, scope),
        ).rejects.toMatchObject(RETAINED);
      },
    },
  ],
  writeBlockManifest: [
    {
      name: "a changed sidecar is refused",
      run: async (c) => {
        await expect(
          hierarchy.writeBlockManifest(
            c.opts(),
            scope,
            c.entry.collectedAt,
            c.forged.manifest,
            c.forged.blocks,
          ),
        ).rejects.toMatchObject(RETAINED);
      },
    },
    {
      name: "the identical sidecar is a no-op",
      run: async (c) => {
        await hierarchy.writeBlockManifest(
          c.opts(),
          scope,
          c.entry.collectedAt,
          c.built.manifest,
          c.built.blocks,
        );
      },
    },
  ],
  deleteDataFile: [
    {
      name: "is refused",
      run: async (c) => {
        await expect(
          hierarchy.deleteDataFile(c.opts(), scope, c.entry.collectedAt),
        ).rejects.toMatchObject(RETAINED);
      },
    },
  ],
  deleteAllForScope: [
    {
      name: "is refused",
      run: async (c) => {
        await expect(
          hierarchy.deleteAllForScope(c.opts(), scope),
        ).rejects.toMatchObject(RETAINED);
      },
    },
    {
      name: "refuses a parent data directory whose scope dir is the data root",
      run: async (c) => {
        await expect(
          hierarchy.deleteAllForScope({ dataDir: c.f.root }, scope),
        ).rejects.toMatchObject(RETAINED);
      },
    },
  ],
  publishIndexedStage: [
    {
      name: "a changed stage for a retained path is held, not published",
      ignore: STAGES,
      run: async (c) => {
        const s = `${c.file}.pending.changed`;
        writeFileSync(s, "changed");
        await expect(
          nodeStorage.publishIndexedStage(
            {
              indexManager: c.f.index,
              hierarchyOptions: c.opts(),
            },
            s,
            c.file,
          ),
        ).resolves.toBe(false);
      },
    },
  ],
  recoverStagedDataFiles: [
    {
      name: "changes no retained file",
      run: async (c) => {
        await nodeStorage.recoverStagedDataFiles({
          indexManager: c.f.index,
          hierarchyOptions: c.opts(),
        });
      },
    },
  ],
  reindexLegacyDataFiles: [
    {
      name: "changes no retained file",
      run: async (c) => {
        await nodeStorage.reindexLegacyDataFiles({
          indexManager: c.f.index,
          hierarchyOptions: c.opts(),
        });
      },
    },
  ],
};

const portCases: Record<string, Case[]> = {
  writeEnvelope: [
    {
      name: "a changed envelope is refused",
      ignore: STAGES,
      run: async (c) => {
        await expect(c.storage.writeEnvelope(c.changed)).rejects.toMatchObject(
          REFUSED,
        );
      },
    },
    {
      name: "the identical envelope is a no-op",
      run: async (c) => {
        await expect(
          c.storage.writeEnvelope(c.envelope),
        ).resolves.toMatchObject({ relativePath: c.entry.path });
      },
    },
  ],
  commitEnvelope: [
    {
      name: "a changed envelope is refused",
      run: async (c) => {
        await expect(
          c.storage.commitEnvelope!(c.changed, {
            fileId: null,
            scope,
            collectedAt: c.entry.collectedAt,
          } as never),
        ).rejects.toMatchObject(REFUSED);
      },
    },
  ],
  commitVersion: [
    {
      name: "a changed replica is refused",
      run: async (c) => {
        await expect(
          c.storage.commitVersion!({
            kind: "replica",
            envelope: c.changed,
            metadata: {
              schemaId: c.entry.schemaId,
              dataPointId: c.entry.dataPointId!,
              version: c.entry.version,
            },
          }),
        ).rejects.toMatchObject(REFUSED);
      },
    },
    {
      name: "the exact replica is a no-op",
      run: async (c) => {
        await expect(
          c.storage.commitVersion!({
            kind: "replica",
            envelope: c.envelope,
            metadata: {
              schemaId: c.entry.schemaId,
              dataPointId: c.entry.dataPointId!,
              version: c.entry.version,
            },
          }),
        ).resolves.toMatchObject({ kind: "stored" });
      },
    },
  ],
  writeBlockManifest: [
    {
      name: "a changed sidecar is refused",
      run: async (c) => {
        await expect(
          c.storage.writeBlockManifest!(
            scope,
            c.entry.collectedAt,
            c.forged.manifest,
            c.forged.blocks,
          ),
        ).rejects.toMatchObject(REFUSED);
      },
    },
    {
      name: "the identical sidecar is a no-op, or fenced while stopped",
      run: async (c) => {
        const write = c.storage.writeBlockManifest!(
          scope,
          c.entry.collectedAt,
          c.built.manifest,
          c.built.blocks,
        );
        // The caller's publication fence refuses every sidecar write in a
        // fenced scope; the owner itself admits identical bytes as a no-op.
        if (c.state === "stopped" || c.state === "restoring")
          await expect(write).rejects.toMatchObject({
            errorCode: "legacy_scope_retired",
          });
        else await write;
      },
    },
  ],
  writeFirstSeenLedger: [
    {
      name: "writes the scope-level ledger only",
      ignore: LEDGER,
      run: async (c) => c.storage.writeFirstSeenLedger!(scope, { seen: 3 }),
    },
  ],
  deleteFirstSeenLedger: [
    {
      name: "removes the scope-level ledger only",
      ignore: LEDGER,
      run: async (c) => c.storage.deleteFirstSeenLedger!(scope),
    },
  ],
  deleteScope: [
    {
      name: "is refused",
      run: async (c) => {
        await expect(c.storage.deleteScope(scope)).rejects.toMatchObject({
          errorCode: "legacy_history_retained",
        });
      },
    },
  ],
  deleteByFileId: [
    {
      name: "is refused",
      run: async (c) => {
        await expect(c.storage.deleteByFileId("file-a")).rejects.toMatchObject(
          REFUSED,
        );
      },
    },
  ],
  deleteVersion: [
    {
      name: "is refused",
      run: async (c) => {
        await expect(
          c.storage.deleteVersion!(scope, c.entry.collectedAt),
        ).rejects.toMatchObject(REFUSED);
      },
    },
  ],
  dropUnsyncedEntry: [
    {
      name: "drops nothing of a synced retained version",
      run: async (c) => {
        await expect(
          Promise.resolve(c.storage.dropUnsyncedEntry!(c.entry.path)),
        ).resolves.toBe(false);
      },
    },
  ],
};

function withoutIgnored(map: Record<string, string>, ignore?: RegExp) {
  return Object.fromEntries(
    Object.entries(map).filter(([path]) => !ignore?.test(path)),
  );
}

describe("retained version file owner", () => {
  it("classifies every exported function of the owner and its storage", () => {
    const exported = (module: object) =>
      Object.entries(module)
        .filter(([, value]) => typeof value === "function")
        .map(([name]) => name)
        .sort();
    expect(exported(hierarchy)).toEqual(Object.keys(hierarchyExports).sort());
    expect(exported(nodeStorage)).toEqual(
      Object.keys(nodeStorageExports).sort(),
    );
    const f = fixture();
    expect(exported(f.storage)).toEqual(Object.keys(portMethods).sort());
    for (const [name, kind] of [
      ...Object.entries(hierarchyExports),
      ...Object.entries(nodeStorageExports),
    ])
      if (kind === "mutation") expect(cases[name], name).toBeDefined();
    for (const [name, kind] of Object.entries(portMethods))
      if (kind === "mutation") expect(portCases[name], name).toBeDefined();
  });

  const matrix = [
    ...Object.entries(cases).flatMap(([name, list]) =>
      list.map((c) => ({ ...c, name: `${name}: ${c.name}` })),
    ),
    ...Object.entries(portCases).flatMap(([name, list]) =>
      list.map((c) => ({ ...c, name: `storage.${name}: ${c.name}` })),
    ),
  ];
  describe.each(states)("while %s", (state) => {
    // Plain titles: `it.each` truncates long `$name` values.
    for (const { name, run, ignore } of matrix)
      it(name, async () => {
        const c = await context(state);
        const before = await observe(c);
        await run(c);
        const after = await observe(c);
        expect(withoutIgnored(after.files, ignore)).toEqual(
          withoutIgnored(before.files, ignore),
        );
        // Version files and seal records are never in an ignored set.
        for (const path of Object.keys(before.files))
          if (!ignore?.test(path))
            expect(after.files[path], path).toBe(before.files[path]);
        expect(after.rows).toEqual(before.rows);
        expect(after.retained).toEqual(before.retained);
        expect(after.blocks).toEqual(before.blocks);
        expect(after.envelope).toEqual(before.envelope);
        expect(statSync(c.file).isFile()).toBe(true);
      });
  });
});
