import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Hono } from "hono";
import pino from "pino";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/node";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { envelopeGeneration } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import { dataRoutes } from "../routes/data.js";
import { initializeDatabase } from "./index-schema.js";
import { createIndexManager } from "./index-manager.js";
import {
  createNodeDataStorage,
  recoverStagedDataFiles,
} from "./node-data-storage.js";
import {
  createLegacyPublicationPolicy,
  type LegacyRestorationAdapter,
} from "./legacy-publication-policy.js";
import {
  optInLegacyPublicationGate,
  retainLegacyVersions,
} from "./legacy-publication-fence.js";

const scope = "spotify.profile";
const owner = "0xowner";
const cleanups: (() => void)[] = [];
afterEach(() => {
  for (const cleanup of cleanups.splice(0).reverse()) cleanup();
});

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "legacy-retained-identity-"));
  cleanups.push(() => rmSync(root, { recursive: true, force: true }));
  const db = initializeDatabase(join(root, "index.db"));
  cleanups.push(() => db.open && db.close());
  const index = createIndexManager(db);
  const hierarchyOptions = { dataDir: join(root, "data") };
  mkdirSync(hierarchyOptions.dataDir);
  const storage = createNodeDataStorage({
    indexManager: index,
    hierarchyOptions,
  });
  // The cohort was enrolled before these versions; they predate its stop.
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
  /** Retain every current version as stop does, then optionally roll back. */
  async function retain(state: "stopped" | "mirroring") {
    for (const entry of index.findByScope({ scope }))
      if (entry.dataPointId === null)
        index.updateDataPointId(entry.path, `remote-${entry.id}`);
    retainLegacyVersions(db, hierarchyOptions, { scope });
    db.prepare("UPDATE legacy_publication_policy SET state='stopped'").run();
    if (state === "mirroring")
      expect(await policy.rollback(scope, { expectedEpoch: 2 })).toMatchObject({
        state: "mirroring",
        epoch: 4,
      });
  }
  async function seedRetained(state: "stopped" | "mirroring") {
    await storage.commitVersion!({
      kind: "append",
      envelope: createDataFileEnvelope(scope, "2026-10-24T00:00:00Z", {
        old: true,
      }),
      metadata: {},
    });
    const seeded = index.findLatestByScope(scope)!;
    await retain(state);
    const old = index.findByPath(seeded.path)!;
    const file = join(hierarchyOptions.dataDir, old.path);
    return { old, file, bytes: readFileSync(file) };
  }
  const holds = () =>
    db
      .prepare(
        "SELECT kind, payload FROM legacy_publication_holds WHERE scope=? ORDER BY kind",
      )
      .all(scope) as { kind: string; payload: Buffer }[];
  return {
    db,
    index,
    storage,
    hierarchyOptions,
    policy,
    retain,
    seedRetained,
    holds,
  };
}

const refusal = {
  stopped: "legacy_scope_retired",
  mirroring: "legacy_history_retained",
} as const;

describe.each(["stopped", "mirroring"] as const)(
  "retained identity while %s",
  (state) => {
    it("refuses different bytes or replica identity at a lost retained path and repairs only the exact known version", async () => {
      const f = fixture();
      const { old, file, bytes } = await f.seedRetained(state);
      const persisted = JSON.parse(bytes.toString("utf8"));
      rmSync(file);

      await expect(
        f.storage.writeEnvelope({ ...persisted, data: { malicious: true } }),
      ).rejects.toMatchObject({ errorCode: refusal[state] });
      const replica = {
        kind: "replica" as const,
        envelope: persisted,
        metadata: {
          schemaId: old.schemaId,
          dataPointId: old.dataPointId!,
          version: old.version,
        },
      };
      for (const command of [
        { ...replica, envelope: { ...persisted, data: { malicious: true } } },
        { ...replica, metadata: { ...replica.metadata, version: 99 } },
        {
          ...replica,
          metadata: { ...replica.metadata, dataPointId: "foreign-remote" },
        },
      ])
        await expect(f.storage.commitVersion!(command)).rejects.toMatchObject({
          errorCode: refusal[state],
        });
      expect(existsSync(file)).toBe(false);
      expect(f.index.findByPath(old.path)).toEqual(old);

      await expect(f.storage.writeEnvelope(persisted)).resolves.toMatchObject({
        relativePath: old.path,
      });
      expect(envelopeGeneration(JSON.parse(readFileSync(file, "utf8")))).toBe(
        old.generation,
      );
      rmSync(file);
      await expect(f.storage.commitVersion!(replica)).resolves.toMatchObject({
        kind: "stored",
        entry: { id: old.id },
      });
      expect(readFileSync(file)).toEqual(bytes);
      expect(f.index.findByPath(old.path)).toEqual(old);
    });

    it("boot recovery quarantines a mismatched stage for a lost retained version and publishes only the exact stage", async () => {
      const f = fixture();
      const { old, file, bytes } = await f.seedRetained(state);
      const persisted = JSON.parse(bytes.toString("utf8"));
      rmSync(file);
      const stale = Buffer.from(
        JSON.stringify({ ...persisted, data: { stale: true } }, null, 2),
      );
      writeFileSync(`${file}.pending.stale`, stale);

      await expect(
        recoverStagedDataFiles({
          indexManager: f.index,
          hierarchyOptions: f.hierarchyOptions,
        }),
      ).resolves.toBeUndefined();
      expect(existsSync(file)).toBe(false);
      expect(f.holds()).toEqual([{ kind: "recovery-stage", payload: stale }]);
      expect(f.policy.read(scope).blockers).toHaveLength(1);
      expect(f.index.findByPath(old.path)).toEqual(old);

      writeFileSync(`${file}.pending.exact`, bytes);
      await recoverStagedDataFiles({
        indexManager: f.index,
        hierarchyOptions: f.hierarchyOptions,
      });
      expect(readFileSync(file)).toEqual(bytes);
      expect(existsSync(`${file}.pending.exact`)).toBe(false);
      expect(f.holds()).toEqual([{ kind: "recovery-stage", payload: stale }]);
      expect(f.index.findByPath(old.path)).toEqual(old);
    });
  },
);

it("boot recovery never publishes a stage for a retained version of unknown generation", async () => {
  const f = fixture();
  await f.storage.commitVersion!({
    kind: "append",
    envelope: createDataFileEnvelope(scope, "2026-10-24T00:00:00Z", {
      old: true,
    }),
    metadata: {},
  });
  f.db.prepare("UPDATE data_files SET generation=NULL").run();
  const old = f.index.findLatestByScope(scope)!;
  await f.retain("stopped");
  const file = join(f.hierarchyOptions.dataDir, old.path);
  const bytes = readFileSync(file);
  rmSync(file);
  writeFileSync(`${file}.pending.exact`, bytes);
  await recoverStagedDataFiles({
    indexManager: f.index,
    hierarchyOptions: f.hierarchyOptions,
  });
  expect(existsSync(file)).toBe(false);
  expect(f.holds()).toEqual([{ kind: "recovery-stage", payload: bytes }]);
});

describe("chunked finalize replay of a retained version after rollback", () => {
  const wallet = createTestWallet(9);
  const origin = "http://127.0.0.1";

  async function send(
    app: Hono,
    method: string,
    path: string,
    body?: Uint8Array,
    headers: Record<string, string> = {},
  ) {
    const response = await app.request(`${origin}${path}`, {
      method,
      body,
      headers: {
        ...headers,
        authorization: await buildWeb3SignedHeader({
          wallet,
          aud: origin,
          method,
          uri: path,
          body,
        }),
      },
    });
    return { status: response.status, body: await response.text() };
  }

  it("refuses to publish a mismatched replay stage, holds it, and replays the exact stage", async () => {
    const f = fixture();
    const app = new Hono();
    app.route(
      "/v1/data",
      dataRoutes({
        indexManager: f.index,
        hierarchyOptions: f.hierarchyOptions,
        logger: pino({ level: "silent" }),
        serverOrigin: origin,
        serverOwner: wallet.address,
        gateway: { isRegisteredBuilder: async () => true } as never,
        accessLogWriter: { write: async () => undefined },
        mountPath: "/v1/data",
      }),
    );
    const payload = Buffer.from('{"profile":{"name":"chunked"}}');
    const path = `/v1/data/${scope}/imports`;
    const begin = await send(
      app,
      "POST",
      path,
      Buffer.from(
        JSON.stringify({
          totalBytes: payload.byteLength,
          totalChunks: 1,
          sha256: createHash("sha256").update(payload).digest("hex"),
        }),
      ),
      { "content-type": "application/json" },
    );
    expect(begin.status, begin.body).toBe(201);
    const { importId } = JSON.parse(begin.body) as { importId: string };
    const chunk = await send(
      app,
      "PUT",
      `${path}/${importId}/chunks/0`,
      payload,
      {
        "content-type": "application/octet-stream",
        "x-chunk-sha256": createHash("sha256").update(payload).digest("hex"),
      },
    );
    expect(chunk.status, chunk.body).toBe(200);
    // Crash after the index commit, before the receipt: the receipt path is
    // unwritable, so the import directory survives for a replay.
    const receipt = join(
      f.hierarchyOptions.dataDir,
      ".scope-imports",
      "receipts",
      `${importId}.json`,
    );
    mkdirSync(join(receipt, "blocker"), { recursive: true });
    const crashed = await send(app, "POST", `${path}/${importId}/finalize`);
    expect(crashed.status).toBe(500);
    rmSync(receipt, { recursive: true });
    const committed = f.index.findLatestByScope(scope)!;
    const file = join(f.hierarchyOptions.dataDir, committed.path);
    const bytes = readFileSync(file);

    await f.retain("mirroring");
    // Chunk finalize indexes no generation; the verified one-time backfill
    // (a read) records it. Without it the identity is unknown and held.
    expect(committed.generation).toBeUndefined();
    await f.storage.backfillGeneration!(f.index.findByPath(committed.path)!);
    const old = f.index.findByPath(committed.path)!;
    expect(old.generation).toBe(
      envelopeGeneration(JSON.parse(bytes.toString("utf8"))),
    );
    rmSync(file);
    const stale = Buffer.from(
      bytes.toString("utf8").replace('"chunked"', '"replaced"'),
    );
    writeFileSync(`${file}.pending.${importId}`, stale);
    const refused = await send(app, "POST", `${path}/${importId}/finalize`);
    expect(refused.status, refused.body).toBe(409);
    expect(JSON.parse(refused.body)).toMatchObject({
      error: "legacy_history_retained",
    });
    expect(existsSync(file)).toBe(false);
    expect(f.holds()).toEqual([{ kind: "recovery-stage", payload: stale }]);
    expect(f.index.findByPath(old.path)).toEqual(old);

    writeFileSync(`${file}.pending.${importId}`, bytes);
    const replayed = await send(app, "POST", `${path}/${importId}/finalize`);
    expect(replayed.status, replayed.body).toBe(201);
    expect(readFileSync(file)).toEqual(bytes);
    expect(f.index.findByPath(old.path)).toEqual(old);
  });
});

describe("indexed stage publication at the writer barrier", () => {
  async function lostVersion(gate: "off" | "opted-in" | "quiescing") {
    const root = mkdtempSync(join(tmpdir(), "legacy-stage-barrier-"));
    cleanups.push(() => rmSync(root, { recursive: true, force: true }));
    const db = initializeDatabase(join(root, "index.db"));
    cleanups.push(() => db.open && db.close());
    if (gate === "opted-in") optInLegacyPublicationGate(db);
    const index = createIndexManager(db);
    const hierarchyOptions = { dataDir: join(root, "data") };
    const storage = createNodeDataStorage({
      indexManager: index,
      hierarchyOptions,
    });
    await storage.commitVersion!({
      kind: "append",
      envelope: createDataFileEnvelope(scope, "2026-10-24T00:00:00Z", {
        current: true,
      }),
      metadata: {},
    });
    const entry = index.findLatestByScope(scope)!;
    if (gate === "quiescing")
      db.prepare(
        "INSERT INTO legacy_publication_policy VALUES (?, 'generation-1', ?, 'quiescing', 1, 1, NULL)",
      ).run(owner, scope);
    const file = join(hierarchyOptions.dataDir, entry.path);
    const bytes = readFileSync(file);
    rmSync(file);
    const recover = () =>
      recoverStagedDataFiles({ indexManager: index, hierarchyOptions });
    const holds = () =>
      db.prepare("SELECT kind, payload FROM legacy_publication_holds").all();
    const stale = Buffer.from(
      JSON.stringify(
        { ...JSON.parse(bytes.toString("utf8")), data: { stale: true } },
        null,
        2,
      ),
    );
    return { file, bytes, stale, recover, holds };
  }

  it("publishes an unchecked stage when the gate is off, as before the gate", async () => {
    const f = await lostVersion("off");
    writeFileSync(`${f.file}.pending.stale`, f.stale);
    await f.recover();
    expect(readFileSync(f.file)).toEqual(f.stale);
    expect(f.holds()).toEqual([]);
  });

  it("holds a mismatched stage of an unretained version once opted in and publishes the exact one", async () => {
    const f = await lostVersion("opted-in");
    writeFileSync(`${f.file}.pending.stale`, f.stale);
    await f.recover();
    expect(existsSync(f.file)).toBe(false);
    expect(existsSync(`${f.file}.pending.stale`)).toBe(true);
    expect(f.holds()).toEqual([{ kind: "recovery-stage", payload: f.stale }]);
    writeFileSync(`${f.file}.pending.exact`, f.bytes);
    await f.recover();
    expect(readFileSync(f.file)).toEqual(f.bytes);
  });

  it("holds even an exact stage of an unretained version in a fenced scope", async () => {
    const f = await lostVersion("quiescing");
    writeFileSync(`${f.file}.pending.exact`, f.bytes);
    await f.recover();
    expect(existsSync(f.file)).toBe(false);
    expect(f.holds()).toEqual([{ kind: "recovery-stage", payload: f.bytes }]);
  });
});
