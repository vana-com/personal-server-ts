import { afterEach, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import { createLegacyScopeView } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import { initializeDatabase } from "./index-schema.js";
import { createIndexManager } from "./index-manager.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { liveSnapshotDigest } from "./pdpp-stream-completion.js";
import { createLegacyCanonicalCoverage } from "./legacy-publication-canonical.js";
import { createLegacyPublicationPolicy } from "./legacy-publication-policy.js";

// spotify.playlists is a reviewed two-stream join: playlists + playlist_items.
const SCOPE = "spotify.playlists";
const SOURCE = "https://registry.pdpp.dev/sources/spotify";
const A = "conn_123e4567-e89b-42d3-a456-426614174000";
const B = "conn_223e4567-e89b-42d3-a456-426614174001";
const declaration: DeclarationSnapshot = {
  source_id: SOURCE,
  source_kind: "connector",
  version: "2026-10-24",
  digest: "a".repeat(64),
  streams: [
    {
      name: "playlists",
      fields: ["id", "name", "track_count"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
    {
      name: "playlist_items",
      fields: ["id", "playlist_id", "position", "track_id"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
};

// oura.activity is one stream, served by the configured `oura` method and by
// `oura-browser`, which this fixture does not configure.
const OURA = "https://registry.pdpp.dev/sources/oura";
const ACTIVITY = "oura.activity";
const oura: DeclarationSnapshot = {
  source_id: OURA,
  source_kind: "connector",
  version: "2026-10-24",
  digest: "c".repeat(64),
  streams: [
    {
      name: "activity",
      fields: ["id", "day", "score"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
};

const databases: ReturnType<typeof initializeDatabase>[] = [];
const dataDirs: string[] = [];
afterEach(() => {
  for (const dir of dataDirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
  for (const db of databases.splice(0)) db.close();
});

/** Storage bound to `db`, so stop can seal the files of indexed versions. */
function storageFor(db: ReturnType<typeof initializeDatabase>) {
  const dataDir = mkdtempSync(join(tmpdir(), "legacy-canonical-storage-"));
  dataDirs.push(dataDir);
  return {
    indexManager: createIndexManager(db),
    hierarchyOptions: { dataDir },
  };
}

function fixture(
  options: {
    declarations?: DeclarationSnapshot[];
    source?: string;
    method?: string;
  } = {},
) {
  const source = options.source ?? SOURCE;
  const configured = options.method ?? "spotify";
  const db = initializeDatabase(":memory:");
  databases.push(db);
  const store = createSqliteRecordStore(db);
  const authority = createLegacyScopeAuthority(db);
  // The registry the legacy view and the gate share.
  const streamDeclarations = { forInstance: () => undefined };
  const port = (declarations = options.declarations ?? [declaration]) =>
    createLegacyCanonicalCoverage({
      store,
      declarations,
      streamDeclarations,
      configuredMethods: new Map([[source, [configured]]]),
      authority,
    });
  /** The live legacy view over the same rows and ledger. */
  const view = (
    readLegacyHead?: () => Promise<unknown>,
    maxExtraBytes?: number,
  ) =>
    createLegacyScopeView({
      authority,
      records: store,
      declarations: streamDeclarations,
      configuredMethods: (sourceId) =>
        sourceId === source ? [configured] : [],
      readLegacyHead: readLegacyHead as never,
      ...(maxExtraBytes === undefined
        ? {}
        : { coverageThresholds: { maxExtraBytes } }),
    });
  const connect = (instance = A, method = configured) =>
    store.registerConnection({
      instance,
      sourceId: source,
      method,
      label: "Personal",
    });
  const write = (
    stream: string,
    key: string,
    data: Record<string, unknown>,
    instance = A,
  ) =>
    store.ingestBatch(
      [
        {
          instance,
          stream,
          key,
          data: { id: key, ...data },
          emitted_at: "2026-10-24T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
      {
        method: store.getInstanceBinding(instance).method!,
        generation: store.getInstanceBinding(instance).generation,
      },
    );
  let tick = 0;
  /** A native full-stream receipt over the stream's current live set, collected later each call. */
  const complete = (streams: string[], instance = A) => {
    const sourceCollectedAt = new Date(
      Date.UTC(2026, 9, 24, 1, 0, tick++),
    ).toISOString();
    const { generation, method } = store.getInstanceBinding(instance);
    store.completeStreams(
      {
        instance,
        sourceId: source,
        method: method!,
        generation,
        sourceCollectedAt,
        collectionTimeBasis: "host_run_finished",
        streams: streams.map((stream) => {
          const rows = db
            .prepare(
              "SELECT record_key, data FROM pdpp_records WHERE instance = ? AND stream = ? AND deleted = 0",
            )
            .all(instance, stream) as { record_key: string; data: string }[];
          return {
            stream,
            coverage: "full_stream" as const,
            liveCount: rows.length,
            snapshotSha256: liveSnapshotDigest(
              {
                sourceId: source,
                instance,
                method: method!,
                generation,
                stream,
              },
              ["id"],
              rows.map((row) => ({
                recordKey: row.record_key,
                dataJson: row.data,
              })),
            ),
          };
        }),
      },
      () => ["id"],
    );
  };
  const insertHead = (scope: string, collectedAt = "2026-10-25T00:00:00Z") =>
    createIndexManager(db).insert({
      scope,
      path: "legacy-head.json",
      collectedAt,
      fileId: null,
      sizeBytes: 10,
      dataPointId: "dp-legacy",
    });
  return {
    db,
    store,
    authority,
    port,
    view,
    connect,
    write,
    complete,
    insertHead,
  };
}

/** An adapter that attests every external fact for whatever it is given. */
function echoingQualification(
  onFreeze: () => unknown = () => {},
): Parameters<typeof createLegacyPublicationPolicy>[1]["qualification"] & {} {
  return {
    async freezeAndQualify(context) {
      await onFreeze();
      return {
        ...context,
        contractVersion: 1,
        inventory: {
          authoritative: true,
          complete: true,
          revision: "registry-1",
          aliasesResolved: true,
          paginationComplete: true,
          issuersConnected: true,
          credentials: [],
          localIntentIds: context.localIntentIds,
        },
        globalFence: {
          id: "fence",
          allIssuers: true,
          renewals: true,
          durable: true,
          writerAdmission: true,
          remotePublicationDrained: true,
        },
        canonical: {
          identity: context.canonical.identity,
          watermark: context.canonical.watermark,
          inputs: context.canonical.inputs,
          completeBaseline: true,
          pagination: true,
          joins: true,
          blobs: true,
          incrementalAndDeletion: true,
          latestLegacyResolved: true,
          noFailedIngest: true,
          noForeignOrHeldHeads: true,
        },
        retention: {
          legacyHistoryReadable: true,
          canonicalHistoryDurable: true,
          ownerReadersQualified: true,
          metricsRecoveryQualified: true,
          noLegacyWritingRecovery: true,
          restartReadbackPassed: true,
          rollbackCompatibilityPassed: true,
        },
      };
    },
    assertCurrent: () => true,
  };
}

/** An oura world whose connection `A` holds `ids`, completed. */
function ouraWorld(ids: string[]) {
  const f = fixture({ declarations: [oura], source: OURA, method: "oura" });
  f.connect();
  for (const id of ids)
    f.write("activity", id, { day: "2026-09-01", score: 80 });
  f.complete(["activity"]);
  return f;
}

/** A legacy body equal to the canonical projection of `ids`. */
async function legacyBodyFor(ids: string[]) {
  const read = await ouraWorld(ids).view().readLatest(ACTIVITY);
  if (read.kind !== "canonical") throw new Error(JSON.stringify(read));
  return read.envelope;
}

/** A world whose latest legacy head equals `ids`, taken over by a parity read. */
async function takenOver(ids: string[]) {
  const body = await legacyBodyFor(ids);
  const f = ouraWorld(ids);
  f.insertHead(ACTIVITY);
  const view = f.view(async () => body);
  expect((await view.readLatest(ACTIVITY)).kind).toBe("canonical");
  return { f, view, body };
}

it("qualifies a complete join, counting an empty completed stream as complete", async () => {
  const f = fixture();
  f.connect();
  f.write("playlists", "p1", { name: "Mix", track_count: 0 });
  f.complete(["playlists", "playlist_items"]);
  const assessed = f.port().assess(SCOPE, "gen");
  expect(assessed).toMatchObject({
    ok: true,
    coverage: {
      scope: SCOPE,
      identity: {
        declaration: `${SOURCE}@2026-10-24#${"a".repeat(64)}`,
        artifact: expect.stringContaining(
          "oci:ghcr.io/pdp-connect/connector/spotify:",
        ),
        projection: expect.stringMatching(
          /^canonical-legacy-view\/\d+:spotify:spotify\.playlists:/,
        ),
        binding: `${A}:spotify:1:0`,
        servingGeneration: "gen",
      },
      inputs: [
        { instance: A, stream: "playlists", generation: 1 },
        { instance: A, stream: "playlist_items", generation: 1 },
      ],
      receipts: [{ liveCount: 1 }, { liveCount: 0 }],
    },
  });
  const qualified = await f.port().qualify(SCOPE, "gen");
  expect(qualified.ok).toBe(true);
  if (!qualified.ok) return;
  expect(qualified.coverage.projectionRevision).toMatch(/\S/);
  expect(f.port().isCurrent(qualified.coverage)).toBe(true);
  // A tampered watermark never passes the barrier.
  expect(
    f.port().isCurrent({ ...qualified.coverage, watermark: "other" }),
  ).toBe(false);
});

it("blocks a missing joined stream, a stale receipt and a projection join failure, regardless of row counts", async () => {
  const f = fixture();
  f.connect();
  f.write("playlists", "p1", { name: "Mix", track_count: 0 });
  f.complete(["playlists"]);
  expect(f.port().assess(SCOPE, "gen")).toEqual({
    ok: false,
    blockers: ["completion_missing:playlist_items"],
  });
  f.complete(["playlists", "playlist_items"]);
  f.write("playlists", "p2", { name: "Later", track_count: 0 });
  expect(f.port().assess(SCOPE, "gen")).toEqual({
    ok: false,
    // Every write deletes the receipt it could invalidate.
    blockers: ["completion_missing:playlists"],
  });
  // Receipts are current, but an item joins no playlist.
  f.write("playlist_items", "i1", { playlist_id: "missing", position: 0 });
  f.complete(["playlists", "playlist_items"]);
  expect(f.port().assess(SCOPE, "gen").ok).toBe(true);
  await expect(f.port().qualify(SCOPE, "gen")).resolves.toEqual({
    ok: false,
    blockers: ["projection_projection_rejected"],
  });
});

it("rejects stale coverage after a receipt-only update, a write, a reset or a declaration change", async () => {
  const f = fixture();
  f.connect();
  f.write("playlists", "p1", { name: "Mix", track_count: 0 });
  f.complete(["playlists", "playlist_items"]);
  const qualify = async () => {
    const result = await f.port().qualify(SCOPE, "gen");
    if (!result.ok) throw new Error(result.blockers.join());
    return result.coverage;
  };

  // Completion metadata does not advance the data clock; its receipt does.
  let coverage = await qualify();
  f.complete(["playlists", "playlist_items"]);
  expect(f.port().isCurrent(coverage)).toBe(false);

  coverage = await qualify();
  f.write("playlists", "p1", { name: "Renamed", track_count: 0 });
  expect(f.port().isCurrent(coverage)).toBe(false);

  f.complete(["playlists", "playlist_items"]);
  coverage = await qualify();
  expect(
    f.port([{ ...declaration, digest: "b".repeat(64) }]).isCurrent(coverage),
  ).toBe(false);
  expect(
    f
      .port([{ ...declaration, streams: [declaration.streams[0]!] }])
      .assess(SCOPE, "gen"),
  ).toEqual({
    ok: false,
    blockers: ["declaration_stream_missing:playlist_items"],
  });

  f.store.resetInstanceBinding({
    instance: A,
    expectedMethod: "spotify",
    expectedGeneration: 1,
    nextMethod: "spotify",
  });
  expect(f.port().isCurrent(coverage)).toBe(false);
  expect(f.port().assess(SCOPE, "gen")).toEqual({
    ok: false,
    blockers: [
      "completion_missing:playlists",
      "completion_missing:playlist_items",
    ],
  });
});

it("verifies referenced blob bytes, not only the completion digest", () => {
  const f = fixture();
  f.connect();
  const meta = f.store.storeBlobBytesForInstance({
    instance: A,
    method: "spotify",
    generation: 1,
    bytes: new TextEncoder().encode('"cover"'),
    mimeType: "application/json",
  });
  f.write("playlists", "p1", {
    name: "Mix",
    track_count: 0,
    blob_ref: {
      blob_id: meta.blobId,
      sha256: meta.sha256,
      size_bytes: meta.sizeBytes,
      mime_type: meta.mimeType,
    },
  });
  f.complete(["playlists", "playlist_items"]);
  expect(f.port().assess(SCOPE, "gen").ok).toBe(true);
  f.db
    .prepare("UPDATE pdpp_blob_bytes SET bytes = ? WHERE blob_id = ?")
    .run(Buffer.from('"other"'), meta.blobId);
  expect(f.port().assess(SCOPE, "gen")).toEqual({
    ok: false,
    blockers: ["blob_missing:playlists"],
  });
});

it("requires one configured connection, a bound scope and a covered latest legacy head", () => {
  const f = fixture();
  expect(f.port().assess("spotify.unbound", "gen")).toEqual({
    ok: false,
    blockers: ["unbound_scope"],
  });
  expect(f.port().assess(SCOPE, "gen")).toEqual({
    ok: false,
    blockers: ["no_connection"],
  });
  f.connect();
  f.write("playlists", "p1", { name: "Mix", track_count: 0 });
  f.complete(["playlists", "playlist_items"]);
  createIndexManager(f.db).insert({
    scope: SCOPE,
    path: "legacy-head.json",
    collectedAt: "2026-10-24T00:00:00Z",
    fileId: null,
    sizeBytes: 10,
    dataPointId: "dp-legacy",
  });
  expect(f.port().assess(SCOPE, "gen")).toEqual({
    ok: false,
    blockers: ["latest_legacy_head_uncovered"],
  });
  f.connect(B);
  expect(f.port().assess(SCOPE, "gen")).toEqual({
    ok: false,
    blockers: ["ambiguous_connection"],
  });
});

it("drives the stop predicate: refuses before quiescing, rechecks at the final barrier and retains the real inputs", async () => {
  const f = fixture();
  let mutate = () => {};
  const policy = createLegacyPublicationPolicy(f.db, {
    owner: "0xowner",
    serverGeneration: "gen",
    enabled: () => true,
    canonical: f.port(),
    qualification: echoingQualification(() => mutate()),
  });
  f.connect();
  f.write("playlists", "p1", { name: "Mix", track_count: 0 });
  f.complete(["playlists"]);
  await expect(
    policy.stop(SCOPE, { ownerOptIn: true, expectedEpoch: 0 }),
  ).rejects.toMatchObject({
    errorCode: "LEGACY_SHUTDOWN_BLOCKED",
    details: { blockers: ["completion_missing:playlist_items"] },
  });
  expect(policy.read(SCOPE).state).toBe("mirroring");
  expect(policy.canonicalCoverage(SCOPE)).toMatchObject({ ok: false });

  f.complete(["playlists", "playlist_items"]);
  // A canonical write lands after qualification, before the barrier.
  mutate = () => {
    f.write("playlists", "p2", { name: "Late", track_count: 0 });
  };
  await expect(
    policy.stop(SCOPE, { ownerOptIn: true, expectedEpoch: 0 }),
  ).rejects.toMatchObject({
    errorCode: "LEGACY_SHUTDOWN_BLOCKED",
    message: "Native canonical inputs changed before commit",
  });
  expect(policy.read(SCOPE)).toMatchObject({ state: "quiescing", epoch: 1 });

  mutate = () => {};
  f.complete(["playlists", "playlist_items"]);
  const stopped = await policy.stop(SCOPE, {
    ownerOptIn: true,
    expectedEpoch: 1,
  });
  expect(stopped).toMatchObject({
    state: "stopped",
    evidence: {
      canonical: {
        inputs: [
          { instance: A, stream: "playlists", generation: 1 },
          { instance: A, stream: "playlist_items", generation: 1 },
        ],
      },
    },
  });
  expect(() =>
    f.db.prepare("DELETE FROM pdpp_record_changes WHERE instance = ?").run(A),
  ).toThrow("canonical_history_retained");
});

it("qualifies a latest legacy head only with a current covered parity verdict, which the final barrier rechecks", async () => {
  const { f, body } = await takenOver(["a1", "a2"]);
  expect(f.port().assess(ACTIVITY, "gen")).toMatchObject({
    ok: true,
    coverage: { identity: { binding: `${A}:oura:1:0` } },
  });
  const qualified = await f.port().qualify(ACTIVITY, "gen");
  expect(qualified.ok).toBe(true);
  if (!qualified.ok) return;
  expect(f.port().isCurrent(qualified.coverage)).toBe(true);

  // After qualification, a parity read under other thresholds re-records
  // the verdict for the same rows; the stop barrier sees the change.
  let reevaluate = async () => {
    await f.view(async () => body, 1).readLatest(ACTIVITY);
  };
  // Stop seals only history whose indexed bytes are really there.
  const storage = storageFor(f.db);
  writeFileSync(
    join(storage.hierarchyOptions.dataDir, "legacy-head.json"),
    "{}",
  );
  const policy = createLegacyPublicationPolicy(f.db, {
    owner: "0xowner",
    serverGeneration: "gen",
    enabled: () => true,
    storage,
    canonical: f.port(),
    qualification: echoingQualification(() => reevaluate()),
  });
  await expect(
    policy.stop(ACTIVITY, { ownerOptIn: true, expectedEpoch: 0 }),
  ).rejects.toMatchObject({
    errorCode: "LEGACY_SHUTDOWN_BLOCKED",
    message: "Native canonical inputs changed before commit",
  });
  expect(f.port().isCurrent(qualified.coverage)).toBe(false);

  // A fresh covered parity read with the serving thresholds qualifies again.
  reevaluate = async () => {};
  expect((await f.view(async () => body).readLatest(ACTIVITY)).kind).toBe(
    "canonical",
  );
  await expect(
    policy.stop(ACTIVITY, { ownerOptIn: true, expectedEpoch: 1 }),
  ).resolves.toMatchObject({ state: "stopped" });
});

it("blocks a canonical shrink after takeover, before and after the legacy view refuses it", async () => {
  const { f, view } = await takenOver(["a1", "a2"]);
  // A later full-stream run without a2, not proven newer than the legacy head.
  f.store.replaceStream({
    instance: A,
    stream: "activity",
    method: "oura",
    generation: 1,
    primaryKey: ["id"],
    emittedAt: "2026-10-23T00:00:00.000Z",
    sourceCollectedAt: "2026-10-23T00:00:00.000Z",
    envelopes: [
      {
        instance: A,
        stream: "activity",
        key: "a1",
        data: { id: "a1", day: "2026-09-01", score: 80 },
        emitted_at: "2026-10-23T00:00:00.000Z",
      },
    ],
  });
  f.complete(["activity"]);
  // The covered verdict no longer describes the current rows.
  expect(f.port().assess(ACTIVITY, "gen")).toEqual({
    ok: false,
    blockers: ["latest_legacy_head_uncovered"],
  });
  expect((await view.readLatest(ACTIVITY)).kind).toBe("refused");
  expect(f.port().assess(ACTIVITY, "gen")).toEqual({
    ok: false,
    blockers: ["latest_legacy_head_uncovered"],
  });
});

it("blocks a head compared only with an earlier generation after a reset and smaller recollection", async () => {
  const { f } = await takenOver(["a1", "a2"]);
  f.store.resetInstanceBinding({
    instance: A,
    expectedMethod: "oura",
    expectedGeneration: 1,
    nextMethod: "oura",
  });
  f.write("activity", "a1", { day: "2026-09-01", score: 80 });
  f.complete(["activity"]);
  expect(f.authority.hasTakeover(ACTIVITY, A, 2)).toBe(false);
  expect(f.port().assess(ACTIVITY, "gen")).toEqual({
    ok: false,
    blockers: ["latest_legacy_head_uncovered"],
  });
});

it("never inherits an unattributed takeover: a migrated blank instance or a confirmation without a verdict", async () => {
  // The v13 migration shape: a takeover with instance ''.
  const migrated = ouraWorld(["b1"]);
  migrated.insertHead(ACTIVITY);
  migrated.db
    .prepare(
      `INSERT INTO legacy_scope_takeovers (scope, superseded_version, superseded_cas_revision, superseded_collected_at, superseded_path)
       SELECT scope, version, cas_revision, collected_at, path FROM data_files WHERE scope = ?`,
    )
    .run(ACTIVITY);
  expect(migrated.port().assess(ACTIVITY, "gen")).toEqual({
    ok: false,
    blockers: ["latest_legacy_head_uncovered"],
  });

  // A view without a legacy reader confirms with no content comparison.
  const unverified = ouraWorld(["a1"]);
  unverified.insertHead(ACTIVITY);
  await unverified.view().readLatest(ACTIVITY);
  expect(
    unverified.db
      .prepare("SELECT instance FROM legacy_scope_takeovers WHERE scope = ?")
      .all(ACTIVITY),
  ).toEqual([{ instance: "" }]);
  expect(unverified.port().assess(ACTIVITY, "gen")).toEqual({
    ok: false,
    blockers: ["latest_legacy_head_uncovered"],
  });
  unverified.store.deleteConnection(A);
  unverified.connect(B);
  unverified.write("activity", "b1", { day: "2026-09-01", score: 80 }, B);
  unverified.complete(["activity"], B);
  expect(unverified.port().assess(ACTIVITY, "gen")).toEqual({
    ok: false,
    blockers: ["latest_legacy_head_uncovered"],
  });
});

it("counts a data-holding connection of an unconfigured method of the scope, as the legacy view does", async () => {
  const f = ouraWorld(["a1"]);
  f.connect(B, "oura-browser");
  f.write("activity", "x1", { day: "2026-09-01", score: 1 }, B);
  expect(await f.view().readLatest(ACTIVITY)).toMatchObject({
    kind: "refused",
    refusal: { reason: "ambiguous_connection", candidates: 2 },
  });
  expect(f.port().assess(ACTIVITY, "gen")).toEqual({
    ok: false,
    blockers: ["ambiguous_connection"],
  });
  await expect(f.port().qualify(ACTIVITY, "gen")).resolves.toEqual({
    ok: false,
    blockers: ["ambiguous_connection"],
  });
  // Alone, the unconfigured method's connection still cannot qualify.
  f.store.deleteConnection(A);
  expect(f.port().assess(ACTIVITY, "gen")).toEqual({
    ok: false,
    blockers: ["connection_method_not_configured"],
  });
});
