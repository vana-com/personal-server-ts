import { afterEach, describe, expect, it } from "vitest";
import { initializeDatabase } from "./index-schema.js";
import { LEGACY_GATE_INDEX_SCHEMA_VERSION } from "./schema-versions.js";
import { createLegacyPublicationPolicy } from "./legacy-publication-policy.js";
import type { LegacyCanonicalCoveragePort } from "./legacy-publication-canonical.js";

const databases: ReturnType<typeof initializeDatabase>[] = [];
afterEach(() => {
  for (const db of databases.splice(0)) db.close();
});
function open(enabled = false) {
  const db = initializeDatabase(":memory:");
  databases.push(db);
  const policy = createLegacyPublicationPolicy(db, {
    owner: "0xowner",
    serverGeneration: "generation-1",
    enabled: () => enabled,
  });
  return { db, policy };
}

describe("legacy publication shutdown", () => {
  it("defaults to mirroring and refuses default-off enrollment", async () => {
    const { policy } = open();
    expect(policy.read("spotify.profile")).toMatchObject({
      state: "mirroring",
      epoch: 0,
    });
    await expect(
      policy.stop("spotify.profile", { ownerOptIn: true, expectedEpoch: 0 }),
    ).rejects.toMatchObject({ errorCode: "LEGACY_SHUTDOWN_DISABLED" });
    expect(policy.read("spotify.profile").state).toBe("mirroring");
  });
});

it("persists an exact-scope fence and retains history across generation changes", async () => {
  const { db } = open(true);
  const { createIndexManager } = await import("./index-manager.js");
  const index = createIndexManager(db);
  const entry = {
    scope: "spotify.profile",
    path: "history.json",
    collectedAt: "2026-10-24T00:00:00Z",
    fileId: null,
    sizeBytes: 10,
    dataPointId: "dp-history",
  };
  index.insert(entry);
  const policy = createLegacyPublicationPolicy(db, {
    owner: "0xowner",
    serverGeneration: "generation-1",
    enabled: () => true,
    canonical: canonicalStub(),
    qualification: qualification(),
  });
  const stopped = await policy.stop(entry.scope, {
    ownerOptIn: true,
    expectedEpoch: 0,
  });
  expect(stopped).toMatchObject({ state: "stopped", epoch: 2 });
  expect(db.pragma("user_version", { simple: true })).toBe(
    LEGACY_GATE_INDEX_SCHEMA_VERSION,
  );
  expect(() => index.insert({ ...entry, path: "new.json" })).toThrow(
    expect.objectContaining({ errorCode: "legacy_scope_retired" }),
  );
  expect(() => index.deleteByScope(entry.scope)).toThrow(
    "legacy_history_retained",
  );
  expect(index.countByScope(entry.scope)).toBe(1);
  index.insert({ ...entry, scope: "spotify.playlists", path: "sibling.json" });
  const next = createLegacyPublicationPolicy(db, {
    owner: "0xowner",
    serverGeneration: "generation-2",
    enabled: () => false,
  });
  expect(next.read(entry.scope)).toMatchObject({
    state: "stopped",
    identityMismatch: true,
  });
  await expect(
    next.stop(entry.scope, { ownerOptIn: true, expectedEpoch: 2 }),
  ).rejects.toMatchObject({ errorCode: "LEGACY_POLICY_IDENTITY_MISMATCH" });
});

function qualification() {
  return {
    async freezeAndQualify(context: any) {
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
          id: "durable-global-fence",
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

it("keeps rollback fenced when recovery is unavailable", async () => {
  const { db } = open(true);
  const policy = createLegacyPublicationPolicy(db, {
    owner: "0xowner",
    serverGeneration: "generation-1",
    enabled: () => true,
    canonical: canonicalStub(),
    qualification: qualification(),
  });
  const stopped = await policy.stop("spotify.profile", {
    ownerOptIn: true,
    expectedEpoch: 0,
  });
  await expect(
    policy.rollback("spotify.profile", { expectedEpoch: stopped.epoch }),
  ).rejects.toMatchObject({ errorCode: "LEGACY_RESTORE_UNAVAILABLE" });
  expect(policy.read("spotify.profile")).toMatchObject({
    state: "restoring",
    epoch: 3,
  });
});

it.each([
  ["inventory.authoritative", false],
  ["inventory.complete", false],
  ["inventory.revision", ""],
  ["inventory.aliasesResolved", false],
  ["inventory.paginationComplete", false],
  ["inventory.issuersConnected", false],
  ["globalFence.allIssuers", false],
  ["globalFence.renewals", false],
  ["globalFence.durable", false],
  ["globalFence.writerAdmission", false],
  ["globalFence.remotePublicationDrained", false],
  ["canonical.completeBaseline", false],
  ["canonical.pagination", false],
  ["canonical.joins", false],
  ["canonical.blobs", false],
  ["canonical.incrementalAndDeletion", false],
  ["canonical.latestLegacyResolved", false],
  ["canonical.noFailedIngest", false],
  ["canonical.noForeignOrHeldHeads", false],
  ["canonical.watermark", ""],
  ["retention.legacyHistoryReadable", false],
  ["retention.canonicalHistoryDurable", false],
  ["retention.ownerReadersQualified", false],
  ["retention.metricsRecoveryQualified", false],
  ["retention.noLegacyWritingRecovery", false],
  ["retention.restartReadbackPassed", false],
  ["retention.rollbackCompatibilityPassed", false],
  ["owner", "0xforeign"],
  ["serverGeneration", "other"],
  ["scope", "spotify.playlists"],
  ["canonical.identity.servingGeneration", "other"],
  ["canonical.identity.artifact", ""],
  ["canonical.identity.declaration", ""],
  ["canonical.identity.projection", ""],
  ["canonical.identity.binding", ""],
  ["contractVersion", 2],
  ["legacyCasRevision", 8],
  ["epoch", 17],
])("refuses incomplete qualification: %s", async (path, value) => {
  const { db } = open(true);
  const adapter = qualification();
  const freeze = adapter.freezeAndQualify;
  adapter.freezeAndQualify = async (context) => {
    const evidence: any = await freeze(context);
    const fields = path.split(".");
    let object = evidence;
    for (const field of fields.slice(0, -1)) object = object[field];
    object[fields.at(-1)!] = value;
    return evidence;
  };
  const policy = createLegacyPublicationPolicy(db, {
    owner: "0xowner",
    serverGeneration: "generation-1",
    enabled: () => true,
    canonical: canonicalStub(),
    qualification: adapter,
  });
  await expect(
    policy.stop("spotify.profile", { ownerOptIn: true, expectedEpoch: 0 }),
  ).rejects.toMatchObject({ errorCode: "LEGACY_SHUTDOWN_BLOCKED" });
  expect(policy.read("spotify.profile").state).toBe("quiescing");
});

it.each([
  "active",
  "pending",
  "submitting",
  "reorged",
  "unknown",
  "expired",
  "revoked",
])("blocks non-final credential %s", async (state) => {
  const { db } = open(true);
  const base = qualification();
  const policy = createLegacyPublicationPolicy(db, {
    owner: "0xowner",
    serverGeneration: "generation-1",
    enabled: () => true,
    canonical: canonicalStub(),
    qualification: {
      ...base,
      freezeAndQualify: async (context) => ({
        ...(await base.freezeAndQualify(context)),
        inventory: {
          ...(await base.freezeAndQualify(context)).inventory,
          credentials: [{ id: "grant", state, scopesResolved: true }],
        },
      }),
    },
  });
  await expect(
    policy.stop("spotify.profile", { ownerOptIn: true, expectedEpoch: 0 }),
  ).rejects.toMatchObject({ errorCode: "LEGACY_SHUTDOWN_BLOCKED" });
});

it("refuses absent capabilities or opt-in without enrolling", async () => {
  const { db } = open(true);
  const policy = createLegacyPublicationPolicy(db, {
    owner: "0xowner",
    serverGeneration: "generation-1",
    enabled: () => true,
  });
  await expect(
    policy.stop("spotify.profile", { ownerOptIn: false, expectedEpoch: 0 }),
  ).rejects.toMatchObject({ errorCode: "LEGACY_OWNER_OPT_IN_REQUIRED" });
  await expect(
    policy.stop("spotify.profile", { ownerOptIn: true, expectedEpoch: 0 }),
  ).rejects.toMatchObject({ errorCode: "LEGACY_SHUTDOWN_UNAVAILABLE" });
  expect(policy.read("spotify.profile").state).toBe("mirroring");
});

it("refuses before quiescing while accepted imports or remote publications need draining", async () => {
  const { db } = open(true);
  const policy = createLegacyPublicationPolicy(db, {
    owner: "0xowner",
    serverGeneration: "generation-1",
    enabled: () => true,
    canonical: canonicalStub(),
    qualification: qualification(),
  });
  db.prepare(
    `INSERT INTO owner_import_operations VALUES ('local', '0xowner', 'spotify.profile', 'pending', 'hash', 'prepared', '2026-10-24T00:00:00Z', 'pending.json', '{}', '{}', NULL)`,
  ).run();
  await expect(
    policy.stop("spotify.profile", { expectedEpoch: 0, ownerOptIn: true }),
  ).rejects.toMatchObject({ errorCode: "LEGACY_SHUTDOWN_BLOCKED" });
  expect(policy.read("spotify.profile").state).toBe("mirroring");
  db.prepare("DELETE FROM owner_import_operations").run();
  const { createIndexManager } = await import("./index-manager.js");
  createIndexManager(db).insert({
    fileId: null,
    scope: "spotify.profile",
    path: "queued.json",
    sizeBytes: 2,
    collectedAt: "2026-10-24T00:00:00Z",
    producer: "pdpp-projector",
  });
  await expect(
    policy.stop("spotify.profile", { expectedEpoch: 0, ownerOptIn: true }),
  ).rejects.toMatchObject({ errorCode: "LEGACY_SHUTDOWN_BLOCKED" });
  expect(policy.read("spotify.profile").state).toBe("mirroring");
});

it("linearizes credential issuance against quiescing and never treats unknown signed intents as zero", async () => {
  const { db } = open(true);
  const { recordLegacyIssuanceIntent } =
    await import("./legacy-publication-issuance.js");
  recordLegacyIssuanceIntent(db, "0xowner", ["spotify.profile"], "grant", {
    pending: "signature",
  });
  const adapter = qualification();
  let release!: () => void;
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  const freeze = adapter.freezeAndQualify;
  adapter.freezeAndQualify = async (context) => {
    await blocked;
    return freeze(context);
  };
  const policy = createLegacyPublicationPolicy(db, {
    owner: "0xowner",
    serverGeneration: "generation-1",
    enabled: () => true,
    canonical: canonicalStub(),
    qualification: adapter,
  });
  const stop = policy.stop("spotify.profile", {
    expectedEpoch: 0,
    ownerOptIn: true,
  });
  expect(policy.read("spotify.profile").state).toBe("quiescing");
  for (const scopes of [
    ["spotify.profile"],
    ["write:spotify.profile"],
    ["spotify.*"],
    ["*"],
    ["unknown-alias"],
  ]) {
    expect(() =>
      recordLegacyIssuanceIntent(db, "0xowner", scopes, "grant", {}),
    ).toThrow(expect.objectContaining({ errorCode: "legacy_scope_retired" }));
  }
  recordLegacyIssuanceIntent(db, "0xowner", ["spotify.playlists"], "grant", {});
  release();
  await expect(stop).rejects.toMatchObject({
    errorCode: "LEGACY_SHUTDOWN_BLOCKED",
  });
  expect(policy.read("spotify.profile").state).toBe("quiescing");
});

it("rejects stale coverage at the final SQLite barrier and flag disable never opens quiescing", async () => {
  const { db } = open(true);
  let enabled = true;
  const adapter = qualification();
  adapter.assertCurrent = () => false;
  const policy = createLegacyPublicationPolicy(db, {
    owner: "0xowner",
    serverGeneration: "generation-1",
    enabled: () => enabled,
    canonical: canonicalStub(),
    qualification: adapter,
  });
  await expect(
    policy.stop("spotify.profile", { expectedEpoch: 0, ownerOptIn: true }),
  ).rejects.toMatchObject({ errorCode: "LEGACY_SHUTDOWN_BLOCKED" });
  enabled = false;
  await expect(
    policy.stop("spotify.profile", { expectedEpoch: 1, ownerOptIn: true }),
  ).rejects.toMatchObject({ errorCode: "LEGACY_SHUTDOWN_DISABLED" });
  expect(policy.read("spotify.profile").state).toBe("quiescing");
});

it("canonical ingestion keeps advancing, history stays retained, and takeover reset cannot clear stop", async () => {
  const { db } = open(true);
  const { createSqliteRecordStore } =
    await import("./pdpp-records-sqlite-store.js");
  const { createLegacyScopeAuthority } =
    await import("./legacy-scope-authority.js");
  const records = createSqliteRecordStore(db);
  records.registerConnection({
    instance: "conn",
    sourceId: "https://example.test/spotify",
    method: "test",
    label: "source",
  });
  const ingest = (name: string) =>
    records.ingestBatch(
      [
        {
          instance: "conn",
          stream: "profile",
          key: "owner",
          data: { id: "owner", name },
          emitted_at: `2026-10-24T00:00:0${name === "before" ? 0 : 1}Z`,
        },
      ],
      () => "upsert",
      () => ["id"],
      { method: "test", generation: 1 },
    );
  expect(ingest("before").results[0].outcome).toBe("accepted");
  const policy = createLegacyPublicationPolicy(db, {
    owner: "0xowner",
    serverGeneration: "generation-1",
    enabled: () => true,
    canonical: canonicalStub(),
    qualification: qualification(),
  });
  await policy.stop("spotify.profile", { expectedEpoch: 0, ownerOptIn: true });
  expect(ingest("after").results[0].outcome).toBe("accepted");
  expect(records.getRecord("conn", "profile", "owner")?.data).toMatchObject({
    name: "after",
  });
  expect(
    db.prepare("SELECT COUNT(*) n FROM pdpp_record_changes").get(),
  ).toEqual({ n: 2 });
  expect(() => db.prepare("DELETE FROM pdpp_record_changes").run()).toThrow(
    "canonical_history_retained",
  );
  await createLegacyScopeAuthority(db).resetTakeover("spotify.profile");
  expect(policy.read("spotify.profile").state).toBe("stopped");
});

// Scope sets are the design's catalog snapshot, not app-owner acceptance.
const catalogContracts = [
  ["Keep Me Weekly", ["spotify.playlists"]],
  [
    "Career Coach",
    [
      "linkedin.profile",
      "linkedin.experience",
      "linkedin.education",
      "linkedin.skills",
      "linkedin.languages",
    ],
  ],
  ["LinkedIn to ReadCV", ["linkedin.profile"]],
  ["Peak Think", ["oura.readiness", "chatgpt.conversations"]],
  ["Personal Museum", ["icloud_notes.notes"]],
  ["Hoe-kemon", ["instagram.profile", "instagram.posts"]],
  ["Car Game", ["shop.orders"]],
  ["Career Quest", ["linkedin.profile"]],
  ["Playlist Shelf", ["spotify.profile"]],
] as const;
it.each(catalogContracts)(
  "all_nine_catalog_contracts_are_explicit: %s",
  async (_name, scopes) => {
    for (const scope of scopes) {
      const { db } = open(true);
      const base = qualification();
      const policy = createLegacyPublicationPolicy(db, {
        owner: "0xowner",
        serverGeneration: "generation-1",
        enabled: () => true,
        canonical: canonicalStub(),
        qualification: {
          ...base,
          async freezeAndQualify(context) {
            const evidence = await base.freezeAndQualify(context);
            return {
              ...evidence,
              inventory: {
                ...evidence.inventory,
                credentials: [
                  {
                    id: "effective-legacy-grant",
                    state: "active",
                    scopesResolved: true,
                  },
                ],
              },
            };
          },
        },
      });
      await expect(
        policy.stop(scope, { ownerOptIn: true, expectedEpoch: 0 }),
      ).rejects.toMatchObject({ errorCode: "LEGACY_SHUTDOWN_BLOCKED" });
      // Force only the backend stopped fixture to check explicit new-grant failure.
      db.prepare(
        "UPDATE legacy_publication_policy SET state = 'stopped'",
      ).run();
      const { recordLegacyIssuanceIntent } =
        await import("./legacy-publication-issuance.js");
      expect(() =>
        recordLegacyIssuanceIntent(db, "0xowner", [scope], "grant", {
          newLegacyGrant: true,
        }),
      ).toThrow(expect.objectContaining({ errorCode: "legacy_scope_retired" }));
    }
  },
);

/** Lifecycle tests stub the native port; legacy-publication-canonical.test.ts covers the real reader. */
function canonicalStub(): LegacyCanonicalCoveragePort {
  const coverage = (scope: string, servingGeneration: string) => ({
    scope,
    identity: {
      declaration: "decl",
      artifact: "artifact",
      projection: "projection",
      binding: "binding",
      servingGeneration,
    },
    inputs: [{ instance: "conn", stream: "profile", generation: 1 }],
    receipts: [],
    additionsTrackedSince: "2026-10-01T00:00:00.000Z",
    inputDigest: "inputs-1",
  });
  return {
    assess: (scope, generation) => ({
      ok: true,
      coverage: coverage(scope, generation),
    }),
    qualify: async (scope, generation) => ({
      ok: true,
      coverage: {
        ...coverage(scope, generation),
        projectionRevision: "projection-1",
        watermark: "committed-1",
      },
    }),
    isCurrent: () => true,
  };
}
