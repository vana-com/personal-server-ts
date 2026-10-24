import { afterEach, describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import {
  AUTHORIZATION_CODE_TTL_SECONDS,
  computeGrantArtifactDigest,
  computeReviewDigest,
  parseDeclaration,
  PdppTokenService,
  timeSortKey,
  type Grant as CoreGrant,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import { openPdppAuthStore } from "@opendatalabs/personal-server-ts-core/pdpp";
import { initializeDatabase } from "./index-schema.js";
import { CONVERGED_INDEX_SCHEMA_VERSION } from "./schema-versions.js";
import { createIndexManager } from "./index-manager.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createSqlitePdppGrantBindingStore } from "./pdpp-grant-binding-sqlite-store.js";

/**
 * Frozen SQL from this head's migration history and prior-version fixtures:
 * index-schema.test.ts (v1/v14), pdpp-history-blob-gc.test.ts (v3),
 * pdpp-records-sqlite-store.ts (the first 15 migration ARRAY entries), and
 * pdpp-grant-binding-sqlite-store.test.ts (binding v1).
 *
 * These are raw on-disk stores, never current stores with a rewound stamp.
 * PDPP v1 is the oldest nonempty schema; byte storage begins at v3, claims
 * at v4, and Claude archives at array version 15 (commented "v14"). Test
 * those feature boundaries separately instead of inventing a v1 archive.
 * The v15 snapshot is synthesized, NOT a captured Desktop 1.61.0 database
 * or validation of its shipped binary/source revision.
 *
 * Scope limit: issued-token consumption/conformance evidence is outside
 * storage. Here a previously issued grant's v1 binding stays inspectable,
 * with no invented grantVersion. Rebinding it fails with an explicit
 * INVALID_SIGNATURE reason. This is not an end-to-end authorization test.
 */
const TIME = "2026-01-01T00:00:00.000Z";
const LIVE = "claude:owner";
const ARCHIVE = "claude:owner:archive:1";
const TAKEN_SCOPE = "claude.conversations";
const UNTAKEN_SCOPE = "instagram.profile";
const PERMISSION = {
  chainId: 14800,
  contractAddress: "0xD54523048AdD05b4d734aFaE7C68324Ebb7373eF" as const,
  permissionId: "42",
};
const GRANT = {
  pdppGrantId: "issued-before-upgrade",
  permission: PERMISSION,
  ownerAddress: "0x00000000000000000000000000000000000000AA" as const,
  granteeAddress: "0x00000000000000000000000000000000000000C1" as const,
  pdppClientId: "client-app-1",
  granteeId: "0x00000000000000000000000000000000000000C1",
  boundAt: TIME,
  grantVersion: null,
};

const PDPP_V1 = `
CREATE TABLE IF NOT EXISTS pdpp_records (
  instance TEXT NOT NULL,
  stream TEXT NOT NULL,
  record_key TEXT NOT NULL,
  data TEXT, -- JSON; NULL when deleted = 1
  version INTEGER NOT NULL,
  emitted_at TEXT NOT NULL,
  deleted INTEGER NOT NULL DEFAULT 0,
  deleted_at TEXT,
  PRIMARY KEY (instance, stream, record_key)
);

CREATE TABLE IF NOT EXISTS pdpp_record_changes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  instance TEXT NOT NULL,
  stream TEXT NOT NULL,
  record_key TEXT NOT NULL,
  version INTEGER NOT NULL,
  data TEXT, -- JSON; NULL for a tombstone version
  emitted_at TEXT NOT NULL,
  deleted INTEGER NOT NULL DEFAULT 0,
  deleted_at TEXT,
  written_at INTEGER NOT NULL -- monotonic write sequence, for changes_since horizons
);

CREATE INDEX IF NOT EXISTS idx_pdpp_record_changes_lookup
  ON pdpp_record_changes (instance, stream, record_key, version);

CREATE INDEX IF NOT EXISTS idx_pdpp_record_changes_horizon
  ON pdpp_record_changes (stream, instance, written_at);

CREATE INDEX IF NOT EXISTS idx_pdpp_records_stream
  ON pdpp_records (stream, instance, emitted_at);

CREATE TABLE IF NOT EXISTS pdpp_blobs (
  blob_id TEXT PRIMARY KEY,
  mime_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  sha256 TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pdpp_write_clock (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  value INTEGER NOT NULL
);
INSERT OR IGNORE INTO pdpp_write_clock (id, value) VALUES (1, 0);
`;
const PDPP_V2_V3 = `
ALTER TABLE pdpp_records ADD COLUMN blob_id TEXT;

CREATE INDEX IF NOT EXISTS idx_pdpp_records_blob_id
  ON pdpp_records (blob_id);

CREATE TABLE IF NOT EXISTS pdpp_blob_bytes (
  blob_id TEXT PRIMARY KEY REFERENCES pdpp_blobs (blob_id),
  bytes BLOB NOT NULL
);
`;
const PDPP_V4_V15 = `
CREATE TABLE IF NOT EXISTS pdpp_instance_binding (
  instance TEXT PRIMARY KEY,
  method TEXT,
  generation INTEGER NOT NULL CHECK (generation > 0),
  reset_clock INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO pdpp_instance_binding (instance, method, generation, reset_clock)
SELECT DISTINCT instance, NULL, 1, 0 FROM pdpp_records;

CREATE TABLE IF NOT EXISTS pdpp_blob_claims (
  blob_id TEXT NOT NULL REFERENCES pdpp_blobs (blob_id),
  instance TEXT NOT NULL,
  generation INTEGER NOT NULL,
  PRIMARY KEY (blob_id, instance)
);

INSERT OR IGNORE INTO pdpp_blob_claims (blob_id, instance, generation)
SELECT DISTINCT r.blob_id, r.instance, b.generation
FROM pdpp_records r
JOIN pdpp_instance_binding b ON b.instance = r.instance
JOIN pdpp_blobs m ON m.blob_id = r.blob_id
WHERE r.blob_id IS NOT NULL AND r.deleted = 0;


CREATE TABLE IF NOT EXISTS pdpp_store_metadata (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  epoch TEXT NOT NULL
);


ALTER TABLE pdpp_instance_binding ADD COLUMN source_id TEXT;
ALTER TABLE pdpp_instance_binding ADD COLUMN label TEXT NOT NULL DEFAULT '';
ALTER TABLE pdpp_instance_binding ADD COLUMN deleted_at TEXT;


CREATE TABLE IF NOT EXISTS pdpp_stream_completion (
  instance TEXT NOT NULL,
  stream TEXT NOT NULL,
  method TEXT NOT NULL,
  generation INTEGER NOT NULL,
  source_collected_at TEXT NOT NULL,
  write_seq INTEGER NOT NULL,
  live_count INTEGER NOT NULL,
  PRIMARY KEY (instance, stream)
);


CREATE TABLE IF NOT EXISTS pdpp_record_arrival (
  instance TEXT NOT NULL,
  stream TEXT NOT NULL,
  record_key TEXT NOT NULL,
  generation INTEGER NOT NULL,
  arrival INTEGER NOT NULL,
  PRIMARY KEY (instance, stream, record_key)
);

CREATE INDEX IF NOT EXISTS idx_pdpp_record_arrival_order
  ON pdpp_record_arrival (instance, stream, arrival);



CREATE INDEX IF NOT EXISTS idx_pdpp_records_live_instance_stream_emitted_at
  ON pdpp_records (instance, stream, emitted_at)
  WHERE deleted = 0;


CREATE TABLE IF NOT EXISTS pdpp_record_arrival_clock (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  value INTEGER NOT NULL
);
INSERT OR IGNORE INTO pdpp_record_arrival_clock (id, value) VALUES (1, 0);


CREATE INDEX IF NOT EXISTS idx_pdpp_record_changes_snapshot_order
  ON pdpp_record_changes (stream, emitted_at, record_key, instance, written_at);
CREATE INDEX IF NOT EXISTS idx_pdpp_record_changes_snapshot_latest
  ON pdpp_record_changes (instance, stream, record_key, written_at DESC, version DESC);



CREATE TABLE IF NOT EXISTS pdpp_claude_transition (
    instance TEXT PRIMARY KEY,
    archive_instance TEXT NOT NULL UNIQUE,
    generation INTEGER NOT NULL,
    snapshots_json TEXT NOT NULL,
    conversations_covered INTEGER NOT NULL DEFAULT 0
  );
ALTER TABLE pdpp_stream_completion ADD COLUMN snapshot_sha256 TEXT;
ALTER TABLE pdpp_stream_completion ADD COLUMN collection_time_basis TEXT;
ALTER TABLE pdpp_records ADD COLUMN emitted_key TEXT;
ALTER TABLE pdpp_record_changes ADD COLUMN emitted_key TEXT;
DROP INDEX IF EXISTS idx_pdpp_record_changes_snapshot_order;
CREATE INDEX idx_pdpp_record_changes_snapshot_key_order
  ON pdpp_record_changes (stream, emitted_key, record_key, instance, written_at);
CREATE INDEX idx_pdpp_records_live_instance_stream_emitted_key
  ON pdpp_records (instance, stream, emitted_key, emitted_at) WHERE deleted = 0;
ALTER TABLE pdpp_store_metadata ADD COLUMN sync_token_key TEXT;
CREATE INDEX idx_pdpp_record_changes_sync_identity
  ON pdpp_record_changes (stream, record_key, instance, written_at);
CREATE TABLE pdpp_sync_state (
  id TEXT PRIMARY KEY, owner TEXT NOT NULL, state TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE INDEX idx_pdpp_sync_state_owner ON pdpp_sync_state (owner);
CREATE INDEX idx_pdpp_sync_state_expires ON pdpp_sync_state (expires_at);
`;

const INDEX_V1 = `
CREATE TABLE data_files (
  id INTEGER PRIMARY KEY AUTOINCREMENT, file_id TEXT, path TEXT NOT NULL UNIQUE,
  scope TEXT NOT NULL, collected_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
  size_bytes INTEGER NOT NULL DEFAULT 0
);`;
const INDEX_V14 = `
CREATE TABLE IF NOT EXISTS data_files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id TEXT,
  schema_id TEXT,
  path TEXT NOT NULL UNIQUE,
  scope TEXT NOT NULL,
  collected_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
  size_bytes INTEGER NOT NULL DEFAULT 0,
  version INTEGER NOT NULL DEFAULT 1,
  cas_revision INTEGER NOT NULL DEFAULT 1,
  data_point_id TEXT,
  after_tombstone_version INTEGER,
  producer TEXT,
  producer_provenance TEXT
);

CREATE TABLE IF NOT EXISTS scope_revisions (
  scope TEXT PRIMARY KEY,
  cas_revision INTEGER NOT NULL,
  closed_for_writes INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS legacy_scope_takeovers (
  scope TEXT NOT NULL,
  instance TEXT NOT NULL DEFAULT '',
  generation INTEGER NOT NULL DEFAULT 1,
  superseded_version INTEGER NOT NULL,
  superseded_cas_revision INTEGER NOT NULL,
  superseded_collected_at TEXT NOT NULL,
  superseded_path TEXT NOT NULL,
  taken_over_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  PRIMARY KEY (scope, instance, generation, superseded_path)
);

CREATE TABLE IF NOT EXISTS legacy_scope_takeover_verdicts (
  scope TEXT NOT NULL,
  instance TEXT NOT NULL,
  generation INTEGER NOT NULL DEFAULT 1,
  legacy_version_id INTEGER NOT NULL,
  canonical_cursor TEXT NOT NULL,
  verdict TEXT NOT NULL CHECK (verdict IN ('covered', 'not_covered')),
  comparison_case TEXT NOT NULL,
  reason_counts_json TEXT NOT NULL,
  applied_exceptions_json TEXT NOT NULL,
  reason_json TEXT,
  legacy_bytes INTEGER NOT NULL,
  canonical_bytes INTEGER NOT NULL,
  byte_delta INTEGER NOT NULL,
  evaluated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  PRIMARY KEY (scope, instance, generation)
);

CREATE TABLE IF NOT EXISTS legacy_scope_takeover_resets (
  scope TEXT PRIMARY KEY,
  reset_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
`;
const GRANTS_V1 = `
CREATE TABLE pdpp_grant_bindings_schema_version (
  id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL
);
INSERT INTO pdpp_grant_bindings_schema_version VALUES (1, 1);
CREATE TABLE pdpp_grant_bindings (
  pdpp_grant_id TEXT PRIMARY KEY, permission_key TEXT NOT NULL UNIQUE,
  chain_id INTEGER NOT NULL, contract_address TEXT NOT NULL,
  permission_id TEXT NOT NULL, owner_address TEXT NOT NULL,
  grantee_address TEXT NOT NULL, pdpp_client_id TEXT NOT NULL,
  grantee_id TEXT NOT NULL, bound_at TEXT NOT NULL
);`;

function snapshot(db: Database.Database) {
  const schema = db
    .prepare(
      "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name",
    )
    .all() as {
    type: string;
    name: string;
    tbl_name: string;
    sql: string | null;
  }[];
  // Include every table (also sequences, epochs, cursors and writer IDs),
  // not just row counts. Logical idempotence does not mean no WAL activity.
  const tables = schema
    .filter((row) => row.type === "table")
    .map((row) => ({
      name: row.name,
      rows: db
        .prepare('SELECT * FROM "' + row.name.replaceAll('"', '""') + '"')
        .all()
        .map((value) => JSON.stringify(value))
        .sort(),
    }));
  return {
    schema,
    tables,
    userVersion: db.pragma("user_version", { simple: true }),
    schemaVersion: db.pragma("schema_version", { simple: true }),
  };
}

function seedGrant(db: Database.Database) {
  db.exec(GRANTS_V1);
  db.prepare(
    "INSERT INTO pdpp_grant_bindings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
  ).run(
    GRANT.pdppGrantId,
    "14800:0xd54523048add05b4d734afae7c68324ebb7373ef:42",
    PERMISSION.chainId,
    PERMISSION.contractAddress,
    PERMISSION.permissionId,
    GRANT.ownerAddress,
    GRANT.granteeAddress,
    GRANT.pdppClientId,
    GRANT.granteeId,
    GRANT.boundAt,
  );
}

function seedFixture(
  dir: string,
  pdppVersion: 1 | 3 | 15,
  indexVersion: 1 | 14,
) {
  const path = join(dir, "index.db");
  const db = new Database(path);
  const blobs = new Map<string, Buffer>();
  const files = new Map<string, string>();
  const snapshots = {
    [TAKEN_SCOPE]: {
      scope: TAKEN_SCOPE,
      collectedAt: TIME,
      data: { conversations: [{ id: "archived" }] },
    },
  };
  try {
    db.exec(indexVersion === 1 ? INDEX_V1 : INDEX_V14);
    db.pragma("user_version = " + indexVersion);
    db.exec(`
      CREATE TABLE pdpp_schema_version (
        id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL
      );
    `);
    db.prepare("INSERT INTO pdpp_schema_version VALUES (1, ?)").run(
      pdppVersion,
    );
    db.exec(PDPP_V1);
    if (pdppVersion >= 3) db.exec(PDPP_V2_V3);
    if (pdppVersion === 15) {
      db.exec(PDPP_V4_V15);
      db.prepare("INSERT INTO pdpp_store_metadata VALUES (1, ?, ?)").run(
        "historical-epoch",
        Buffer.alloc(32, 1).toString("base64"),
      );
      db.prepare(
        `INSERT INTO pdpp_instance_binding
        (instance, method, generation, reset_clock, source_id, label)
        VALUES (?, 'anthropic-live', 2, 3, ?, 'Work')`,
      ).run(LIVE, "https://registry.pdpp.dev/sources/claude");
      db.prepare(
        "INSERT INTO pdpp_claude_transition VALUES (?, ?, 2, ?, 0)",
      ).run(LIVE, ARCHIVE, JSON.stringify(snapshots));
    }
    seedGrant(db);

    function blob(id: string) {
      const bytes = Buffer.from("retained bytes for " + id);
      blobs.set(id, bytes);
      db.prepare("INSERT INTO pdpp_blobs VALUES (?, 'text/plain', ?, ?)").run(
        id,
        bytes.length,
        createHash("sha256").update(bytes).digest("hex"),
      );
      db.prepare("INSERT INTO pdpp_blob_bytes VALUES (?, ?)").run(id, bytes);
      return { blob_ref: { blob_id: id } };
    }
    let clock = 0;
    function record(instance: string, key: string, data: object, version = 1) {
      db.prepare(
        `INSERT INTO pdpp_records
        (instance, stream, record_key, data, version, emitted_at)
        VALUES (?, 'conversations', ?, ?, ?, ?)`,
      ).run(instance, key, JSON.stringify(data), version, TIME);
      if (pdppVersion >= 3) {
        const id =
          (data as { blob_ref?: { blob_id: string } }).blob_ref?.blob_id ??
          null;
        db.prepare(
          "UPDATE pdpp_records SET blob_id = ? WHERE instance = ? AND record_key = ?",
        ).run(id, instance, key);
      }
    }
    function history(instance: string, key: string, data: object, version = 1) {
      db.prepare(
        `INSERT INTO pdpp_record_changes
        (instance, stream, record_key, version, data, emitted_at, written_at)
        VALUES (?, 'conversations', ?, ?, ?, ?, ?)`,
      ).run(instance, key, version, JSON.stringify(data), TIME, ++clock);
    }
    record(LIVE, "overwritten", { id: "overwritten", text: "latest" }, 2);
    history(LIVE, "overwritten", {
      id: "overwritten",
      ...(pdppVersion >= 3
        ? blob("blob-overwritten-history")
        : { text: "old" }),
    });
    history(LIVE, "overwritten", { id: "overwritten", text: "latest" }, 2);
    if (pdppVersion >= 3) {
      // Deliberately no history/claim for this record: it is independently a GC root.
      record(LIVE, "current-only", {
        id: "current-only",
        ...blob("blob-current"),
      });
      history(LIVE, "history-only", {
        id: "history-only",
        ...blob("blob-history-only"),
      });
      blob("blob-orphan");
    }
    if (pdppVersion === 15) {
      record(ARCHIVE, "archived", {
        id: "archived",
        ...blob("blob-archive-record"),
      });
      history(ARCHIVE, "archived-history-only", {
        id: "archived-history-only",
        ...blob("blob-archive-history"),
      });
      blob("blob-pending-claim");
      blob("blob-archive-claim");
      blob("blob-stale-claim");
      const claim = db.prepare("INSERT INTO pdpp_blob_claims VALUES (?, ?, ?)");
      claim.run("blob-pending-claim", LIVE, 2);
      claim.run("blob-archive-claim", ARCHIVE, 1);
      claim.run("blob-stale-claim", LIVE, 1);
      // A stale claim must not cause its separately retained history to be erased.
      claim.run("blob-overwritten-history", LIVE, 1);
      db.prepare("UPDATE pdpp_records SET emitted_key = ?").run(
        timeSortKey(TIME),
      );
      db.prepare("UPDATE pdpp_record_changes SET emitted_key = ?").run(
        timeSortKey(TIME),
      );
    }
    db.prepare("UPDATE pdpp_write_clock SET value = ?").run(clock);
    for (const scope of [TAKEN_SCOPE, UNTAKEN_SCOPE]) {
      const relativePath = scope.replace(".", "/") + "/old.json";
      const bytes = JSON.stringify({
        scope,
        collectedAt: TIME,
        data: { original: scope },
      });
      files.set(relativePath, bytes);
      mkdirSync(dirname(join(dir, relativePath)), { recursive: true });
      writeFileSync(join(dir, relativePath), bytes);
      db.prepare(
        `INSERT INTO data_files
        (path, scope, collected_at, created_at, size_bytes) VALUES (?, ?, ?, ?, ?)`,
      ).run(relativePath, scope, TIME, TIME, Buffer.byteLength(bytes));
    }
    if (indexVersion === 14) {
      db.prepare("INSERT INTO scope_revisions VALUES (?, 1, ?)").run(
        TAKEN_SCOPE,
        1,
      );
      db.prepare("INSERT INTO scope_revisions VALUES (?, 1, ?)").run(
        UNTAKEN_SCOPE,
        0,
      );
      db.prepare(
        "INSERT INTO legacy_scope_takeovers VALUES (?, ?, 2, 1, 1, ?, ?, ?)",
      ).run(TAKEN_SCOPE, LIVE, TIME, "claude/conversations/old.json", TIME);
      db.prepare(
        `INSERT INTO legacy_scope_takeover_verdicts VALUES
        (?, ?, 2, 1, 'legacy-cursor', 'covered', 'same_time', '{}', '[]', NULL,
         42, 42, 0, ?)`,
      ).run(TAKEN_SCOPE, LIVE, TIME);
    }
    const records = db
      .prepare(
        `SELECT instance, stream, record_key, data, version,
      emitted_at, deleted, deleted_at FROM pdpp_records ORDER BY instance, record_key`,
      )
      .all();
    const historyRows = db
      .prepare(
        `SELECT id, instance, stream, record_key, version,
      data, emitted_at, deleted, deleted_at, written_at FROM pdpp_record_changes ORDER BY id`,
      )
      .all();
    expect(db.pragma("user_version", { simple: true })).toBe(indexVersion);
    expect(db.prepare("SELECT version FROM pdpp_schema_version").get()).toEqual(
      { version: pdppVersion },
    );
    expect(db.prepare("PRAGMA table_info(data_files)").all()).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "pdpp_origin" }),
      ]),
    );
    return { path, blobs, files, snapshots, records, historyRows, clock };
  } finally {
    db.close();
  }
}

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

describe("writable upgrades from historical desktop storage schemas", () => {
  it.each([
    { pdpp: 1, index: 1, label: "oldest nonempty schemas" },
    { pdpp: 3, index: 1, label: "oldest byte-capable schema before claims" },
    {
      pdpp: 15,
      index: 14,
      label: "synthesized archive-capable pre-head schemas",
    },
  ] as const)(
    "$label (PDPP $pdpp / index $index)",
    ({ pdpp, index }) => {
      mkdirSync(join(homedir(), ".tmp"), { recursive: true });
      const dir = mkdtempSync(join(homedir(), ".tmp", "desktop-upgrade-"));
      dirs.push(dir);
      const fixture = seedFixture(dir, pdpp, index);
      let firstSnapshot: ReturnType<typeof snapshot> | undefined;
      for (let open = 0; open < 2; open++) {
        // These are the real writable initializers, including startup GC.
        const db = initializeDatabase(fixture.path);
        try {
          const records = createSqliteRecordStore(db);
          const grants = createSqlitePdppGrantBindingStore(db);
          const authority = createLegacyScopeAuthority(db);
          const manager = createIndexManager(db);
          expect(db.pragma("integrity_check", { simple: true })).toBe("ok");
          expect(db.pragma("foreign_key_check")).toEqual([]);
          // Never-enrolled roots take the converged stamp, not the gate's.
          expect(db.pragma("user_version", { simple: true })).toBe(
            CONVERGED_INDEX_SCHEMA_VERSION,
          );
          expect(
            db.prepare("SELECT version FROM pdpp_schema_version").get(),
          ).toEqual({ version: 25 });
          expect(
            db
              .prepare("SELECT version FROM pdpp_grant_bindings_schema_version")
              .get(),
          ).toEqual({ version: 2 });
          expect(
            db
              .prepare(
                `SELECT instance, stream, record_key, data, version,
          emitted_at, deleted, deleted_at FROM pdpp_records ORDER BY instance, record_key`,
              )
              .all(),
          ).toEqual(fixture.records);
          expect(
            db
              .prepare(
                `SELECT id, instance, stream, record_key, version,
          data, emitted_at, deleted, deleted_at, written_at FROM pdpp_record_changes ORDER BY id`,
              )
              .all(),
          ).toEqual(fixture.historyRows);
          expect(records.transitionWriteClock()).toBe(fixture.clock);
          expect(
            records.getRecord(LIVE, "conversations", "overwritten")?.data,
          ).toEqual({ id: "overwritten", text: "latest" });

          // Enumerate all actual roots, not merely the IDs the fixture expects.
          const referenced = db
            .prepare(
              `
          SELECT CAST(json_extract(data, '$.blob_ref.blob_id') AS TEXT) AS id
            FROM pdpp_records WHERE deleted = 0 AND json_extract(data, '$.blob_ref.blob_id') IS NOT NULL
          UNION SELECT CAST(json_extract(data, '$.blob_ref.blob_id') AS TEXT) AS id
            FROM pdpp_record_changes WHERE json_extract(data, '$.blob_ref.blob_id') IS NOT NULL
          UNION SELECT blob_id AS id FROM pdpp_blob_claims
          ORDER BY id
        `,
            )
            .all() as { id: string }[];
          const retained = [...fixture.blobs.keys()]
            .filter((id) => id !== "blob-orphan" && id !== "blob-stale-claim")
            .sort();
          expect(referenced.map((row) => row.id)).toEqual(retained);
          for (const { id } of referenced) {
            const bytes = records.getBlobBytes(id);
            expect(
              bytes,
              "referenced blob must remain readable: " + id,
            ).toBeDefined();
            expect(Buffer.from(bytes!)).toEqual(fixture.blobs.get(id));
            expect(records.getBlobMeta(id)?.sha256).toBe(
              createHash("sha256").update(fixture.blobs.get(id)!).digest("hex"),
            );
          }
          if (pdpp >= 3) {
            // These negative controls prove the collector really ran.
            expect(records.getBlobBytes("blob-orphan")).toBeUndefined();
            expect(records.getBlobMeta("blob-orphan")).toBeUndefined();
          }
          if (pdpp === 15) {
            expect(records.getBlobBytes("blob-stale-claim")).toBeUndefined();
            expect(
              db
                .prepare("SELECT * FROM pdpp_blob_claims ORDER BY blob_id")
                .all(),
            ).toEqual([
              {
                blob_id: "blob-archive-claim",
                instance: ARCHIVE,
                generation: 1,
              },
              { blob_id: "blob-pending-claim", instance: LIVE, generation: 2 },
            ]);
            // Do NOT call getInstanceBinding(ARCHIVE): that would create a row
            // and hide the archive-GC regression this fixture is meant to catch.
            expect(
              db
                .prepare(
                  "SELECT 1 FROM pdpp_instance_binding WHERE instance = ?",
                )
                .get(ARCHIVE),
            ).toBeUndefined();
            expect(records.claudeTransition(LIVE)).toEqual({
              instance: LIVE,
              archiveInstance: ARCHIVE,
              generation: 2,
              snapshots: fixture.snapshots,
              conversationsCovered: false,
            });
            expect(records.getInstanceBinding(LIVE)).toMatchObject({
              method: "anthropic-live",
              generation: 2,
              label: "Work",
            });
          }

          const legacyGrant = grants.getByPdppGrantId(GRANT.pdppGrantId);
          expect(legacyGrant).toEqual(GRANT);
          expect(grants.getBindingsForPermission(PERMISSION)).toEqual([GRANT]);
          let rejection: unknown;
          try {
            grants.putBinding({ ...GRANT, grantVersion: "1" });
          } catch (error) {
            rejection = error;
          }
          expect(rejection).toMatchObject({
            errorCode: "INVALID_SIGNATURE",
            details: {
              reason:
                "A different binding already exists for this PDPP grant id",
            },
          });
          expect(grants.getByPdppGrantId(GRANT.pdppGrantId)).toEqual(GRANT);

          for (const [path, bytes] of fixture.files) {
            expect(readFileSync(join(dir, path), "utf8")).toBe(bytes);
            const entry = manager.findByPath(path);
            expect(entry).toMatchObject({
              path,
              version: 1,
              casRevision: 1,
              sizeBytes: Buffer.byteLength(bytes),
            });
            // Newly added provenance must remain unknown, never fabricated.
            expect(
              db
                .prepare(
                  "SELECT pdpp_origin, generation FROM data_files WHERE path = ?",
                )
                .get(path),
            ).toEqual({ pdpp_origin: null, generation: null });
            const taken = index === 14 && path.startsWith("claude/");
            expect(manager.isHistoryOnly(entry!.scope, path)).toBe(taken);
          }
          expect(authority.hasTakeover(TAKEN_SCOPE)).toBe(index === 14);
          expect(authority.hasCanonicalAuthority(TAKEN_SCOPE)).toBe(
            index === 14,
          );
          expect(authority.hasTakeover(UNTAKEN_SCOPE)).toBe(false);
          expect(authority.hasCanonicalAuthority(UNTAKEN_SCOPE)).toBe(false);
          if (index === 14) {
            expect(
              db.prepare("SELECT * FROM legacy_scope_takeovers").all(),
            ).toEqual([
              {
                scope: TAKEN_SCOPE,
                instance: LIVE,
                generation: 2,
                method: "",
                superseded_version: 1,
                superseded_cas_revision: 1,
                superseded_collected_at: TIME,
                superseded_path: "claude/conversations/old.json",
                taken_over_at: TIME,
              },
            ]);
            expect(
              db.prepare("SELECT * FROM legacy_scope_takeover_verdicts").all(),
            ).toEqual([
              {
                scope: TAKEN_SCOPE,
                instance: LIVE,
                generation: 2,
                legacy_version_id: 1,
                canonical_cursor: "legacy-cursor",
                verdict: "covered",
                comparison_case: "same_time",
                reason_counts_json: "{}",
                applied_exceptions_json: "[]",
                reason_json: null,
                legacy_bytes: 42,
                canonical_bytes: 42,
                byte_delta: 0,
                evaluated_at: TIME,
              },
            ]);
            expect(
              authority.hasMethodTakeover(TAKEN_SCOPE, "anthropic-live"),
            ).toBe(false);
          }
          const current = snapshot(db);
          if (open === 0) firstSnapshot = current;
          else expect(current).toEqual(firstSnapshot);
        } finally {
          db.close();
        }
      }
    },
    30_000,
  );

  it("keeps an existing client bearer inactive without retained grant-digest evidence", () => {
    mkdirSync(join(homedir(), ".tmp"), { recursive: true });
    const dir = mkdtempSync(join(homedir(), ".tmp", "desktop-upgrade-auth-"));
    dirs.push(dir);
    const authPath = join(dir, "pdpp-auth.db");
    const grant: CoreGrant = {
      version: "0.1.0",
      grant_id: "grant-from-desktop-line",
      issued_at: TIME,
      subject: { id: "owner-1" },
      client: { client_id: "client-1" },
      source: { kind: "connector", id: "source-1" },
      source_declaration: { version: "v1" },
      purpose_code: "purpose-1",
      access_mode: "continuous",
      streams: [
        { name: "records", instance_ids: ["instance-1"], fields: ["id"] },
      ],
    };
    const declarationDocument = JSON.stringify({
      source_id: grant.source.id,
      source_kind: grant.source.kind,
      version: grant.source_declaration.version,
      streams: [
        {
          name: "records",
          fields: ["id"],
          required_fields: ["id"],
          primary_key: ["id"],
        },
      ],
    });
    const declaration = parseDeclaration(declarationDocument, grant.source.id);
    if (!declaration.ok) throw new Error("invalid upgrade grant declaration");
    const reviewDigest = computeReviewDigest({
      subject_id: grant.subject.id,
      client_id: grant.client.client_id,
      source_id: grant.source.id,
      source_kind: grant.source.kind,
      source_declaration_version: grant.source_declaration.version,
      declaration_digest: declaration.snapshot.digest,
      purpose_code: grant.purpose_code,
      access_mode: grant.access_mode,
      streams: grant.streams,
    });
    const code = "desktop-line-auth-code";
    let auth = openPdppAuthStore(authPath);
    const tokens = new PdppTokenService(auth);
    auth.insertGrantWithAuthCode({
      grant,
      subjectId: grant.subject.id,
      reviewDigest,
      consentEvidence: {
        review_digest: reviewDigest,
        grant_digest: computeGrantArtifactDigest(grant),
        approved_at: TIME,
        declaration: {
          source_id: grant.source.id,
          version: grant.source_declaration.version,
          digest: declaration.snapshot.digest,
        },
      },
      declarationSnapshot: declaration.snapshot,
      declarationDocument,
      code,
      authCode: {
        grantId: grant.grant_id,
        clientId: grant.client.client_id,
        redirectUri: "https://client.example/callback",
        codeChallenge: null,
        codeChallengeMethod: null,
        expiresAt: new Date(
          Date.now() + AUTHORIZATION_CODE_TTL_SECONDS * 1000,
        ).toISOString(),
      },
    });
    const redeemed = tokens.redeemAuthorizationCode({
      code,
      clientId: grant.client.client_id,
      redirectUri: "https://client.example/callback",
    });
    expect(redeemed.ok).toBe(true);
    if (!redeemed.ok) return;
    const bearer = redeemed.issued.access_token;
    auth.close();

    // This is the evidence shape a prior build could persist: approval and
    // declaration identity exist, but no digest binds the stored rights.
    const legacyDb = new Database(authPath);
    legacyDb
      .prepare(
        "UPDATE pdpp_grants SET consent_evidence_json = ? WHERE grant_id = ?",
      )
      .run(
        JSON.stringify({
          review_digest: reviewDigest,
          approved_at: TIME,
          declaration: {
            source_id: grant.source.id,
            version: grant.source_declaration.version,
            digest: declaration.snapshot.digest,
          },
        }),
        grant.grant_id,
      );
    legacyDb.close();

    auth = openPdppAuthStore(authPath);
    const upgradedTokens = new PdppTokenService(auth);
    expect(upgradedTokens.resolveToken(bearer)).toMatchObject({
      active: false,
      inactiveReason: "unknown",
    });
    expect(upgradedTokens.introspect(bearer)).toEqual({ active: false });
    auth.close();
  });
});
