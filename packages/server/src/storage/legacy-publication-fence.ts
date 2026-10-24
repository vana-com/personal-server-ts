import type {
  DataPointFeedRecord,
  DataStoragePort,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { StorageAdapter } from "@opendatalabs/personal-server-ts-core/storage/adapters";
import { keccak256, stringToHex } from "viem";
import {
  canonicalJson,
  envelopeGeneration,
} from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import {
  decryptWithPassword,
  deriveScopeKey,
  isTombstoneHashes,
} from "@opendatalabs/vana-sdk/node";
import { classifySyncFailure } from "@opendatalabs/personal-server-ts-core/sync";
import { createHash } from "node:crypto";
import type Database from "better-sqlite3";
import type { IndexEntry } from "@opendatalabs/personal-server-ts-core/storage/index";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";

const optedIn = new WeakSet<Database.Database>();

/** Retention triggers need SQLite REPLACE deletes to fire them. A never-enrolled
 * root keeps the connection default, so its existing triggers behave as before.
 */
export function armLegacyPublicationGate(db: Database.Database): void {
  db.pragma("recursive_triggers = ON");
}

/** The host's explicit `legacyWriteShutdownEnabled` opt-in for this handle.
 * Direct storage stays off unless the host opts in or the root is enrolled.
 */
export function optInLegacyPublicationGate(db: Database.Database): void {
  optedIn.add(db);
  armLegacyPublicationGate(db);
}

/** Durable enrollment history: a policy or transition row in any state,
 * including mirroring after rollback. Gate tables alone are not enrollment.
 */
export function legacyPublicationEnrolled(db: Database.Database): boolean {
  return ["legacy_publication_policy", "legacy_publication_transitions"].some(
    (table) =>
      !!db
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?")
        .get(table) && !!db.prepare(`SELECT 1 FROM ${table} LIMIT 1`).get(),
  );
}

/** Whether gate effects apply. Off, storage and issuance behave as before the
 * gate: no journal writes, producer changes or barrier transactions. Enrolled
 * roots keep their fences and retention even after the flag is disabled.
 */
export function legacyPublicationGateActive(db: Database.Database): boolean {
  return optedIn.has(db) || legacyPublicationEnrolled(db);
}

export function initializeLegacyPublicationPolicy(db: Database.Database): void {
  db.transaction(() => {
    db.exec(`CREATE TABLE IF NOT EXISTS legacy_publication_restorations (
          owner TEXT NOT NULL, server_generation TEXT NOT NULL, scope TEXT NOT NULL, epoch INTEGER NOT NULL,
          receipt_json TEXT NOT NULL, confirmation_json TEXT NOT NULL,
          PRIMARY KEY(owner, server_generation, scope, epoch))`);
    db.exec(`
    CREATE TABLE IF NOT EXISTS legacy_publication_transitions (
      owner TEXT NOT NULL, server_generation TEXT NOT NULL, scope TEXT NOT NULL,
      state TEXT NOT NULL, epoch INTEGER NOT NULL, evidence_json TEXT,
      PRIMARY KEY(owner, server_generation, scope, epoch)
    );
    CREATE TABLE IF NOT EXISTS legacy_publication_policy (
      owner TEXT NOT NULL, server_generation TEXT NOT NULL, scope TEXT NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('mirroring','quiescing','stopped','restoring')),
      epoch INTEGER NOT NULL CHECK(epoch > 0), owner_opt_in INTEGER NOT NULL,
      evidence_json TEXT,
      PRIMARY KEY(owner, server_generation, scope)
    );
    CREATE INDEX IF NOT EXISTS idx_legacy_publication_fence ON legacy_publication_policy(scope, state);
    CREATE TABLE IF NOT EXISTS legacy_publication_retained_versions (
      version_id INTEGER PRIMARY KEY
    );
    CREATE TABLE IF NOT EXISTS legacy_publication_restore_versions (
      version_id INTEGER PRIMARY KEY, owner TEXT NOT NULL, server_generation TEXT NOT NULL,
      epoch INTEGER NOT NULL, operation TEXT NOT NULL, data_hash TEXT NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('current','superseded','confirmed'))
    );
    CREATE TABLE IF NOT EXISTS legacy_publication_issuance (
      id TEXT PRIMARY KEY, owner TEXT NOT NULL, scopes_json TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'grant', message_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS legacy_publication_generation_backfill (
      version_id INTEGER PRIMARY KEY, generation TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS legacy_publication_holds (
      id TEXT PRIMARY KEY, scope TEXT NOT NULL, kind TEXT NOT NULL,
      identity_json TEXT NOT NULL, payload BLOB NOT NULL, created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_legacy_publication_holds_scope ON legacy_publication_holds(scope);
    CREATE TABLE IF NOT EXISTS legacy_publication_restore_publications (
      scope TEXT NOT NULL, operation TEXT NOT NULL, head_generation TEXT NOT NULL,
      version TEXT NOT NULL, data_hash TEXT NOT NULL, metadata_hash TEXT NOT NULL,
      ciphertext_sha256 TEXT NOT NULL,
      PRIMARY KEY(scope, operation)
    );
    CREATE TABLE IF NOT EXISTS legacy_publication_restore_authorization (
      scope TEXT PRIMARY KEY, owner TEXT NOT NULL, server_generation TEXT NOT NULL,
      epoch INTEGER NOT NULL, operation TEXT NOT NULL, authority TEXT NOT NULL, body_sha256 TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS legacy_publication_insert_fence
    BEFORE INSERT ON data_files
    WHEN EXISTS (SELECT 1 FROM legacy_publication_policy WHERE scope = NEW.scope AND state != 'mirroring')
      AND NOT EXISTS (
        SELECT 1 FROM legacy_publication_restore_authorization a
        JOIN legacy_publication_policy p ON p.scope = a.scope AND p.owner = a.owner AND p.server_generation = a.server_generation AND p.epoch = a.epoch AND p.state = 'restoring'
        JOIN owner_import_operations o ON o.scope = a.scope AND o.operation = a.operation AND o.owner = a.owner AND o.authority = a.authority AND o.body_sha256 = a.body_sha256 AND o.path = NEW.path AND o.state = 'prepared'
        WHERE a.scope = NEW.scope
      )
    BEGIN SELECT RAISE(ABORT, 'legacy_scope_retired'); END;
    CREATE TRIGGER IF NOT EXISTS legacy_publication_history_delete_fence
    BEFORE DELETE ON data_files
    WHEN EXISTS (SELECT 1 FROM legacy_publication_retained_versions WHERE version_id = OLD.id)
    BEGIN SELECT RAISE(ABORT, 'legacy_history_retained'); END;
    CREATE TRIGGER IF NOT EXISTS legacy_publication_history_identity_fence
    BEFORE UPDATE OF scope, path, collected_at, generation ON data_files
    WHEN EXISTS (SELECT 1 FROM legacy_publication_retained_versions WHERE version_id = OLD.id)
      AND (NEW.scope != OLD.scope OR NEW.path != OLD.path OR NEW.collected_at != OLD.collected_at OR (NEW.generation IS NOT OLD.generation AND NOT (
        OLD.generation IS NULL AND NEW.generation IS NOT NULL AND EXISTS (
          SELECT 1 FROM legacy_publication_generation_backfill b WHERE b.version_id=OLD.id AND b.generation=NEW.generation
        )
      )))
    BEGIN SELECT RAISE(ABORT, 'legacy_history_retained'); END;
  `);
  }).immediate();
}

export function assertLegacyPublicationAllowed(
  db: Database.Database,
  scope: string,
  restoration?: {
    operation?: string;
    authority?: string;
    bodySha256?: string;
    path?: string;
  },
): void {
  if (
    restoration &&
    db
      .prepare(
        `SELECT 1 FROM legacy_publication_restore_authorization a
    JOIN legacy_publication_policy p ON p.scope=a.scope AND p.owner=a.owner AND p.server_generation=a.server_generation AND p.epoch=a.epoch AND p.state='restoring'
    WHERE a.scope=? AND ((a.operation=? AND a.authority=? AND a.body_sha256=?) OR EXISTS (SELECT 1 FROM owner_import_operations o WHERE o.scope=a.scope AND o.operation=a.operation AND o.owner=a.owner AND o.authority=a.authority AND o.body_sha256=a.body_sha256 AND o.path=? AND o.state='prepared'))`,
      )
      .get(
        scope,
        restoration.operation ?? null,
        restoration.authority ?? null,
        restoration.bodySha256 ?? null,
        restoration.path ?? null,
      )
  )
    return;
  const row = db
    .prepare(
      "SELECT state, epoch FROM legacy_publication_policy WHERE scope = ? AND state != 'mirroring' LIMIT 1",
    )
    .get(scope);
  if (row)
    throw new ProtocolError(
      409,
      "legacy_scope_retired",
      "Legacy publication and issuance are fenced for this exact scope",
      { scope, ...(row as { state: string; epoch: number }) },
    );
}

/** Whether bytes carry an indexed version's exact known identity: its
 * generation, scope and timestamp, and for a replica its registered version
 * and data point. A NULL generation is unknown and never matches.
 */
export function exactVersionIdentity(
  entry: IndexEntry,
  envelope: { scope: string; collectedAt: string } | undefined,
  replica?: { version: number; dataPointId: string | null },
): boolean {
  return (
    !!envelope &&
    !!entry.generation &&
    entry.scope === envelope.scope &&
    entry.collectedAt === envelope.collectedAt &&
    entry.generation === envelopeGeneration(envelope) &&
    (!replica ||
      (replica.version === entry.version &&
        replica.dataPointId === entry.dataPointId))
  );
}

export function isRetainedVersion(
  db: Database.Database,
  versionId: number,
): boolean {
  return !!db
    .prepare(
      "SELECT 1 FROM legacy_publication_retained_versions WHERE version_id=?",
    )
    .get(versionId);
}

/** Identity of a write at an indexed path. A retained version is immutable in
 * every policy state, including mirroring after rollback: only its exact known
 * identity may repair a lost file.
 */
export function retainedVersionIdentity(
  db: Database.Database,
  entry: IndexEntry | undefined,
  envelope: { scope: string; collectedAt: string } | undefined,
  replica?: { version: number; dataPointId: string | null },
): "unretained" | "exact" | "mismatch" {
  if (!entry || !isRetainedVersion(db, entry.id)) return "unretained";
  return exactVersionIdentity(entry, envelope, replica) ? "exact" : "mismatch";
}

/** Refuse a write that does not match a retained version, before any effect.
 * Returns true for an exact repair, which bypasses the publication fence.
 */
export function assertRetainedVersionRepair(
  db: Database.Database,
  entry: IndexEntry | undefined,
  envelope: { scope: string; collectedAt: string },
  replica?: { version: number; dataPointId: string | null },
): boolean {
  const identity = retainedVersionIdentity(db, entry, envelope, replica);
  if (identity === "exact") return true;
  if (identity === "mismatch") throwRetainedMismatch(db, entry!.scope);
  return false;
}

export function throwRetainedMismatch(
  db: Database.Database,
  scope: string,
): never {
  // A fenced scope keeps its retired refusal; otherwise history wins.
  assertLegacyPublicationAllowed(db, scope);
  throw new ProtocolError(
    409,
    "legacy_history_retained",
    "A retained legacy version can be repaired only with its exact known identity",
    { scope },
  );
}

/** Local deletion/drop guard. A fenced scope refuses every deletion, retained
 * or not. Otherwise only retained versions are protected: scope-wide for a
 * scope deletion, or the one targeted version for individual cleanup.
 */
export function assertLegacyHistoryMutable(
  db: Database.Database,
  scope: string,
  versionId?: number,
): void {
  const fenced = legacyPublicationFenced(db, scope);
  const retained =
    versionId === undefined
      ? db
          .prepare(
            `SELECT 1 FROM data_files f JOIN legacy_publication_retained_versions r ON r.version_id = f.id WHERE f.scope = ? LIMIT 1`,
          )
          .get(scope)
      : db
          .prepare(
            "SELECT 1 FROM legacy_publication_retained_versions WHERE version_id = ?",
          )
          .get(versionId);
  if (fenced || retained) {
    throw new ProtocolError(
      409,
      "legacy_history_retained",
      "Shutdown-qualified legacy history must remain readable",
      { scope, fenced },
    );
  }
}

/** Local enforcement complements the trusted retention adapter. Retain the
 * exact input streams, including future revisions, and their historical blobs.
 * This never treats the presence of these tables as proof of qualification.
 */
export function retainCanonicalInputs(
  db: Database.Database,
  inputs: { instance: string; stream: string; generation: number }[],
): void {
  armLegacyPublicationGate(db);
  db.exec(`CREATE TABLE IF NOT EXISTS legacy_publication_canonical_retention (
    instance TEXT NOT NULL, stream TEXT NOT NULL, generation INTEGER NOT NULL,
    PRIMARY KEY(instance, stream, generation))`);
  for (const input of inputs)
    db.prepare(
      "INSERT OR IGNORE INTO legacy_publication_canonical_retention VALUES (?, ?, ?)",
    ).run(input.instance, input.stream, input.generation);
  const hasTable = (name: string) =>
    !!db
      .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?")
      .get(name);
  if (hasTable("pdpp_record_changes"))
    db.exec(`
    CREATE TRIGGER IF NOT EXISTS legacy_canonical_history_delete BEFORE DELETE ON pdpp_record_changes
    WHEN EXISTS (SELECT 1 FROM legacy_publication_canonical_retention r WHERE r.instance=OLD.instance AND r.stream=OLD.stream)
    BEGIN SELECT RAISE(ABORT, 'canonical_history_retained'); END;
    CREATE TRIGGER IF NOT EXISTS legacy_canonical_history_update BEFORE UPDATE ON pdpp_record_changes
    WHEN EXISTS (SELECT 1 FROM legacy_publication_canonical_retention r WHERE r.instance=OLD.instance AND r.stream=OLD.stream)
    BEGIN SELECT RAISE(ABORT, 'canonical_history_retained'); END;
  `);
  if (hasTable("pdpp_blob_claims")) {
    db.exec(`CREATE TRIGGER IF NOT EXISTS legacy_canonical_claim_delete BEFORE DELETE ON pdpp_blob_claims
      WHEN EXISTS (SELECT 1 FROM legacy_publication_canonical_retention r WHERE r.instance=OLD.instance AND r.generation=OLD.generation)
      BEGIN SELECT RAISE(ABORT, 'canonical_history_retained'); END;`);
    for (const table of ["pdpp_blobs", "pdpp_blob_bytes"])
      if (hasTable(table)) {
        for (const event of ["DELETE", "UPDATE"])
          db.exec(`CREATE TRIGGER IF NOT EXISTS legacy_canonical_${table}_${event}
        BEFORE ${event} ON ${table}
        WHEN EXISTS (SELECT 1 FROM pdpp_blob_claims c JOIN legacy_publication_canonical_retention r ON r.instance=c.instance AND r.generation=c.generation WHERE c.blob_id=OLD.blob_id)
        BEGIN SELECT RAISE(ABORT, 'canonical_history_retained'); END;`);
      }
  }
}

export function legacyPublicationFenced(
  db: Database.Database,
  scope: string,
): boolean {
  return !!db
    .prepare(
      "SELECT 1 FROM legacy_publication_policy WHERE scope=? AND state!='mirroring' LIMIT 1",
    )
    .get(scope);
}

export function holdLegacyPublication(
  db: Database.Database,
  scope: string,
  kind: string,
  identity: unknown,
  payload: Uint8Array,
): string {
  const identityJson = JSON.stringify(identity);
  const id = createHash("sha256")
    .update(kind)
    .update(identityJson)
    .update(payload)
    .digest("hex");
  db.prepare(
    "INSERT OR IGNORE INTO legacy_publication_holds VALUES (?, ?, ?, ?, ?, ?)",
  ).run(
    id,
    scope,
    kind,
    identityJson,
    Buffer.from(payload),
    new Date().toISOString(),
  );
  return id;
}

export function canonicalRetentionConflict(
  error: unknown,
): ProtocolError | undefined {
  if (
    error instanceof Error &&
    (error as { code?: string }).code === "SQLITE_CONSTRAINT_TRIGGER" &&
    error.message === "canonical_history_retained"
  )
    return new ProtocolError(
      409,
      "canonical_history_retained",
      "Shutdown-qualified canonical history must remain readable, including after rollback",
    );
  return undefined;
}

/** Capture remote ciphertext before releasing a download page. This is an
 * unresolved foreign change, never evidence of canonical coverage/delivery.
 * `storage` must be the unfenced remote reader: a foreign occupant of a pinned
 * restore key is captured here, while the publisher's fenced reader refuses it.
 */
export function createLegacyDownloadHold(
  db: Database.Database,
  storage: StorageAdapter,
  local?: DataStoragePort,
  masterKey?: Uint8Array,
): (record: DataPointFeedRecord) => Promise<boolean> {
  return async (record) => {
    // The upload worker may have just registered the authorized rollback head.
    // A lost registration response leaves data_point_id NULL (and the local
    // version may differ). The accepted journal and pinned commitments identify
    // our publication independently of that acknowledgement.
    const restoration = db.prepare(
      `SELECT f.generation, f.collected_at, a.body_sha256, a.operation FROM legacy_publication_restore_publications r
      JOIN legacy_publication_restore_authorization a ON a.scope=r.scope AND a.operation=r.operation
      JOIN legacy_publication_policy p ON p.scope=a.scope AND p.owner=a.owner AND p.server_generation=a.server_generation AND p.epoch=a.epoch AND p.state='restoring'
      JOIN owner_import_operations o ON o.scope=a.scope AND o.operation=a.operation AND o.owner=a.owner AND o.authority=a.authority AND o.body_sha256=a.body_sha256 AND o.state='accepted'
      JOIN data_files f ON f.path=o.path AND f.scope=a.scope AND f.generation=r.head_generation
      WHERE r.scope=? AND r.version=? AND r.data_hash=? AND r.metadata_hash=? AND a.owner=?
      AND f.id=(SELECT id FROM data_files WHERE scope=a.scope ORDER BY julianday(collected_at) DESC, id DESC LIMIT 1)
      AND NOT EXISTS (SELECT 1 FROM legacy_publication_policy other WHERE other.scope=a.scope AND other.state!='mirroring' AND (other.owner!=a.owner OR other.server_generation!=a.server_generation))`,
    );
    const currentRestore = () =>
      restoration.get(
        record.scope,
        record.expectedVersion,
        record.dataHash,
        record.metadataHash,
        record.ownerAddress?.toLowerCase() ?? "",
      ) as
        | {
            generation: string;
            collected_at: string;
            body_sha256: string;
            operation: string;
          }
        | undefined;
    // Our pinned publication of a superseded restore: the same owner and
    // serving generation as the restoring policy, its accepted journal row and
    // its retained version, still history-only.
    const superseded = db.prepare(
      `SELECT f.generation, f.collected_at, o.body_sha256, v.operation FROM legacy_publication_restore_publications r
      JOIN legacy_publication_restore_versions v ON v.operation=r.operation AND v.data_hash=r.data_hash AND v.state='superseded'
      JOIN data_files f ON f.id=v.version_id AND f.scope=r.scope AND f.generation=r.head_generation
      JOIN owner_import_operations o ON o.scope=f.scope AND o.operation=v.operation AND o.owner=v.owner AND o.path=f.path AND o.collected_at=f.collected_at AND o.state='accepted'
      JOIN legacy_publication_policy p ON p.scope=f.scope AND p.owner=v.owner AND p.server_generation=v.server_generation AND p.state='restoring'
      WHERE r.scope=? AND r.version=? AND r.data_hash=? AND r.metadata_hash=? AND v.owner=?
      AND NOT EXISTS (SELECT 1 FROM legacy_publication_policy other WHERE other.scope=f.scope AND other.state!='mirroring' AND (other.owner!=v.owner OR other.server_generation!=v.server_generation))`,
    );
    const supersededRestore = () =>
      superseded.get(
        record.scope,
        record.expectedVersion,
        record.dataHash,
        record.metadataHash,
        record.ownerAddress?.toLowerCase() ?? "",
      ) as
        | {
            generation: string;
            collected_at: string;
            body_sha256: string;
            operation: string;
          }
        | undefined;
    const tombstone =
      !!record.deletedAt ||
      isTombstoneHashes(record.dataHash, record.metadataHash);
    const restored = !tombstone && currentRestore();
    if (restored && local) {
      try {
        const envelope = await local.readEnvelope(
          record.scope,
          restored.collected_at,
        );
        if (
          envelopeGeneration(envelope) === restored.generation &&
          keccak256(stringToHex(JSON.stringify(envelope))) ===
            record.dataHash &&
          createHash("sha256")
            .update(canonicalJson(envelope.data))
            .digest("hex") === restored.body_sha256 &&
          currentRestore()?.operation === restored.operation
        )
          return true;
      } catch {
        // An indexed identity alone does not prove its file remains readable.
      }
    }
    const retained = db
      .prepare(
        `SELECT 1 FROM data_files f JOIN legacy_publication_retained_versions r ON r.version_id=f.id WHERE f.scope=? LIMIT 1`,
      )
      .get(record.scope);
    if (!legacyPublicationFenced(db, record.scope) && !(tombstone && retained))
      return false;
    let payload: Uint8Array;
    try {
      payload = tombstone
        ? Buffer.from(JSON.stringify(record))
        : await storage.download(
            storage.urlForKey(`${record.scope}/${record.expectedVersion}`),
          );
    } catch (error) {
      // Only a proven-absent blob (404/410) is a durable disposition. The
      // blocker keeps the record metadata; there are no bytes to preserve.
      const { issue } = classifySyncFailure({
        error,
        fileId: record.id,
        syncRunId: "legacy-publication-hold",
        stage: "download",
        scope: record.scope,
      });
      if (issue.retryable) throw error;
      holdLegacyPublication(
        db,
        record.scope,
        "remote-head-missing-blob",
        {
          record,
          failure: {
            stage: issue.stage,
            errorClass: issue.errorClass,
            disposition: issue.disposition,
          },
        },
        new Uint8Array(0),
      );
      return true;
    }
    if (!tombstone && local && masterKey) {
      let clear: Uint8Array | undefined;
      // The remote bytes decrypt under our scope key to this record's
      // commitments and to a readable local version of the same generation.
      const exactLocalCopy = async (
        collectedAt: string,
        generation: string,
      ) => {
        try {
          clear ??= await decryptWithPassword(
            payload,
            Buffer.from(deriveScopeKey(masterKey, record.scope)).toString(
              "hex",
            ),
          );
          const remote = JSON.parse(new TextDecoder().decode(clear)) as {
            scope: string;
            collectedAt: string;
          };
          const stored = await local.readEnvelope(record.scope, collectedAt);
          if (
            remote.scope === record.scope &&
            remote.collectedAt === collectedAt &&
            envelopeGeneration(remote) === generation &&
            envelopeGeneration(stored) === generation &&
            keccak256(clear) === record.dataHash &&
            keccak256(
              stringToHex(
                JSON.stringify({
                  scope: remote.scope,
                  collectedAt: remote.collectedAt,
                  sizeBytes: payload.byteLength,
                }),
              ),
            ) === record.metadataHash
          )
            return stored;
        } catch {
          // Unknown/missing/corrupt local bytes still need a durable hold.
        }
        return undefined;
      };
      const known = local.findByDataPointId(record.id);
      if (
        known?.scope === record.scope &&
        known.version === Number(record.expectedVersion) &&
        known.generation &&
        (await exactLocalCopy(known.collectedAt, known.generation))
      )
        return true; // Exact retained history already readable locally.
      // A superseded restore of ours whose registration response was lost has
      // no data_point_id and never gets one. The current restore's own
      // registration supersedes it remotely; until then it is our history,
      // not a foreign head. This clears no hold and confirms nothing.
      const own = supersededRestore();
      if (own) {
        const stored = await exactLocalCopy(own.collected_at, own.generation);
        if (
          stored &&
          Buffer.from(clear!).equals(Buffer.from(JSON.stringify(stored))) &&
          createHash("sha256")
            .update(canonicalJson(stored.data))
            .digest("hex") === own.body_sha256 &&
          supersededRestore()?.operation === own.operation
        )
          return true;
      }
    }
    // Keep the disposition even if policy changed during download. The caller
    // already observed the fence; a future recovery must resolve these bytes.
    holdLegacyPublication(
      db,
      record.scope,
      tombstone ? "remote-tombstone" : "remote-head",
      record,
      payload,
    );
    return true;
  };
}
