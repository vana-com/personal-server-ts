/**
 * Persisted PDPP authorization state: declarations, grants, authorization
 * codes, and the token/refresh-family graph.
 *
 * SQLite via better-sqlite3, matching `../storage/index/schema.ts`. The choice
 * is not incidental: three requirements in §7/§9 are atomicity requirements,
 * and a JSON file (the pattern `server/src/token-store.ts` uses for session
 * tokens) cannot express them without a lock of its own.
 *
 *   - §9 AS item 10: a `single_use` grant is consumed *atomically* with first
 *     client-token issuance.
 *   - §9 AS item 19: an authorization code is consumed *atomically* on first
 *     successful redemption; every later redemption fails.
 *   - §9 AS item 20: refresh reuse revokes the family and all linked tokens.
 *
 * Each is implemented as a conditional UPDATE inside a transaction, where the
 * WHERE clause carries the precondition. `changes === 0` then means "someone
 * else won the race", which is the only correct answer — checking state and
 * then writing it would be exactly the TOCTOU bug these items exist to close.
 *
 * Tokens are stored as SHA-256 hashes, never plaintext, so a store dump does
 * not yield usable credentials (§10 "Token security").
 */

import { createHash, randomBytes } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import Database from "better-sqlite3";
import { parseDeclaration } from "./declaration.js";
import { computeGrantArtifactDigest, computeReviewDigest } from "./review.js";
import { hasFiniteExpiration } from "./token-expiry.js";
import type {
  DeclarationSnapshot,
  Grant,
  GrantStatus,
  PdppTokenKind,
} from "./types.js";

/**
 * Persisted-state contract version. §7 "Version layering" and §9 AS item 21
 * require the reader to reject state it cannot validate against a supported
 * contract, and forbid reconstructing missing facts from current config.
 */
export const PDPP_AUTH_STATE_VERSION = 1;

export class UnsupportedAuthStateError extends Error {
  constructor(
    readonly foundVersion: number,
    readonly supportedVersion: number = PDPP_AUTH_STATE_VERSION,
  ) {
    super(
      `Persisted PDPP authorization state is version ${foundVersion}, which this build cannot validate ` +
        `(supports ${supportedVersion}). Migrate from retained facts or require fresh consent; ` +
        `authorization facts must not be reconstructed from current configuration.`,
    );
    this.name = "UnsupportedAuthStateError";
  }
}

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS pdpp_state_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  version INTEGER NOT NULL
);

-- The exact retained declaration snapshot. Keyed by (source_id, version) so a
-- later revision is a new row and never overwrites the snapshot an issued
-- grant was resolved against (§9 AS item 16).
CREATE TABLE IF NOT EXISTS pdpp_declarations (
  source_id TEXT NOT NULL,
  version TEXT NOT NULL,
  digest TEXT NOT NULL,
  snapshot_json TEXT NOT NULL,
  -- The exact retrieved bytes. snapshot_json is the parsed snapshot, so
  -- re-digesting it does not reproduce digest. Without the original document
  -- the retained digest is unverifiable from the store alone, which is the
  -- gap this column closes. Nullable because rows retained before this
  -- column existed have no document to recover; readers must treat NULL as
  -- cannot-verify, never as verified.
  document TEXT,
  retrieved_at TEXT NOT NULL,
  PRIMARY KEY (source_id, version)
);

CREATE TABLE IF NOT EXISTS pdpp_grants (
  grant_id TEXT PRIMARY KEY,
  subject_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  declaration_version TEXT NOT NULL,
  access_mode TEXT NOT NULL CHECK (access_mode IN ('single_use','continuous')),
  grant_json TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT,
  revoked_at TEXT,
  -- Set atomically with first client-token issuance for single_use grants.
  consumed_at TEXT,
  review_digest TEXT NOT NULL,
  -- Consent evidence: the normalized bound claims, kept out of grant_json so
  -- they cannot leak into introspection or RS enforcement (§6 client claims).
  consent_evidence_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_pdpp_grants_subject ON pdpp_grants (subject_id);

CREATE TABLE IF NOT EXISTS pdpp_auth_codes (
  code_hash TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT,
  code_challenge_method TEXT,
  expires_at TEXT NOT NULL,
  redeemed_at TEXT,
  FOREIGN KEY (grant_id) REFERENCES pdpp_grants (grant_id)
);

-- One row per refresh-token family. Rotation supersedes a token within the
-- family; reuse of a superseded token kills the whole family (§9 AS item 20).
CREATE TABLE IF NOT EXISTS pdpp_refresh_families (
  family_id TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL,
  revoked_at TEXT,
  FOREIGN KEY (grant_id) REFERENCES pdpp_grants (grant_id)
);

CREATE TABLE IF NOT EXISTS pdpp_refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  family_id TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  -- Non-null once rotated out. Presenting a superseded token is reuse.
  superseded_at TEXT,
  FOREIGN KEY (family_id) REFERENCES pdpp_refresh_families (family_id)
);

CREATE TABLE IF NOT EXISTS pdpp_access_tokens (
  token_hash TEXT PRIMARY KEY,
  grant_id TEXT,
  subject_id TEXT NOT NULL,
  client_id TEXT,
  token_kind TEXT NOT NULL CHECK (token_kind IN ('owner','client')),
  owner_source_id TEXT,
  owner_instance_ids_json TEXT,
  family_id TEXT,
  issued_at TEXT NOT NULL,
  expires_at TEXT,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_pdpp_access_grant ON pdpp_access_tokens (grant_id);
CREATE INDEX IF NOT EXISTS idx_pdpp_access_family ON pdpp_access_tokens (family_id);
`;

export function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export function newOpaqueToken(prefix: string): string {
  return `${prefix}_${randomBytes(32).toString("hex")}`;
}

export interface StoredGrant {
  grant: Grant;
  subjectId: string;
  clientId: string;
  reviewDigest: string;
  issuedAt: string;
  expiresAt: string | null;
  revokedAt: string | null;
  consumedAt: string | null;
}

export interface AccessTokenRecord {
  tokenHash: string;
  grantId: string | null;
  subjectId: string;
  clientId: string | null;
  tokenKind: PdppTokenKind;
  ownerSourceId: string | null;
  ownerInstanceIds: string[] | null;
  familyId: string | null;
  issuedAt: string;
  expiresAt: string | null;
  revokedAt: string | null;
}

export interface AuthCodeRecord {
  grantId: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string | null;
  codeChallengeMethod: string | null;
  expiresAt: string;
}

interface GrantRow {
  grant_id: string;
  subject_id: string;
  client_id: string;
  source_id: string;
  declaration_version: string;
  access_mode: string;
  grant_json: string;
  issued_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  consumed_at: string | null;
  review_digest: string;
  consent_evidence_json: string | null;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(
  value: Record<string, unknown>,
  allowed: string[],
): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function validDate(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/i.test(
      value,
    ) &&
    Number.isFinite(Date.parse(value))
  );
}

function validTimeBound(value: unknown, type: unknown): value is string {
  if (type === "date") {
    if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
      return false;
    }
    return Number.isFinite(Date.parse(`${value}T00:00:00Z`));
  }
  return validDate(value);
}

function uniqueStrings(value: unknown, allowEmpty = false): value is string[] {
  return (
    Array.isArray(value) &&
    (allowEmpty || value.length > 0) &&
    value.every(nonEmptyString) &&
    new Set(value).size === value.length
  );
}

/** Runtime counterpart to the normative grant shape; persisted JSON is untrusted. */
function isSupportedGrant(value: unknown): value is Grant {
  if (!isObject(value)) return false;
  const v02 = value.version === "0.2.0";
  const candidate = value.version === "0.1.0-candidate";
  if (!(value.version === "0.1.0" || v02 || candidate)) return false;
  const keys = [
    "version",
    "grant_id",
    "issued_at",
    "subject",
    "client",
    "source",
    "source_declaration",
    "purpose_code",
    "purpose_description",
    "access_mode",
    "streams",
    "selection_preset",
    "retention",
    "expires_at",
    ...(v02 ? ["requested"] : []),
  ];
  if (!hasOnlyKeys(value, keys)) return false;
  if (
    !nonEmptyString(value.grant_id) ||
    !validDate(value.issued_at) ||
    !isObject(value.subject) ||
    !hasOnlyKeys(value.subject, ["id"]) ||
    !nonEmptyString(value.subject.id) ||
    !isObject(value.client) ||
    !hasOnlyKeys(value.client, ["client_id", "client_display"]) ||
    !nonEmptyString(value.client.client_id) ||
    !isObject(value.source) ||
    !hasOnlyKeys(value.source, ["kind", "id"]) ||
    !(
      value.source.kind === "connector" ||
      value.source.kind === "provider_native"
    ) ||
    !nonEmptyString(value.source.id) ||
    !isObject(value.source_declaration) ||
    !hasOnlyKeys(value.source_declaration, ["version"]) ||
    !nonEmptyString(value.source_declaration.version) ||
    !nonEmptyString(value.purpose_code) ||
    (value.purpose_description !== undefined &&
      typeof value.purpose_description !== "string") ||
    !(
      value.access_mode === "single_use" || value.access_mode === "continuous"
    ) ||
    !Array.isArray(value.streams) ||
    value.streams.length === 0 ||
    (value.selection_preset !== undefined &&
      !nonEmptyString(value.selection_preset)) ||
    (value.expires_at !== undefined && !validDate(value.expires_at))
  )
    return false;
  if (value.client.client_display !== undefined) {
    const display = value.client.client_display;
    if (
      !isObject(display) ||
      !hasOnlyKeys(display, [
        "name",
        "uri",
        "logo_uri",
        "policy_uri",
        "tos_uri",
      ]) ||
      !nonEmptyString(display.name) ||
      Object.values(display).some((member) => typeof member !== "string")
    )
      return false;
  }
  if (value.retention !== undefined) {
    if (
      !isObject(value.retention) ||
      !hasOnlyKeys(value.retention, ["max_duration", "on_expiry"]) ||
      !nonEmptyString(value.retention.max_duration) ||
      !(
        value.retention.on_expiry === "delete" ||
        value.retention.on_expiry === "anonymize"
      )
    )
      return false;
  }
  const names = new Set<string>();
  for (const stream of value.streams) {
    if (
      !isObject(stream) ||
      !hasOnlyKeys(stream, [
        "name",
        "instance_ids",
        "fields",
        "time_constraint",
        "resources",
        ...(candidate ? ["required_fields"] : []),
      ]) ||
      !nonEmptyString(stream.name) ||
      names.has(stream.name) ||
      !uniqueStrings(stream.instance_ids) ||
      !uniqueStrings(stream.fields) ||
      (stream.resources !== undefined && !uniqueStrings(stream.resources))
    )
      return false;
    names.add(stream.name);
    if (candidate && !uniqueStrings(stream.required_fields, true)) return false;
    if (
      candidate &&
      (stream.required_fields as string[]).some(
        (field) => !(stream.fields as string[]).includes(field),
      )
    )
      return false;
    if (stream.time_constraint !== undefined) {
      const time = stream.time_constraint;
      if (
        !isObject(time) ||
        !hasOnlyKeys(time, ["type", "field", "since", "until"]) ||
        !nonEmptyString(time.field) ||
        (time.type !== undefined &&
          !(time.type === "date" || time.type === "date-time")) ||
        (time.since !== undefined && !validTimeBound(time.since, time.type)) ||
        (time.until !== undefined && !validTimeBound(time.until, time.type)) ||
        (time.since !== undefined &&
          time.until !== undefined &&
          Date.parse(time.since) >= Date.parse(time.until))
      )
        return false;
    }
  }
  if (v02) {
    const requested = value.requested;
    if (
      !isObject(requested) ||
      !hasOnlyKeys(requested, ["streams", "omitted_streams"]) ||
      !Array.isArray(requested.streams) ||
      requested.streams.length === 0 ||
      (requested.omitted_streams !== undefined &&
        !uniqueStrings(requested.omitted_streams, true))
    )
      return false;
    const requestedNames = new Set<string>();
    const optionalNames = new Set<string>();
    for (const requestedStream of requested.streams) {
      if (
        !isObject(requestedStream) ||
        !hasOnlyKeys(requestedStream, [
          "name",
          "necessity",
          "fields",
          "time_range",
          "minimum",
        ]) ||
        !nonEmptyString(requestedStream.name) ||
        requestedNames.has(requestedStream.name) ||
        !(
          requestedStream.necessity === "required" ||
          requestedStream.necessity === "optional"
        ) ||
        !uniqueStrings(requestedStream.fields)
      )
        return false;
      requestedNames.add(requestedStream.name);
      if (requestedStream.necessity === "optional")
        optionalNames.add(requestedStream.name);
      if (requestedStream.time_range !== undefined) {
        const range = requestedStream.time_range;
        if (
          !isObject(range) ||
          !hasOnlyKeys(range, ["since", "until"]) ||
          (range.since !== undefined && !validDate(range.since)) ||
          (range.until !== undefined && !validDate(range.until)) ||
          (range.since !== undefined &&
            range.until !== undefined &&
            Date.parse(range.since) >= Date.parse(range.until))
        )
          return false;
      }
      if (requestedStream.minimum !== undefined) {
        const minimum = requestedStream.minimum;
        if (
          !isObject(minimum) ||
          !hasOnlyKeys(minimum, ["fields", "time_range"]) ||
          (minimum.fields !== undefined && !uniqueStrings(minimum.fields))
        )
          return false;
        if (minimum.time_range !== undefined) {
          const range = minimum.time_range;
          if (
            !isObject(range) ||
            !hasOnlyKeys(range, ["since", "until"]) ||
            !validDate(range.since) ||
            !validDate(range.until) ||
            Date.parse(range.since) >= Date.parse(range.until)
          )
            return false;
        }
      }
    }
    if (
      Array.isArray(requested.omitted_streams) &&
      requested.omitted_streams.some((name) => !optionalNames.has(name))
    )
      return false;
  }
  return true;
}

function isConsentEvidence(value: unknown): value is {
  review_digest: string;
  grant_digest: string;
  approved_at: string;
  declaration: { source_id: string; version: string; digest: string };
  client_claims?: { attributed_to: string; commitments: string[] };
} {
  if (
    !isObject(value) ||
    !nonEmptyString(value.review_digest) ||
    !/^[a-f0-9]{64}$/.test(String(value.grant_digest ?? "")) ||
    !validDate(value.approved_at) ||
    !isObject(value.declaration) ||
    !hasOnlyKeys(value.declaration, ["source_id", "version", "digest"]) ||
    !nonEmptyString(value.declaration.source_id) ||
    !nonEmptyString(value.declaration.version) ||
    !nonEmptyString(value.declaration.digest)
  )
    return false;
  if (value.client_claims !== undefined) {
    return (
      isObject(value.client_claims) &&
      hasOnlyKeys(value.client_claims, ["attributed_to", "commitments"]) &&
      nonEmptyString(value.client_claims.attributed_to) &&
      Array.isArray(value.client_claims.commitments) &&
      value.client_claims.commitments.every((item) => typeof item === "string")
    );
  }
  return true;
}

/**
 * Open (and if needed create) the PDPP authorization store.
 *
 * Rejects a store whose persisted version this build cannot validate, before
 * any caller reads authorization facts out of it. That is §9 AS item 21: the
 * failure is loud and up front, not a silently-degraded read path.
 */
export function openPdppAuthStore(dbPath: string): PdppAuthStore {
  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  // Transactions here express atomicity guarantees; a torn write would defeat
  // exactly the single-use and code-consumption invariants they protect.
  db.pragma("synchronous = FULL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA_SQL);

  // Additive column migration. `CREATE TABLE IF NOT EXISTS` above does not
  // alter an existing table, so a database created before `document` existed
  // still lacks it. Adding a nullable column is backward compatible in both
  // directions: an older build ignores it, and this build treats NULL as
  // "not verifiable from the store" rather than as a failure. That is why
  // this does NOT bump PDPP_AUTH_STATE_VERSION, which would throw
  // UnsupportedAuthStateError and refuse to boot an existing deployment.
  const declarationColumns = db
    .prepare("PRAGMA table_info(pdpp_declarations)")
    .all() as { name: string }[];
  if (!declarationColumns.some((column) => column.name === "document")) {
    db.exec("ALTER TABLE pdpp_declarations ADD COLUMN document TEXT");
  }

  const accessTokenColumns = db
    .prepare("PRAGMA table_info(pdpp_access_tokens)")
    .all() as { name: string }[];
  if (!accessTokenColumns.some((column) => column.name === "owner_source_id")) {
    db.exec("ALTER TABLE pdpp_access_tokens ADD COLUMN owner_source_id TEXT");
  }
  if (
    !accessTokenColumns.some(
      (column) => column.name === "owner_instance_ids_json",
    )
  ) {
    db.exec(
      "ALTER TABLE pdpp_access_tokens ADD COLUMN owner_instance_ids_json TEXT",
    );
  }

  const meta = db
    .prepare("SELECT version FROM pdpp_state_meta WHERE id = 1")
    .get() as { version: number } | undefined;

  if (meta === undefined) {
    db.prepare("INSERT INTO pdpp_state_meta (id, version) VALUES (1, ?)").run(
      PDPP_AUTH_STATE_VERSION,
    );
  } else if (meta.version !== PDPP_AUTH_STATE_VERSION) {
    db.close();
    throw new UnsupportedAuthStateError(meta.version);
  }

  return new PdppAuthStore(db);
}

export class PdppAuthStore {
  constructor(private readonly db: Database.Database) {}

  close(): void {
    this.db.close();
  }

  // -- declarations -------------------------------------------------------

  /**
   * Retain a declaration snapshot, and the exact bytes it was parsed from.
   *
   * Idempotent per (source_id, version): a re-retrieval of the same revision
   * must not disturb the retained facts an issued grant points at, so the
   * first snapshot wins and is never overwritten.
   *
   * The one exception is BACKFILLING `document`. A deployment that retained a
   * version before this column existed has a NULL document, and a plain
   * `DO NOTHING` would leave it NULL forever — the existing row would keep
   * winning on every restart, so the digest would stay unverifiable until the
   * declaration version happened to change. `COALESCE` fills it in once and
   * then never changes it, so backfill happens exactly when it is missing and
   * the retained bytes remain immutable thereafter.
   */
  retainDeclaration(snapshot: DeclarationSnapshot, document?: string): void {
    this.db
      .prepare(
        `INSERT INTO pdpp_declarations
           (source_id, version, digest, snapshot_json, document, retrieved_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (source_id, version) DO UPDATE SET
           document = COALESCE(pdpp_declarations.document, excluded.document)`,
      )
      .run(
        snapshot.source_id,
        snapshot.version,
        snapshot.digest,
        JSON.stringify(snapshot),
        document ?? null,
        new Date().toISOString(),
      );
  }

  getDeclaration(
    sourceId: string,
    version: string,
  ): DeclarationSnapshot | null {
    const row = this.db
      .prepare(
        "SELECT snapshot_json FROM pdpp_declarations WHERE source_id = ? AND version = ?",
      )
      .get(sourceId, version) as { snapshot_json: string } | undefined;
    return row ? (JSON.parse(row.snapshot_json) as DeclarationSnapshot) : null;
  }

  /**
   * The exact retrieved bytes a retained declaration was parsed from.
   *
   * Returns null when this row predates the `document` column and has not been
   * backfilled. A caller MUST treat null as "cannot verify from the store",
   * never as "verified" — the whole point of this accessor is that re-digesting
   * `snapshot_json` would silently produce a different value than the retained
   * `digest`.
   */
  getDeclarationDocument(sourceId: string, version: string): string | null {
    const row = this.db
      .prepare(
        "SELECT document FROM pdpp_declarations WHERE source_id = ? AND version = ?",
      )
      .get(sourceId, version) as { document: string | null } | undefined;
    return row?.document ?? null;
  }

  // -- grants -------------------------------------------------------------

  insertGrant(input: {
    grant: Grant;
    subjectId: string;
    reviewDigest: string;
    /** Normalized bound client claims, retained as consent evidence only. */
    consentEvidence?: unknown;
  }): void {
    const { grant } = input;
    this.db
      .prepare(
        `INSERT INTO pdpp_grants
           (grant_id, subject_id, client_id, source_id, declaration_version,
            access_mode, grant_json, issued_at, expires_at, review_digest,
            consent_evidence_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        grant.grant_id,
        input.subjectId,
        grant.client.client_id,
        grant.source.id,
        grant.source_declaration.version,
        grant.access_mode,
        JSON.stringify(grant),
        grant.issued_at,
        grant.expires_at ?? null,
        input.reviewDigest,
        input.consentEvidence ? JSON.stringify(input.consentEvidence) : null,
      );
  }

  /**
   * Persist an issued grant and its authorization code as one durable unit.
   *
   * An owner approval produces exactly one grant and exactly one redeemable
   * code; there is no meaningful state where one exists without the other.
   * Without this, a failure between the two inserts (disk full, process
   * kill) could leave a grant with no code ever issued for it — and, worse,
   * strand the caller's in-memory approval state with nothing durable to
   * show for it. Wrapping both in one transaction makes the local write
   * atomic: it either lands completely or not at all, so a caller can retry
   * the same approval decision safely on failure.
   */
  insertGrantWithAuthCode(input: {
    grant: Grant;
    subjectId: string;
    reviewDigest: string;
    consentEvidence?: unknown;
    declarationSnapshot?: DeclarationSnapshot;
    declarationDocument?: string;
    code: string;
    authCode: AuthCodeRecord;
  }): void {
    const tx = this.db.transaction(() => {
      if (
        input.declarationSnapshot &&
        input.declarationDocument !== undefined
      ) {
        this.retainDeclaration(
          input.declarationSnapshot,
          input.declarationDocument,
        );
      }
      this.insertGrant({
        grant: input.grant,
        subjectId: input.subjectId,
        reviewDigest: input.reviewDigest,
        consentEvidence: input.consentEvidence,
      });
      this.insertAuthCode(input.code, input.authCode);
    });
    tx();
  }

  getGrant(grantId: string): StoredGrant | null {
    const row = this.db
      .prepare("SELECT * FROM pdpp_grants WHERE grant_id = ?")
      .get(grantId) as GrantRow | undefined;
    if (!row) return null;
    return {
      grant: JSON.parse(row.grant_json) as Grant,
      subjectId: row.subject_id,
      clientId: row.client_id,
      reviewDigest: row.review_digest,
      issuedAt: row.issued_at,
      expiresAt: row.expires_at,
      revokedAt: row.revoked_at,
      consumedAt: row.consumed_at,
    };
  }

  /**
   * Load a grant only when its persisted representation still matches the
   * approved consent artifact and exact retained declaration. Token
   * validation uses this single boundary before returning any rights.
   */
  getValidatedGrant(
    grantId: string,
  ): (StoredGrant & { declarationSnapshot: DeclarationSnapshot }) | null {
    const row = this.db
      .prepare("SELECT * FROM pdpp_grants WHERE grant_id = ?")
      .get(grantId) as GrantRow | undefined;
    if (!row) return null;
    try {
      const value: unknown = JSON.parse(row.grant_json);
      if (!isSupportedGrant(value)) return null;
      const grant = value;
      if (
        grant.grant_id !== row.grant_id ||
        grant.subject.id !== row.subject_id ||
        grant.client.client_id !== row.client_id ||
        grant.source.id !== row.source_id ||
        grant.source_declaration.version !== row.declaration_version ||
        grant.access_mode !== row.access_mode ||
        grant.issued_at !== row.issued_at ||
        (grant.expires_at ?? null) !== row.expires_at
      ) {
        return null;
      }
      if (!row.consent_evidence_json) return null;
      const evidence: unknown = JSON.parse(row.consent_evidence_json);
      if (
        !isConsentEvidence(evidence) ||
        evidence.review_digest !== row.review_digest ||
        evidence.grant_digest !== computeGrantArtifactDigest(grant) ||
        evidence.declaration.source_id !== grant.source.id ||
        evidence.declaration.version !== grant.source_declaration.version
      ) {
        return null;
      }

      const declarationSnapshot = this.getDeclaration(
        evidence.declaration.source_id,
        evidence.declaration.version,
      );
      const document = this.getDeclarationDocument(
        evidence.declaration.source_id,
        evidence.declaration.version,
      );
      if (!declarationSnapshot || document === null) return null;
      const parsedDeclaration = parseDeclaration(
        document,
        evidence.declaration.source_id,
        evidence.declaration.digest,
      );
      if (
        !parsedDeclaration.ok ||
        !isDeepStrictEqual(parsedDeclaration.snapshot, declarationSnapshot) ||
        declarationSnapshot.version !== grant.source_declaration.version
      ) {
        return null;
      }

      const approvedDigest = computeReviewDigest({
        subject_id: grant.subject.id,
        client_id: grant.client.client_id,
        source_id: grant.source.id,
        source_kind: grant.source.kind,
        source_declaration_version: grant.source_declaration.version,
        declaration_digest: evidence.declaration.digest,
        purpose_code: grant.purpose_code,
        purpose_description: grant.purpose_description,
        access_mode: grant.access_mode,
        streams: grant.streams,
        ...(grant.requested?.omitted_streams && {
          omitted_streams: grant.requested.omitted_streams,
        }),
        retention: grant.retention,
        expires_at: grant.expires_at,
        client_claims: evidence.client_claims,
      });
      if (approvedDigest !== row.review_digest) return null;

      return {
        grant,
        declarationSnapshot,
        subjectId: row.subject_id,
        clientId: row.client_id,
        reviewDigest: row.review_digest,
        issuedAt: row.issued_at,
        expiresAt: row.expires_at,
        revokedAt: row.revoked_at,
        consumedAt: row.consumed_at,
      };
    } catch {
      // Corrupt persisted facts are unusable. Never rebuild them from config.
      return null;
    }
  }

  listGrantsForSubject(subjectId: string): StoredGrant[] {
    const rows = this.db
      .prepare(
        "SELECT * FROM pdpp_grants WHERE subject_id = ? ORDER BY issued_at DESC",
      )
      .all(subjectId) as GrantRow[];
    return rows.map((row) => ({
      grant: JSON.parse(row.grant_json) as Grant,
      subjectId: row.subject_id,
      clientId: row.client_id,
      reviewDigest: row.review_digest,
      issuedAt: row.issued_at,
      expiresAt: row.expires_at,
      revokedAt: row.revoked_at,
      consumedAt: row.consumed_at,
    }));
  }

  /**
   * Grant lifecycle (§9 AS item 8). Revoked beats expired: once an owner
   * revokes, that is the fact worth reporting, and it does not become
   * "expired" later just because the clock passed.
   */
  grantStatus(stored: StoredGrant, now: Date = new Date()): GrantStatus {
    if (stored.revokedAt) return "revoked";
    if (stored.expiresAt && Date.parse(stored.expiresAt) <= now.getTime()) {
      return "expired";
    }
    return "active";
  }

  /**
   * Revoke a grant and everything linked to it, in one transaction.
   *
   * §2 of the delivery scope: the AS marks the grant and every linked token
   * family inactive *immediately*. Doing this in one transaction means there
   * is no window where the grant reads revoked but a linked access token still
   * introspects active.
   *
   * Returns false if the grant does not exist or was already revoked, so a
   * double revoke is not reported as a fresh one.
   */
  revokeGrant(grantId: string, now: Date = new Date()): boolean {
    const at = now.toISOString();
    const tx = this.db.transaction((): boolean => {
      const result = this.db
        .prepare(
          "UPDATE pdpp_grants SET revoked_at = ? WHERE grant_id = ? AND revoked_at IS NULL",
        )
        .run(at, grantId);
      if (result.changes === 0) return false;

      this.db
        .prepare(
          "UPDATE pdpp_access_tokens SET revoked_at = ? WHERE grant_id = ? AND revoked_at IS NULL",
        )
        .run(at, grantId);
      this.db
        .prepare(
          "UPDATE pdpp_refresh_families SET revoked_at = ? WHERE grant_id = ? AND revoked_at IS NULL",
        )
        .run(at, grantId);
      return true;
    });
    return tx();
  }

  // -- authorization codes ------------------------------------------------

  insertAuthCode(code: string, record: AuthCodeRecord): void {
    this.db
      .prepare(
        `INSERT INTO pdpp_auth_codes
           (code_hash, grant_id, client_id, redirect_uri, code_challenge,
            code_challenge_method, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        hashToken(code),
        record.grantId,
        record.clientId,
        record.redirectUri,
        record.codeChallenge,
        record.codeChallengeMethod,
        record.expiresAt,
      );
  }

  /**
   * Consume an authorization code atomically (§9 AS item 19).
   *
   * The `redeemed_at IS NULL` predicate lives in the UPDATE, so two concurrent
   * redemptions of the same code cannot both see it unredeemed. Exactly one
   * gets `changes === 1`; the loser gets null and the caller returns
   * `invalid_grant`. An expired code fails the same way, and a replayed code
   * never issues a second token.
   */
  consumeAuthCode(code: string, now: Date = new Date()): AuthCodeRecord | null {
    const hash = hashToken(code);
    const at = now.toISOString();
    const tx = this.db.transaction((): AuthCodeRecord | null => {
      const result = this.db
        .prepare(
          `UPDATE pdpp_auth_codes SET redeemed_at = ?
           WHERE code_hash = ? AND redeemed_at IS NULL AND expires_at > ?`,
        )
        .run(at, hash, at);
      if (result.changes === 0) return null;

      const row = this.db
        .prepare("SELECT * FROM pdpp_auth_codes WHERE code_hash = ?")
        .get(hash) as {
        grant_id: string;
        client_id: string;
        redirect_uri: string;
        code_challenge: string | null;
        code_challenge_method: string | null;
        expires_at: string;
      };
      return {
        grantId: row.grant_id,
        clientId: row.client_id,
        redirectUri: row.redirect_uri,
        codeChallenge: row.code_challenge,
        codeChallengeMethod: row.code_challenge_method,
        expiresAt: row.expires_at,
      };
    });
    return tx();
  }

  // -- tokens -------------------------------------------------------------

  /**
   * Consume a `single_use` grant atomically with the first client access token
   * (§9 AS item 10 / §7 access modes).
   *
   * Both the consumption and the token insert happen in one transaction with
   * the precondition in the UPDATE's WHERE clause, so a second concurrent
   * issuance attempt finds `changes === 0` and issues nothing. A `continuous`
   * grant skips the consume step and may issue repeatedly.
   *
   * Returns false when the grant was already consumed — the caller maps that
   * to `invalid_grant`. Note §7: the RS still honors tokens already issued
   * against a consumed grant until they expire or are revoked; consumption
   * blocks *new* token issuance, not use of the existing token.
   */
  issueAccessToken(input: {
    token: string;
    grantId: string | null;
    subjectId: string;
    clientId: string | null;
    tokenKind: PdppTokenKind;
    ownerSourceId?: string | null;
    ownerInstanceIds?: string[] | null;
    familyId?: string | null;
    expiresAt: string | null;
    /** Enforce single-use consumption as part of this issuance. */
    consumeSingleUse: boolean;
    now?: Date;
  }): boolean {
    if (input.tokenKind === "client" && !hasFiniteExpiration(input.expiresAt)) {
      throw new Error("Client access tokens require a finite expiration");
    }
    const now = input.now ?? new Date();
    const at = now.toISOString();

    const tx = this.db.transaction((): boolean => {
      if (input.consumeSingleUse) {
        if (!input.grantId) return false;
        const consumed = this.db
          .prepare(
            `UPDATE pdpp_grants SET consumed_at = ?
             WHERE grant_id = ? AND consumed_at IS NULL
               AND access_mode = 'single_use' AND revoked_at IS NULL`,
          )
          .run(at, input.grantId);
        if (consumed.changes === 0) return false;
      }

      this.db
        .prepare(
          `INSERT INTO pdpp_access_tokens
             (token_hash, grant_id, subject_id, client_id, token_kind, owner_source_id,
              owner_instance_ids_json, family_id, issued_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          hashToken(input.token),
          input.grantId,
          input.subjectId,
          input.clientId,
          input.tokenKind,
          input.ownerSourceId ?? null,
          input.ownerInstanceIds
            ? JSON.stringify(input.ownerInstanceIds)
            : null,
          input.familyId ?? null,
          at,
          input.expiresAt,
        );
      return true;
    });
    return tx();
  }

  getAccessToken(token: string): AccessTokenRecord | null {
    const row = this.db
      .prepare("SELECT * FROM pdpp_access_tokens WHERE token_hash = ?")
      .get(hashToken(token)) as
      | {
          token_hash: string;
          grant_id: string | null;
          subject_id: string;
          client_id: string | null;
          token_kind: PdppTokenKind;
          owner_source_id: string | null;
          owner_instance_ids_json: string | null;
          family_id: string | null;
          issued_at: string;
          expires_at: string | null;
          revoked_at: string | null;
        }
      | undefined;
    if (!row) return null;
    return {
      tokenHash: row.token_hash,
      grantId: row.grant_id,
      subjectId: row.subject_id,
      clientId: row.client_id,
      tokenKind: row.token_kind,
      ownerSourceId: row.owner_source_id,
      ownerInstanceIds: row.owner_instance_ids_json
        ? (JSON.parse(row.owner_instance_ids_json) as string[])
        : null,
      familyId: row.family_id,
      issuedAt: row.issued_at,
      expiresAt: row.expires_at,
      revokedAt: row.revoked_at,
    };
  }

  // -- refresh families ---------------------------------------------------

  createRefreshFamily(grantId: string): string {
    const familyId = `rfam_${randomBytes(16).toString("hex")}`;
    this.db
      .prepare(
        "INSERT INTO pdpp_refresh_families (family_id, grant_id) VALUES (?, ?)",
      )
      .run(familyId, grantId);
    return familyId;
  }

  insertRefreshToken(
    token: string,
    familyId: string,
    now: Date = new Date(),
  ): void {
    this.db
      .prepare(
        "INSERT INTO pdpp_refresh_tokens (token_hash, family_id, issued_at) VALUES (?, ?, ?)",
      )
      .run(hashToken(token), familyId, now.toISOString());
  }

  /**
   * Rotate a refresh token, detecting reuse (§9 AS item 20).
   *
   * Three outcomes:
   *   - `{ ok: true }`: the presented token was current; it is superseded and
   *     the caller issues a replacement in the same family.
   *   - `{ ok: false, reason: "reuse_detected" }`: the token was already
   *     superseded. The family and every family-linked access token are
   *     revoked here, atomically, before returning. The caller returns
   *     `invalid_grant` and the client must obtain fresh authorization.
   *   - `{ ok: false, reason: "unknown" | "family_revoked" }`: nothing to
   *     rotate.
   *
   * Reuse revoking the family is the whole point: an attacker who replays a
   * stolen refresh token and a legitimate client who replays after a dropped
   * response are indistinguishable, so the safe response is to kill both and
   * force a fresh grant-backed authorization.
   */
  rotateRefreshToken(
    presented: string,
    now: Date = new Date(),
  ):
    | { ok: true; familyId: string; grantId: string }
    | { ok: false; reason: "unknown" | "reuse_detected" | "family_revoked" } {
    const hash = hashToken(presented);
    const at = now.toISOString();

    const tx = this.db.transaction(() => {
      const row = this.db
        .prepare(
          `SELECT t.token_hash, t.family_id, t.superseded_at,
                  f.revoked_at AS family_revoked_at, f.grant_id
           FROM pdpp_refresh_tokens t
           JOIN pdpp_refresh_families f ON f.family_id = t.family_id
           WHERE t.token_hash = ?`,
        )
        .get(hash) as
        | {
            family_id: string;
            superseded_at: string | null;
            family_revoked_at: string | null;
            grant_id: string;
          }
        | undefined;

      if (!row) return { ok: false as const, reason: "unknown" as const };

      if (row.family_revoked_at) {
        return { ok: false as const, reason: "family_revoked" as const };
      }

      if (row.superseded_at) {
        // Reuse. Burn the family and every access token issued under it.
        this.db
          .prepare(
            "UPDATE pdpp_refresh_families SET revoked_at = ? WHERE family_id = ?",
          )
          .run(at, row.family_id);
        this.db
          .prepare(
            `UPDATE pdpp_access_tokens SET revoked_at = ?
             WHERE family_id = ? AND revoked_at IS NULL`,
          )
          .run(at, row.family_id);
        return { ok: false as const, reason: "reuse_detected" as const };
      }

      this.db
        .prepare(
          "UPDATE pdpp_refresh_tokens SET superseded_at = ? WHERE token_hash = ?",
        )
        .run(at, hash);
      return {
        ok: true as const,
        familyId: row.family_id,
        grantId: row.grant_id,
      };
    });

    return tx();
  }

  /** Revoke one access token. Returns false if unknown or already revoked. */
  revokeAccessToken(token: string, now: Date = new Date()): boolean {
    const result = this.db
      .prepare(
        "UPDATE pdpp_access_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
      )
      .run(now.toISOString(), hashToken(token));
    return result.changes > 0;
  }

  isFamilyRevoked(familyId: string): boolean {
    const row = this.db
      .prepare(
        "SELECT revoked_at FROM pdpp_refresh_families WHERE family_id = ?",
      )
      .get(familyId) as { revoked_at: string | null } | undefined;
    return row ? row.revoked_at !== null : true;
  }
}
