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
import Database from "better-sqlite3";
import {
  HistoryRecorder,
  PendingActionJournal,
  type AnchorEvidence,
  type AnchorIo,
  type AnchoredElection,
  type AnchoredErasure,
  type PendingJournalIo,
} from "./history.js";
import {
  LifecycleRecords,
  STOP_USE_BOUND_MS,
  type ErasureInstructionRecord,
} from "./lifecycle-store.js";
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

-- AS item 25 / spec-core L2785: a \`pdpp_disposition\` conveyed on an RFC 7009
-- revocation with current client authentication, recorded in the same
-- transaction as the revocation it rides on (L2787: "before, or atomically
-- with"). Append-only: a matching retry inserts nothing, so clocks never move.
-- A recorded \`delete\` also creates the grant's erasure instruction in the
-- same transaction (L2785, L1612; see lifecycle-store.ts).
CREATE TABLE IF NOT EXISTS pdpp_revocation_dispositions (
  grant_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  disposition TEXT NOT NULL CHECK (disposition IN ('keep','delete')),
  reported_at TEXT,
  credential TEXT NOT NULL CHECK (credential IN ('access_token','refresh_token')),
  recorded_at TEXT NOT NULL,
  FOREIGN KEY (grant_id) REFERENCES pdpp_grants (grant_id)
);
CREATE INDEX IF NOT EXISTS idx_pdpp_dispositions_grant ON pdpp_revocation_dispositions (grant_id);
-- Design 2 (Vana-6.1 / 6.2): the chain registration of each PDPP grant. Written
-- in the same transaction as the grant when the deployment enforces chain
-- permissions, so a grant never exists without its registration state. The
-- salt is the secret that keeps the grant terms off the public chain; it must
-- never be logged. status: pending (not yet on the gateway) -> bound (entry
-- registered; reads are chain-checked) -> ending (removal owed) -> ended.
CREATE TABLE IF NOT EXISTS pdpp_chain_registrations (
  grant_id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  grantee_address TEXT NOT NULL,
  salt TEXT NOT NULL,
  entry TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK (status IN ('pending','bound','ending','ended')),
  chain_id INTEGER,
  contract_address TEXT,
  permission_id TEXT,
  grantee_id TEXT,
  registered_version TEXT,
  ended_version TEXT,
  -- how the entry leaves the slot: 'removal' (removal-only upsert keeping the
  -- other entries) or 'revocation' (V2 revocation: the slot holds nothing else)
  ending_kind TEXT CHECK (ending_kind IN ('removal','revocation')),
  -- when the PS began deferring its write for this slot because another
  -- surface's registration is still settling there (bounded)
  deferred_since TEXT,
  last_error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (grant_id) REFERENCES pdpp_grants (grant_id)
);
-- AS item 29 / spec-core L1427-L1435, L2004: the pairwise instance handle
-- each client receives for one of the subject's instances. Random, assigned
-- once per (subject, client, instance), never reassigned (UNIQUE), so it
-- names one instance across all sources for that client. Recorded before any
-- grant or record discloses it (L1824). The stored grant keeps the internal
-- instance ids the RS enforces with; clients see these handles.
CREATE TABLE IF NOT EXISTS pdpp_pairwise_instances (
  subject_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  instance_id TEXT NOT NULL,
  handle TEXT NOT NULL UNIQUE,
  assigned_at TEXT NOT NULL,
  PRIMARY KEY (subject_id, client_id, instance_id)
);
-- AS item 29 / spec-core L1427-L1435: the pairwise subject identifier each
-- client receives as grant \`subject.id\`. Random (so no client can reverse it
-- to the internal subject or to another client's value), assigned once per
-- (subject, client) and never changed or reassigned. Recorded in the history
-- log before any grant discloses it (L1824).
CREATE TABLE IF NOT EXISTS pdpp_pairwise_subjects (
  subject_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  pairwise_id TEXT NOT NULL UNIQUE,
  assigned_at TEXT NOT NULL,
  PRIMARY KEY (subject_id, client_id)
);
CREATE INDEX IF NOT EXISTS idx_pdpp_access_family ON pdpp_access_tokens (family_id);
`;

/** A grant with each stream's instance ids replaced through `handles`. */
export function translateGrantInstances(
  grant: Grant,
  handles: Record<string, string> | Map<string, string>,
): Grant {
  const get = (i: string) =>
    handles instanceof Map ? handles.get(i) : handles[i];
  return {
    ...grant,
    streams: grant.streams.map((stream) => ({
      ...stream,
      instance_ids: stream.instance_ids.map((i) => {
        const handle = get(i);
        if (!handle) throw new Error("no pairwise handle for a grant instance");
        return handle;
      }),
    })),
  };
}

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

/** Design 2: one PDPP grant's chain registration (see the table comment). */
export interface ChainRegistration {
  grantId: string;
  clientId: string;
  granteeAddress: string;
  salt: string;
  entry: string;
  status: "pending" | "bound" | "ending" | "ended";
  chainId: number | null;
  contractAddress: string | null;
  permissionId: string | null;
  granteeId: string | null;
  registeredVersion: string | null;
  endedVersion: string | null;
  endingKind: "removal" | "revocation" | null;
  deferredSince: string | null;
  lastError: string | null;
  createdAt: string;
  updatedAt: string;
}

interface ChainRegistrationRow {
  grant_id: string;
  client_id: string;
  grantee_address: string;
  salt: string;
  entry: string;
  status: ChainRegistration["status"];
  chain_id: number | null;
  contract_address: string | null;
  permission_id: string | null;
  grantee_id: string | null;
  registered_version: string | null;
  ended_version: string | null;
  ending_kind: "removal" | "revocation" | null;
  deferred_since: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

function chainRegistrationFromRow(row: ChainRegistrationRow): ChainRegistration {
  return {
    grantId: row.grant_id,
    clientId: row.client_id,
    granteeAddress: row.grantee_address,
    salt: row.salt,
    entry: row.entry,
    status: row.status,
    chainId: row.chain_id,
    contractAddress: row.contract_address,
    permissionId: row.permission_id,
    granteeId: row.grantee_id,
    registeredVersion: row.registered_version,
    endedVersion: row.ended_version,
    endingKind: row.ending_kind,
    deferredSince: row.deferred_since,
    lastError: row.last_error,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
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
  grant_json: string;
  issued_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  consumed_at: string | null;
  review_digest: string;
}

/**
 * Open (and if needed create) the PDPP authorization store.
 *
 * Rejects a store whose persisted version this build cannot validate, before
 * any caller reads authorization facts out of it. That is §9 AS item 21: the
 * failure is loud and up front, not a silently-degraded read path.
 */
export interface OpenPdppAuthStoreOptions {
  /**
   * The lifecycle-durability anchor file (history.ts). Defaults to
   * `<dbPath>.history-anchor.json`; null disables restore detection. An
   * in-memory database has no anchor.
   */
  anchorPath?: string | null;
  /** Owner actions accepted while the history is unavailable (L1827). */
  pendingJournalPath?: string | null;
  anchorIo?: AnchorIo;
  pendingJournalIo?: PendingJournalIo;
}

export function openPdppAuthStore(
  dbPath: string,
  options: OpenPdppAuthStoreOptions = {},
): PdppAuthStore {
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

  // Additive: a registrations table created before `deferred_since`.
  const registrationColumns = db
    .prepare("PRAGMA table_info(pdpp_chain_registrations)")
    .all() as { name: string }[];
  if (!registrationColumns.some((column) => column.name === "deferred_since")) {
    db.exec(
      "ALTER TABLE pdpp_chain_registrations ADD COLUMN deferred_since TEXT",
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

  const inMemory = dbPath === ":memory:" || dbPath === "";
  const anchorPath =
    options.anchorPath !== undefined
      ? options.anchorPath
      : inMemory
        ? null
        : `${dbPath}.history-anchor.json`;
  const journalPath =
    options.pendingJournalPath !== undefined
      ? options.pendingJournalPath
      : inMemory
        ? null
        : `${dbPath}.pending-owner-actions.jsonl`;
  const history = new HistoryRecorder(db, anchorPath, options.anchorIo);
  const journal = new PendingActionJournal(
    journalPath,
    options.pendingJournalIo,
  );
  const store = new PdppAuthStore(db, history, journal);
  // F1/F3: a current history whose anchor lags the database owes an advance,
  // written now (or before the next acknowledgement).
  history.catchUp(new Date().toISOString());
  return store;
}

/** How a grant ended, for the owner surface (L1572). */
export type GrantEndingReason =
  | "owner_withdrawal"
  | "client_revocation"
  | "client_erasure"
  | "erasure_request"
  | "security"
  | "history_restore";

/** Token digests the anchor keeps per erased grant (newest first, then sorted). */
export const MAX_ANCHORED_TOKEN_DIGESTS = 64;

export class PdppAuthStore {
  readonly lifecycle: LifecycleRecords;

  constructor(
    private readonly db: Database.Database,
    readonly history: HistoryRecorder = new HistoryRecorder(db, null),
    readonly pendingActions: PendingActionJournal = new PendingActionJournal(
      null,
    ),
  ) {
    this.lifecycle = new LifecycleRecords(db, history);
    history.setEvidenceProvider((now) => this.anchorEvidence(new Date(now)));
  }

  /**
   * The anchor's evidence, derived from the tables at every advance (F2-F4):
   * every effective instruction with its grant-ending facts, subject and
   * token digests; every advance election; every token digest disabled for
   * lifecycle use; and erasures restored for grants a restore lost.
   */
  anchorEvidence(now: Date = new Date()): AnchorEvidence {
    const erasures: Record<string, AnchoredErasure> = {};
    const elections: Record<string, AnchoredElection> = {};
    for (const i of this.lifecycle.listInstructions()) {
      if (!i.effectiveAt) {
        elections[i.grantId] = {
          grant_id: i.grantId,
          client_id: i.clientId,
          instruction_id: i.instructionId,
          accepted_at: i.acceptedAt,
          advance: true,
          ...(this.getGrant(i.grantId) && {
            subject_id: this.getGrant(i.grantId)!.subjectId,
          }),
        };
        continue;
      }
      const stored = this.getGrant(i.grantId);
      const ending = stored
        ? this.endingOf(
            stored,
            new Date(Math.max(now.getTime(), Date.parse(i.effectiveAt))),
          )
        : null;
      erasures[i.grantId] = {
        grant_id: i.grantId,
        client_id: i.clientId,
        instruction_id: i.instructionId,
        accepted_at: i.acceptedAt,
        effective_at: i.effectiveAt,
        stop_use_by: new Date(
          Date.parse(i.effectiveAt) + STOP_USE_BOUND_MS,
        ).toISOString(),
        read_state: ending?.readState ?? "revoked",
        ended_at: ending?.endedAt ?? i.effectiveAt,
        ...(stored && { subject_id: stored.subjectId }),
        // Bounded (extra item): none once the client reported completion
        // (nothing is left to deliver), otherwise the newest
        // MAX_ANCHORED_TOKEN_DIGESTS tokens issued for the grant. The tokens
        // a client still holds are its newest ones.
        token_digests: i.completedReportedAt
          ? []
          : this.lifecycle
              .recentTokenDigestsFor(
                i.clientId,
                i.grantId,
                MAX_ANCHORED_TOKEN_DIGESTS,
              )
              .sort(),
      };
    }
    for (const o of this.lifecycle.listOrphanErasures()) {
      erasures[o.grant_id] ??= o;
    }
    return {
      erasures,
      elections,
      disabled_digests: this.lifecycle.listDisabledDigests().sort(),
    };
  }

  /**
   * Run `fn` as one transaction, then advance the durability evidence before
   * the caller can acknowledge anything (L1816, L1823). Nested calls join the
   * outer transaction and leave the advance to it.
   */
  commit<T>(fn: () => T, now: Date = new Date()): T {
    if (this.db.inTransaction) return fn();
    let result: T;
    try {
      result = this.db.transaction(fn)();
    } catch (err) {
      this.history.discardPending();
      throw err;
    }
    this.history.markCommitted();
    this.history.advance(now.toISOString());
    return result;
  }

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

  // -- pairwise identifiers (AS item 29) -----------------------------------

  /**
   * The pairwise `subject.id` for this subject and client, assigning one on
   * first use. Idempotent: the same pair always yields the same value, and a
   * value is never given to another pair (UNIQUE). The value is 32 random
   * bytes, so it carries nothing a client could reverse.
   */
  pairwiseSubjectId(
    subjectId: string,
    clientId: string,
    now: Date = new Date(),
  ): string {
    const existing = this.findPairwiseSubjectId(subjectId, clientId);
    if (existing) return existing;
    return this.commit(() => {
      const raced = this.findPairwiseSubjectId(subjectId, clientId);
      if (raced) return raced;
      const pairwiseId = `pws_${randomBytes(32).toString("base64url")}`;
      const at = now.toISOString();
      this.db
        .prepare(
          `INSERT INTO pdpp_pairwise_subjects
             (subject_id, client_id, pairwise_id, assigned_at)
           VALUES (?, ?, ?, ?)`,
        )
        .run(subjectId, clientId, pairwiseId, at);
      // L1824: assignment of a pairwise identifier is a recorded event.
      this.history.append(
        "pairwise_subject_assigned",
        null,
        { client_id: clientId },
        at,
      );
      return pairwiseId;
    }, now);
  }

  /**
   * Assign (once) the pairwise handle of each instance for this client, in
   * one transaction with its history event. Returns internal → handle.
   */
  assignPairwiseInstanceHandles(
    subjectId: string,
    clientId: string,
    instances: readonly string[],
    now: Date = new Date(),
  ): Map<string, string> {
    const missing = [...new Set(instances)].filter(
      (i) => this.findInstanceHandle(subjectId, clientId, i) === null,
    );
    if (missing.length > 0) {
      this.commit(() => {
        const at = now.toISOString();
        let assigned = 0;
        for (const instance of missing) {
          if (this.findInstanceHandle(subjectId, clientId, instance)) continue;
          this.db
            .prepare(
              `INSERT INTO pdpp_pairwise_instances
                 (subject_id, client_id, instance_id, handle, assigned_at)
               VALUES (?, ?, ?, ?, ?)`,
            )
            .run(
              subjectId,
              clientId,
              instance,
              `pwi_${randomBytes(32).toString("base64url")}`,
              at,
            );
          assigned++;
        }
        // L1824: assignment of a pairwise identifier is a recorded event.
        if (assigned > 0)
          this.history.append(
            "pairwise_instance_assigned",
            null,
            { client_id: clientId, count: assigned },
            at,
          );
      }, now);
    }
    const out = new Map<string, string>();
    for (const instance of instances) {
      const handle = this.findInstanceHandle(subjectId, clientId, instance);
      if (handle) out.set(instance, handle);
    }
    return out;
  }

  findInstanceHandle(
    subjectId: string,
    clientId: string,
    instanceId: string,
  ): string | null {
    const row = this.db
      .prepare(
        `SELECT handle FROM pdpp_pairwise_instances
         WHERE subject_id = ? AND client_id = ? AND instance_id = ?`,
      )
      .get(subjectId, clientId, instanceId) as { handle: string } | undefined;
    return row?.handle ?? null;
  }

  /** The internal instance behind this client's handle, or null. */
  instanceForHandle(
    subjectId: string,
    clientId: string,
    handle: string,
  ): string | null {
    const row = this.db
      .prepare(
        `SELECT instance_id FROM pdpp_pairwise_instances
         WHERE subject_id = ? AND client_id = ? AND handle = ?`,
      )
      .get(subjectId, clientId, handle) as { instance_id: string } | undefined;
    return row?.instance_id ?? null;
  }

  /**
   * internal instance → this client's handle, for every instance of a grant
   * issued with pairwise handles; undefined for a grant issued before them
   * (its document is immutable and keeps the ids it was issued with).
   */
  clientInstanceHandles(stored: StoredGrant): Record<string, string> | undefined {
    const evidence = this.getConsentEvidence(stored.grant.grant_id);
    if (evidence?.instance_handles !== "pairwise") return undefined;
    const out: Record<string, string> = {};
    for (const stream of stored.grant.streams)
      for (const instance of stream.instance_ids) {
        const handle = this.findInstanceHandle(
          stored.subjectId,
          stored.clientId,
          instance,
        );
        // Assigned before the grant was stored; a missing row is corrupt
        // state and must not fall back to disclosing the internal id.
        if (!handle)
          throw new Error(
            `pairwise handle missing for an instance of grant ${stored.grant.grant_id}`,
          );
        out[instance] = handle;
      }
    return out;
  }

  /** The grant document as the client receives it (pairwise handles). */
  clientGrantView(stored: StoredGrant): Grant {
    const handles = this.clientInstanceHandles(stored);
    return handles
      ? translateGrantInstances(stored.grant, handles)
      : stored.grant;
  }

  /** The assigned pairwise `subject.id`, or null when none was assigned. */
  findPairwiseSubjectId(subjectId: string, clientId: string): string | null {
    const row = this.db
      .prepare(
        `SELECT pairwise_id FROM pdpp_pairwise_subjects
         WHERE subject_id = ? AND client_id = ?`,
      )
      .get(subjectId, clientId) as { pairwise_id: string } | undefined;
    return row?.pairwise_id ?? null;
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
    this.commit(() => {
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
      // L1824: grant issuance and grant_id assignment are recorded events.
      this.history.append(
        "grant_issued",
        grant.grant_id,
        { client_id: grant.client.client_id },
        grant.issued_at,
      );
    });
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
    code: string;
    authCode: AuthCodeRecord;
    /**
     * Design 2: the pending chain registration, written in the same
     * transaction so a chain-enforced grant always has one (the read gate
     * denies a grant with none).
     */
    chainRegistration?: {
      granteeAddress: string;
      salt: string;
      entry: string;
    };
  }): void {
    this.commit(() => {
      this.insertGrant({
        grant: input.grant,
        subjectId: input.subjectId,
        reviewDigest: input.reviewDigest,
        consentEvidence: input.consentEvidence,
      });
      if (input.chainRegistration) {
        const at = input.grant.issued_at;
        this.db
          .prepare(
            `INSERT INTO pdpp_chain_registrations
               (grant_id, client_id, grantee_address, salt, entry, status,
                created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)`,
          )
          .run(
            input.grant.grant_id,
            input.grant.client.client_id,
            input.chainRegistration.granteeAddress,
            input.chainRegistration.salt,
            input.chainRegistration.entry,
            at,
            at,
          );
      }
      this.insertAuthCode(input.code, input.authCode);
    });
  }

  /** The retained consent evidence of a grant, parsed; null when none. */
  getConsentEvidence(grantId: string): Record<string, unknown> | null {
    const row = this.db
      .prepare("SELECT consent_evidence_json FROM pdpp_grants WHERE grant_id = ?")
      .get(grantId) as { consent_evidence_json: string | null } | undefined;
    if (!row?.consent_evidence_json) return null;
    try {
      const parsed: unknown = JSON.parse(row.consent_evidence_json);
      return parsed && typeof parsed === "object"
        ? (parsed as Record<string, unknown>)
        : null;
    } catch {
      return null;
    }
  }

  // -- design-2 chain registrations ----------------------------------------

  getChainRegistration(grantId: string): ChainRegistration | null {
    const row = this.db
      .prepare("SELECT * FROM pdpp_chain_registrations WHERE grant_id = ?")
      .get(grantId) as ChainRegistrationRow | undefined;
    return row ? chainRegistrationFromRow(row) : null;
  }

  listChainRegistrations(
    statuses: ChainRegistration["status"][],
  ): ChainRegistration[] {
    if (statuses.length === 0) return [];
    const rows = this.db
      .prepare(
        `SELECT * FROM pdpp_chain_registrations
         WHERE status IN (${statuses.map(() => "?").join(",")})
         ORDER BY created_at, grant_id`,
      )
      .all(...statuses) as ChainRegistrationRow[];
    return rows.map(chainRegistrationFromRow);
  }

  /** Record the gateway's acceptance of the entry. Only from pending. */
  markChainBound(input: {
    grantId: string;
    chainId: number;
    contractAddress: string;
    permissionId: string;
    granteeId: string;
    registeredVersion: string;
    now?: Date;
  }): boolean {
    const result = this.db
      .prepare(
        `UPDATE pdpp_chain_registrations
         SET status = 'bound', chain_id = ?, contract_address = ?,
             permission_id = ?, grantee_id = ?, registered_version = ?,
             last_error = NULL, updated_at = ?
         WHERE grant_id = ? AND status = 'pending'`,
      )
      .run(
        input.chainId,
        input.contractAddress,
        input.permissionId,
        input.granteeId,
        input.registeredVersion,
        (input.now ?? new Date()).toISOString(),
        input.grantId,
      );
    return result.changes > 0;
  }

  /**
   * A pending registration for a grant stored before chain grants were on
   * (boot backfill). Inserts nothing when one exists. True when created.
   */
  createChainRegistration(input: {
    grantId: string;
    clientId: string;
    granteeAddress: string;
    salt: string;
    entry: string;
    now?: Date;
  }): boolean {
    const at = (input.now ?? new Date()).toISOString();
    const result = this.db
      .prepare(
        `INSERT OR IGNORE INTO pdpp_chain_registrations
           (grant_id, client_id, grantee_address, salt, entry, status,
            created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)`,
      )
      .run(
        input.grantId,
        input.clientId,
        input.granteeAddress,
        input.salt,
        input.entry,
        at,
        at,
      );
    return result.changes > 0;
  }

  /** A bound registration whose chain transaction failed: register again. */
  markChainPending(grantId: string, now: Date = new Date()): boolean {
    const result = this.db
      .prepare(
        `UPDATE pdpp_chain_registrations
         SET status = 'pending', last_error = 'registration failed on chain; registering again', updated_at = ?
         WHERE grant_id = ? AND status = 'bound'`,
      )
      .run(now.toISOString(), grantId);
    return result.changes > 0;
  }

  /** Whether a client access token of this grant is still usable. */
  hasLiveClientToken(grantId: string, now: Date = new Date()): boolean {
    const row = this.db
      .prepare(
        `SELECT 1 FROM pdpp_access_tokens
         WHERE grant_id = ? AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > ?) LIMIT 1`,
      )
      .get(grantId, now.toISOString());
    return row !== undefined;
  }

  /** The grant ended: its entry must leave the slot. Never goes backwards. */
  markChainEnding(grantId: string, now: Date = new Date()): boolean {
    const result = this.db
      .prepare(
        `UPDATE pdpp_chain_registrations
         SET status = 'ending', updated_at = ?
         WHERE grant_id = ? AND status IN ('pending','bound')`,
      )
      .run(now.toISOString(), grantId);
    return result.changes > 0;
  }

  /**
   * The gateway accepted the upsert that drops the entry, at `version`. The
   * row stays `ending` until that upsert is final on chain (`markChainEnded`).
   */
  noteChainEndingSent(
    grantId: string,
    version: string,
    kind: "removal" | "revocation",
    now: Date = new Date(),
  ): boolean {
    const result = this.db
      .prepare(
        `UPDATE pdpp_chain_registrations
         SET ended_version = ?, ending_kind = ?, last_error = NULL,
             updated_at = ?
         WHERE grant_id = ? AND status = 'ending'`,
      )
      .run(version, kind, now.toISOString(), grantId);
    return result.changes > 0;
  }

  /** The entry is off the slot on chain (or was never there). Terminal. */
  markChainEnded(grantId: string, now: Date = new Date()): boolean {
    const result = this.db
      .prepare(
        `UPDATE pdpp_chain_registrations
         SET status = 'ended', last_error = NULL, updated_at = ?
         WHERE grant_id = ? AND status = 'ending'`,
      )
      .run(now.toISOString(), grantId);
    return result.changes > 0;
  }

  /**
   * Record (once) when the PS began deferring its slot write, or clear it
   * (`since` null). Returns the deferral start in force.
   */
  noteChainDeferral(grantId: string, since: Date | null): string | null {
    if (since === null) {
      this.db
        .prepare(
          "UPDATE pdpp_chain_registrations SET deferred_since = NULL WHERE grant_id = ?",
        )
        .run(grantId);
      return null;
    }
    this.db
      .prepare(
        `UPDATE pdpp_chain_registrations SET deferred_since = ?
         WHERE grant_id = ? AND deferred_since IS NULL`,
      )
      .run(since.toISOString(), grantId);
    return this.getChainRegistration(grantId)?.deferredSince ?? null;
  }

  /** Why the last gateway attempt failed; never the salt or document. */
  noteChainError(grantId: string, error: string, now: Date = new Date()) {
    this.db
      .prepare(
        `UPDATE pdpp_chain_registrations SET last_error = ?, updated_at = ?
         WHERE grant_id = ?`,
      )
      .run(error.slice(0, 500), now.toISOString(), grantId);
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

  /** Every grant, for history re-establishment only. */
  listAllGrants(): StoredGrant[] {
    const rows = this.db
      .prepare("SELECT grant_id FROM pdpp_grants ORDER BY issued_at")
      .all() as { grant_id: string }[];
    return rows.map((r) => this.getGrant(r.grant_id)!);
  }

  /**
   * Re-establish a history that the anchor showed not current (history.ts,
   * L1823). `apply` runs in one transaction without the currency gate; the
   * anchor is then rewritten under a new epoch.
   */
  reestablishHistory(apply: () => void, now: Date): void {
    try {
      this.db.transaction(apply)();
    } catch (err) {
      this.history.discardPending();
      throw err;
    }
    this.history.markCommitted();
    this.history.reanchor(now.toISOString());
  }

  /** Restore one anchored instruction and its grant-ending facts (L1820). */
  restoreAnchoredInstructionInTx(e: AnchoredErasure, now: Date): boolean {
    const at = now.toISOString();
    if (e.read_state === "revoked") {
      const changed = this.db
        .prepare(
          "UPDATE pdpp_grants SET revoked_at = ? WHERE grant_id = ? AND revoked_at IS NULL",
        )
        .run(e.ended_at, e.grant_id);
      if (changed.changes > 0) {
        this.lifecycle.recordEnding(
          e.grant_id,
          "erasure_request",
          "restored from durability evidence",
          at,
        );
      }
    }
    this.db
      .prepare(
        "UPDATE pdpp_access_tokens SET revoked_at = ? WHERE grant_id = ? AND revoked_at IS NULL",
      )
      .run(at, e.grant_id);
    this.db
      .prepare(
        "UPDATE pdpp_refresh_families SET revoked_at = ? WHERE grant_id = ? AND revoked_at IS NULL",
      )
      .run(at, e.grant_id);
    return this.lifecycle.restoreInstruction(e, at);
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
  revokeGrant(
    grantId: string,
    now: Date = new Date(),
    ending: { reason: GrantEndingReason; detail?: string } = {
      reason: "owner_withdrawal",
    },
  ): boolean {
    return this.commit(() => this.endGrantInTx(grantId, now, ending), now);
  }

  /**
   * End one grant inside the caller's transaction. A grant keeps its first
   * ending (L1735): an already revoked or expired grant gets no new
   * `revoked_at`, but its tokens and families are still disabled. An advance
   * erasure election takes effect at the ending (L1586). Returns whether
   * this call ended the grant.
   */
  endGrantInTx(
    grantId: string,
    now: Date,
    ending: { reason: GrantEndingReason; detail?: string },
  ): boolean {
    const at = now.toISOString();
    const result = this.db
      .prepare(
        `UPDATE pdpp_grants SET revoked_at = ?
         WHERE grant_id = ? AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > ?)`,
      )
      .run(at, grantId, at);
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
    const ended = result.changes > 0;
    if (ended) {
      this.lifecycle.recordEnding(
        grantId,
        ending.reason,
        ending.detail ?? null,
        at,
      );
      this.history.append(
        "grant_revoked",
        grantId,
        { reason: ending.reason, detail: ending.detail ?? null },
        at,
      );
    }
    this.settleAdvanceInTx(grantId, now);
    return ended;
  }

  /**
   * The ending facts the lifecycle operation reports (L1729-L1735): the
   * first ending wins, so a revocation after `expires_at` never replaces the
   * expiry.
   */
  endingOf(
    stored: StoredGrant,
    now: Date,
  ): { readState: "revoked" | "expired"; endedAt: string } | null {
    const exp = stored.expiresAt ? Date.parse(stored.expiresAt) : null;
    if (
      stored.revokedAt &&
      (exp === null || Date.parse(stored.revokedAt) < exp)
    ) {
      return { readState: "revoked", endedAt: stored.revokedAt };
    }
    if (exp !== null && exp <= now.getTime()) {
      return { readState: "expired", endedAt: stored.expiresAt! };
    }
    return null;
  }

  /**
   * Make an advance election effective once its grant has ended, at the
   * ending time (L1586, case P6 variant: `effective_at` equals
   * `expires_at`). Inside the caller's transaction.
   */
  settleAdvanceInTx(
    grantId: string,
    now: Date,
  ): ErasureInstructionRecord | null {
    const instruction = this.lifecycle.getInstruction(grantId);
    if (!instruction) return null;
    if (instruction.effectiveAt) return instruction;
    const stored = this.getGrant(grantId);
    if (!stored) return instruction;
    const ending = this.endingOf(stored, now);
    if (!ending) return instruction;
    this.lifecycle.makeEffective(
      instruction.instructionId,
      ending.endedAt,
      now.toISOString(),
    );
    return this.lifecycle.getInstruction(grantId)!;
  }

  /**
   * Record an immediate erasure request for one grant (L1586, L1612, L1746),
   * inside the caller's transaction. Ends the grant if it has not ended. An
   * advance instruction becomes effective at that ending; an effective one
   * is returned unchanged (L1622: "a repeated request returns the existing
   * instruction"; clocks never move); otherwise a new instruction is
   * accepted and effective now.
   */
  requestErasureInTx(input: {
    grantId: string;
    clientId: string;
    origin: "owner" | "client";
    now: Date;
    ending: { reason: GrantEndingReason; detail?: string };
    /** The client's first receipt, when the request reports it (L1746). */
    receiptReportedAt?: string;
  }): { instruction: ErasureInstructionRecord; ended: boolean } {
    const at = input.now.toISOString();
    const ended = this.endGrantInTx(input.grantId, input.now, input.ending);
    let instruction = this.lifecycle.getInstruction(input.grantId);
    if (!instruction) {
      instruction = this.lifecycle.insertInstruction({
        grantId: input.grantId,
        clientId: input.clientId,
        origin: input.origin,
        advance: false,
        at,
        effectiveAt: at,
      });
    }
    // endGrantInTx already settled an advance election at the ending.
    instruction = this.lifecycle.getInstruction(input.grantId)!;
    const stored = this.getGrant(input.grantId)!;
    const ending = this.endingOf(stored, input.now);
    if (input.receiptReportedAt) {
      this.lifecycle.recordReceipt(
        instruction.instructionId,
        input.receiptReportedAt,
        at,
      );
      instruction = this.lifecycle.getInstruction(input.grantId)!;
    }
    return { instruction, ended };
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
    return this.commit((): AuthCodeRecord | null => {
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
      // L1824: authorization-code redemption is a recorded event.
      this.history.append("code_redeemed", row.grant_id, {}, at);
      return {
        grantId: row.grant_id,
        clientId: row.client_id,
        redirectUri: row.redirect_uri,
        codeChallenge: row.code_challenge,
        codeChallengeMethod: row.code_challenge_method,
        expiresAt: row.expires_at,
      };
    }, now);
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
    const now = input.now ?? new Date();
    const at = now.toISOString();

    return this.commit((): boolean => {
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
        // L1824: `single_use` consumption is a recorded event.
        this.history.append("single_use_consumed", input.grantId, {}, at);
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
    }, now);
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

    return this.commit(() => {
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
        // A credential event, not a grant ending (L1573, case P8).
        this.history.append(
          "refresh_family_revoked",
          row.grant_id,
          { family_id: row.family_id, reason: "reuse" },
          at,
        );
        return { ok: false as const, reason: "reuse_detected" as const };
      }

      this.db
        .prepare(
          "UPDATE pdpp_refresh_tokens SET superseded_at = ? WHERE token_hash = ?",
        )
        .run(at, hash);
      // L1824: refresh-token supersession is a recorded event.
      this.history.append("refresh_superseded", row.grant_id, {}, at);
      return {
        ok: true as const,
        familyId: row.family_id,
        grantId: row.grant_id,
      };
    }, now);
  }

  /** Revoke one access token. Returns false if unknown or already revoked. */
  revokeAccessToken(token: string, now: Date = new Date()): boolean {
    return this.commit(() => {
      const result = this.db
        .prepare(
          "UPDATE pdpp_access_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
        )
        .run(now.toISOString(), hashToken(token));
      if (result.changes > 0) {
        this.history.append(
          "access_token_revoked",
          null,
          { token_hash: hashToken(token) },
          now.toISOString(),
        );
      }
      return result.changes > 0;
    }, now);
  }

  /**
   * Read a refresh token's state without rotating it (RFC 7009 revocation).
   * Null when unknown.
   */
  inspectRefreshToken(token: string): {
    familyId: string;
    grantId: string;
    superseded: boolean;
    familyRevoked: boolean;
  } | null {
    const row = this.db
      .prepare(
        `SELECT t.family_id, t.superseded_at, f.revoked_at AS family_revoked_at,
                f.grant_id
         FROM pdpp_refresh_tokens t
         JOIN pdpp_refresh_families f ON f.family_id = t.family_id
         WHERE t.token_hash = ?`,
      )
      .get(hashToken(token)) as
      | {
          family_id: string;
          superseded_at: string | null;
          family_revoked_at: string | null;
          grant_id: string;
        }
      | undefined;
    if (!row) return null;
    return {
      familyId: row.family_id,
      grantId: row.grant_id,
      superseded: row.superseded_at !== null,
      familyRevoked: row.family_revoked_at !== null,
    };
  }

  /** Whether a live (unrevoked) refresh-token family covers the grant. */
  refreshFamilyCovers(grantId: string): boolean {
    const row = this.db
      .prepare(
        "SELECT 1 FROM pdpp_refresh_families WHERE grant_id = ? AND revoked_at IS NULL LIMIT 1",
      )
      .get(grantId);
    return row !== undefined;
  }

  /**
   * One RFC 7009 client revocation as a single durable unit (AS items 25, 44).
   * Returns the grants this call ended (active before it, revoked after).
   *
   * `endGrants` are ended exactly as `revokeGrant` ends one: grant, linked
   * access tokens and refresh families. `accessTokenOnly` ends just that
   * token (spec-core L2777: an access token's grants end "only when no
   * refresh-token family covers them"). A disposition, when given, is
   * recorded for every grant in `dispositionScope` inside the same
   * transaction, so the 200 the route returns is never ahead of the record
   * (L2787). An already-ended grant keeps its `revoked_at` (L2785: "MUST NOT
   * change the `read_state` or `ended_at` of a grant that had already expired
   * or been revoked").
   */
  revokeForClient(input: {
    endGrants: string[];
    accessTokenOnly?: string;
    disposition?: {
      value: "keep" | "delete";
      reportedAt?: string;
      clientId: string;
      credential: "access_token" | "refresh_token";
      scope: string[];
    };
    now?: Date;
  }): string[] {
    const now = input.now ?? new Date();
    const at = now.toISOString();
    return this.commit((): string[] => {
      const ended: string[] = [];
      const d = input.disposition;
      if (d) {
        for (const grantId of d.scope) {
          const existing = this.db
            .prepare(
              `SELECT 1 FROM pdpp_revocation_dispositions
               WHERE grant_id = ? AND client_id = ? AND disposition = ?
                 AND reported_at IS ?`,
            )
            .get(grantId, d.clientId, d.value, d.reportedAt ?? null);
          if (existing) continue;
          this.db
            .prepare(
              `INSERT INTO pdpp_revocation_dispositions
                 (grant_id, client_id, disposition, reported_at, credential, recorded_at)
               VALUES (?, ?, ?, ?, ?, ?)`,
            )
            .run(
              grantId,
              d.clientId,
              d.value,
              d.reportedAt ?? null,
              d.credential,
              at,
            );
          this.history.append(
            "client_disposition",
            grantId,
            { disposition: d.value, reported_at: d.reportedAt ?? null },
            at,
          );
        }
      }
      if (input.accessTokenOnly !== undefined) {
        this.db
          .prepare(
            "UPDATE pdpp_access_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
          )
          .run(at, hashToken(input.accessTokenOnly));
        this.history.append(
          "access_token_revoked",
          null,
          { token_hash: hashToken(input.accessTokenOnly) },
          at,
        );
      }
      for (const grantId of input.endGrants) {
        // Only an active grant gets a new ending (L2785); endGrantInTx keeps
        // an expired grant's `expires_at` as its end and still disables its
        // tokens and families.
        if (this.endGrantInTx(grantId, now, { reason: "client_revocation" })) {
          ended.push(grantId);
        }
      }
      // L2785: "A recorded `delete` creates an erasure instruction for each
      // grant in that scope." Recorded atomically with the revocation, and
      // an existing instruction keeps its clocks (L1622). With `reported_at`
      // the request also reports the owner's choice as the client's first
      // receipt; without it no receipt is inferred (L1746, L2785).
      if (d && d.value === "delete") {
        for (const grantId of d.scope) {
          this.requestErasureInTx({
            grantId,
            clientId: d.clientId,
            origin: "client",
            now,
            ending: { reason: "client_revocation" },
            ...(d.reportedAt !== undefined && {
              receiptReportedAt: d.reportedAt,
            }),
          });
        }
      }
      return ended;
    }, now);
  }

  /** Dispositions recorded for a grant, oldest first (tests and owner views). */
  listDispositions(grantId: string): Array<{
    clientId: string;
    disposition: "keep" | "delete";
    reportedAt: string | null;
    credential: "access_token" | "refresh_token";
    recordedAt: string;
  }> {
    return (
      this.db
        .prepare(
          `SELECT client_id, disposition, reported_at, credential, recorded_at
           FROM pdpp_revocation_dispositions WHERE grant_id = ? ORDER BY rowid`,
        )
        .all(grantId) as Array<{
        client_id: string;
        disposition: "keep" | "delete";
        reported_at: string | null;
        credential: "access_token" | "refresh_token";
        recorded_at: string;
      }>
    ).map((r) => ({
      clientId: r.client_id,
      disposition: r.disposition,
      reportedAt: r.reported_at,
      credential: r.credential,
      recordedAt: r.recorded_at,
    }));
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
