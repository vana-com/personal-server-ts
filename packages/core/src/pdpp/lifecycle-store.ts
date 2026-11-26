/**
 * Persisted held-data lifecycle facts (spec-core §7 L1532-L1830): erasure
 * instructions and their separately recorded stages, owner dispositions,
 * grant-ending reasons, lifecycle token disabling, and lifecycle recovery
 * approvals, codes and tokens.
 *
 * Every method that writes is called by `PdppAuthStore` inside a transaction
 * that also appends the event to the hash-chained history (`history.ts`), so
 * a terminal event is never durable without its evidence position.
 */

import { randomBytes } from "node:crypto";
import type Database from "better-sqlite3";
import type { AnchoredErasure, HistoryRecorder } from "./history.js";

/**
 * Core's held-data time limits (spec-core L1547-L1556). Elapsed time; a day
 * is 24 hours.
 */
export const RECONCILIATION_INTERVAL_MS = 24 * 60 * 60 * 1000;
export const RETRY_INTERVAL_MS = 60 * 60 * 1000;
export const STOP_USE_BOUND_MS = 48 * 60 * 60 * 1000;
export const DELETION_BOUND_MS = 30 * 24 * 60 * 60 * 1000;

export const LIFECYCLE_SCHEMA_SQL = `
-- One erasure instruction per grant at most (L1622: "At most one erasure
-- instruction applies to a grant"). Acceptance, first return, reported
-- receipt and reported completion are separate columns (L1660, AS item 42).
CREATE TABLE IF NOT EXISTS pdpp_erasure_instructions (
  instruction_id TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL UNIQUE,
  client_id TEXT NOT NULL,
  origin TEXT NOT NULL CHECK (origin IN ('owner','client')),
  -- 1 for an election made in advance (L1586); effective_at is then NULL
  -- until the grant ends.
  advance INTEGER NOT NULL DEFAULT 0,
  accepted_at TEXT NOT NULL,
  effective_at TEXT,
  first_returned_at TEXT,
  receipt_reported_at TEXT,
  receipt_recorded_at TEXT,
  completed_reported_at TEXT,
  completed_recorded_at TEXT,
  FOREIGN KEY (grant_id) REFERENCES pdpp_grants (grant_id)
);

-- L1756: each retained report is kept with the time the AS received it; a
-- later one corrects an earlier one and does not overwrite it.
CREATE TABLE IF NOT EXISTS pdpp_retained_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  instruction_id TEXT NOT NULL,
  reported_at TEXT NOT NULL,
  retained_until TEXT NOT NULL,
  retention_basis TEXT,
  retention_scope TEXT,
  received_at TEXT NOT NULL,
  FOREIGN KEY (instruction_id) REFERENCES pdpp_erasure_instructions (instruction_id)
);

-- Owner dispositions (L1560 "Ending paths"). Append-only.
CREATE TABLE IF NOT EXISTS pdpp_owner_dispositions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  grant_id TEXT NOT NULL,
  disposition TEXT NOT NULL CHECK (disposition IN ('keep','delete')),
  path TEXT NOT NULL,
  action_id TEXT NOT NULL,
  recorded_at TEXT NOT NULL,
  FOREIGN KEY (grant_id) REFERENCES pdpp_grants (grant_id)
);
CREATE INDEX IF NOT EXISTS idx_pdpp_owner_dispositions_grant ON pdpp_owner_dispositions (grant_id);

-- Why a grant ended, for the owner surface (L1572: a security revocation
-- shows "that the grant ended and why"). Written only by the call that ends
-- the grant, so the first ending wins.
CREATE TABLE IF NOT EXISTS pdpp_grant_endings (
  grant_id TEXT PRIMARY KEY,
  reason TEXT NOT NULL,
  detail TEXT,
  recorded_at TEXT NOT NULL,
  FOREIGN KEY (grant_id) REFERENCES pdpp_grants (grant_id)
);

-- L1716 "Compromise": tokens disabled for lifecycle use, by digest, so a
-- token never presented to the operation can be disabled too.
CREATE TABLE IF NOT EXISTS pdpp_lifecycle_disabled_tokens (
  token_hash TEXT PRIMARY KEY,
  disabled_at TEXT NOT NULL
);

-- Lifecycle recovery (L1802): approval evidence, the one-time code, and the
-- lifecycle-only token. Kept apart from pdpp_access_tokens so no read path
-- can ever resolve a recovery token (introspection active:false, RS reject).
CREATE TABLE IF NOT EXISTS pdpp_recovery_approvals (
  approval_id TEXT PRIMARY KEY,
  subject_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  grant_ids_json TEXT NOT NULL,
  review_digest TEXT NOT NULL,
  statement TEXT NOT NULL,
  approved_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pdpp_recovery_codes (
  code_hash TEXT PRIMARY KEY,
  approval_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT,
  code_challenge_method TEXT,
  expires_at TEXT NOT NULL,
  redeemed_at TEXT,
  FOREIGN KEY (approval_id) REFERENCES pdpp_recovery_approvals (approval_id)
);
CREATE TABLE IF NOT EXISTS pdpp_recovery_tokens (
  token_hash TEXT PRIMARY KEY,
  approval_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  grant_ids_json TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  revoked_at TEXT,
  FOREIGN KEY (approval_id) REFERENCES pdpp_recovery_approvals (approval_id)
);

-- Erasure instructions restored from the anchor for grants a restore lost
-- (F5): the database has no grant row, but the client can still query and
-- receive the instruction with a token whose digest the evidence carries.
CREATE TABLE IF NOT EXISTS pdpp_orphan_erasures (
  grant_id TEXT PRIMARY KEY,
  evidence_json TEXT NOT NULL,
  restored_at TEXT NOT NULL,
  first_returned_at TEXT
);

-- Owner actions accepted while the history was unavailable that named a
-- grant the re-established store does not hold (F5). Kept for the owner.
CREATE TABLE IF NOT EXISTS pdpp_unapplied_owner_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action_id TEXT NOT NULL,
  grant_id TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  action TEXT NOT NULL,
  disposition TEXT,
  recorded_at TEXT NOT NULL,
  outcome TEXT NOT NULL
);

-- AS decommission (L1574): when the owner confirmed it.
CREATE TABLE IF NOT EXISTS pdpp_decommission (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  confirmed_at TEXT NOT NULL
);
`;

export interface ErasureInstructionRecord {
  instructionId: string;
  grantId: string;
  clientId: string;
  origin: "owner" | "client";
  advance: boolean;
  acceptedAt: string;
  effectiveAt: string | null;
  firstReturnedAt: string | null;
  receiptReportedAt: string | null;
  receiptRecordedAt: string | null;
  completedReportedAt: string | null;
  completedRecordedAt: string | null;
}

export interface RetainedReportRecord {
  reportedAt: string;
  retainedUntil: string;
  retentionBasis: string | null;
  retentionScope: string | null;
  receivedAt: string;
}

export interface OwnerDispositionRecord {
  disposition: "keep" | "delete";
  path: string;
  actionId: string;
  recordedAt: string;
}

export interface GrantEndingRecord {
  reason: string;
  detail: string | null;
  recordedAt: string;
}

export interface RecoveryTokenRecord {
  approvalId: string;
  clientId: string;
  subjectId: string;
  grantIds: string[];
  issuedAt: string;
  revokedAt: string | null;
}

interface InstructionRow {
  instruction_id: string;
  grant_id: string;
  client_id: string;
  origin: "owner" | "client";
  advance: number;
  accepted_at: string;
  effective_at: string | null;
  first_returned_at: string | null;
  receipt_reported_at: string | null;
  receipt_recorded_at: string | null;
  completed_reported_at: string | null;
  completed_recorded_at: string | null;
}

function toInstruction(row: InstructionRow): ErasureInstructionRecord {
  return {
    instructionId: row.instruction_id,
    grantId: row.grant_id,
    clientId: row.client_id,
    origin: row.origin,
    advance: row.advance === 1,
    acceptedAt: row.accepted_at,
    effectiveAt: row.effective_at,
    firstReturnedAt: row.first_returned_at,
    receiptReportedAt: row.receipt_reported_at,
    receiptRecordedAt: row.receipt_recorded_at,
    completedReportedAt: row.completed_reported_at,
    completedRecordedAt: row.completed_recorded_at,
  };
}

/** L1824: an `instruction_id` never repeats, even after a restore. */
export function newInstructionId(): string {
  return `ers_${randomBytes(16).toString("hex")}`;
}

export class LifecycleRecords {
  constructor(
    private readonly db: Database.Database,
    private readonly history: HistoryRecorder,
  ) {
    db.exec(LIFECYCLE_SCHEMA_SQL);
    // Additive: round-2 stores created the orphan table without this column.
    const orphanColumns = db
      .prepare("PRAGMA table_info(pdpp_orphan_erasures)")
      .all() as { name: string }[];
    if (!orphanColumns.some((c) => c.name === "first_returned_at")) {
      db.exec(
        "ALTER TABLE pdpp_orphan_erasures ADD COLUMN first_returned_at TEXT",
      );
    }
  }

  // -- instructions --------------------------------------------------------

  listInstructions(): ErasureInstructionRecord[] {
    return (
      this.db
        .prepare("SELECT * FROM pdpp_erasure_instructions ORDER BY rowid")
        .all() as InstructionRow[]
    ).map(toInstruction);
  }

  listDisabledDigests(): string[] {
    return (
      this.db
        .prepare("SELECT token_hash FROM pdpp_lifecycle_disabled_tokens")
        .all() as { token_hash: string }[]
    ).map((r) => r.token_hash);
  }

  /** Every recovery token digest (re-establishment disables them all, F4). */
  listRecoveryTokenDigests(): string[] {
    return (
      this.db.prepare("SELECT token_hash FROM pdpp_recovery_tokens").all() as {
        token_hash: string;
      }[]
    ).map((r) => r.token_hash);
  }

  insertOrphanErasure(e: AnchoredErasure, at: string): void {
    this.db
      .prepare(
        `INSERT INTO pdpp_orphan_erasures (grant_id, evidence_json, restored_at)
         VALUES (?, ?, ?) ON CONFLICT (grant_id) DO NOTHING`,
      )
      .run(e.grant_id, JSON.stringify(e), at);
    this.history.append("orphan_erasure_restored", e.grant_id, e, at);
  }

  listOrphanErasures(): AnchoredErasure[] {
    return (
      this.db
        .prepare("SELECT evidence_json FROM pdpp_orphan_erasures")
        .all() as { evidence_json: string }[]
    ).map((r) => JSON.parse(r.evidence_json) as AnchoredErasure);
  }

  /** First return of an orphan instruction in a lifecycle answer (L1660). */
  recordOrphanFirstReturn(grantId: string, at: string): void {
    const result = this.db
      .prepare(
        `UPDATE pdpp_orphan_erasures SET first_returned_at = ?
         WHERE grant_id = ? AND first_returned_at IS NULL`,
      )
      .run(at, grantId);
    if (result.changes > 0) {
      this.history.append("orphan_erasure_first_returned", grantId, {}, at);
    }
  }

  getOrphanFirstReturn(grantId: string): string | null {
    const row = this.db
      .prepare(
        "SELECT first_returned_at FROM pdpp_orphan_erasures WHERE grant_id = ?",
      )
      .get(grantId) as { first_returned_at: string | null } | undefined;
    return row?.first_returned_at ?? null;
  }

  getOrphanErasure(grantId: string): AnchoredErasure | null {
    const row = this.db
      .prepare(
        "SELECT evidence_json FROM pdpp_orphan_erasures WHERE grant_id = ?",
      )
      .get(grantId) as { evidence_json: string } | undefined;
    return row ? (JSON.parse(row.evidence_json) as AnchoredErasure) : null;
  }

  insertUnappliedAction(input: {
    actionId: string;
    grantId: string;
    subjectId: string;
    kind: string;
    action: string;
    disposition: string | null;
    recordedAt: string;
    outcome: string;
    at: string;
  }): void {
    this.db
      .prepare(
        `INSERT INTO pdpp_unapplied_owner_actions
           (action_id, grant_id, subject_id, kind, action, disposition, recorded_at, outcome)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.actionId,
        input.grantId,
        input.subjectId,
        input.kind,
        input.action,
        input.disposition,
        input.recordedAt,
        input.outcome,
      );
    this.history.append(
      "owner_action_unapplied",
      input.grantId,
      { action_id: input.actionId, outcome: input.outcome },
      input.at,
    );
  }

  listUnappliedActions(subjectId: string): Array<{
    action_id: string;
    grant_id: string;
    kind: string;
    action: string;
    disposition: string | null;
    recorded_at: string;
    outcome: string;
  }> {
    return this.db
      .prepare(
        `SELECT action_id, grant_id, kind, action, disposition, recorded_at, outcome
         FROM pdpp_unapplied_owner_actions WHERE subject_id = ? ORDER BY id`,
      )
      .all(subjectId) as Array<{
      action_id: string;
      grant_id: string;
      kind: string;
      action: string;
      disposition: string | null;
      recorded_at: string;
      outcome: string;
    }>;
  }

  getInstruction(grantId: string): ErasureInstructionRecord | null {
    const row = this.db
      .prepare("SELECT * FROM pdpp_erasure_instructions WHERE grant_id = ?")
      .get(grantId) as InstructionRow | undefined;
    return row ? toInstruction(row) : null;
  }

  /** Insert a new instruction. Caller holds the transaction. */
  insertInstruction(input: {
    grantId: string;
    clientId: string;
    origin: "owner" | "client";
    advance: boolean;
    at: string;
    effectiveAt: string | null;
  }): ErasureInstructionRecord {
    const id = newInstructionId();
    this.db
      .prepare(
        `INSERT INTO pdpp_erasure_instructions
           (instruction_id, grant_id, client_id, origin, advance, accepted_at, effective_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        input.grantId,
        input.clientId,
        input.origin,
        input.advance ? 1 : 0,
        input.at,
        input.effectiveAt,
      );
    this.history.append(
      "erasure_instruction",
      input.grantId,
      {
        instruction_id: id,
        origin: input.origin,
        advance: input.advance,
        accepted_at: input.at,
        effective_at: input.effectiveAt,
      },
      input.at,
    );
    return this.getInstruction(input.grantId)!;
  }

  /**
   * Re-insert an anchored instruction a restored database lacks, with its
   * original identifier and clocks (L1820, L1824: never reassigned).
   */
  restoreInstruction(
    e: {
      instruction_id: string;
      grant_id: string;
      client_id: string;
      accepted_at: string;
      /** Null for an advance election (F2). */
      effective_at: string | null;
      advance?: boolean;
    },
    at: string,
  ): boolean {
    const existing = this.getInstruction(e.grant_id);
    if (existing) {
      if (!existing.effectiveAt && e.effective_at)
        this.makeEffective(existing.instructionId, e.effective_at, at);
      return false;
    }
    this.db
      .prepare(
        `INSERT INTO pdpp_erasure_instructions
           (instruction_id, grant_id, client_id, origin, advance, accepted_at, effective_at)
         VALUES (?, ?, ?, 'owner', ?, ?, ?)`,
      )
      .run(
        e.instruction_id,
        e.grant_id,
        e.client_id,
        e.advance ? 1 : 0,
        e.accepted_at,
        e.effective_at,
      );
    this.history.append("erasure_instruction_restored", e.grant_id, e, at);
    return true;
  }

  /** An advance election takes effect at grant end (L1586). Never moves a set time. */
  makeEffective(instructionId: string, effectiveAt: string, at: string): void {
    const result = this.db
      .prepare(
        `UPDATE pdpp_erasure_instructions SET effective_at = ?
         WHERE instruction_id = ? AND effective_at IS NULL`,
      )
      .run(effectiveAt, instructionId);
    if (result.changes > 0) {
      this.history.append(
        "erasure_effective",
        null,
        { instruction_id: instructionId, effective_at: effectiveAt },
        at,
      );
    }
  }

  /** L1660: record the first time the AS returned the instruction. */
  recordFirstReturn(instructionId: string, at: string): void {
    const result = this.db
      .prepare(
        `UPDATE pdpp_erasure_instructions SET first_returned_at = ?
         WHERE instruction_id = ? AND first_returned_at IS NULL`,
      )
      .run(at, instructionId);
    if (result.changes > 0) {
      this.history.append(
        "erasure_first_returned",
        null,
        { instruction_id: instructionId },
        at,
      );
    }
  }

  /** L1756: the first `received` report is recorded; a repeat changes nothing. */
  recordReceipt(instructionId: string, reportedAt: string, at: string): void {
    const result = this.db
      .prepare(
        `UPDATE pdpp_erasure_instructions
         SET receipt_reported_at = ?, receipt_recorded_at = ?
         WHERE instruction_id = ? AND receipt_reported_at IS NULL`,
      )
      .run(reportedAt, at, instructionId);
    if (result.changes > 0) {
      this.history.append(
        "erasure_receipt_reported",
        null,
        { instruction_id: instructionId, reported_at: reportedAt },
        at,
      );
    }
  }

  recordCompleted(instructionId: string, reportedAt: string, at: string): void {
    const result = this.db
      .prepare(
        `UPDATE pdpp_erasure_instructions
         SET completed_reported_at = ?, completed_recorded_at = ?
         WHERE instruction_id = ? AND completed_reported_at IS NULL`,
      )
      .run(reportedAt, at, instructionId);
    if (result.changes > 0) {
      this.history.append(
        "erasure_completed_reported",
        null,
        { instruction_id: instructionId, reported_at: reportedAt },
        at,
      );
    }
  }

  addRetained(
    instructionId: string,
    report: Omit<RetainedReportRecord, "receivedAt">,
    at: string,
  ): void {
    this.db
      .prepare(
        `INSERT INTO pdpp_retained_reports
           (instruction_id, reported_at, retained_until, retention_basis, retention_scope, received_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        instructionId,
        report.reportedAt,
        report.retainedUntil,
        report.retentionBasis,
        report.retentionScope,
        at,
      );
    this.history.append(
      "erasure_retained_reported",
      null,
      { instruction_id: instructionId, ...report },
      at,
    );
  }

  listRetained(instructionId: string): RetainedReportRecord[] {
    return (
      this.db
        .prepare(
          `SELECT reported_at, retained_until, retention_basis, retention_scope, received_at
           FROM pdpp_retained_reports WHERE instruction_id = ? ORDER BY id`,
        )
        .all(instructionId) as Array<{
        reported_at: string;
        retained_until: string;
        retention_basis: string | null;
        retention_scope: string | null;
        received_at: string;
      }>
    ).map((r) => ({
      reportedAt: r.reported_at,
      retainedUntil: r.retained_until,
      retentionBasis: r.retention_basis,
      retentionScope: r.retention_scope,
      receivedAt: r.received_at,
    }));
  }

  // -- dispositions and endings -------------------------------------------

  insertOwnerDisposition(input: {
    grantId: string;
    disposition: "keep" | "delete";
    path: string;
    actionId: string;
    at: string;
  }): void {
    this.db
      .prepare(
        `INSERT INTO pdpp_owner_dispositions (grant_id, disposition, path, action_id, recorded_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(
        input.grantId,
        input.disposition,
        input.path,
        input.actionId,
        input.at,
      );
    this.history.append(
      "owner_disposition",
      input.grantId,
      {
        disposition: input.disposition,
        path: input.path,
        action_id: input.actionId,
      },
      input.at,
    );
  }

  /** Whether this action already recorded a disposition for the grant (retry). */
  hasOwnerDisposition(grantId: string, actionId: string): boolean {
    return (
      this.db
        .prepare(
          "SELECT 1 FROM pdpp_owner_dispositions WHERE grant_id = ? AND action_id = ?",
        )
        .get(grantId, actionId) !== undefined
    );
  }

  listOwnerDispositions(grantId: string): OwnerDispositionRecord[] {
    return (
      this.db
        .prepare(
          `SELECT disposition, path, action_id, recorded_at FROM pdpp_owner_dispositions
           WHERE grant_id = ? ORDER BY id`,
        )
        .all(grantId) as Array<{
        disposition: "keep" | "delete";
        path: string;
        action_id: string;
        recorded_at: string;
      }>
    ).map((r) => ({
      disposition: r.disposition,
      path: r.path,
      actionId: r.action_id,
      recordedAt: r.recorded_at,
    }));
  }

  /** Any disposition (owner- or client-conveyed) recorded for the grant. */
  latestDisposition(grantId: string): "keep" | "delete" | null {
    const row = this.db
      .prepare(
        `SELECT disposition, at FROM (
           SELECT disposition, recorded_at AS at FROM pdpp_owner_dispositions WHERE grant_id = ?
           UNION ALL
           SELECT disposition, recorded_at AS at FROM pdpp_revocation_dispositions WHERE grant_id = ?
         ) ORDER BY at DESC LIMIT 1`,
      )
      .get(grantId, grantId) as { disposition: "keep" | "delete" } | undefined;
    return row?.disposition ?? null;
  }

  recordEnding(
    grantId: string,
    reason: string,
    detail: string | null,
    at: string,
  ): void {
    this.db
      .prepare(
        `INSERT INTO pdpp_grant_endings (grant_id, reason, detail, recorded_at)
         VALUES (?, ?, ?, ?) ON CONFLICT (grant_id) DO NOTHING`,
      )
      .run(grantId, reason, detail, at);
  }

  getEnding(grantId: string): GrantEndingRecord | null {
    const row = this.db
      .prepare(
        "SELECT reason, detail, recorded_at FROM pdpp_grant_endings WHERE grant_id = ?",
      )
      .get(grantId) as
      | { reason: string; detail: string | null; recorded_at: string }
      | undefined;
    return row
      ? { reason: row.reason, detail: row.detail, recordedAt: row.recorded_at }
      : null;
  }

  // -- lifecycle token disabling (L1716) ----------------------------------

  disableDigest(tokenHash: string, at: string): boolean {
    const result = this.db
      .prepare(
        `INSERT INTO pdpp_lifecycle_disabled_tokens (token_hash, disabled_at)
         VALUES (?, ?) ON CONFLICT (token_hash) DO NOTHING`,
      )
      .run(tokenHash, at);
    if (result.changes > 0) {
      this.history.append(
        "lifecycle_token_disabled",
        null,
        { token_hash: tokenHash },
        at,
      );
    }
    return result.changes > 0;
  }

  isDigestDisabled(tokenHash: string): boolean {
    return (
      this.db
        .prepare(
          "SELECT 1 FROM pdpp_lifecycle_disabled_tokens WHERE token_hash = ?",
        )
        .get(tokenHash) !== undefined
    );
  }

  /**
   * The newest `limit` token digests issued to `clientId` for one grant
   * (access, refresh and recovery tokens together, by issue time).
   */
  recentTokenDigestsFor(
    clientId: string,
    grantId: string,
    limit: number,
  ): string[] {
    const rows = this.db
      .prepare(
        `SELECT token_hash, issued_at FROM (
           SELECT token_hash, issued_at FROM pdpp_access_tokens
             WHERE grant_id = ? AND client_id = ? AND token_kind = 'client'
           UNION ALL
           SELECT t.token_hash, t.issued_at FROM pdpp_refresh_tokens t
             JOIN pdpp_refresh_families f ON f.family_id = t.family_id
             JOIN pdpp_grants g ON g.grant_id = f.grant_id
             WHERE f.grant_id = ? AND g.client_id = ?
         ) ORDER BY issued_at DESC LIMIT ?`,
      )
      .all(grantId, clientId, grantId, clientId, limit) as {
      token_hash: string;
    }[];
    const recovery = (
      this.db
        .prepare(
          "SELECT token_hash, grant_ids_json FROM pdpp_recovery_tokens WHERE client_id = ? ORDER BY issued_at DESC",
        )
        .all(clientId) as { token_hash: string; grant_ids_json: string }[]
    )
      .filter((r) =>
        (JSON.parse(r.grant_ids_json) as string[]).includes(grantId),
      )
      .slice(0, limit);
    return Array.from(
      new Set([
        ...rows.map((r) => r.token_hash),
        ...recovery.map((r) => r.token_hash),
      ]),
    ).slice(0, limit);
  }

  /** Digests of every data token issued to `clientId` for these grants. */
  tokenDigestsFor(clientId: string, grantIds: string[]): string[] {
    const out: string[] = [];
    for (const grantId of grantIds) {
      const access = this.db
        .prepare(
          `SELECT token_hash FROM pdpp_access_tokens
           WHERE grant_id = ? AND client_id = ? AND token_kind = 'client'`,
        )
        .all(grantId, clientId) as { token_hash: string }[];
      const refresh = this.db
        .prepare(
          `SELECT t.token_hash FROM pdpp_refresh_tokens t
           JOIN pdpp_refresh_families f ON f.family_id = t.family_id
           JOIN pdpp_grants g ON g.grant_id = f.grant_id
           WHERE f.grant_id = ? AND g.client_id = ?`,
        )
        .all(grantId, clientId) as { token_hash: string }[];
      const recovery = (
        this.db
          .prepare(
            "SELECT token_hash, grant_ids_json FROM pdpp_recovery_tokens WHERE client_id = ?",
          )
          .all(clientId) as { token_hash: string; grant_ids_json: string }[]
      ).filter((r) =>
        (JSON.parse(r.grant_ids_json) as string[]).includes(grantId),
      );
      out.push(
        ...access.map((r) => r.token_hash),
        ...refresh.map((r) => r.token_hash),
        ...recovery.map((r) => r.token_hash),
      );
    }
    return Array.from(new Set(out));
  }

  // -- lifecycle recovery (L1802) -----------------------------------------

  insertRecoveryApproval(input: {
    approvalId: string;
    subjectId: string;
    clientId: string;
    grantIds: string[];
    reviewDigest: string;
    statement: string;
    at: string;
    codeHash: string;
    redirectUri: string;
    codeChallenge: string | null;
    codeChallengeMethod: string | null;
    codeExpiresAt: string;
  }): void {
    this.db
      .prepare(
        `INSERT INTO pdpp_recovery_approvals
           (approval_id, subject_id, client_id, grant_ids_json, review_digest, statement, approved_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.approvalId,
        input.subjectId,
        input.clientId,
        JSON.stringify(input.grantIds),
        input.reviewDigest,
        input.statement,
        input.at,
      );
    this.db
      .prepare(
        `INSERT INTO pdpp_recovery_codes
           (code_hash, approval_id, client_id, redirect_uri, code_challenge, code_challenge_method, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.codeHash,
        input.approvalId,
        input.clientId,
        input.redirectUri,
        input.codeChallenge,
        input.codeChallengeMethod,
        input.codeExpiresAt,
      );
    this.history.append(
      "recovery_approved",
      null,
      {
        approval_id: input.approvalId,
        client_id: input.clientId,
        grant_ids: input.grantIds,
      },
      input.at,
    );
  }

  hasRecoveryCode(codeHash: string): boolean {
    return (
      this.db
        .prepare("SELECT 1 FROM pdpp_recovery_codes WHERE code_hash = ?")
        .get(codeHash) !== undefined
    );
  }

  /** Consume a recovery code atomically (same rule as AS item 19). */
  consumeRecoveryCode(
    codeHash: string,
    at: string,
  ): {
    approvalId: string;
    clientId: string;
    subjectId: string;
    grantIds: string[];
    redirectUri: string;
    codeChallenge: string | null;
    codeChallengeMethod: string | null;
  } | null {
    const result = this.db
      .prepare(
        `UPDATE pdpp_recovery_codes SET redeemed_at = ?
         WHERE code_hash = ? AND redeemed_at IS NULL AND expires_at > ?`,
      )
      .run(at, codeHash, at);
    if (result.changes === 0) return null;
    const row = this.db
      .prepare(
        `SELECT c.approval_id, c.client_id, c.redirect_uri, c.code_challenge, c.code_challenge_method,
                a.subject_id, a.grant_ids_json
         FROM pdpp_recovery_codes c JOIN pdpp_recovery_approvals a ON a.approval_id = c.approval_id
         WHERE c.code_hash = ?`,
      )
      .get(codeHash) as {
      approval_id: string;
      client_id: string;
      redirect_uri: string;
      code_challenge: string | null;
      code_challenge_method: string | null;
      subject_id: string;
      grant_ids_json: string;
    };
    this.history.append(
      "recovery_code_redeemed",
      null,
      { approval_id: row.approval_id },
      at,
    );
    return {
      approvalId: row.approval_id,
      clientId: row.client_id,
      subjectId: row.subject_id,
      grantIds: JSON.parse(row.grant_ids_json) as string[],
      redirectUri: row.redirect_uri,
      codeChallenge: row.code_challenge,
      codeChallengeMethod: row.code_challenge_method,
    };
  }

  insertRecoveryToken(input: {
    tokenHash: string;
    approvalId: string;
    clientId: string;
    subjectId: string;
    grantIds: string[];
    at: string;
  }): void {
    this.db
      .prepare(
        `INSERT INTO pdpp_recovery_tokens
           (token_hash, approval_id, client_id, subject_id, grant_ids_json, issued_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.tokenHash,
        input.approvalId,
        input.clientId,
        input.subjectId,
        JSON.stringify(input.grantIds),
        input.at,
      );
  }

  getRecoveryToken(tokenHash: string): RecoveryTokenRecord | null {
    const row = this.db
      .prepare("SELECT * FROM pdpp_recovery_tokens WHERE token_hash = ?")
      .get(tokenHash) as
      | {
          approval_id: string;
          client_id: string;
          subject_id: string;
          grant_ids_json: string;
          issued_at: string;
          revoked_at: string | null;
        }
      | undefined;
    if (!row) return null;
    return {
      approvalId: row.approval_id,
      clientId: row.client_id,
      subjectId: row.subject_id,
      grantIds: JSON.parse(row.grant_ids_json) as string[],
      issuedAt: row.issued_at,
      revokedAt: row.revoked_at,
    };
  }

  revokeRecoveryToken(tokenHash: string, at: string): boolean {
    const result = this.db
      .prepare(
        "UPDATE pdpp_recovery_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
      )
      .run(at, tokenHash);
    if (result.changes > 0) {
      this.history.append(
        "recovery_token_revoked",
        null,
        { token_hash: tokenHash },
        at,
      );
    }
    return result.changes > 0;
  }

  // -- decommission --------------------------------------------------------

  confirmDecommission(at: string): void {
    this.db
      .prepare(
        "INSERT INTO pdpp_decommission (id, confirmed_at) VALUES (1, ?) ON CONFLICT (id) DO NOTHING",
      )
      .run(at);
    this.history.append("decommission_confirmed", null, {}, at);
  }

  decommissionConfirmedAt(): string | null {
    const row = this.db
      .prepare("SELECT confirmed_at FROM pdpp_decommission WHERE id = 1")
      .get() as { confirmed_at: string } | undefined;
    return row?.confirmed_at ?? null;
  }

  /** Whether any client data token was ever issued for the grant. */
  everIssuedClientToken(grantId: string): boolean {
    return (
      this.db
        .prepare(
          "SELECT 1 FROM pdpp_access_tokens WHERE grant_id = ? AND token_kind = 'client' LIMIT 1",
        )
        .get(grantId) !== undefined
    );
  }

  /** Whether some client access token for the grant is still live at `now`. */
  hasLiveAccessToken(grantId: string, now: string): boolean {
    return (
      this.db
        .prepare(
          `SELECT 1 FROM pdpp_access_tokens
           WHERE grant_id = ? AND token_kind = 'client' AND revoked_at IS NULL
             AND (expires_at IS NULL OR expires_at > ?) LIMIT 1`,
        )
        .get(grantId, now) !== undefined
    );
  }
}
