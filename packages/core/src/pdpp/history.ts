/**
 * Lifecycle durability evidence for the PDPP Authorization Server (spec-core
 * §7 "Lifecycle durability" L1810-L1829, §9 AS item 44).
 *
 * The mechanism this AS declares:
 *
 *   1. Every recorded event (terminal events: revocations, dispositions,
 *      erasure instructions; and the other recorded events L1824 lists:
 *      grant issuance, code redemption, `single_use` consumption, refresh
 *      supersession, instruction-id assignment, first return) is appended to a
 *      hash-chained log, `pdpp_history_log`, in the SAME SQLite transaction as
 *      its effect. Each row's hash covers the previous row's hash, so the head
 *      (seq, hash) commits to the whole prefix.
 *   2. After the commit and BEFORE the AS acknowledges the event, the AS
 *      durably rewrites an anchor file outside the SQLite file (write to a
 *      temporary file, fsync, rename, fsync the directory). The anchor holds
 *      the history epoch, the head (seq, hash), and the complete record of
 *      every effective erasure instruction (L1820: an `erase` answer MAY come
 *      from stale state only when the complete instruction was durable).
 *      L1823: "Before acknowledging a terminal event, the AS MUST durably
 *      advance whatever evidence its mechanism uses." A failed anchor write
 *      throws, and the route answers 503 instead of acknowledging.
 *   3. At open, the store compares the database with the anchor. The history
 *      is current only when the epochs match and the database contains the
 *      anchored head with the anchored hash. A database behind the anchor
 *      (restored from an older file), one whose row at the anchored position
 *      differs, one with a different epoch, or a missing anchor for a store
 *      that was anchored before, is NOT current, and every enforcement point
 *      fails closed (L1825) until the owner re-establishes it.
 *
 * Evidence may lag unacknowledged events (L1823): a database AHEAD of the
 * anchor is current, and the next advance catches the anchor up.
 *
 * What this does not detect is stated in docs/pdpp-durability-statement.md:
 * a rollback that restores the anchor together with the database (a whole
 * `<storageRoot>` or VM snapshot revert) leaves them consistent with each
 * other, so it is undetected (L1814 permits that only when disclosed).
 */

import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  openSync,
  readFileSync,
  renameSync,
  writeSync,
} from "node:fs";
import { dirname } from "node:path";
import type Database from "better-sqlite3";

export const HISTORY_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS pdpp_history_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  epoch TEXT NOT NULL,
  -- 1 once an anchor file has been written for this epoch. A missing anchor
  -- for an anchored store is history loss, not a fresh install.
  anchored INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS pdpp_history_log (
  seq INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,
  grant_id TEXT,
  payload_json TEXT NOT NULL,
  at TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
`;

/** The complete record of an effective erasure instruction (L1820). */
export interface AnchoredErasure {
  grant_id: string;
  client_id: string;
  instruction_id: string;
  accepted_at: string;
  effective_at: string;
  stop_use_by: string;
  read_state: "revoked" | "expired";
  ended_at: string;
  /** The grant's owner, so a pending owner action can be matched (L1827). */
  subject_id?: string;
  /**
   * Digests of every token issued to the client for the grant, so the
   * client can still authenticate the query that delivers the instruction
   * when the grant's row is missing from a restored store (F5, L1820).
   */
  token_digests?: string[];
}

/** An erasure elected in advance, not yet effective (L1586). */
export interface AnchoredElection {
  grant_id: string;
  client_id: string;
  instruction_id: string;
  accepted_at: string;
  advance: true;
}

/**
 * Everything the anchor carries besides the head. Derived from the database
 * at every advance, so it always covers every effective instruction, advance
 * election and lifecycle-disabled token up to the anchored position.
 */
export interface AnchorEvidence {
  erasures: Record<string, AnchoredErasure>;
  elections: Record<string, AnchoredElection>;
  /** Token digests disabled for lifecycle use (L1716), incl. revoked recovery tokens. */
  disabled_digests: string[];
}

export interface AnchorDocument extends AnchorEvidence {
  format: 1 | 2;
  epoch: string;
  seq: number;
  hash: string;
  updated_at: string;
}

const EMPTY_EVIDENCE: AnchorEvidence = {
  erasures: {},
  elections: {},
  disabled_digests: [],
};

function evidenceKey(e: AnchorEvidence): string {
  const sorted = <T>(r: Record<string, T>) =>
    Object.keys(r)
      .sort()
      .map((k) => [k, r[k]]);
  return JSON.stringify([
    sorted(e.erasures),
    sorted(e.elections),
    [...e.disabled_digests].sort(),
  ]);
}

/** File I/O the anchor uses. Injectable so tests can fail the advance. */
export interface AnchorIo {
  read(path: string): string | null;
  /** Replace `path` with `content` durably, or throw. */
  writeDurably(path: string, content: string): void;
}

export const defaultAnchorIo: AnchorIo = {
  read(path) {
    if (!existsSync(path)) return null;
    return readFileSync(path, "utf8");
  },
  writeDurably(path, content) {
    const tmp = `${path}.tmp-${randomBytes(6).toString("hex")}`;
    const fd = openSync(tmp, "w", 0o600);
    try {
      writeSync(fd, content);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, path);
    // The rename is durable only once the directory entry is flushed.
    fsyncDirectory(path);
  },
};

/** Count of directory fsyncs the platform refused (durability statement). */
export let directoryFsyncFailures = 0;

/**
 * fsync the directory that holds `path`, so a created or renamed entry is
 * durable. Some platforms refuse fsync on a directory handle. That is not
 * swallowed silently: it is counted, a process warning is emitted once, and
 * the durability statement says that the entry's durability then rests on
 * the filesystem.
 */
export function fsyncDirectory(path: string): boolean {
  try {
    const dirFd = openSync(dirname(path), "r");
    try {
      fsyncSync(dirFd);
    } finally {
      closeSync(dirFd);
    }
    return true;
  } catch (err) {
    directoryFsyncFailures += 1;
    if (directoryFsyncFailures === 1) {
      process.emitWarning(
        `PDPP durability: fsync of directory ${dirname(path)} failed (${
          err instanceof Error ? err.message : String(err)
        }); a new or renamed anchor or journal entry may not survive power loss`,
        "PdppDurabilityWarning",
      );
    }
    return false;
  }
}

/** Thrown when the evidence cannot be advanced: the event is NOT acknowledged. */
export class HistoryEvidenceError extends Error {
  constructor(cause: unknown) {
    super(
      `PDPP lifecycle evidence could not be advanced: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
    );
    this.name = "HistoryEvidenceError";
  }
}

export type HistoryStatus =
  | { current: true }
  | {
      current: false;
      reason:
        | "anchor_missing"
        | "anchor_unreadable"
        | "epoch_mismatch"
        | "history_behind_anchor"
        | "history_diverged";
    };

const GENESIS_HASH = "0".repeat(64);

function chainHash(
  prev: string,
  seq: number,
  kind: string,
  grantId: string | null,
  payload: string,
  at: string,
): string {
  return createHash("sha256")
    .update(JSON.stringify([prev, seq, kind, grantId, payload, at]), "utf8")
    .digest("hex");
}

/**
 * The hash-chained log plus its anchor. One per store.
 *
 * `anchorPath` null disables the anchor (an in-memory test database). Such a
 * store is always current and its statement is "no restore detection".
 */
export class HistoryRecorder {
  private epoch: string;
  private status: HistoryStatus = { current: true };
  private anchor: AnchorDocument | null = null;
  private txAppended = false;
  /**
   * Committed events (or evidence) not yet written to the anchor. Kept
   * across a failed advance, and recomputed at open (`catchUp`), so the next
   * advance writes it before anything is acknowledged (F1).
   */
  private owed = false;
  private evidenceProvider: () => AnchorEvidence = () => EMPTY_EVIDENCE;
  private anchoredBefore = false;

  constructor(
    private readonly db: Database.Database,
    private readonly anchorPath: string | null,
    private readonly io: AnchorIo = defaultAnchorIo,
  ) {
    db.exec(HISTORY_SCHEMA_SQL);
    const meta = db
      .prepare("SELECT epoch, anchored FROM pdpp_history_meta WHERE id = 1")
      .get() as { epoch: string; anchored: number } | undefined;
    if (!meta) {
      this.epoch = newEpoch();
      db.prepare(
        "INSERT INTO pdpp_history_meta (id, epoch, anchored) VALUES (1, ?, 0)",
      ).run(this.epoch);
    } else {
      this.epoch = meta.epoch;
    }
    this.anchoredBefore = meta?.anchored === 1;
    this.status = this.check();
  }

  /** The store supplies the evidence, derived from its tables. */
  setEvidenceProvider(provider: () => AnchorEvidence): void {
    this.evidenceProvider = provider;
  }

  /**
   * At open, after the provider is set: a current history whose anchor lags
   * the database head, or lacks evidence the database holds (F1, F3), owes
   * an advance. It is attempted now; if it fails, it stays owed and the next
   * acknowledgement writes it first (or fails).
   */
  catchUp(now: string): void {
    if (!this.anchorPath || !this.status.current) return;
    const head = this.head();
    if (
      !this.anchor ||
      this.anchor.seq !== head.seq ||
      evidenceKey(this.anchor) !== evidenceKey(this.evidenceProvider())
    ) {
      this.owed = true;
    }
    if (!this.owed) return;
    try {
      this.advance(now);
    } catch {
      // stays owed
    }
  }

  /** Whether committed evidence is still unwritten (tests and the statement). */
  evidenceOwed(): boolean {
    return this.owed;
  }

  /** The anchored election (usable while the history is not current). */
  anchoredElection(grantId: string): AnchoredElection | null {
    return this.anchor?.elections?.[grantId] ?? null;
  }

  anchoredElections(): AnchoredElection[] {
    return Object.values(this.anchor?.elections ?? {});
  }

  anchoredDisabledDigests(): string[] {
    return this.anchor?.disabled_digests ?? [];
  }

  /** Whether the database history is current under the declared mechanism. */
  current(): HistoryStatus {
    return this.status;
  }

  isCurrent(): boolean {
    return this.status.current;
  }

  /** The anchored erasure evidence (usable while the history is not current). */
  anchoredErasure(grantId: string): AnchoredErasure | null {
    return this.anchor?.erasures[grantId] ?? null;
  }

  anchoredErasures(): AnchoredErasure[] {
    return Object.values(this.anchor?.erasures ?? {});
  }

  /** Append one recorded event. Call only inside the effect's transaction. */
  append(
    kind: string,
    grantId: string | null,
    payload: unknown,
    at: string,
  ): void {
    const head = this.head();
    const seq = head.seq + 1;
    const body = JSON.stringify(payload ?? null);
    const hash = chainHash(head.hash, seq, kind, grantId, body, at);
    this.db
      .prepare(
        `INSERT INTO pdpp_history_log (seq, kind, grant_id, payload_json, at, prev_hash, hash)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(seq, kind, grantId, body, at, head.hash, hash);
    this.txAppended = true;
  }

  /** Forget the append flag of a rolled-back transaction. */
  discardPending(): void {
    this.txAppended = false;
  }

  /** The transaction committed: its events are now owed to the anchor. */
  markCommitted(): void {
    this.owed = this.owed || this.txAppended;
    this.txAppended = false;
  }

  /**
   * Advance the anchor to the database head. Throws HistoryEvidenceError on
   * failure, so the caller does not acknowledge (L1823, case D4).
   */
  advance(now: string): void {
    if (!this.anchorPath) {
      this.owed = false;
      return;
    }
    if (!this.owed) return;
    // A store that is not current must never re-anchor on its own: that would
    // bless a rolled-back history. Only `reestablish` may do that.
    if (!this.status.current)
      throw new HistoryEvidenceError("history is not current");
    const head = this.head();
    const next: AnchorDocument = {
      format: 2,
      epoch: this.epoch,
      seq: head.seq,
      hash: head.hash,
      updated_at: now,
      // F3: derived from the database, so the anchored set always contains
      // every effective instruction, election and disabled digest up to the
      // anchored position, whatever an earlier failed advance dropped.
      ...this.evidenceProvider(),
    };
    try {
      this.io.writeDurably(this.anchorPath, JSON.stringify(next));
    } catch (err) {
      throw new HistoryEvidenceError(err);
    }
    this.owed = false;
    this.anchor = next;
    this.db
      .prepare("UPDATE pdpp_history_meta SET anchored = 1 WHERE id = 1")
      .run();
  }

  /**
   * Accept the database as the new authoritative history under a new epoch.
   * The caller (`PdppAuthStore.reestablishHistory`) must first apply every
   * anchored instruction and pending owner action and invalidate every grant
   * whose terminal events may be missing (L1823).
   */
  reanchor(now: string): void {
    this.epoch = newEpoch();
    this.db
      .prepare(
        "UPDATE pdpp_history_meta SET epoch = ?, anchored = 0 WHERE id = 1",
      )
      .run(this.epoch);
    this.status = { current: true };
    this.owed = true;
    this.advance(now);
  }

  private head(): { seq: number; hash: string } {
    const row = this.db
      .prepare(
        "SELECT seq, hash FROM pdpp_history_log ORDER BY seq DESC LIMIT 1",
      )
      .get() as { seq: number; hash: string } | undefined;
    return row ?? { seq: 0, hash: GENESIS_HASH };
  }

  private check(): HistoryStatus {
    const anchoredBefore = this.anchoredBefore;
    if (!this.anchorPath) return { current: true };
    let raw: string | null;
    try {
      raw = this.io.read(this.anchorPath);
    } catch {
      return { current: false, reason: "anchor_unreadable" };
    }
    if (raw === null) {
      if (anchoredBefore) return { current: false, reason: "anchor_missing" };
      // A fresh store, or one created before this mechanism existed: anchor
      // it now. Earlier restores of such a store cannot be detected; the
      // durability statement says so. `catchUp` writes the first anchor.
      this.owed = true;
      return { current: true };
    }
    let doc: AnchorDocument;
    try {
      doc = JSON.parse(raw) as AnchorDocument;
      if ((doc.format !== 1 && doc.format !== 2) || typeof doc.seq !== "number")
        throw new Error();
      // Format 1 (first WP6 build) carried erasures only.
      doc.elections ??= {};
      doc.disabled_digests ??= [];
      doc.erasures ??= {};
    } catch {
      return { current: false, reason: "anchor_unreadable" };
    }
    this.anchor = doc;
    if (doc.epoch !== this.epoch)
      return { current: false, reason: "epoch_mismatch" };
    const head = this.head();
    if (head.seq < doc.seq)
      return { current: false, reason: "history_behind_anchor" };
    if (doc.seq > 0) {
      const row = this.db
        .prepare("SELECT hash FROM pdpp_history_log WHERE seq = ?")
        .get(doc.seq) as { hash: string } | undefined;
      if (!row || row.hash !== doc.hash) {
        return { current: false, reason: "history_diverged" };
      }
    }
    return { current: true };
  }
}

function newEpoch(): string {
  return `ep_${randomBytes(16).toString("hex")}`;
}

/**
 * Owner actions accepted while the history is unavailable (L1827: "While its
 * history is unavailable, the AS MUST still accept an owner's revocation,
 * disposition, or erasure request [...] MUST record each such request durably
 * before it acknowledges it, and MUST apply each to the history before any
 * answer for the affected grant once the history is re-established").
 *
 * Kept as an append-only JSON-lines file beside the anchor, outside the
 * SQLite file whose history is unavailable. Each line is written and
 * fsync'd before the route answers 202.
 */
export interface PendingOwnerAction {
  action_id: string;
  subject_id: string;
  recorded_at: string;
  /**
   * `end` and `erasure` are owner actions; `first_return` records that a
   * stale history returned an anchored instruction (L1820).
   */
  kind: "end" | "erasure" | "first_return";
  /** For `end`: the owner action; for `erasure`: immediate or advance. */
  action: string;
  grant_ids: string[];
  dispositions: Record<string, "keep" | "delete">;
}

export interface PendingJournalIo {
  read(path: string): string | null;
  appendDurably(path: string, line: string): void;
  writeDurably(path: string, content: string): void;
}

export const defaultPendingJournalIo: PendingJournalIo = {
  read: (path) => (existsSync(path) ? readFileSync(path, "utf8") : null),
  appendDurably(path, line) {
    const created = !existsSync(path);
    const fd = openSync(path, "a", 0o600);
    try {
      writeSync(fd, line);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    // F6: a new journal file's directory entry must be durable before the
    // first 202 that relies on it.
    if (created) fsyncDirectory(path);
  },
  writeDurably: (path, content) => defaultAnchorIo.writeDurably(path, content),
};

export class PendingActionJournal {
  constructor(
    private readonly path: string | null,
    private readonly io: PendingJournalIo = defaultPendingJournalIo,
  ) {}

  /** Durably record one action, or throw (the route then answers 503). */
  append(action: PendingOwnerAction): void {
    if (!this.path) throw new Error("no pending-action journal is configured");
    this.io.appendDurably(this.path, `${JSON.stringify(action)}\n`);
  }

  list(): PendingOwnerAction[] {
    if (!this.path) return [];
    const raw = this.io.read(this.path);
    if (!raw) return [];
    return raw
      .split("\n")
      .filter((line) => line.trim().length > 0)
      .flatMap((line) => {
        try {
          return [JSON.parse(line) as PendingOwnerAction];
        } catch {
          // A torn last line was never acknowledged (the fsync precedes the
          // 202), so dropping it loses no acknowledged action.
          return [];
        }
      });
  }

  /** Empty the journal once every action is applied to the history. */
  clear(): void {
    if (!this.path) return;
    this.io.writeDurably(this.path, "");
  }
}
