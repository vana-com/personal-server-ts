import type { Database } from "better-sqlite3";
import { createHash } from "node:crypto";
import {
  canonicalJson,
  type ReplicaEnvelope,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  decideCopyPromotion,
  indexEvidenceFromFacts,
  replicaCopyKey,
  type CopyDecision,
  type CopyDisposition,
  type FinalizedFact,
  type Hex,
  type IndexEvidence,
} from "@opendatalabs/personal-server-ts-core/replication/copy-promotion";
import { replicaChainCommitment } from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import type { Predecessor } from "@opendatalabs/personal-server-ts-core/replication/transport";

/**
 * Batch-copy retention, finalized-fact history and batch disposition
 * (contract v3.1, replica-copy-promotion-contract-1021-v3.md). Replica tables
 * only; no main table changes. Every transition is one SQLite transaction and
 * idempotent under replay.
 */
export const REPLICA_COPY_MIGRATION = `
CREATE TABLE IF NOT EXISTS pdpp_replica_copies (
  id TEXT NOT NULL,
  copy_key TEXT NOT NULL,
  writer_id TEXT NOT NULL,
  batch_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  previous_json TEXT,
  fragment_count INTEGER NOT NULL CHECK (fragment_count >= 1),
  fragment_commitments_json TEXT NOT NULL,
  envelope_digest TEXT NOT NULL,
  envelope_json TEXT NOT NULL,
  blobs_json TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','confirmed','quarantined')),
  reason TEXT CHECK (reason IS NULL OR reason IN ('copy_conflict','finalized_conflict')),
  CHECK ((state = 'quarantined') = (reason IS NOT NULL)),
  PRIMARY KEY (id, copy_key)
);
CREATE TABLE IF NOT EXISTS pdpp_replica_copy_rejects (
  id TEXT NOT NULL, reject_key TEXT NOT NULL, claimed_copy_key TEXT,
  reason TEXT NOT NULL, received_at INTEGER NOT NULL,
  PRIMARY KEY (id, reject_key)
);
CREATE TRIGGER IF NOT EXISTS pdpp_copy_rejects_no_update BEFORE UPDATE ON pdpp_replica_copy_rejects BEGIN SELECT RAISE(ABORT, 'copy rejects are append-only'); END;
CREATE TRIGGER IF NOT EXISTS pdpp_copy_rejects_no_delete BEFORE DELETE ON pdpp_replica_copy_rejects BEGIN SELECT RAISE(ABORT, 'copy rejects are append-only'); END;
CREATE TABLE IF NOT EXISTS pdpp_replica_finalized_facts (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  chain_id INTEGER NOT NULL, registry TEXT NOT NULL, owner TEXT NOT NULL,
  scope TEXT NOT NULL, fragment_index INTEGER NOT NULL, id TEXT NOT NULL,
  current_version TEXT NOT NULL, status TEXT NOT NULL, commitment TEXT NOT NULL,
  block_number TEXT NOT NULL, block_hash TEXT NOT NULL, eligible INTEGER NOT NULL,
  observed_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS pdpp_finalized_facts_id ON pdpp_replica_finalized_facts(id, fragment_index, seq);
CREATE INDEX IF NOT EXISTS pdpp_finalized_facts_scope ON pdpp_replica_finalized_facts(scope, seq);
CREATE TRIGGER IF NOT EXISTS pdpp_finalized_facts_no_update BEFORE UPDATE ON pdpp_replica_finalized_facts BEGIN SELECT RAISE(ABORT, 'finalized facts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS pdpp_finalized_facts_no_delete BEFORE DELETE ON pdpp_replica_finalized_facts BEGIN SELECT RAISE(ABORT, 'finalized facts are append-only'); END;
CREATE TABLE IF NOT EXISTS pdpp_replica_batch_disposition (
  id TEXT PRIMARY KEY,
  writer_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('open','promoted','terminal')),
  promoted_copy_key TEXT,
  terminal_reason TEXT,
  CHECK ((state = 'promoted') = (promoted_copy_key IS NOT NULL)),
  CHECK ((state = 'terminal') = (terminal_reason IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS pdpp_batch_disposition_writer ON pdpp_replica_batch_disposition(writer_id, sequence);
CREATE TRIGGER IF NOT EXISTS pdpp_batch_disposition_absorbing BEFORE UPDATE ON pdpp_replica_batch_disposition
WHEN OLD.state = 'terminal' OR (OLD.state = 'promoted' AND NEW.state = 'open')
BEGIN SELECT RAISE(ABORT, 'batch disposition transitions are absorbing'); END;
CREATE TABLE IF NOT EXISTS pdpp_replica_promotion_receipts (
  id TEXT PRIMARY KEY, copy_key TEXT NOT NULL, envelope_digest TEXT NOT NULL
);
`;

/** One fragment of a copy, as verified at download (bytes hash to these). */
export interface CopyFragment {
  dataHash: string;
  metadataHash: string;
}

export interface StagedCopy {
  id: string;
  writer: string;
  batch: string;
  sequence: number;
  previous: Predecessor | null;
  /** The payload digest every fragment embeds (`sha256:<hex>`). */
  envelopeDigest: string;
  envelope: ReplicaEnvelope;
  fragments: readonly CopyFragment[];
  /** Verified pending custody, already under pendingBlobKey(id, blobId). */
  blobs: readonly { blobId: string; size: number }[];
}

export type CopyPromotion =
  | { kind: "promoted"; copyKey: Hex; envelopeDigest: string; replay: boolean }
  | { kind: "wait_predecessor"; predecessor: string }
  | { kind: "terminal"; reason: string };

/** Precondition failures a caller can act on; never exception text. */
export class ReplicaCopyRefused extends Error {
  readonly code = "replica_copy_refused";
  constructor(readonly reason: string) {
    super(reason);
    this.name = "ReplicaCopyRefused";
  }
}

/** Completed non-matching re-downloads before the owner decides (contract F4). */
export const REPLICA_REFETCH_BUDGET = 5;

const lowerHex = /^0x[0-9a-f]{64}$/;

export function createReplicaCopies(deps: {
  db: Database;
  owner: string;
  /** Import an envelope into canonical state (the receiver's import). */
  importEnvelope(
    envelope: ReplicaEnvelope,
    blobs: StagedCopy["blobs"],
    id: string,
  ): void;
  /**
   * Withdraw a connection from every reader: connection quarantine, canonical
   * withdrawal and an integrity epoch raise, in the caller's transaction.
   */
  quarantineConnection(instance: string): void;
  /**
   * The single pending preview of a batch, keyed by id: at most one copy is
   * ever `pending` (contract B), so the read side keeps its id key.
   */
  preview: {
    show(id: string, envelope: ReplicaEnvelope, blobsJson: string): void;
    hide(id: string, state: "confirmed" | "quarantined"): void;
  };
  /** Drop pending custody bytes no retained copy still needs. */
  releaseBytes(id: string, blobIds: readonly string[]): void;
  now: () => number;
}) {
  const { db } = deps;
  type Row = {
    id: string;
    copy_key: string;
    writer_id: string;
    batch_id: string;
    sequence: number;
    previous_json: string | null;
    fragment_count: number;
    fragment_commitments_json: string;
    envelope_digest: string;
    envelope_json: string;
    blobs_json: string;
    state: "pending" | "confirmed" | "quarantined";
    reason: "copy_conflict" | "finalized_conflict" | null;
  };
  const rows = (id: string) =>
    db
      .prepare("SELECT * FROM pdpp_replica_copies WHERE id=? ORDER BY copy_key")
      .all(id) as Row[];
  const dispositionRow = (id: string) =>
    db
      .prepare("SELECT * FROM pdpp_replica_batch_disposition WHERE id=?")
      .get(id) as
      | {
          writer_id: string;
          sequence: number;
          state: "open" | "promoted" | "terminal";
          promoted_copy_key: string | null;
          terminal_reason: string | null;
        }
      | undefined;
  function disposition(id: string): CopyDisposition {
    const row = dispositionRow(id);
    if (!row || row.state === "open") return { state: "open" };
    if (row.state === "promoted")
      return { state: "promoted", copyKey: row.promoted_copy_key as Hex };
    return { state: "terminal", reason: row.terminal_reason! };
  }
  function evidence(id: string): Map<number, IndexEvidence> {
    const facts = db
      .prepare(
        "SELECT * FROM pdpp_replica_finalized_facts WHERE id=? ORDER BY fragment_index,seq",
      )
      .all(id) as {
      fragment_index: number;
      chain_id: number;
      registry: string;
      owner: string;
      current_version: string;
      status: string;
      commitment: string;
      block_number: string;
      block_hash: string;
      eligible: number;
    }[];
    const byIndex = new Map<number, FinalizedFact[]>();
    for (const f of facts)
      byIndex.set(f.fragment_index, [
        ...(byIndex.get(f.fragment_index) ?? []),
        {
          chainId: f.chain_id,
          registry: f.registry,
          owner: f.owner,
          currentVersion: f.current_version,
          status: f.status,
          commitment: f.commitment as Hex,
          blockNumber: BigInt(f.block_number),
          blockHash: f.block_hash as Hex,
          eligible: f.eligible === 1,
        },
      ]);
    return new Map(
      [...byIndex].map(([index, list]) => [
        index,
        indexEvidenceFromFacts(list),
      ]),
    );
  }
  function decide(
    id: string,
    refetch: { attempts: number; budget: number },
  ): CopyDecision {
    return decideCopyPromotion({
      id,
      disposition: disposition(id),
      copies: rows(id).map((row) => ({
        copyKey: row.copy_key as Hex,
        fragmentCommitments: JSON.parse(row.fragment_commitments_json) as Hex[],
        validity: "valid",
      })),
      evidence: evidence(id),
      refetch,
    });
  }

  /** Raise reasons only: copy_conflict < finalized_conflict; confirmed copies stay. */
  function quarantine(
    id: string,
    keys: readonly string[],
    reason: "copy_conflict" | "finalized_conflict",
    includeConfirmed = false,
  ) {
    for (const key of keys) {
      const row = db
        .prepare(
          "SELECT state,reason FROM pdpp_replica_copies WHERE id=? AND copy_key=?",
        )
        .get(id, key) as Pick<Row, "state" | "reason"> | undefined;
      if (!row) continue;
      if (row.state === "confirmed" && !includeConfirmed) continue;
      if (row.reason === "finalized_conflict") continue;
      if (row.reason === reason) continue;
      db.prepare(
        "UPDATE pdpp_replica_copies SET state='quarantined',reason=? WHERE id=? AND copy_key=?",
      ).run(reason, id, key);
    }
  }
  /** Keep the read side's single pending preview equal to the copy states. */
  function syncPreview(id: string) {
    const all = rows(id);
    const pending = all.filter((row) => row.state === "pending");
    if (pending.length === 1) {
      const row = pending[0]!;
      deps.preview.show(
        id,
        JSON.parse(row.envelope_json) as ReplicaEnvelope,
        row.blobs_json,
      );
    } else
      deps.preview.hide(
        id,
        all.some((row) => row.state === "confirmed")
          ? "confirmed"
          : "quarantined",
      );
  }
  function apply(id: string, decision: CopyDecision) {
    if (decision.kind === "terminal") terminate(id, decision.reason);
    else if (decision.kind !== "promote")
      quarantine(id, decision.quarantine, "copy_conflict");
    syncPreview(id);
  }
  /** The batch at (writer, sequence - 1), and whether it may precede this one. */
  function predecessorOf(row: Row): CopyPromotion | undefined {
    const previous = row.previous_json
      ? (JSON.parse(row.previous_json) as Predecessor)
      : null;
    if (row.sequence === 1)
      return previous
        ? { kind: "terminal", reason: "predecessor_mismatch" }
        : undefined;
    if (!previous) return { kind: "terminal", reason: "predecessor_mismatch" };
    const predecessor = canonicalJson([row.writer_id, previous.batch]);
    const state = dispositionRow(predecessor);
    if (state?.state === "terminal")
      return { kind: "terminal", reason: "predecessor_terminal" };
    if (state?.state !== "promoted" || state.sequence !== row.sequence - 1)
      return { kind: "wait_predecessor", predecessor };
    const receipt = db
      .prepare(
        "SELECT envelope_digest FROM pdpp_replica_promotion_receipts WHERE id=?",
      )
      .get(predecessor) as { envelope_digest: string } | undefined;
    return receipt?.envelope_digest === previous.digest
      ? undefined
      : { kind: "terminal", reason: "predecessor_mismatch" };
  }

  /**
   * Terminal transition (contract F3, amendments A and H): the batch and every
   * later batch of its writer become terminal; their valid copies rise to
   * finalized_conflict; every connection a promoted batch in that set touched
   * is withdrawn from all readers in this same transaction.
   */
  function terminate(id: string, reason: string) {
    const root = dispositionRow(id);
    if (!root) return;
    const chain = db
      .prepare(
        "SELECT id,state,promoted_copy_key FROM pdpp_replica_batch_disposition WHERE writer_id=? AND sequence>=? ORDER BY sequence",
      )
      .all(root.writer_id, root.sequence) as {
      id: string;
      state: string;
      promoted_copy_key: string | null;
    }[];
    const connections = new Set<string>();
    for (const batch of chain) {
      if (batch.state === "promoted" && batch.promoted_copy_key) {
        const promoted = db
          .prepare(
            "SELECT envelope_json FROM pdpp_replica_copies WHERE id=? AND copy_key=?",
          )
          .get(batch.id, batch.promoted_copy_key) as
          { envelope_json: string } | undefined;
        if (promoted)
          for (const op of (
            JSON.parse(promoted.envelope_json) as ReplicaEnvelope
          ).operations)
            connections.add(op.connectionId);
      }
      if (batch.state !== "terminal")
        db.prepare(
          "UPDATE pdpp_replica_batch_disposition SET state='terminal',promoted_copy_key=NULL,terminal_reason=? WHERE id=?",
        ).run(batch.id === id ? reason : "predecessor_terminal", batch.id);
      quarantine(
        batch.id,
        rows(batch.id).map((row) => row.copy_key),
        "finalized_conflict",
        true,
      );
      syncPreview(batch.id);
    }
    for (const instance of connections) deps.quarantineConnection(instance);
  }

  return {
    REPLICA_COPY_MIGRATION,
    decide,
    disposition,
    copies(id: string) {
      return rows(id).map((row) => ({
        copyKey: row.copy_key as Hex,
        state: row.state,
        reason: row.reason,
        envelopeDigest: row.envelope_digest,
      }));
    },
    /**
     * Retain one valid copy (contract §3 "Stage copy", amendment C), then
     * decide and apply the quarantine set. Returns the copy key and decision.
     * An input failing a validity check is recorded as a reject only.
     */
    stage(
      copy: StagedCopy,
      refetch: { attempts: number; budget: number },
    ): { copyKey: Hex | undefined; decision: CopyDecision } {
      return db
        .transaction(() => {
          const pairs = copy.fragments.map((f) => [f.dataHash, f.metadataHash]);
          const invalid =
            copy.id !== canonicalJson([copy.writer, copy.batch])
              ? "identity_mismatch"
              : !copy.fragments.length
                ? "empty"
                : pairs.flat().some((h) => !lowerHex.test(h))
                  ? "hash_encoding"
                  : copy.envelope.owner !== deps.owner
                    ? "owner"
                    : undefined;
          if (invalid) {
            db.prepare(
              "INSERT OR IGNORE INTO pdpp_replica_copy_rejects VALUES (?,?,?,?,?)",
            ).run(
              copy.id,
              createHash("sha256").update(canonicalJson(pairs)).digest("hex"),
              null,
              invalid,
              deps.now(),
            );
            return {
              copyKey: undefined,
              decision: decide(copy.id, refetch),
            };
          }
          const commitments = copy.fragments.map(
            (f) =>
              replicaChainCommitment(
                f.dataHash as Hex,
                f.metadataHash as Hex,
              ).toLowerCase() as Hex,
          );
          const copyKey = replicaCopyKey(commitments);
          db.prepare(
            "INSERT OR IGNORE INTO pdpp_replica_batch_disposition (id,writer_id,sequence,state) VALUES (?,?,?,'open')",
          ).run(copy.id, copy.writer, copy.sequence);
          const existing = db
            .prepare(
              "SELECT envelope_digest,fragment_commitments_json FROM pdpp_replica_copies WHERE id=? AND copy_key=?",
            )
            .get(copy.id, copyKey) as
            | { envelope_digest: string; fragment_commitments_json: string }
            | undefined;
          if (existing) {
            // Same key, different content would need a keccak collision.
            if (
              existing.envelope_digest !== copy.envelopeDigest ||
              existing.fragment_commitments_json !== canonicalJson(commitments)
            )
              terminate(copy.id, "finalized_conflict");
          } else
            db.prepare(
              "INSERT INTO pdpp_replica_copies VALUES (?,?,?,?,?,?,?,?,?,?,?,'pending',NULL)",
            ).run(
              copy.id,
              copyKey,
              copy.writer,
              copy.batch,
              copy.sequence,
              copy.previous ? canonicalJson(copy.previous) : null,
              copy.fragments.length,
              canonicalJson(commitments),
              copy.envelopeDigest,
              canonicalJson(copy.envelope),
              canonicalJson(copy.blobs),
            );
          // A later batch of a terminal writer chain is terminal on staging (H).
          const earlierTerminal = db
            .prepare(
              "SELECT 1 FROM pdpp_replica_batch_disposition WHERE writer_id=? AND sequence<? AND state='terminal' LIMIT 1",
            )
            .get(copy.writer, copy.sequence);
          if (earlierTerminal && disposition(copy.id).state !== "terminal")
            terminate(copy.id, "predecessor_terminal");
          // A copy arriving after promotion decides reconcile_promoted, which
          // quarantines it below; the confirmed copy is untouched.
          const decision = decide(copy.id, refetch);
          if (decision.kind !== "promote") apply(copy.id, decision);
          else {
            quarantine(copy.id, decision.quarantine, "copy_conflict");
            syncPreview(copy.id);
          }
          return { copyKey, decision };
        })
        .immediate();
    },
    /**
     * Append a verified finalized fact for one fragment scope (F2). A fact
     * from another owner is refused (a diagnostic, never a fact). Returns
     * true when it is new.
     */
    recordFact(input: {
      id: string;
      scope: string;
      fragmentIndex: number;
      fact: FinalizedFact;
    }): boolean {
      if (input.fact.owner.toLowerCase() !== deps.owner.toLowerCase())
        throw new ReplicaCopyRefused("fact_authority");
      // A poll that observes the same state at a later block adds nothing a
      // decision reads (the latest fact's content is unchanged), so polling
      // a waiting slot does not grow the history.
      const latest = (
        db
          .prepare(
            "SELECT current_version,status,commitment,block_number,eligible FROM pdpp_replica_finalized_facts WHERE chain_id=? AND registry=? AND owner=? AND scope=? ORDER BY seq",
          )
          .all(
            input.fact.chainId,
            input.fact.registry.toLowerCase(),
            input.fact.owner.toLowerCase(),
            input.scope,
          ) as {
          current_version: string;
          status: string;
          commitment: string;
          block_number: string;
          eligible: number;
        }[]
      ).reduce<
        | {
            current_version: string;
            status: string;
            commitment: string;
            block_number: string;
            eligible: number;
          }
        | undefined
      >(
        (a, b) =>
          a === undefined || BigInt(b.block_number) >= BigInt(a.block_number)
            ? b
            : a,
        undefined,
      );
      if (
        latest &&
        BigInt(latest.block_number) <= input.fact.blockNumber &&
        latest.current_version === input.fact.currentVersion &&
        latest.status === input.fact.status &&
        latest.commitment === input.fact.commitment.toLowerCase() &&
        latest.eligible === (input.fact.eligible ? 1 : 0)
      )
        return false;
      return (
        db
          .prepare(
            "INSERT INTO pdpp_replica_finalized_facts (chain_id,registry,owner,scope,fragment_index,id,current_version,status,commitment,block_number,block_hash,eligible,observed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
          )
          .run(
            input.fact.chainId,
            input.fact.registry.toLowerCase(),
            input.fact.owner.toLowerCase(),
            input.scope,
            input.fragmentIndex,
            input.id,
            input.fact.currentVersion,
            input.fact.status,
            input.fact.commitment.toLowerCase(),
            input.fact.blockNumber.toString(),
            input.fact.blockHash.toLowerCase(),
            input.fact.eligible ? 1 : 0,
            deps.now(),
          ).changes > 0
      );
    },
    /** Apply a non-promoting decision's durable effects (coordinator step). */
    apply(id: string, decision: CopyDecision) {
      db.transaction(() => apply(id, decision)).immediate();
    },
    terminate(id: string, reason: string) {
      db.transaction(() => terminate(id, reason)).immediate();
    },
    /**
     * Promote one copy (contract §3, amendments E and F). Inside one
     * transaction: re-decide and re-check the predecessor; import the copy
     * under a savepoint; confirm it, quarantine the rest, record the
     * disposition and the receipt. A replay of a completed promotion returns
     * the original receipt and changes nothing. A bare promote (no key) is
     * refused when more than one copy is retained.
     */
    promote(input: { id: string; copyKey?: string }): CopyPromotion {
      return db
        .transaction((): CopyPromotion => {
          const all = rows(input.id);
          if (input.copyKey === undefined && all.length !== 1)
            throw new ReplicaCopyRefused("ambiguous_copy");
          const copyKey = (input.copyKey ?? all[0]!.copy_key).toLowerCase();
          const receipt = db
            .prepare(
              "SELECT copy_key,envelope_digest FROM pdpp_replica_promotion_receipts WHERE id=?",
            )
            .get(input.id) as
            { copy_key: string; envelope_digest: string } | undefined;
          const state = disposition(input.id);
          if (state.state === "terminal")
            return { kind: "terminal", reason: state.reason };
          if (state.state === "promoted" && receipt?.copy_key === copyKey)
            return {
              kind: "promoted",
              copyKey: copyKey as Hex,
              envelopeDigest: receipt.envelope_digest,
              replay: true,
            };
          const decision = decide(input.id, { attempts: 0, budget: 1 });
          if (decision.kind === "terminal") {
            terminate(input.id, decision.reason);
            return { kind: "terminal", reason: decision.reason };
          }
          if (decision.kind !== "promote" || decision.copyKey !== copyKey)
            throw new ReplicaCopyRefused("not_promotable");
          const row = all.find((r) => r.copy_key === copyKey)!;
          const precondition = predecessorOf(row);
          if (precondition?.kind === "terminal") {
            terminate(input.id, precondition.reason);
            return precondition;
          }
          if (precondition) return precondition;
          if (receipt && receipt.copy_key !== copyKey) {
            terminate(input.id, "receipt_conflict");
            return { kind: "terminal", reason: "receipt_conflict" };
          }
          // The import runs in a savepoint: an invariant violation inside it
          // rolls back the import alone, and the terminal transition commits.
          const blobs = JSON.parse(row.blobs_json) as StagedCopy["blobs"];
          try {
            db.transaction(() =>
              deps.importEnvelope(
                JSON.parse(row.envelope_json) as ReplicaEnvelope,
                blobs,
                input.id,
              ),
            )();
          } catch (error) {
            if (!(error instanceof ReplicaCopyRefused)) throw error;
            terminate(input.id, error.reason);
            return { kind: "terminal", reason: error.reason };
          }
          db.prepare(
            "UPDATE pdpp_replica_copies SET state='confirmed',reason=NULL WHERE id=? AND copy_key=?",
          ).run(input.id, copyKey);
          quarantine(input.id, decision.quarantine, "copy_conflict");
          db.prepare(
            "UPDATE pdpp_replica_batch_disposition SET state='promoted',promoted_copy_key=? WHERE id=?",
          ).run(copyKey, input.id);
          db.prepare(
            "INSERT INTO pdpp_replica_promotion_receipts VALUES (?,?,?)",
          ).run(input.id, copyKey, row.envelope_digest);
          syncPreview(input.id);
          const kept = new Set(
            rows(input.id)
              .filter((r) => r.copy_key !== copyKey)
              .flatMap((r) =>
                (JSON.parse(r.blobs_json) as StagedCopy["blobs"]).map(
                  (b) => b.blobId,
                ),
              ),
          );
          deps.releaseBytes(
            input.id,
            blobs.map((b) => b.blobId).filter((b) => !kept.has(b)),
          );
          return {
            kind: "promoted",
            copyKey: copyKey as Hex,
            envelopeDigest: row.envelope_digest,
            replay: false,
          };
        })
        .immediate();
    },
  };
}
export type ReplicaCopies = ReturnType<typeof createReplicaCopies>;
