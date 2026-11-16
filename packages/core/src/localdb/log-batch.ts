// One batch of the stream-sync log's operations as local state: checked and
// hashed (`prepareOperations`), turned into the statements that write it
// (`operationStatements`, `mergeStaged`, `streamHeadStatements`), and written
// with its neighbours (`commitStaged`, `applyInGroups`). The reader that picks
// the batches and their order is `log-apply.ts`; the one that loads a whole
// first load key by key is `log-keyed.ts`. Both build their statements here, so
// a rule of the merge (a tombstone's rank, which row a delete spares) has one
// owner.

import { sha256 } from "@noble/hashes/sha2";
import {
  HEAD_FORMAT,
  canonicalJson,
  firstDeletionKeyMismatch,
  pkHash,
  toHex,
  type LogKey,
  type LogOmitted,
  type LogOperation,
  type LogStreamMeta,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { computeRecordKeyFromData } from "../storage/pdpp-records/record-key.js";
import type { LocalSyncDeps } from "./deps.js";
import type { SqlStatement } from "./driver.js";
import type { LogState } from "./log-state.js";
import { writeLogState } from "./log-state.js";
import { mergeIncoming, seenPair, withOrigin } from "./merge.js";
import { readPartsAhead } from "./part-readahead.js";
import {
  holdKeys,
  hideStoredRows,
  partialRowStatement,
  showIncomingKeys,
  type PartialIdentity,
} from "./partial-load.js";

const sha = async (bytes: Uint8Array) => sha256(bytes);

/**
 * The rank of a tombstone beside its stamp (`log_tombstones.rank`), as the
 * model orders them: an omission's cutoff, then an observation at that stamp,
 * then an explicit delete at that stamp.
 */
export const OMISSION_RANK = 0;
export const UPSERT_RANK = 1;
export const EXPLICIT_DELETE_RANK = 2;

/** Variables a statement binds at most; a long key set goes in chunks. */
export const KEYS_PER_STATEMENT = 400;

const chunks = <T>(items: readonly T[], size: number): T[][] => {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size)
    out.push(items.slice(i, i + size));
  return out;
};

/** What `stageBatch` needs of a segment or of a snapshot part. */
export interface OperationBatch {
  readonly generation: number;
  readonly observedAt: number;
  readonly streams: readonly LogStreamMeta[];
  readonly operations: readonly (LogOperation | LogOmitted)[];
}

/** The hash and blob a batch's stream heads name. */
export interface BatchIdentity {
  readonly dataHash: string;
  readonly blobName: string;
}

/**
 * What one batch does for a stream that loads progressively (see
 * `log-progressive.ts`). The stream's head, and with it `complete`, is written
 * only by the batch that `final` names.
 */
export interface BatchStep {
  /** The first batch of a load that is not a resumed one hides the stored rows. */
  readonly begin: boolean;
  readonly final: boolean;
  /** Keys of this batch a later, fetched batch deletes or omits. */
  readonly held: readonly string[];
  /** The stream's row after this batch; absent in the final batch. */
  readonly row?: {
    readonly head: PartialIdentity;
    readonly applied: number;
    readonly total: number;
  };
}

/**
 * The canonical record key of a deletion's typed primary-key values: the key
 * `computeRecordKeyFromData` gives a record holding these values, which is how
 * an upsert's key derives. The values are already checked against the hash.
 */
export function recordKeyOfKey(
  primaryKey: readonly string[],
  key: readonly unknown[],
): string {
  return computeRecordKeyFromData(
    Object.fromEntries(primaryKey.map((field, i) => [field, key[i]])),
    [...primaryKey],
  );
}

/**
 * One operation, checked and ready to write. An upsert's body is the value's
 * canonical form (what the merge compares) with its hash; a deletion's and an
 * omission's record key derives from the typed key they carry.
 */
export type PreparedOperation =
  | {
      readonly kind: "upsert";
      readonly stream: string;
      readonly pkHash: string;
      readonly recordKey: string;
      readonly stampO: number;
      readonly stampR: string;
      readonly body: string;
      readonly bodySha256: string;
      readonly firstO: number | null;
      /** The intake batch of its run that wrote it; 0 when absent. */
      readonly ordinal: number;
    }
  | {
      readonly kind: "delete" | "omitted";
      readonly stream: string;
      readonly pkHash: string;
      readonly recordKey: string;
      readonly stampO: number;
      readonly stampR: string;
    }
  | {
      readonly kind: "complete";
      readonly stream: string;
      readonly stampO: number;
      readonly stampR: string;
      readonly omitted: readonly {
        readonly pkHash: string;
        readonly recordKey: string;
      }[];
    };

/**
 * The JS half of an apply: check a batch's operations and hash them. Nothing
 * is written. A deletion names its record by hash and by canonical key; they
 * must name the same record before anything is built or written (the hash
 * picks the row removed, the key is what a record-level reader deletes), and an
 * upsert's key must hash to the pkHash it carries.
 */
export async function prepareOperations(
  streams: readonly LogStreamMeta[],
  operations: readonly (LogOperation | LogOmitted)[],
): Promise<PreparedOperation[]> {
  const mismatch = await firstDeletionKeyMismatch(sha, streams, operations);
  if (mismatch)
    throw new Error(
      `apply: log deletion key does not match its hash (${mismatch.stream}/${mismatch.pkHash})`,
    );
  const primaryKeyOf = new Map(
    streams.map((meta) => [meta.stream, meta.primaryKey]),
  );
  const keyOf = (stream: string, key: LogKey) =>
    recordKeyOfKey(primaryKeyOf.get(stream)!, key);
  const out: PreparedOperation[] = [];
  for (const operation of operations) {
    if (operation.kind === "upsert") {
      const primaryKey = primaryKeyOf.get(operation.stream)!;
      // The body the merge compares is the value's canonical form.
      const canonical = canonicalJson(operation.value);
      if ((await pkHash(sha, operation.value, primaryKey)) !== operation.pkHash)
        throw new Error("apply: invalid log record key");
      out.push({
        kind: "upsert",
        stream: operation.stream,
        pkHash: operation.pkHash,
        recordKey: computeRecordKeyFromData(operation.value, [...primaryKey]),
        stampO: operation.stamp.o,
        stampR: operation.stamp.r,
        body: canonical,
        bodySha256: toHex(sha256(new TextEncoder().encode(canonical))),
        firstO: operation.firstSeen,
        ordinal: operation.ordinal ?? 0,
      });
    } else if (operation.kind === "complete")
      out.push({
        kind: "complete",
        stream: operation.stream,
        stampO: operation.cutoff.o,
        stampR: operation.cutoff.r,
        omitted: operation.omitted.map((omission) => ({
          pkHash: omission.pkHash,
          recordKey: keyOf(operation.stream, omission.key),
        })),
      });
    else
      out.push({
        kind: operation.kind,
        stream: operation.stream,
        pkHash: operation.pkHash,
        recordKey: keyOf(operation.stream, operation.key),
        stampO: operation.stamp.o,
        stampR: operation.stamp.r,
      });
  }
  return out;
}

/**
 * The statements that write prepared operations as one batch: tombstones, then
 * the deletes and omissions of rows this device holds, then the upserts
 * (staged under `op`, filtered by the tombstones, merged by stamp).
 */
export function operationStatements(
  connectionId: string,
  op: string,
  operations: readonly PreparedOperation[],
  steps: ReadonlyMap<string, BatchStep> = new Map(),
): SqlStatement[] {
  const statements: SqlStatement[] = [];

  // 1. Tombstones first, so the upserts of this very segment see them. A
  // tombstone has a rank beside its stamp, the model's order: an omission's
  // cutoff ranks below an observation at its stamp (a pass proved a key absent
  // only before its cutoff), an explicit delete above it. A key keeps the
  // greatest (stamp, rank), which is the one that refuses the most.
  // The tombstone also keeps the deletion's canonical record key, derived from
  // the typed key the operation names (as an upsert's derives from its value),
  // so a record-level reader of this table needs no map from hash to key (a
  // key this device never held has no row to ask).
  const tombstone = (
    stream: string,
    pk: string,
    recordKey: string,
    o: number,
    r: string,
    rank: number,
  ): SqlStatement[] => [
    {
      sql: `INSERT OR IGNORE INTO log_tombstones (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, rank)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
      params: [connectionId, stream, pk, recordKey, o, r, rank],
    },
    {
      sql: `UPDATE log_tombstones SET record_key = ?, stamp_o = ?, stamp_r = ?, rank = ?
             WHERE connection_id = ? AND stream = ? AND pk_hash = ?
               AND (stamp_o, stamp_r, rank) < (?, ?, ?)`,
      params: [recordKey, o, r, rank, connectionId, stream, pk, o, r, rank],
    },
  ];
  for (const operation of operations) {
    if (operation.kind === "delete")
      statements.push(
        ...tombstone(
          operation.stream,
          operation.pkHash,
          operation.recordKey,
          operation.stampO,
          operation.stampR,
          EXPLICIT_DELETE_RANK,
        ),
      );
    else if (operation.kind === "omitted")
      statements.push(
        ...tombstone(
          operation.stream,
          operation.pkHash,
          operation.recordKey,
          operation.stampO,
          operation.stampR,
          OMISSION_RANK,
        ),
      );
    else if (operation.kind === "complete")
      for (const omission of operation.omitted)
        statements.push(
          ...tombstone(
            operation.stream,
            omission.pkHash,
            omission.recordKey,
            operation.stampO,
            operation.stampR,
            OMISSION_RANK,
          ),
        );
  }

  // 2. Deletes and omissions of rows this device holds, before the upserts: a
  // resurrection that follows a deletion then merges into no row, so its row
  // has the resurrection's own first-seen checkpoint, as it does for a reader
  // that applied the two in separate segments. A row some run of this
  // device observed at or after the stamp survives, and is published again
  // under that observation (as `applyDelete` does for a head that omits it).
  const survivors = (
    stream: string,
    keys: readonly string[],
    o: number,
    r: string,
    inclusive: boolean,
  ): SqlStatement[] => {
    const out: SqlStatement[] = [];
    const cmp = inclusive ? "<=" : "<";
    for (const group of chunks(keys, KEYS_PER_STATEMENT)) {
      const marks = group.map(() => "?").join(",");
      out.push(
        {
          sql: `UPDATE write_ctx SET origin = 'local' WHERE id = 1 AND origin = 'remote'`,
          params: [],
        },
        {
          sql: `UPDATE records SET stamp_o = seen_o, stamp_r = seen_r, stamp_n = 0
                 WHERE connection_id = ? AND stream = ? AND pk_hash IN (${marks})
                   AND seen_o IS NOT NULL AND NOT (${seenPair()} ${cmp} (?, ?))`,
          params: [connectionId, stream, ...group, o, r],
        },
        {
          sql: `UPDATE write_ctx SET origin = 'remote' WHERE id = 1 AND origin = 'local'`,
          params: [],
        },
        {
          sql: `DELETE FROM records
                 WHERE connection_id = ? AND stream = ? AND pk_hash IN (${marks})
                   AND ${seenPair()} ${cmp} (?, ?)`,
          params: [connectionId, stream, ...group, o, r],
        },
      );
    }
    return out;
  };
  for (const operation of operations) {
    if (operation.kind === "delete")
      statements.push(
        ...survivors(
          operation.stream,
          [operation.pkHash],
          operation.stampO,
          operation.stampR,
          true,
        ),
      );
    else if (operation.kind === "omitted")
      statements.push(
        ...survivors(
          operation.stream,
          [operation.pkHash],
          operation.stampO,
          operation.stampR,
          false,
        ),
      );
    else if (operation.kind === "complete")
      statements.push(
        ...survivors(
          operation.stream,
          operation.omitted.map((omission) => omission.pkHash),
          operation.stampO,
          operation.stampR,
          false,
        ),
      );
  }

  // 3. Upserts: staged, filtered by the tombstones, merged by stamp.
  let staged = 0;
  for (const operation of operations) {
    if (operation.kind !== "upsert") continue;
    statements.push({
      sql: `INSERT OR REPLACE INTO temp.incoming (op, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o, stamp_n)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      params: [
        op,
        operation.stream,
        operation.pkHash,
        operation.recordKey,
        operation.stampO,
        operation.stampR,
        operation.body,
        operation.bodySha256,
        operation.firstO,
        operation.ordinal,
      ],
    });
    staged++;
  }
  if (staged > 0) statements.push(...mergeStaged(connectionId, op, steps));
  return statements;
}

/**
 * The statements that merge the rows staged in `temp.incoming` under `op`:
 * filtered by the tombstones, then merged by stamp. See `mergeIncoming`.
 */
export function mergeStaged(
  connectionId: string,
  op: string,
  steps: ReadonlyMap<string, BatchStep> = new Map(),
): SqlStatement[] {
  const statements: SqlStatement[] = [
    {
      // An upsert ranks between the two tombstone kinds at its stamp: an
      // explicit delete at the stamp refuses it, an omission there does not.
      sql: `DELETE FROM temp.incoming WHERE op = ? AND EXISTS (
                SELECT 1 FROM log_tombstones t
                 WHERE t.connection_id = ? AND t.stream = incoming.stream
                   AND t.pk_hash = incoming.pk_hash
                   AND (t.stamp_o, t.stamp_r, t.rank) > (incoming.stamp_o, incoming.stamp_r, ${UPSERT_RANK}))`,
      params: [op, connectionId],
    },
  ];
  // The rows this batch writes show in a progressive view, but for the keys
  // a later batch removes.
  for (const [stream, step] of steps)
    if (!step.final)
      statements.push(
        showIncomingKeys(connectionId, stream, op),
        ...holdKeys(connectionId, stream, step.held),
      );
  statements.push(
    ...mergeIncoming(op, connectionId, {
      promoteSeen: true,
      firstSeenOfWinner: true,
    }),
  );
  return statements;
}

/**
 * Each stream a batch touched now reads from it: a local version above
 * anything the registry's own stream row holds, so the per-stream path never
 * replaces what the log wrote (see `applyOneOnce`).
 */
export function streamHeadStatements(
  connectionId: string,
  metas: readonly LogStreamMeta[],
  batch: { readonly generation: number; readonly observedAt: number },
  identity: BatchIdentity,
): SqlStatement[] {
  const { dataHash, blobName } = identity;
  const statements: SqlStatement[] = [];
  for (const meta of metas)
    statements.push(
      {
        sql: `INSERT OR REPLACE INTO stream_versions (connection_id, stream, version, generation,
                head_blob, head_format, record_count, observed_at, complete, kind)
              SELECT ?, ?, MAX(s.head_version, s.last_delete_version) + 1, ?, ?, ?,
                     (SELECT COUNT(*) FROM records r WHERE r.connection_id = ? AND r.stream = ?),
                     ?, ?, 'applied'
                FROM stream_state s WHERE s.connection_id = ? AND s.stream = ?`,
        params: [
          connectionId,
          meta.stream,
          batch.generation,
          blobName,
          HEAD_FORMAT,
          connectionId,
          meta.stream,
          batch.observedAt,
          meta.complete ? 1 : 0,
          connectionId,
          meta.stream,
        ],
      },
      {
        sql: `UPDATE stream_state SET primary_key = ?, profile_key = ?, profile_version = ?, complete = ?,
                head_version = MAX(head_version, last_delete_version) + 1,
                head_generation = ?, head_data_hash = ?, head_blob = ?
              WHERE connection_id = ? AND stream = ?`,
        params: [
          JSON.stringify(meta.primaryKey),
          meta.profile.key,
          meta.profile.version,
          meta.complete ? 1 : 0,
          batch.generation,
          dataHash,
          blobName,
          connectionId,
          meta.stream,
        ],
      },
    );
  return statements;
}

/** The row a stream's state starts as, unless it holds one. */
export function streamStateStatement(
  connectionId: string,
  meta: Pick<LogStreamMeta, "stream" | "primaryKey">,
): SqlStatement {
  return {
    sql: `INSERT OR IGNORE INTO stream_state (connection_id, stream, primary_key, semantics, incremental)
            VALUES (?, ?, ?, 'mutable_state', 1)`,
    params: [connectionId, meta.stream, JSON.stringify(meta.primaryKey)],
  };
}

/** A batch built (checked, canonicalized, hashed) and not yet written. */
export interface StagedBatch {
  /** The id of its rows in `temp.incoming`. */
  readonly op: string;
  readonly statements: readonly SqlStatement[];
}

/**
 * Staging is the JS half of an apply: it reads the batch's operations, checks
 * and hashes them, and builds the statements. It does not touch the database,
 * so it runs while an earlier commit is writing (see `applyInGroups`).
 */
export async function stageBatch(
  deps: Pick<LocalSyncDeps, "newOp">,
  connectionId: string,
  segment: OperationBatch,
  identity: BatchIdentity,
  state?: LogState,
  steps: ReadonlyMap<string, BatchStep> = new Map(),
): Promise<StagedBatch> {
  const op = deps.newOp();
  const operations = await prepareOperations(
    segment.streams,
    segment.operations,
  );
  const statements: SqlStatement[] = [];
  for (const meta of segment.streams)
    statements.push(streamStateStatement(connectionId, meta));
  // A progressive load's first batch hides what the stream held, in the same
  // transaction as its first rows (see `hideStoredRows`).
  for (const [stream, step] of steps)
    if (step.begin) statements.push(...hideStoredRows(connectionId, stream));
  statements.push(...operationStatements(connectionId, op, operations, steps));
  // A stream still loading progressively has no head yet; its last batch
  // writes it, with `complete`.
  statements.push(
    ...streamHeadStatements(
      connectionId,
      segment.streams.filter((meta) => steps.get(meta.stream)?.final !== false),
      segment,
      identity,
    ),
  );
  for (const step of steps.values())
    if (step.row)
      statements.push(
        partialRowStatement(step.row.head, step.row.applied, step.row.total, 0),
      );
  if (state) statements.push(writeLogState(connectionId, state));
  return { op, statements };
}

/**
 * Write staged batches in one transaction, in order. Each batch's statements
 * see the rows of the ones before it, as they do when the batches commit one
 * by one, so the rows are the same; what differs is that no state between two
 * of them is committed. A failure writes none of them.
 */
export async function commitStaged(
  deps: Pick<LocalSyncDeps, "db">,
  batches: readonly StagedBatch[],
): Promise<void> {
  const statements: SqlStatement[] = [];
  // One by one: a group's statements can outnumber what a call takes as arguments.
  for (const batch of batches)
    for (const statement of batch.statements) statements.push(statement);
  try {
    await deps.db.batch(withOrigin("remote", statements));
  } finally {
    await deps.db.batch(
      batches.map((batch) => ({
        sql: "DELETE FROM temp.incoming WHERE op = ?",
        params: [batch.op],
      })),
    );
  }
}

export async function applyBatch(
  deps: LocalSyncDeps,
  connectionId: string,
  segment: OperationBatch,
  identity: BatchIdentity,
  state?: LogState,
  steps: ReadonlyMap<string, BatchStep> = new Map(),
): Promise<void> {
  await commitStaged(deps, [
    await stageBatch(deps, connectionId, segment, identity, state, steps),
  ]);
}

/** One batch of a pass: what it weighs, and how it is fetched and staged. */
export interface PassItem {
  /** The clear length of the segment or snapshot part. */
  readonly bytes: number;
  /**
   * It commits as the last of its group. A progressive load sets it on the
   * batch that completes a stream, so the stream is complete when that batch
   * commits and not when the group that holds it would.
   */
  readonly closesGroup?: boolean;
  /** Fetch it (unless it is in hand), verify it and stage it. */
  readonly stage: () => Promise<StagedBatch>;
}

/**
 * Apply a pass's batches in order, fetching and staging the ones that follow
 * while the commit of an earlier one writes (`readPartsAhead`, the reader a
 * head's parts use), and committing the batches that are ready together.
 *
 * Why commit together: on a first load a batch's rows land across the whole of
 * `records` and its indexes (the keys of a log are in publish order, not key
 * order), so a commit writes about as many pages as it has rows, and a host
 * whose every page write is a call (the Web's OPFS) pays for each. Batches
 * committed together write a page once for all of them. Why it is safe: see
 * `ApplyRun` in docs/formal/log-protocol/LogProtocol.tla. The batches apply in
 * position order in one transaction, the position is written by the last of
 * them, and the reader never sees a position whose rows are not all there.
 *
 * How many go together is not a number here: the commit goes when the next
 * batch is not yet staged, so a group is the batches the reader staged during
 * the commit before it, and the store's memory budget bounds that (each batch
 * holds its bytes until its commit). With `firstAlone` the first batch commits
 * by itself, for the first screen of a progressive load.
 *
 * A batch that cannot be fetched or staged is not ready, so the commit that
 * holds the batches before it goes first, and then the error is raised.
 */
export async function applyInGroups(
  deps: LocalSyncDeps,
  items: readonly PassItem[],
  options: {
    readonly firstAlone: boolean;
    /** The batches `first..last` are committed. */
    readonly onCommit?: (first: number, last: number) => void;
  },
): Promise<void> {
  const ahead = readPartsAhead(deps.blobs, items, (item) => item.stage());
  let pending: StagedBatch[] = [];
  let first = 0;
  let began = !options.firstAlone;
  try {
    for (const [index, item] of items.entries()) {
      pending.push(await ahead.load(item, index));
      if (began && !item.closesGroup && ahead.ready(index + 1)) continue;
      await commitStaged(deps, pending);
      pending = [];
      began = true;
      ahead.committed(index);
      options.onCommit?.(first, index);
      first = index + 1;
    }
  } finally {
    ahead.close();
  }
}
