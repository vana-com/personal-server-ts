// The reader of the stream-sync log (stream-sync/src/log.ts).
//
// One registry read says the log's position. A device at position n fetches
// the newest segment (the head: it lists the older ones) and then only the
// segments after n, and applies them in position order, one batch each. A
// segment's operations are order- and duplicate-insensitive: an upsert merges
// by greatest observation stamp, and every delete and omission leaves a
// tombstone `(stream, pk_hash, stamp)` that an upsert at or before it cannot
// pass. So the order of delivery matters only for gap detection: position n+1
// is never applied before n, and a segment that cannot be fetched stops the
// pass there (the position stays; the next pass tries again).
//
// A gap (the registry is behind this device, or the log begins after it) is a
// full check: the position goes back to the log's `base` and every segment
// the head lists is applied again. That is safe because re-applying is
// idempotent. What the log does not hold below `base` (a snapshot, or the
// streams published before the log began) is read by the per-stream path.

import { sha256 } from "@noble/hashes/sha2";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  HEAD_FORMAT,
  canonicalJson,
  classifyStreamRow,
  digestSegment,
  encodeSegment,
  logScope,
  pkHash,
  planOpsSince,
  segmentBlobName,
  toHex,
  verifySegment,
  type ControlHashes,
  type Segment,
  type SegmentRef,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { computeRecordKeyFromData } from "../storage/pdpp-records/record-key.js";
import type { LocalSyncDeps } from "./deps.js";
import type { SqlStatement } from "./driver.js";
import { mergeIncoming, seenPair, withOrigin } from "./merge.js";

const sha = async (bytes: Uint8Array) => sha256(bytes);
const keccak = async (bytes: Uint8Array) => keccak_256(bytes);

/** Rows a statement list binds at most; a long omitted set goes in chunks. */
const KEYS_PER_STATEMENT = 400;

export interface LogState {
  readonly position: number;
  readonly base: number;
  /** Refs of positions base+1..position: the list the next segment carries. */
  readonly refs: readonly SegmentRef[];
}

const NO_LOG: LogState = { position: 0, base: 0, refs: [] };

export async function readLogState(
  deps: Pick<LocalSyncDeps, "db">,
  connectionId: string,
): Promise<LogState> {
  const [row] = await deps.db.query<{
    position: number;
    base: number;
    refs: string;
  }>("SELECT position, base, refs FROM log_state WHERE connection_id = ?", [
    connectionId,
  ]);
  return row
    ? {
        position: row.position,
        base: row.base,
        refs: JSON.parse(row.refs) as SegmentRef[],
      }
    : NO_LOG;
}

export function writeLogState(
  connectionId: string,
  state: LogState,
): SqlStatement {
  return {
    sql: `INSERT OR REPLACE INTO log_state (connection_id, position, base, refs)
          VALUES (?, ?, ?, ?)`,
    params: [
      connectionId,
      state.position,
      state.base,
      JSON.stringify(state.refs),
    ],
  };
}

const chunks = <T>(items: readonly T[], size: number): T[][] => {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size)
    out.push(items.slice(i, i + size));
  return out;
};

/**
 * Apply one segment's operations to local state, in one batch (origin
 * `remote`). Safe to repeat and to run in any order against other segments:
 * see the file comment. With `state`, the log position is written in the same
 * batch, so a position never runs ahead of the rows it stands for.
 */
export async function applySegmentOperations(
  deps: LocalSyncDeps,
  connectionId: string,
  segment: Segment,
  state?: LogState,
): Promise<void> {
  const { dataHash, blobName } = await digestSegment(
    keccak,
    encodeSegment(segment),
  );
  const op = deps.newOp();
  const primaryKeyOf = new Map(
    segment.streams.map((meta) => [meta.stream, meta.primaryKey]),
  );
  const statements: SqlStatement[] = [];

  for (const meta of segment.streams)
    statements.push({
      sql: `INSERT OR IGNORE INTO stream_state (connection_id, stream, primary_key, semantics, incremental)
            VALUES (?, ?, ?, 'mutable_state', 1)`,
      params: [connectionId, meta.stream, JSON.stringify(meta.primaryKey)],
    });

  // 1. Tombstones first, so the upserts of this very segment see them.
  const tombstone = (
    stream: string,
    pk: string,
    o: number,
    r: string,
  ): SqlStatement[] => [
    {
      sql: `INSERT OR IGNORE INTO log_tombstones (connection_id, stream, pk_hash, stamp_o, stamp_r)
            VALUES (?, ?, ?, ?, ?)`,
      params: [connectionId, stream, pk, o, r],
    },
    {
      sql: `UPDATE log_tombstones SET stamp_o = ?, stamp_r = ?
             WHERE connection_id = ? AND stream = ? AND pk_hash = ?
               AND (stamp_o, stamp_r) < (?, ?)`,
      params: [o, r, connectionId, stream, pk, o, r],
    },
  ];
  for (const operation of segment.operations) {
    if (operation.kind === "delete")
      statements.push(
        ...tombstone(
          operation.stream,
          operation.pkHash,
          operation.stamp.o,
          operation.stamp.r,
        ),
      );
    else if (operation.kind === "complete")
      for (const pk of operation.omitted)
        statements.push(
          ...tombstone(
            operation.stream,
            pk,
            operation.cutoff.o,
            operation.cutoff.r,
          ),
        );
  }

  // 2. Upserts: staged, filtered by the tombstones, merged by stamp.
  let staged = 0;
  for (const operation of segment.operations) {
    if (operation.kind !== "upsert") continue;
    const primaryKey = primaryKeyOf.get(operation.stream)!;
    // The body the merge compares is the value's canonical form.
    const canonical = canonicalJson(operation.value);
    if ((await pkHash(sha, operation.value, primaryKey)) !== operation.pkHash)
      throw new Error("apply: invalid log record key");
    statements.push({
      sql: `INSERT OR REPLACE INTO temp.incoming (op, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      params: [
        op,
        operation.stream,
        operation.pkHash,
        computeRecordKeyFromData(operation.value, [...primaryKey]),
        operation.stamp.o,
        operation.stamp.r,
        canonical,
        toHex(sha256(new TextEncoder().encode(canonical))),
        operation.firstSeen,
      ],
    });
    staged++;
  }
  if (staged > 0)
    statements.push(
      {
        // A delete wins a tie, as an explicit delete does everywhere else.
        sql: `DELETE FROM temp.incoming WHERE op = ? AND EXISTS (
                SELECT 1 FROM log_tombstones t
                 WHERE t.connection_id = ? AND t.stream = incoming.stream
                   AND t.pk_hash = incoming.pk_hash
                   AND (t.stamp_o, t.stamp_r) >= (incoming.stamp_o, incoming.stamp_r))`,
        params: [op, connectionId],
      },
      ...mergeIncoming(op, connectionId, { promoteSeen: true }),
    );

  // 3. Deletes and omissions of rows this device holds. A row some run of this
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
          sql: `UPDATE records SET stamp_o = seen_o, stamp_r = seen_r
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
  for (const operation of segment.operations) {
    if (operation.kind === "delete")
      statements.push(
        ...survivors(
          operation.stream,
          [operation.pkHash],
          operation.stamp.o,
          operation.stamp.r,
          true,
        ),
      );
    else if (operation.kind === "complete")
      statements.push(
        ...survivors(
          operation.stream,
          operation.omitted,
          operation.cutoff.o,
          operation.cutoff.r,
          false,
        ),
      );
  }

  // 4. Each stream the segment touched now reads from it: a local version
  // above anything the registry's own stream row holds, so the per-stream
  // path never replaces what the log wrote (see `applyOneOnce`).
  for (const meta of segment.streams) {
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
          segment.generation,
          blobName,
          HEAD_FORMAT,
          connectionId,
          meta.stream,
          segment.observedAt,
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
          segment.generation,
          dataHash,
          blobName,
          connectionId,
          meta.stream,
        ],
      },
    );
  }
  if (state) statements.push(writeLogState(connectionId, state));

  try {
    await deps.db.batch(withOrigin("remote", statements));
  } finally {
    await deps.db.batch([
      { sql: "DELETE FROM temp.incoming WHERE op = ?", params: [op] },
    ]);
  }
}

export interface LogApplyContext {
  readonly connector: string;
  readonly ns: string;
  readonly generation: number;
  readonly keyCheck: string;
  readonly hashes: ControlHashes;
  /** The registry's row for the log, if the caller already holds a fresh one. */
  readonly read?: Awaited<ReturnType<LocalSyncDeps["registry"]["read"]>>;
}

/**
 * Bring this device to the log's position. One registry read, one GET for the
 * newest segment, one GET for each older segment this device lacks.
 */
export async function applyLog(
  deps: LocalSyncDeps,
  connectionId: string,
  context: LogApplyContext,
): Promise<{ readonly applied: number }> {
  const scope = logScope(context.connector, context.ns);
  const read = context.read ?? (await deps.registry.read(scope));
  const classification = classifyStreamRow(read, context.hashes);
  if (!read.found || classification === "absent") return { applied: 0 };
  const local = await readLogState(deps, connectionId);

  if (classification === "tombstoned") {
    // The log of an ended lifetime. A new one begins after its version.
    if (read.version > local.position)
      await deps.db.batch([
        writeLogState(connectionId, {
          position: read.version,
          base: read.version,
          refs: [],
        }),
      ]);
    return { applied: 0 };
  }

  const lastRef = local.refs.at(-1);
  if (
    read.version === local.position &&
    lastRef?.dataHash.toLowerCase() === read.dataHash.toLowerCase()
  )
    return { applied: 0 };

  const fetchSegment = async (
    dataHash: string,
    position: number,
  ): Promise<{ segment: Segment; bytes: number }> => {
    const cipher = await deps.blobs.get(
      `${scope}/${segmentBlobName(dataHash)}`,
    );
    if (cipher === null)
      throw new Error(`apply: missing log segment ${position}`);
    const verified = await verifySegment(
      keccak,
      await deps.keys.decrypt(scope, cipher),
      {
        dataHash,
        connector: context.connector,
        ns: context.ns,
        keyCheck: context.keyCheck,
        position,
      },
    );
    if (verified.kind !== "ok")
      throw new Error(
        `apply: invalid log segment ${position} (${verified.kind})`,
      );
    return verified;
  };

  const newest = await fetchSegment(read.dataHash, read.version);
  const head = newest.segment;
  if (head.generation < context.generation) {
    // A log of an earlier lifetime holds none of this one.
    await deps.db.batch([
      writeLogState(connectionId, {
        position: read.version,
        base: read.version,
        refs: [],
      }),
    ]);
    return { applied: 0 };
  }
  if (head.generation > context.generation) return { applied: 0 };

  const headRef: SegmentRef = {
    position: head.position,
    dataHash: read.dataHash.toLowerCase() as `0x${string}`,
    bytes: newest.bytes,
  };
  const allRefs: SegmentRef[] = [...head.refs, headRef];
  let since = local.position;
  let plan = planOpsSince(head, headRef, since);
  if (plan.kind === "gap") {
    // A full check: replay everything the log holds.
    since = head.base;
    plan = planOpsSince(head, headRef, since);
  }
  if (plan.kind !== "segments") return { applied: 0 };

  // Older segments in parallel; they are applied strictly in position order.
  const fetched = new Map<number, Segment>();
  fetched.set(head.position, head);
  await Promise.all(
    plan.refs
      .filter((ref) => ref.position !== head.position)
      .map(async (ref) => {
        fetched.set(
          ref.position,
          (await fetchSegment(ref.dataHash, ref.position)).segment,
        );
      }),
  );
  let applied = 0;
  for (const ref of plan.refs) {
    const segment = fetched.get(ref.position)!;
    await applySegmentOperations(deps, connectionId, segment, {
      position: ref.position,
      base: head.base,
      refs: allRefs.filter((r) => r.position <= ref.position),
    });
    applied++;
  }
  return { applied };
}
