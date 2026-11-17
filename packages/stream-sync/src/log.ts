/**
 * The stream-sync LOG: head format 6's transport tier. One immutable segment
 * per committed batch holds the operations of every stream the batch touched;
 * one registry commit per batch advances one per-connection log position.
 *
 * This file is the contract. It has no I/O: formats, names, bounds, the
 * ops-since read plan, and the codec. The writer and reader are in
 * `core/src/localdb/log-publish.ts` and `log-apply.ts`.
 *
 * ## Where the log sits
 *
 *   registry row   `pdpp.<c>~<ns>.~log`     (`logScope`)
 *   its version    the log POSITION (registry versions are dense: 1, 2, 3…)
 *   its dataHash   Keccak-256 of the clear NEWEST segment
 *   blob           `<log scope>/s-<keccak hex>` (`segmentBlobName`)
 *
 * The newest segment is the log head: it carries its position, the list of
 * the older segments (`refs`), and the snapshot pointer. A reader that holds
 * position n reads the registry row (1 request), the newest segment (1 GET),
 * and the older segments n+1..position-1 named by `refs` (parallel GETs). It
 * never lists the streams.
 *
 * ## What an operation is
 *
 * Operations reuse the vocabulary of replication profile v1
 * (`core/src/replication/envelope.ts`): `upsert`, `delete`, and a completion
 * (`stream-complete`). They differ from profile v1 in three stated ways:
 *
 * 1. ORDER. The merge winner per record is the GREATEST OBSERVATION STAMP
 *    `(o, r)`, as in `localdb/merge.ts`: not a Lamport counter, and not the
 *    log position. Position orders delivery and gap detection only. A delete
 *    wins a tie with an upsert of the same stamp (`deleteRunRecords` uses
 *    `<=`). Between two upserts at one stamp, the greater ORDINAL wins, then
 *    the greater body hash (`upsertAfter`). Applying the same operations in
 *    any order, any number of times, gives the same records, once the reader
 *    keeps a tombstone per deleted key (see `LogDelete`).
 * 2. OMISSION. A full pass that dropped records is a completion operation that
 *    names the dropped keys. A cutoff alone is unsound: a record the pass saw
 *    again unchanged moves only its local SEEN stamp (`merge.ts`), publishes
 *    nothing, and so a receiver cannot tell it from a dropped one by stamp.
 *    The writer therefore names the dropped keys exactly (`LogCompletion`).
 *    Every deletion (explicit delete, omission, and their snapshot forms) names
 *    its key twice: `pkHash`, the log's identity, and `key`, the typed
 *    primary-key values the hash was computed from (format 2). A record-level
 *    replica needs the key and cannot recover it from the hash. The key rides
 *    only inside the encrypted segment or part.
 * 3. NO PER-WRITER CHAIN. Profile v1 chains batches per writer (`sequence`,
 *    `previous`). The log has one chain per connection, ordered by the
 *    registry's compare-and-set on the log row.
 *
 * ## Bounds, derived
 *
 * `refs` and the snapshot's part list are both listed in the head, so together
 * they are bounded by the head's own limit (`HEAD_LIMIT_BYTES`):
 * `maxSegmentRefs()`. `compactionRequired` is the hard backstop: a writer whose
 * next segment would pass it must compact first.
 *
 * ## Compaction
 *
 * Compaction folds the log's prefix up to the head's position into SNAPSHOT
 * PARTS (`SnapshotPart`, blob `q-<hex>`): the latest winner per key, as an
 * upsert, or as a delete when the latest word on the key is a deletion or an
 * omission. Tombstones stay in the snapshot, because a reader behind the
 * snapshot may hold the record the tombstone deletes (P4). The next segment
 * is written with `base` = the folded position, `snapshot` pointing at the
 * parts, and no refs at or below `base`. A reader behind `base` installs the
 * parts (an idempotent apply, in any order) and then applies the tail.
 *
 * WHEN TO COMPACT is a cost comparison (`shouldCompact`), derived below from
 * measured primitives, with the hard backstop above.
 *
 * ## Bodies out of line
 *
 * A segment and a part are each one object of at most `PART_LIMIT_BYTES`, and
 * a record is never split across segments. A record whose upsert does not fit
 * the writer's part target (the size of one object it PUTs) therefore goes
 * OUT OF LINE, as an attachment store keeps a file beside the record that
 * names it: its canonical JSON body is cut into pieces of at most that target,
 * each encrypted and stored under the log scope by the Keccak-256 of its
 * clear bytes (`v-<hex>`, `bodyPieceBlobName`), and the upsert carries the
 * piece hashes, the body's length and its SHA-256 (`LogUpsertByRef`) instead
 * of the value. Everything else about the upsert, and so the merge, is
 * unchanged: `upsertAfter` compares the same body hash. A reader fetches the
 * pieces, checks each against its hash and the whole against its SHA-256, and
 * applies the upsert as if the body had been inline. Pieces are never deleted
 * (as segments, see `log-compact.ts`), and a snapshot entry names the same
 * pieces as the segment it folds.
 */

import { sha256 as sha256Sync } from "@noble/hashes/sha2";
import {
  DEFAULT_PART_TARGET_BYTES,
  HEAD_LIMIT_BYTES,
  HEX16,
  PART_LIMIT_BYTES,
  REGISTRY_HASH,
  keccakHex,
  utf8,
  type Keccak256,
  type Sha256,
} from "./bytes.js";
import { InvalidArgumentError } from "./errors.js";
import {
  canonicalJson,
  hasOwn,
  isPlainObject,
  type JsonObject,
} from "./json.js";
import { streamScope } from "./names.js";
import { deletionKeyMatchesHash } from "./records.js";

/**
 * The segment and snapshot-part format this build writes and reads.
 *
 * 1  A delete, an omitted entry and a completion's omitted list named a key by
 *    `pkHash` alone. No device wrote one: the log was behind a default-off flag.
 * 2  They also carry the typed primary-key values (`key`, wire `rk`): exactly
 *    what `pkHash` hashes. A hash is one-way, so a deletion that carries only
 *    a hash cannot tell a replica that never held the record which key it
 *    removes. The reader checks `pkHash === hash(key)`, so the two cannot name
 *    different records, and derives the string record key from `key` as it
 *    does for an upsert's value.
 *
 * Format 1 is `unsupported_format`: not read, and not read as keyless. Nothing
 * wrote it, so there is nothing to carry forward, and a reader that took a
 * hash-only deletion would apply it in a form this format forbids.
 */
export const LOG_FORMAT = 2;

/**
 * The reserved stream name of the log row. A connector stream is a manifest
 * name (letters, digits, underscores); `~` never occurs in one, so the log row
 * cannot collide with a stream.
 */
export const LOG_STREAM = "~log";

export function isLogStream(stream: string): boolean {
  return stream === LOG_STREAM;
}

/** Registry scope of the connection's log row. */
export function logScope(connector: string, ns: string): string {
  return streamScope(connector, ns, LOG_STREAM);
}

const SEGMENT_BLOB = /^s-([0-9a-f]{64})$/;

/** `s-<hex>`: the blob name of a segment, from its registry data hash. */
export function segmentBlobName(dataHash: string): string {
  const hex = dataHash.startsWith("0x") ? dataHash.slice(2) : dataHash;
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new InvalidArgumentError(
      `segment hash is not 64 lowercase hex characters: ${dataHash}`,
    );
  }
  return `s-${hex}`;
}

export function isSegmentBlobName(name: string): boolean {
  return SEGMENT_BLOB.test(name);
}

/** A record observation stamp: run time, then run id. Greatest wins. */
export interface LogStamp {
  readonly o: number;
  readonly r: string;
}

/** Strictly after, by `o` then `r`. */
export function stampAfter(a: LogStamp, b: LogStamp): boolean {
  return a.o !== b.o ? a.o > b.o : a.r > b.r;
}

/**
 * Between two upserts of one key at one stamp `(o, r)`: the later intake batch
 * of that run wins, then the greater body hash. A run's batches are one writer's
 * observations in order, and a connector may emit a key again with a changed
 * body, so the later batch is the fresher observation. The upsert's `ordinal`
 * is the intake batch index of the run that observed the body; absent is 0
 * (an entry from before the field, or the run's first batch).
 *
 * The full order of two entries of a key is `(o, r, kind, [writer], ordinal,
 * body hash)`: the kind rank (omission < upsert < explicit delete) comes before
 * the ordinal because deletes and omissions are written at run end, so they
 * carry no ordinal and must beat or lose to every upsert of the run by kind
 * alone. A later writer-incarnation field goes between kind and ordinal; for
 * entries of one run and one writer it is equal, so no outcome for such
 * entries changes. The body hash is the last tie: writers that share a run id
 * (a cloned device) can emit one stamp and ordinal with different bodies, and
 * the hash gives every reader the same winner, whatever order it applies them.
 */
export function upsertAfter(a: LogUpsert, b: LogUpsert): boolean {
  if (stampAfter(a.stamp, b.stamp)) return true;
  if (stampAfter(b.stamp, a.stamp)) return false;
  const an = a.ordinal ?? 0;
  const bn = b.ordinal ?? 0;
  if (an !== bn) return an > bn;
  return bodyHash(a.value) > bodyHash(b.value);
}

/** The hash `records.body_sha256` holds for the same body: SHA-256 of its canonical JSON. */
function bodyHash(value: JsonObject): string {
  let hex = "";
  for (const byte of sha256Sync(utf8(canonicalJson(value))))
    hex += byte.toString(16).padStart(2, "0");
  return hex;
}

/**
 * The record's current body at its observation stamp. `firstSeen` is the
 * record's first-seen checkpoint (`first_o`) as the observing device knew it,
 * `null` when unknown. It belongs to this observation: a reader keeps it while
 * this upsert is the winner and replaces it when a newer one wins.
 */
export interface LogUpsert {
  readonly kind: "upsert";
  readonly stream: string;
  readonly pkHash: string;
  readonly stamp: LogStamp;
  /** Intake batch index of the observing run; absent means 0. See `upsertAfter`. */
  readonly ordinal?: number;
  readonly firstSeen: number | null;
  readonly value: JsonObject;
}

/**
 * An upsert's body stored out of line (see "Bodies out of line" above): the
 * clear pieces, in order, are the canonical JSON of the body.
 */
export interface LogBodyRef {
  /** SHA-256 hex of the canonical JSON: `records.body_sha256`. */
  readonly sha256: string;
  /** Length of the canonical JSON in bytes: the sum of the clear pieces. */
  readonly bytes: number;
  /** Keccak-256 of each clear piece: blob `v-<hex>` (`bodyPieceBlobName`). */
  readonly pieces: readonly `0x${string}`[];
}

/**
 * An upsert whose body is out of line: the form it has in an encoded segment
 * or part. A reader resolves it to a `LogUpsert` before it applies or folds it.
 */
export interface LogUpsertByRef extends Omit<LogUpsert, "kind" | "value"> {
  readonly kind: "upsert-ref";
  readonly body: LogBodyRef;
}

/** One primary-key value. A key is never null, an object or an array. */
export type LogKeyValue = string | number | boolean;

/** A record's primary-key values in `primaryKey` order: what `pkHash` hashes. */
export type LogKey = readonly LogKeyValue[];

/**
 * The record is gone as of `stamp`. A reader keeps a tombstone `(stream,
 * pkHash, stamp)` so an upsert that arrives later with a stamp at or before it
 * (a re-delivered or reordered segment) does not bring the record back.
 *
 * `key` is the record's primary-key values in `primaryKey` order, with their
 * types: the array `pkHash` hashes. An upsert carries its data, so its key
 * derives from the value and the stream's primary key; a deletion carries no
 * data and must say the key itself.
 */
export interface LogDelete {
  readonly kind: "delete";
  readonly stream: string;
  readonly pkHash: string;
  readonly key: LogKey;
  readonly stamp: LogStamp;
}

/** One key a completion dropped: its hash (the log's identity) and typed key. */
export interface LogOmission {
  readonly pkHash: string;
  readonly key: LogKey;
}

/**
 * A full pass proved these keys absent. `cutoff` is the replacing run's stamp.
 * `omitted` is every key the pass dropped, ascending by `pkHash`, each a tombstone at
 * `cutoff`. A key the pass saw again (even unchanged) is NOT in it. A reader
 * deletes a listed record only if it has not observed the record at or after
 * `cutoff`.
 */
export interface LogCompletion {
  readonly kind: "complete";
  readonly stream: string;
  readonly cutoff: LogStamp;
  readonly omitted: readonly LogOmission[];
}

export type LogOperation = LogUpsert | LogDelete | LogCompletion;

/**
 * Whether a segment's operations remove a key: an explicit delete, or a
 * completion that omits at least one. This is the fact a ref carries as
 * `removes`.
 */
export function segmentRemoves(operations: readonly WireOperation[]): boolean {
  return operations.some(
    (op) =>
      op.kind === "delete" || (op.kind === "complete" && op.omitted.length > 0),
  );
}

/** What the stream's head said, carried with the batch that touched the stream. */
export interface LogStreamMeta {
  readonly stream: string;
  readonly primaryKey: readonly string[];
  readonly profile: { readonly key: string | null; readonly version: string };
  readonly complete: boolean;
}

/** One older segment of the log. */
export interface SegmentRef {
  readonly position: number;
  /** Keccak-256 of the clear segment: its registry data hash and blob name. */
  readonly dataHash: `0x${string}`;
  /** Encrypted length is not known to a reader; this is the CLEAR length. */
  readonly bytes: number;
  /**
   * Whether the segment deletes or omits any key (`segmentRemoves`). A reader
   * that applies a log while it still downloads reads the segments that say
   * `true` first: the keys they remove are the rows it keeps out of its view
   * until the log's end. A ref without the fact (a log an older writer made)
   * counts as removing, so that reader falls back to reading every segment
   * first. A segment that says `false` and removes a key is invalid.
   */
  readonly removes?: boolean;
}

/** One snapshot part, as the head names it. */
export interface SnapshotPartRef {
  /** Keccak-256 of the clear part: blob `q-<hex>` (`snapshotPartBlobName`). */
  readonly dataHash: `0x${string}`;
  /** The CLEAR length. */
  readonly bytes: number;
}

/**
 * The snapshot a compacted log rests on: the parts that hold the fold of
 * every segment up to `position`, which is the head's `base`. `null` until the
 * log has been compacted once. A reader behind `base` installs every part,
 * then applies the segments after `position`.
 */
export interface SnapshotPointer {
  readonly position: number;
  readonly parts: readonly SnapshotPartRef[];
}

/** An operation as a segment encodes it: an upsert's body may be out of line. */
export type WireOperation = LogOperation | LogUpsertByRef;

/**
 * One batch of the log. `Op` is `LogOperation` once every body is in hand;
 * `WireSegment` is the form encoded and decoded, whose upserts may name their
 * bodies out of line.
 */
export interface Segment<Op extends WireOperation = LogOperation> {
  readonly format: typeof LOG_FORMAT;
  readonly connector: string;
  readonly ns: string;
  readonly generation: number;
  readonly keyCheck: string;
  /** The registry version of the log row this segment is the data of. */
  readonly position: number;
  /** When the writer built the batch (ms); informational. */
  readonly observedAt: number;
  /**
   * Position before the first segment listed in `refs`: the snapshot's
   * position, or, with no snapshot, the position before the log began.
   * State at `base` is NOT in this segment's lineage; the reader has it from
   * the snapshot pointer or from the stream heads (a full check).
   */
  readonly base: number;
  readonly snapshot: SnapshotPointer | null;
  /** Older segments, positions `base+1 .. position-1`, ascending, no gap. */
  readonly refs: readonly SegmentRef[];
  readonly streams: readonly LogStreamMeta[];
  readonly operations: readonly Op[];
}

export type WireSegment = Segment<WireOperation>;

/**
 * The most segments a head may list: the head limit over the largest encoded
 * ref. A derived bound (the head's own byte limit), not a tuned count.
 */
const REF_ENCODED_BOUND = 160;
export function maxSegmentRefs(): number {
  return Math.floor(HEAD_LIMIT_BYTES / REF_ENCODED_BOUND);
}

/** Why a head cannot take another segment without compaction, or `null`. */
export function compactionRequired(refs: number, parts = 0): boolean {
  return refs + parts + 1 > maxSegmentRefs();
}

// ---------------------------------------------------------------------------
// Snapshot parts, the fold, and when to compact.
// ---------------------------------------------------------------------------

/**
 * A completion's cutoff on one key, as a snapshot part keeps it. A snapshot
 * entry must say which boundary it is: an explicit delete at a stamp removes
 * an observation at that stamp, an omission at that stamp does not (the model's
 * rank: an omission ranks just below an observation at its stamp, an explicit
 * delete above it). Only parts carry this kind; a segment lists the omitted
 * keys in its completion.
 */
export interface LogOmitted {
  readonly kind: "omitted";
  readonly stream: string;
  readonly pkHash: string;
  readonly key: LogKey;
  readonly stamp: LogStamp;
}

/**
 * One key's words in a snapshot: the deletion frontier when a deletion erased
 * something (it comes first), then the winning upsert if there is one.
 */
export type LogEntry = LogUpsert | LogDelete | LogOmitted;

/**
 * One part of a snapshot: the winners of a key range, sorted by (stream,
 * pkHash). Each part carries the stream metas, so a part applies by itself.
 */
/** A snapshot entry as a part encodes it: an upsert's body may be out of line. */
export type WireEntry = LogEntry | LogUpsertByRef;

export interface SnapshotPart<E extends WireEntry = LogEntry> {
  readonly format: typeof LOG_FORMAT;
  readonly connector: string;
  readonly ns: string;
  readonly generation: number;
  readonly keyCheck: string;
  /** The snapshot's position: the head's `base`. */
  readonly position: number;
  /** 0-based, in the order the pointer lists the parts. */
  readonly index: number;
  readonly streams: readonly LogStreamMeta[];
  readonly entries: readonly E[];
}

export type WireSnapshotPart = SnapshotPart<WireEntry>;

const SNAPSHOT_BLOB = /^q-([0-9a-f]{64})$/;

/** `q-<hex>`: the blob name of a snapshot part, from its data hash. */
export function snapshotPartBlobName(dataHash: string): string {
  const hex = dataHash.startsWith("0x") ? dataHash.slice(2) : dataHash;
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new InvalidArgumentError(
      `snapshot part hash is not 64 lowercase hex characters: ${dataHash}`,
    );
  }
  return `q-${hex}`;
}

export function isSnapshotPartBlobName(name: string): boolean {
  return SNAPSHOT_BLOB.test(name);
}

const BODY_PIECE_BLOB = /^v-([0-9a-f]{64})$/;

/** `v-<hex>`: the blob name of one piece of an out-of-line body, from its hash. */
export function bodyPieceBlobName(dataHash: string): string {
  const hex = dataHash.startsWith("0x") ? dataHash.slice(2) : dataHash;
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new InvalidArgumentError(
      `body piece hash is not 64 lowercase hex characters: ${dataHash}`,
    );
  }
  return `v-${hex}`;
}

export function isBodyPieceBlobName(name: string): boolean {
  return BODY_PIECE_BLOB.test(name);
}

/**
 * The first deletion (delete, omitted entry, or a completion's omission) whose
 * `key` is not the key its `pkHash` hashes for its stream, or `null`. A reader
 * applies this before it writes anything: the hash decides which record a
 * deletion removes and the key is what a record-level replica deletes, so a
 * deletion that names two different records would remove one and tombstone
 * the other. Encryption does not bind the two; this does.
 */
export async function firstDeletionKeyMismatch(
  sha256: Sha256,
  streams: readonly LogStreamMeta[],
  operations: readonly (WireOperation | WireEntry)[],
): Promise<{ readonly stream: string; readonly pkHash: string } | null> {
  const primaryKeyOf = new Map(streams.map((m) => [m.stream, m.primaryKey]));
  for (const op of operations) {
    const named =
      op.kind === "complete"
        ? op.omitted
        : op.kind === "upsert" || op.kind === "upsert-ref"
          ? []
          : [op];
    for (const { pkHash, key } of named)
      if (
        !(await deletionKeyMatchesHash(
          sha256,
          primaryKeyOf.get(op.stream) ?? [],
          key,
          pkHash,
        ))
      )
        return { stream: op.stream, pkHash };
  }
  return null;
}

export interface LogFold {
  readonly streams: readonly LogStreamMeta[];
  readonly entries: readonly LogEntry[];
}

const entryKey = (stream: string, pk: string) => `${stream}\u0000${pk}`;

/**
 * The fold of a log prefix: for every key, the latest winner, INCLUDING the
 * deletions (P4). `snapshot` is the previous snapshot's parts (none for the
 * first compaction); `segments` are the segments after it, any order.
 *
 * The rule is the reader's (`applySegmentOperations`), with the model's ranks:
 * per key, the greatest upsert and the greatest deletion are kept apart. A
 * deletion is an explicit delete or the cutoff of a completion that omitted
 * the key. At one stamp an omission ranks below an observation (the pass
 * proved the key absent only before its cutoff) and an explicit delete ranks
 * above it. The upsert wins if its (stamp, rank) is above the deletion's.
 *
 * A deletion that wins stays as a `delete` or `omitted` entry, so a reader that
 * is behind the snapshot and holds the record still loses it. A deletion that a
 * later upsert came strictly after stays too, in front of the upsert: the
 * reader drops the row it holds, and with it the row's first-seen checkpoint,
 * before it merges the resurrection. A deletion the upsert only ties (an
 * omission at the observation's stamp) erased nothing and is left out.
 *
 * A record's first-seen checkpoint is the one its winning upsert carries, NULL
 * included. Nothing takes a minimum over upserts: a reader that applied them
 * one segment at a time has already folded the older ones into a row it cannot
 * take apart again when a late delete or an unknown value arrives, so only the
 * winner's own value is something every reader can compute.
 *
 * Applying the fold gives the same records as applying the prefix in order.
 */
export function foldLog(input: {
  readonly snapshot: readonly SnapshotPart[];
  readonly segments: readonly Segment[];
}): LogFold {
  type Deletion = { stamp: LogStamp; explicit: boolean; key: LogKey };
  type Cell = {
    upsert: LogUpsert | null;
    deletion: Deletion | null;
  };
  const cells = new Map<string, Cell>();
  const cell = (stream: string, pk: string): Cell => {
    const key = entryKey(stream, pk);
    let c = cells.get(key);
    if (!c) cells.set(key, (c = { upsert: null, deletion: null }));
    return c;
  };
  const upsert = (op: LogUpsert) => {
    const c = cell(op.stream, op.pkHash);
    if (!c.upsert || upsertAfter(op, c.upsert)) c.upsert = op;
  };
  const deletion = (
    stream: string,
    pk: string,
    stamp: LogStamp,
    explicit: boolean,
    key: LogKey,
  ) => {
    const c = cell(stream, pk);
    const d = c.deletion;
    if (
      !d ||
      stampAfter(stamp, d.stamp) ||
      (explicit && !d.explicit && !stampAfter(d.stamp, stamp))
    )
      c.deletion = { stamp, explicit, key };
  };
  /** An upsert is above a deletion: later, or tied with an omission. */
  const outlives = (stamp: LogStamp, d: Deletion | null) =>
    !d ||
    stampAfter(stamp, d.stamp) ||
    (!d.explicit && !stampAfter(d.stamp, stamp));
  const metas = new Map<string, LogStreamMeta>();
  for (const part of input.snapshot) {
    for (const meta of part.streams) metas.set(meta.stream, meta);
    for (const entry of part.entries)
      if (entry.kind === "upsert") upsert(entry);
      else
        deletion(
          entry.stream,
          entry.pkHash,
          entry.stamp,
          entry.kind === "delete",
          entry.key,
        );
  }
  const ordered = [...input.segments].sort((a, b) => a.position - b.position);
  for (const segment of ordered) {
    for (const meta of segment.streams) metas.set(meta.stream, meta);
    for (const op of segment.operations)
      if (op.kind === "upsert") upsert(op);
      else if (op.kind === "delete")
        deletion(op.stream, op.pkHash, op.stamp, true, op.key);
      else
        for (const o of op.omitted)
          deletion(op.stream, o.pkHash, op.cutoff, false, o.key);
  }
  const entries: LogEntry[] = [];
  for (const [key, c] of cells) {
    const [stream, pkHash] = key.split("\u0000") as [string, string];
    const d = c.deletion;
    const tombstone = (): LogEntry => {
      const { stamp, key } = d!;
      return d!.explicit
        ? { kind: "delete", stream, pkHash, key, stamp }
        : { kind: "omitted", stream, pkHash, key, stamp };
    };
    if (c.upsert && outlives(c.upsert.stamp, d)) {
      // Only a deletion the winner is strictly after has erased anything.
      if (d && stampAfter(c.upsert.stamp, d.stamp)) entries.push(tombstone());
      entries.push({ ...c.upsert, stream, pkHash });
    } else if (d) {
      entries.push(tombstone());
    }
  }
  entries.sort(
    (a, b) =>
      (a.stream < b.stream ? -1 : a.stream > b.stream ? 1 : 0) ||
      (a.pkHash < b.pkHash ? -1 : a.pkHash > b.pkHash ? 1 : 0) ||
      // Within a key the stable sort keeps the deletion before the upsert.
      0,
  );
  return {
    streams: [...metas.values()].sort((a, b) =>
      a.stream < b.stream ? -1 : a.stream > b.stream ? 1 : 0,
    ),
    entries,
  };
}

/**
 * Split a fold into parts of about `targetBytes` each, in key order. A part
 * holds at least one entry, and a fold with none still yields one part, which
 * carries the stream metas. The size of an entry is its wire size.
 */
export function partitionFold(
  fold: {
    readonly streams: readonly LogStreamMeta[];
    readonly entries: readonly WireEntry[];
  },
  context: {
    readonly connector: string;
    readonly ns: string;
    readonly generation: number;
    readonly keyCheck: string;
    readonly position: number;
  },
  targetBytes: number = DEFAULT_PART_TARGET_BYTES,
): WireSnapshotPart[] {
  const base = (index: number, entries: WireEntry[]): WireSnapshotPart => ({
    format: LOG_FORMAT,
    ...context,
    index,
    streams: fold.streams,
    entries,
  });
  const metaBytes =
    JSON.stringify(fold.streams.map((m) => m.stream)).length +
    200 * fold.streams.length;
  const parts: WireSnapshotPart[] = [];
  let current: WireEntry[] = [];
  let size = metaBytes;
  for (const entry of fold.entries) {
    const bytes = JSON.stringify(opToWire(entry)).length + 1;
    if (current.length > 0 && size + bytes > targetBytes) {
      parts.push(base(parts.length, current));
      current = [];
      size = metaBytes;
    }
    current.push(entry);
    size += bytes;
  }
  parts.push(base(parts.length, current));
  return parts;
}

// ---------------------------------------------------------------------------
// When to compact: a cost comparison from measured primitives.
// ---------------------------------------------------------------------------
//
// A reader that is far behind has two ways to catch up:
//
//   replay    GET the n segments after `base` (in parallel) and apply them one
//             after another:
//               replayMs   = TTFB + tailBytes / BANDWIDTH + n * APPLY
//   snapshot  GET the snapshot parts (in parallel) and apply each, with
//             nothing after them to replay:
//               snapshotMs = TTFB + snapshotBytes / BANDWIDTH + parts * APPLY
//
// The saving per catch-up is replayMs - snapshotMs. Compacting costs the writer
// one time: it reads the previous snapshot and the tail, and writes the parts:
//               compactMs  = TTFB + (previousSnapshotBytes + tailBytes) /
//                            BANDWIDTH + parts * PUT
//
// Compact when one catch-up repays it: replayMs - snapshotMs > compactMs.
// Every further reader that has to catch up is then a gain. The snapshot is
// not built yet, so its size is bounded from above by the sum of what it folds
// (`previousSnapshotBytes + tailBytes`; a fold only drops bytes). That bound
// makes the rule late, never early: whenever it fires, the real snapshot is no
// larger than the estimate, so the saving is at least as large.
//
// What this leaves out, on purpose: the apply cost per record (a replay
// applies superseded versions that the snapshot does not, so ignoring it
// favours waiting), and the TTFB of each ref GET beyond the first (they run in
// parallel). The hard backstop (`compactionRequired`) applies regardless.

/** One GET's time to first byte. Measured by the Lead, 2026-11: ~100 ms. */
export const GET_TTFB_MS = 100;
/**
 * Transfer rate of a GET. Measured: 4 MiB takes ~0.46 s end to end, of which
 * ~0.10 s is TTFB, so 4 MiB / 0.36 s.
 */
export const BLOB_BYTES_PER_MS = Math.round((4 * 1024 * 1024) / 360);
/**
 * Applying one small segment: measured 20-31 ms (stream-sync apply
 * benchmarks); the midpoint.
 */
export const APPLY_MS_PER_SEGMENT = 25;
/**
 * One object store write. Measured: ~520 ms each, even for 16 KiB (the
 * reason the log exists).
 */
export const PUT_MS = 520;

export interface CompactionInputs {
  /** Segments after `base`, including the head. */
  readonly tailSegments: number;
  /** Their clear bytes: the sum of the refs' `bytes`. */
  readonly tailBytes: number;
  /** The current snapshot's clear bytes; 0 if there is none. */
  readonly snapshotBytes: number;
  readonly partTargetBytes?: number;
}

export interface CompactionCost {
  readonly replayMs: number;
  readonly snapshotMs: number;
  readonly compactMs: number;
  readonly parts: number;
}

export function compactionCost(input: CompactionInputs): CompactionCost {
  const target = input.partTargetBytes ?? DEFAULT_PART_TARGET_BYTES;
  const folded = input.snapshotBytes + input.tailBytes;
  const parts = Math.max(1, Math.ceil(folded / target));
  return {
    parts,
    replayMs:
      GET_TTFB_MS +
      input.tailBytes / BLOB_BYTES_PER_MS +
      input.tailSegments * APPLY_MS_PER_SEGMENT,
    snapshotMs:
      GET_TTFB_MS + folded / BLOB_BYTES_PER_MS + parts * APPLY_MS_PER_SEGMENT,
    compactMs: GET_TTFB_MS + folded / BLOB_BYTES_PER_MS + parts * PUT_MS,
  };
}

/** True when one catch-up through a snapshot would repay building it. */
export function shouldCompact(input: CompactionInputs): boolean {
  if (input.tailSegments === 0) return false;
  const cost = compactionCost(input);
  return cost.replayMs - cost.snapshotMs > cost.compactMs;
}

// ---------------------------------------------------------------------------
// Ops since: the read API.
// ---------------------------------------------------------------------------

export type OpsSincePlan =
  /** The reader holds the head's position: nothing newer. */
  | { readonly kind: "current" }
  /** Fetch these, apply in order. The last one is the head itself. */
  | { readonly kind: "segments"; readonly refs: readonly SegmentRef[] }
  /**
   * The log cannot answer "since n" from its own segments. The reader runs a
   * full check (stream heads, then the log from `base`).
   *   behind_base: n < base (compacted past it, or a new lifetime)
   *   ahead_of_head: n > head position (a restored registry)
   */
  | {
      readonly kind: "gap";
      readonly reason: "behind_base" | "ahead_of_head";
    };

/**
 * The segments a reader at position `since` must apply to reach `head`, in
 * order. Position n+1 is never applied before n: the list is the dense run
 * `since+1 .. head.position`, or it is a gap.
 */
export function planOpsSince(
  head: Segment,
  headRef: SegmentRef,
  since: number,
): OpsSincePlan {
  if (since === head.position) return { kind: "current" };
  if (since > head.position) return { kind: "gap", reason: "ahead_of_head" };
  if (since < head.base) return { kind: "gap", reason: "behind_base" };
  return {
    kind: "segments",
    refs: [...head.refs.filter((ref) => ref.position > since), headRef],
  };
}

// ---------------------------------------------------------------------------
// Codec.
// ---------------------------------------------------------------------------

const SEGMENT_FIELDS = [
  "base",
  "connector",
  "format",
  "generation",
  "keyCheck",
  "ns",
  "observedAt",
  "operations",
  "position",
  "refs",
  "snapshot",
  "streams",
];
const REF_FIELDS = ["bytes", "dataHash", "position"];
const REF_FIELDS_WITH_REMOVES = ["bytes", "dataHash", "position", "removes"];
const META_FIELDS = ["complete", "primaryKey", "profile", "stream"];
const UPSERT_FIELDS = ["f", "k", "o", "p", "r", "s", "v"];
/** An upsert of a run's later intake batch also carries its ordinal `n` (>= 1). */
const UPSERT_ORDINAL_FIELDS = ["f", "k", "n", "o", "p", "r", "s", "v"];
/** An upsert whose body is out of line carries `x` (`LogBodyRef`) in place of `v`. */
const UPSERT_REF_FIELDS = ["f", "k", "o", "p", "r", "s", "x"];
const UPSERT_REF_ORDINAL_FIELDS = ["f", "k", "n", "o", "p", "r", "s", "x"];
const BODY_FIELDS = ["b", "h", "p"];
const DELETE_FIELDS = ["k", "o", "p", "r", "rk", "s"];
const COMPLETE_FIELDS = ["k", "o", "omit", "r", "s"];
const OMISSION_FIELDS = ["p", "rk"];
const SNAPSHOT_FIELDS = ["parts", "position"];
const SNAPSHOT_PART_REF_FIELDS = ["bytes", "dataHash"];
const SNAPSHOT_PART_FIELDS = [
  "connector",
  "entries",
  "format",
  "generation",
  "index",
  "keyCheck",
  "ns",
  "position",
  "streams",
];

function exactKeys(value: object, expected: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  return (
    keys.length === expected.length && keys.every((k, i) => k === expected[i])
  );
}

const isCount = (value: unknown, min: number): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= min;

const isHex64 = (value: unknown): value is string =>
  typeof value === "string" && /^[0-9a-f]{64}$/.test(value);

const isStamp = (o: unknown, r: unknown): boolean =>
  isCount(o, 0) && typeof r === "string" && r !== "";

function refProblem(ref: unknown, at: string): string | null {
  if (
    !isPlainObject(ref) ||
    !(exactKeys(ref, REF_FIELDS) || exactKeys(ref, REF_FIELDS_WITH_REMOVES))
  )
    return `${at} must have exactly ${REF_FIELDS.join(", ")}, and may have removes`;
  if ("removes" in ref && typeof ref["removes"] !== "boolean")
    return `${at} removes must be a boolean`;
  if (!isCount(ref["position"], 1)) return `${at} position must be >= 1`;
  if (
    typeof ref["dataHash"] !== "string" ||
    !REGISTRY_HASH.test(ref["dataHash"])
  )
    return `${at} dataHash must be 0x + 64 lowercase hex`;
  if (!isCount(ref["bytes"], 1)) return `${at} bytes must be >= 1`;
  return null;
}

/** A non-empty array of primary-key values: strings, finite numbers, booleans. */
function isKeyValues(value: unknown): boolean {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every(
      (v) =>
        typeof v === "string" ||
        typeof v === "boolean" ||
        (typeof v === "number" && Number.isFinite(v)),
    )
  );
}

/** A `LogBodyRef` on the wire: `{b: bytes, h: sha256 hex, p: piece hashes}`. */
function bodyProblem(body: unknown): string | null {
  if (!isPlainObject(body) || !exactKeys(body, BODY_FIELDS))
    return "out-of-line body must be {b, h, p}";
  const pieces = body["p"];
  if (
    !Array.isArray(pieces) ||
    pieces.length === 0 ||
    pieces.some((h) => typeof h !== "string" || !REGISTRY_HASH.test(h))
  )
    return "out-of-line body pieces must be a non-empty list of 0x + 64 hex";
  if (!isHex64(body["h"])) return "out-of-line body sha256 must be 64 hex";
  // Every piece holds at least one byte and fits one part.
  if (
    !isCount(body["b"], pieces.length) ||
    body["b"] > pieces.length * PART_LIMIT_BYTES
  )
    return "out-of-line body length does not fit its pieces";
  return null;
}

function operationProblem(op: unknown, at: string): string | null {
  if (!isPlainObject(op)) return `${at} must be an object`;
  const kind = op["k"];
  if (kind === "u") {
    const inline =
      exactKeys(op, UPSERT_FIELDS) || exactKeys(op, UPSERT_ORDINAL_FIELDS);
    const byRef =
      exactKeys(op, UPSERT_REF_FIELDS) ||
      exactKeys(op, UPSERT_REF_ORDINAL_FIELDS);
    if (!inline && !byRef) return `${at} upsert fields`;
    if (hasOwn(op, "n") && !isCount(op["n"], 1))
      return `${at} ordinal must be a count of at least 1`;
    if (inline && !isPlainObject(op["v"]))
      return `${at} value must be an object`;
    if (byRef) {
      const problem = bodyProblem(op["x"]);
      if (problem) return `${at} ${problem}`;
    }
    if (op["f"] !== null && !isCount(op["f"], 0))
      return `${at} first-seen must be null or a count`;
  } else if (kind === "d" || kind === "o") {
    if (!exactKeys(op, DELETE_FIELDS)) return `${at} delete fields`;
  } else if (kind === "c") {
    if (!exactKeys(op, COMPLETE_FIELDS)) return `${at} completion fields`;
    const omit = op["omit"];
    if (
      !Array.isArray(omit) ||
      omit.some(
        (k) =>
          !isPlainObject(k) ||
          !exactKeys(k, OMISSION_FIELDS) ||
          !isHex64(k["p"]) ||
          !isKeyValues(k["rk"]),
      )
    )
      return `${at} omit must list {p: 64 hex, rk: primary-key values}`;
    const hashes = omit.map((k) => (k as { p: string }).p);
    for (let i = 1; i < hashes.length; i += 1)
      if (hashes[i]! <= hashes[i - 1]!)
        return `${at} omit must be ascending and distinct`;
  } else {
    return `${at} unknown operation kind`;
  }
  if (typeof op["s"] !== "string" || op["s"] === "")
    return `${at} stream must be non-empty`;
  if (isLogStream(op["s"])) return `${at} names the reserved log stream`;
  if (kind !== "c" && !isHex64(op["p"])) return `${at} pkHash must be 64 hex`;
  if (kind !== "c" && kind !== "u" && !isKeyValues(op["rk"]))
    return `${at} key must be a non-empty array of strings, numbers or booleans`;
  if (!isStamp(op["o"], op["r"])) return `${at} stamp must be (count, run id)`;
  return null;
}

function streamsProblem(streams: unknown): {
  readonly problem: string | null;
  readonly seen: Set<string>;
} {
  const seen = new Set<string>();
  if (!Array.isArray(streams))
    return { problem: "streams must be an array", seen };
  for (let i = 0; i < streams.length; i += 1) {
    const meta: unknown = streams[i];
    if (!isPlainObject(meta) || !exactKeys(meta, META_FIELDS))
      return {
        problem: `stream ${i} must have exactly ${META_FIELDS.join(", ")}`,
        seen,
      };
    const name = meta["stream"];
    if (typeof name !== "string" || name === "" || isLogStream(name))
      return { problem: `stream ${i} name is invalid`, seen };
    if (seen.has(name)) return { problem: `stream ${i} is listed twice`, seen };
    seen.add(name);
    if (typeof meta["complete"] !== "boolean")
      return { problem: `stream ${i} complete must be a boolean`, seen };
    const pk = meta["primaryKey"];
    if (
      !Array.isArray(pk) ||
      pk.length === 0 ||
      pk.some((f) => typeof f !== "string" || f === "")
    )
      return {
        problem: `stream ${i} primaryKey must be non-empty strings`,
        seen,
      };
    const profile = meta["profile"];
    if (
      !isPlainObject(profile) ||
      !exactKeys(profile, ["key", "version"]) ||
      (profile["key"] !== null && typeof profile["key"] !== "string") ||
      typeof profile["version"] !== "string" ||
      profile["version"] === ""
    )
      return { problem: `stream ${i} profile must be {key, version}`, seen };
  }
  return { problem: null, seen };
}

function segmentProblem(value: Record<string, unknown>): string | null {
  if (!exactKeys(value, SEGMENT_FIELDS))
    return `fields must be exactly: ${SEGMENT_FIELDS.join(", ")}`;
  const v = value;
  if (typeof v["connector"] !== "string" || v["connector"] === "")
    return "connector must be non-empty";
  if (typeof v["ns"] !== "string" || (v["ns"] !== "" && !HEX16.test(v["ns"])))
    return "ns must be empty or 16 lowercase hex";
  if (!isCount(v["generation"], 1)) return "generation must be >= 1";
  if (typeof v["keyCheck"] !== "string" || !HEX16.test(v["keyCheck"]))
    return "keyCheck must be 16 lowercase hex";
  if (!isCount(v["position"], 1)) return "position must be >= 1";
  if (!isCount(v["observedAt"], 0)) return "observedAt must be a count";
  if (!isCount(v["base"], 0)) return "base must be a count";
  const base = v["base"] as number;
  const position = v["position"] as number;
  const refs = v["refs"];
  if (!Array.isArray(refs)) return "refs must be an array";
  if (base + refs.length + 1 !== position)
    return "refs must be the dense positions base+1 .. position-1";
  for (let i = 0; i < refs.length; i += 1) {
    const problem = refProblem(refs[i], `ref ${i}`);
    if (problem) return problem;
    if ((refs[i] as SegmentRef).position !== base + 1 + i)
      return `ref ${i} must be position ${base + 1 + i}`;
  }
  const snapshot = v["snapshot"];
  let snapshotParts = 0;
  if (snapshot !== null) {
    if (!isPlainObject(snapshot) || !exactKeys(snapshot, SNAPSHOT_FIELDS))
      return "snapshot must be null or {parts, position}";
    if (!isCount(snapshot["position"], 1) || snapshot["position"] !== base)
      return "snapshot position must equal base";
    const parts = snapshot["parts"];
    if (
      !Array.isArray(parts) ||
      parts.length === 0 ||
      parts.some(
        (h) =>
          !isPlainObject(h) ||
          !exactKeys(h, SNAPSHOT_PART_REF_FIELDS) ||
          typeof h["dataHash"] !== "string" ||
          !REGISTRY_HASH.test(h["dataHash"]) ||
          !isCount(h["bytes"], 1),
      )
    )
      return "snapshot parts must be a non-empty list of {dataHash, bytes}";
    snapshotParts = parts.length;
  }
  if (refs.length + snapshotParts > maxSegmentRefs())
    return "refs and snapshot parts exceed the head bound";
  const checked = streamsProblem(v["streams"]);
  if (checked.problem) return checked.problem;
  const seen = checked.seen;
  const operations = v["operations"];
  if (!Array.isArray(operations)) return "operations must be an array";
  for (let i = 0; i < operations.length; i += 1) {
    const problem = operationProblem(operations[i], `operation ${i}`);
    if (problem) return problem;
    if ((operations[i] as { k: string }).k === "o")
      return `operation ${i} is a snapshot entry, not an operation`;
    if (!seen.has((operations[i] as { s: string }).s))
      return `operation ${i} names a stream with no meta`;
  }
  return null;
}

function opToWire(op: WireOperation | WireEntry): Record<string, unknown> {
  switch (op.kind) {
    case "upsert-ref":
      return {
        f: op.firstSeen,
        k: "u",
        ...(op.ordinal ? { n: op.ordinal } : {}),
        o: op.stamp.o,
        p: op.pkHash,
        r: op.stamp.r,
        s: op.stream,
        x: { b: op.body.bytes, h: op.body.sha256, p: [...op.body.pieces] },
      };
    case "upsert":
      return {
        f: op.firstSeen,
        k: "u",
        ...(op.ordinal ? { n: op.ordinal } : {}),
        o: op.stamp.o,
        p: op.pkHash,
        r: op.stamp.r,
        s: op.stream,
        v: op.value,
      };
    case "delete":
      return {
        k: "d",
        o: op.stamp.o,
        p: op.pkHash,
        r: op.stamp.r,
        rk: op.key,
        s: op.stream,
      };
    case "omitted":
      return {
        k: "o",
        o: op.stamp.o,
        p: op.pkHash,
        r: op.stamp.r,
        rk: op.key,
        s: op.stream,
      };
    case "complete":
      return {
        k: "c",
        o: op.cutoff.o,
        omit: op.omitted.map((o) => ({ p: o.pkHash, rk: o.key })),
        r: op.cutoff.r,
        s: op.stream,
      };
  }
}

function toWire(segment: WireSegment): Record<string, unknown> {
  return {
    base: segment.base,
    connector: segment.connector,
    format: segment.format,
    generation: segment.generation,
    keyCheck: segment.keyCheck,
    ns: segment.ns,
    observedAt: segment.observedAt,
    operations: segment.operations.map(opToWire),
    position: segment.position,
    refs: segment.refs.map((r) => ({
      bytes: r.bytes,
      dataHash: r.dataHash,
      position: r.position,
      ...(r.removes === undefined ? {} : { removes: r.removes }),
    })),
    snapshot: segment.snapshot
      ? {
          parts: segment.snapshot.parts.map((h) => ({
            bytes: h.bytes,
            dataHash: h.dataHash,
          })),
          position: segment.snapshot.position,
        }
      : null,
    streams: segment.streams.map((m) => ({
      complete: m.complete,
      primaryKey: [...m.primaryKey],
      profile: { key: m.profile.key, version: m.profile.version },
      stream: m.stream,
    })),
  };
}

/** Canonical clear segment bytes. Throws on a segment that would not decode. */
export function encodeSegment(segment: WireSegment): Uint8Array {
  const wire = toWire(segment);
  const problem = segmentProblem(wire);
  if (problem) throw new InvalidArgumentError(`invalid segment: ${problem}`);
  const bytes = utf8(canonicalJson(wire));
  if (bytes.length > PART_LIMIT_BYTES)
    throw new InvalidArgumentError("segment exceeds the 16 MiB segment limit");
  return bytes;
}

export interface SegmentDigest {
  readonly dataHash: `0x${string}`;
  /** `s-<hex>`. */
  readonly blobName: string;
}

export async function digestSegment(
  keccak256: Keccak256,
  bytes: Uint8Array,
): Promise<SegmentDigest> {
  const dataHash = await keccakHex(keccak256, bytes);
  return { dataHash, blobName: segmentBlobName(dataHash) };
}

export type DecodedSegment =
  | { readonly kind: "ok"; readonly segment: WireSegment }
  | { readonly kind: "unsupported_format"; readonly format: unknown }
  | { readonly kind: "malformed"; readonly reason: string };

const decoder = new TextDecoder("utf-8", { fatal: true });

function opFromWire(op: Record<string, unknown>): WireOperation | WireEntry {
  const stream = op["s"] as string;
  const stamp = { o: op["o"] as number, r: op["r"] as string };
  if (op["k"] === "u" && hasOwn(op, "x")) {
    const x = op["x"] as { b: number; h: string; p: `0x${string}`[] };
    return {
      kind: "upsert-ref",
      stream,
      pkHash: op["p"] as string,
      stamp,
      ...(hasOwn(op, "n") ? { ordinal: op["n"] as number } : {}),
      firstSeen: op["f"] as number | null,
      body: { sha256: x.h, bytes: x.b, pieces: x.p },
    };
  }
  if (op["k"] === "u")
    return {
      kind: "upsert",
      stream,
      pkHash: op["p"] as string,
      stamp,
      ...(hasOwn(op, "n") ? { ordinal: op["n"] as number } : {}),
      firstSeen: op["f"] as number | null,
      value: op["v"] as JsonObject,
    };
  if (op["k"] === "d")
    return {
      kind: "delete",
      stream,
      pkHash: op["p"] as string,
      key: op["rk"] as LogKey,
      stamp,
    };
  if (op["k"] === "o")
    return {
      kind: "omitted",
      stream,
      pkHash: op["p"] as string,
      key: op["rk"] as LogKey,
      stamp,
    };
  return {
    kind: "complete",
    stream,
    cutoff: stamp,
    omitted: (op["omit"] as { p: string; rk: LogKey }[]).map((o) => ({
      pkHash: o.p,
      key: o.rk,
    })),
  };
}

export function decodeSegment(bytes: Uint8Array): DecodedSegment {
  if (bytes.length > PART_LIMIT_BYTES)
    return { kind: "malformed", reason: "segment exceeds the 16 MiB limit" };
  let text: string;
  let parsed: unknown;
  try {
    text = decoder.decode(bytes);
    parsed = JSON.parse(text);
  } catch {
    return { kind: "malformed", reason: "segment is not UTF-8 JSON" };
  }
  if (!isPlainObject(parsed))
    return { kind: "malformed", reason: "segment is not an object" };
  const format = hasOwn(parsed, "format") ? parsed["format"] : undefined;
  if (format !== LOG_FORMAT) return { kind: "unsupported_format", format };
  const problem = segmentProblem(parsed);
  if (problem) return { kind: "malformed", reason: problem };
  if (canonicalJson(parsed) !== text)
    return { kind: "malformed", reason: "segment is not canonical JSON" };
  const p = parsed as Record<string, unknown>;
  return {
    kind: "ok",
    segment: {
      format: LOG_FORMAT,
      connector: p["connector"] as string,
      ns: p["ns"] as string,
      generation: p["generation"] as number,
      keyCheck: p["keyCheck"] as string,
      position: p["position"] as number,
      observedAt: p["observedAt"] as number,
      base: p["base"] as number,
      snapshot: p["snapshot"] as Segment["snapshot"],
      refs: p["refs"] as SegmentRef[],
      streams: p["streams"] as LogStreamMeta[],
      // `segmentProblem` refuses a snapshot-only entry kind, so none is here.
      operations: (p["operations"] as Record<string, unknown>[]).map(
        opFromWire,
      ) as WireOperation[],
    },
  };
}

export type VerifiedSegment =
  | {
      readonly kind: "ok";
      readonly segment: WireSegment;
      readonly bytes: number;
    }
  | { readonly kind: "hash_mismatch" }
  | { readonly kind: "unsupported_format"; readonly format: unknown }
  | { readonly kind: "malformed"; readonly reason: string }
  | { readonly kind: "name_mismatch" }
  | { readonly kind: "key_mismatch" }
  | { readonly kind: "position_mismatch" };

/**
 * Reader checks on decrypted segment bytes: `keccak = dataHash`, format and
 * shape, connector and namespace against the scope, `keyCheck`, and, when the
 * reader knows it, the position the ref or the registry row promised.
 */
export async function verifySegment(
  keccak256: Keccak256,
  bytes: Uint8Array,
  expected: {
    readonly dataHash: string;
    readonly connector: string;
    readonly ns: string;
    readonly keyCheck: string;
    readonly position?: number;
  },
): Promise<VerifiedSegment> {
  const dataHash = await keccakHex(keccak256, bytes);
  if (dataHash !== expected.dataHash.toLowerCase())
    return { kind: "hash_mismatch" };
  const decoded = decodeSegment(bytes);
  if (decoded.kind !== "ok") return decoded;
  const { segment } = decoded;
  if (segment.connector !== expected.connector || segment.ns !== expected.ns)
    return { kind: "name_mismatch" };
  if (segment.keyCheck !== expected.keyCheck) return { kind: "key_mismatch" };
  if (expected.position !== undefined && segment.position !== expected.position)
    return { kind: "position_mismatch" };
  return { kind: "ok", segment, bytes: bytes.length };
}

// ---------------------------------------------------------------------------
// Snapshot part codec.
// ---------------------------------------------------------------------------

function partProblem(value: Record<string, unknown>): string | null {
  if (!exactKeys(value, SNAPSHOT_PART_FIELDS))
    return `fields must be exactly: ${SNAPSHOT_PART_FIELDS.join(", ")}`;
  if (typeof value["connector"] !== "string" || value["connector"] === "")
    return "connector must be non-empty";
  if (
    typeof value["ns"] !== "string" ||
    (value["ns"] !== "" && !HEX16.test(value["ns"]))
  )
    return "ns must be empty or 16 lowercase hex";
  if (!isCount(value["generation"], 1)) return "generation must be >= 1";
  if (typeof value["keyCheck"] !== "string" || !HEX16.test(value["keyCheck"]))
    return "keyCheck must be 16 lowercase hex";
  if (!isCount(value["position"], 1)) return "position must be >= 1";
  if (!isCount(value["index"], 0)) return "index must be a count";
  const checked = streamsProblem(value["streams"]);
  if (checked.problem) return checked.problem;
  const entries = value["entries"];
  if (!Array.isArray(entries)) return "entries must be an array";
  let previous = "";
  let previousKind = "";
  for (let i = 0; i < entries.length; i += 1) {
    const entry = entries[i] as unknown;
    const problem = operationProblem(entry, `entry ${i}`);
    if (problem) return problem;
    const op = entry as { k: string; s: string; p: string };
    if (op.k === "c") return `entry ${i} must be an upsert or a delete`;
    if (!checked.seen.has(op.s))
      return `entry ${i} names a stream with no meta`;
    // Keys ascend. A key repeats once, as its deletion frontier (`d` or `o`)
    // followed by its winning upsert (`u`).
    const key = entryKey(op.s, op.p);
    if (i > 0 && key < previous)
      return `entry ${i} must be after the previous key`;
    if (i > 0 && key === previous && !(op.k === "u" && previousKind !== "u"))
      return `entry ${i} repeats a key other than as its upsert after its deletion`;
    previous = key;
    previousKind = op.k;
  }
  return null;
}

/** Canonical clear part bytes. Throws on a part that would not decode. */
export function encodeSnapshotPart(part: WireSnapshotPart): Uint8Array {
  const wire = {
    connector: part.connector,
    entries: part.entries.map(opToWire),
    format: part.format,
    generation: part.generation,
    index: part.index,
    keyCheck: part.keyCheck,
    ns: part.ns,
    position: part.position,
    streams: part.streams.map((m) => ({
      complete: m.complete,
      primaryKey: [...m.primaryKey],
      profile: { key: m.profile.key, version: m.profile.version },
      stream: m.stream,
    })),
  };
  const problem = partProblem(wire);
  if (problem)
    throw new InvalidArgumentError(`invalid snapshot part: ${problem}`);
  const bytes = utf8(canonicalJson(wire));
  if (bytes.length > PART_LIMIT_BYTES)
    throw new InvalidArgumentError("snapshot part exceeds the 16 MiB limit");
  return bytes;
}

export async function digestSnapshotPart(
  keccak256: Keccak256,
  bytes: Uint8Array,
): Promise<SegmentDigest> {
  const dataHash = await keccakHex(keccak256, bytes);
  return { dataHash, blobName: snapshotPartBlobName(dataHash) };
}

export type DecodedSnapshotPart =
  | { readonly kind: "ok"; readonly part: WireSnapshotPart }
  | { readonly kind: "unsupported_format"; readonly format: unknown }
  | { readonly kind: "malformed"; readonly reason: string };

export function decodeSnapshotPart(bytes: Uint8Array): DecodedSnapshotPart {
  if (bytes.length > PART_LIMIT_BYTES)
    return { kind: "malformed", reason: "part exceeds the 16 MiB limit" };
  let text: string;
  let parsed: unknown;
  try {
    text = decoder.decode(bytes);
    parsed = JSON.parse(text);
  } catch {
    return { kind: "malformed", reason: "part is not UTF-8 JSON" };
  }
  if (!isPlainObject(parsed))
    return { kind: "malformed", reason: "part is not an object" };
  const format = hasOwn(parsed, "format") ? parsed["format"] : undefined;
  if (format !== LOG_FORMAT) return { kind: "unsupported_format", format };
  const problem = partProblem(parsed);
  if (problem) return { kind: "malformed", reason: problem };
  if (canonicalJson(parsed) !== text)
    return { kind: "malformed", reason: "part is not canonical JSON" };
  const p = parsed as Record<string, unknown>;
  return {
    kind: "ok",
    part: {
      format: LOG_FORMAT,
      connector: p["connector"] as string,
      ns: p["ns"] as string,
      generation: p["generation"] as number,
      keyCheck: p["keyCheck"] as string,
      position: p["position"] as number,
      index: p["index"] as number,
      streams: p["streams"] as LogStreamMeta[],
      entries: (p["entries"] as Record<string, unknown>[]).map(
        opFromWire,
      ) as WireEntry[],
    },
  };
}

export type VerifiedSnapshotPart =
  | {
      readonly kind: "ok";
      readonly part: WireSnapshotPart;
      readonly bytes: number;
    }
  | { readonly kind: "hash_mismatch" }
  | { readonly kind: "unsupported_format"; readonly format: unknown }
  | { readonly kind: "malformed"; readonly reason: string }
  | { readonly kind: "name_mismatch" }
  | { readonly kind: "key_mismatch" }
  | { readonly kind: "position_mismatch" };

/** The reader's checks on a decrypted part, as `verifySegment` does. */
export async function verifySnapshotPart(
  keccak256: Keccak256,
  bytes: Uint8Array,
  expected: {
    readonly dataHash: string;
    readonly connector: string;
    readonly ns: string;
    readonly keyCheck: string;
    readonly position?: number;
  },
): Promise<VerifiedSnapshotPart> {
  const dataHash = await keccakHex(keccak256, bytes);
  if (dataHash !== expected.dataHash.toLowerCase())
    return { kind: "hash_mismatch" };
  const decoded = decodeSnapshotPart(bytes);
  if (decoded.kind !== "ok") return decoded;
  const { part } = decoded;
  if (part.connector !== expected.connector || part.ns !== expected.ns)
    return { kind: "name_mismatch" };
  if (part.keyCheck !== expected.keyCheck) return { kind: "key_mismatch" };
  if (expected.position !== undefined && part.position !== expected.position)
    return { kind: "position_mismatch" };
  return { kind: "ok", part, bytes: bytes.length };
}
