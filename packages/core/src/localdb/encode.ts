import { SEEN_PAIR } from "./merge.js";
import { BODY_BYTES } from "./part-layout.js";
import {
  encodeFramePart,
  encodePiece,
  frameOfBody,
  PART_LIMIT_BYTES,
  type FrameBytes,
  type JsonValue,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { readerOf, type SqlReader, type SqlValue } from "./driver.js";
import type { LocalSyncDeps } from "./deps.js";
import { nobleStreamCrypto } from "../stream-sync/crypto-port.js";
import { meteredBlobs, type PublishMeter } from "./publish-meter.js";
import { newUploadWave, type UploadWave } from "./upload-wave.js";
import { holdMemory } from "./transfer-memory.js";
import type { Reservation } from "../stream-sync/send-gate.js";

/** A reservation of nothing: the part has no memory held for it. */
const NO_RESERVATION: Reservation = Object.assign(() => {}, {
  shrink: () => {},
});

/**
 * Extra fields a head carries beside its parts (pending r5.2: the first-seen
 * checkpoint, "history-checkpoint"). Opaque here: encode copies them into the
 * head unchanged. Absent today.
 */
export type HeadExtras = Readonly<Record<string, JsonValue>>;

/** One uploaded (or already present) part of a head. */
export interface EncodedPart {
  readonly prefix: string;
  readonly seq: number;
  readonly partHash: string;
  readonly bytes: number;
  readonly count: number;
  /** Blob name `g<gen>-p-<sha256>`. */
  readonly blobName: string;
}

/** One `records` row as the encoder reads it. */
export type FrozenRow = {
  readonly pk_hash: string;
  readonly stamp_o: number;
  readonly stamp_r: string;
  readonly body: string;
  readonly body_sha256: string;
  readonly first_o: number | null;
};

/**
 * What the snapshot spooled of one changed prefix: how many rows it copied
 * into `publish_spool`. The rows themselves stay on disk; this is all the
 * candidate keeps in memory.
 */
export interface FrozenPrefix {
  readonly prefix: string;
  /** Rows copied into the spool; `null` for a frozen view, which cannot lose any. */
  readonly rows: number | null;
}

/**
 * Rows read straight from `records` through a `SqlSnapshot`, so the version's
 * content is the state the snapshot was opened on and no row is copied.
 */
export interface FrozenView {
  readonly view: SqlReader;
  readonly connectionId: string;
  readonly stream: string;
  readonly replaceBelow?: { readonly o: number; readonly r: string };
}

/**
 * The prefixes a snapshot has frozen, handed to the transfer one at a time
 * while the snapshot is still freezing the next ones. One producer (the freeze)
 * and one consumer (the encoder). The feed holds a count per prefix, never
 * rows, so it adds no memory that grows with the stream.
 *
 * `end` says the freeze finished. `fail` says it did not: the consumer throws
 * the error at once and gets none of the prefixes still waiting. `abandon` is
 * the consumer's way to say it stopped (a failed upload, a purge): the
 * producer sees `abandoned()` and stops freezing prefixes nobody will read.
 */
export interface FrozenFeed extends AsyncIterable<FrozenPrefix> {
  push(frozen: FrozenPrefix): void;
  end(): void;
  fail(error: unknown): void;
  abandon(): void;
  abandoned(): boolean;
}

export function newFrozenFeed(): FrozenFeed {
  const waiting: FrozenPrefix[] = [];
  let finished: { readonly error?: unknown } | undefined;
  let gone = false;
  let wake: (() => void) | undefined;
  const signal = () => {
    const resume = wake;
    wake = undefined;
    resume?.();
  };
  return {
    push(frozen) {
      if (finished || gone) return;
      waiting.push(frozen);
      signal();
    },
    end() {
      finished ??= {};
      signal();
    },
    fail(error) {
      if (finished) return;
      finished = { error };
      waiting.length = 0;
      signal();
    },
    abandon() {
      gone = true;
      waiting.length = 0;
    },
    abandoned: () => gone,
    async *[Symbol.asyncIterator]() {
      for (;;) {
        const next = waiting.shift();
        if (next) {
          yield next;
        } else if (finished) {
          if ("error" in finished) throw finished.error;
          return;
        } else {
          await new Promise<void>((resolve) => (wake = resolve));
        }
      }
    },
  };
}

/**
 * The spool no longer holds the rows the snapshot copied (a purge, or another
 * process, removed them). The candidate is stale: the caller discards it and
 * snapshots again. Later writes to `records` never cause this; the commit's
 * revalidation is what rejects a snapshot that real changes made wrong.
 */
export class FrozenRowsChanged extends Error {
  constructor(readonly prefix: string) {
    super(`spooled rows of prefix "${prefix}" are gone`);
    this.name = "FrozenRowsChanged";
  }
}

/**
 * A transfer page holds at most `PAGE_BYTES` of bodies when two or more rows
 * fit. A row larger than that is a page of its own: one body is the floor,
 * because a body is encoded whole. Row sizes are read `META_ROWS` at a time
 * and cut into pages; a page also holds at most `META_ROWS` rows.
 */
export const META_ROWS = 2048;
export const PAGE_BYTES = 2 * 1024 * 1024;

/** The byte target a part is cut at: `deps.partTargetBytes`, default 4 MiB. */
export function partTargetOf(deps: LocalSyncDeps): number {
  const target = deps.partTargetBytes ?? 4 * 1024 * 1024;
  if (
    !Number.isSafeInteger(target) ||
    target < 1 ||
    target > PART_LIMIT_BYTES
  ) {
    throw new Error("partTargetBytes must be between 1 and 16 MiB");
  }
  return target;
}

function partTarget(deps: LocalSyncDeps, generation: number): number {
  const target = partTargetOf(deps);
  if (!Number.isSafeInteger(generation) || generation < 1) {
    throw new Error("generation must be a positive safe integer");
  }
  return target;
}

type PrefixQuery = {
  readonly connectionId: string;
  readonly stream: string;
  readonly replaceBelow?: { readonly o: number; readonly r: string };
};

function checkedPrefixes(changedPrefixes: readonly string[]): string[] {
  const prefixes = [...new Set(changedPrefixes)].sort();
  for (let i = 0; i < prefixes.length; i += 1) {
    const prefix = prefixes[i]!;
    if (!/^[01]{0,16}$/.test(prefix)) throw new Error("invalid part prefix");
    if (i > 0 && prefix.startsWith(prefixes[i - 1]!)) {
      throw new Error("part prefixes must not overlap");
    }
  }
  return prefixes;
}

/** The `pk_hash` range a part prefix covers, as SQL and parameters. */
function keyRange(prefix: string): { sql: string; params: SqlValue[] } {
  if (prefix === "") return { sql: "", params: [] };
  const lo = parseInt(prefix.padEnd(16, "0"), 2);
  const hi = lo + 2 ** (16 - prefix.length);
  return {
    sql: " AND pk_hash >= ? AND pk_hash < ?",
    params: [
      lo.toString(16).padStart(4, "0").padEnd(64, "0"),
      hi === 65536 ? "g" : hi.toString(16).padStart(4, "0").padEnd(64, "0"),
    ],
  };
}

/** A fresh id for one publish attempt's spool rows. */
export function newSpoolAttempt(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

/**
 * Delete an attempt's spool rows: on commit, on discard, on failure. `prefixes`
 * are the ones the attempt froze (`freezePrefixRows`), so each delete is one
 * key range on the spool's primary key. One batch per prefix, so no batch holds
 * the worker for the whole spool. Rows outside those prefixes are not possible:
 * only `freezePrefixRows` writes an attempt's rows, and only for these prefixes.
 */
export async function dropSpool(
  deps: LocalSyncDeps,
  attempt: string,
  prefixes: readonly string[],
): Promise<void> {
  for (const prefix of new Set(prefixes)) {
    const range = keyRange(prefix);
    await deps.db.batch([
      {
        sql: `DELETE FROM publish_spool WHERE attempt = ?${range.sql}`,
        params: [attempt, ...range.params],
      },
    ]);
  }
}

/**
 * Copy the changed prefixes' rows into `publish_spool` under `attempt`, one
 * batch per prefix and one `INSERT ... SELECT` per batch, so no row passes
 * through memory and no batch holds the worker for the whole spool. Run under
 * the connection's queue slot: no other writer of `records` for this
 * connection runs between the batches, so together they copy one consistent
 * state. Under replace (H), rows below `replaceBelow` are left out. What is
 * kept in memory grows with the number of prefixes (at most 65,536), not with
 * the rows.
 *
 * The transfer reads only this copy, so a write to `records` after this call
 * cannot change what is sent. A write that makes the snapshot wrong is the
 * commit's to catch.
 *
 * `onFrozen` lets the transfer start on a prefix as soon as its batch has
 * committed, while later prefixes are still being copied. That does not weaken
 * the snapshot: its consistency comes from the slot (no writer of `records`
 * runs between the batches), not from the order the transfer reads in.
 */
export async function freezePrefixRows(
  deps: LocalSyncDeps,
  input: PrefixQuery & {
    readonly attempt: string;
    readonly changedPrefixes: readonly string[];
    /**
     * Called with each prefix once its batch has committed, in key order, so a
     * transfer can read it while the next prefixes are still being copied.
     */
    readonly onFrozen?: (frozen: FrozenPrefix) => void;
    /** Asked before each prefix: true means nobody will read more, so stop. */
    readonly stopped?: () => boolean;
  },
): Promise<readonly FrozenPrefix[]> {
  const prefixes = checkedPrefixes(input.changedPrefixes);
  const frozen: FrozenPrefix[] = [];
  for (const prefix of prefixes) {
    if (input.stopped?.()) break;
    const range = keyRange(prefix);
    let where = "connection_id = ? AND stream = ?" + range.sql;
    const params: SqlValue[] = [
      input.attempt,
      input.connectionId,
      input.stream,
      ...range.params,
    ];
    if (input.replaceBelow) {
      // A row an equal-body run only observed still belongs to the replacement.
      where += ` AND ${SEEN_PAIR} >= (?, ?)`;
      params.push(input.replaceBelow.o, input.replaceBelow.r);
    }
    const { changes } = await deps.db.batch([
      {
        sql: `INSERT INTO publish_spool
        (attempt, connection_id, pk_hash, stamp_o, stamp_r, first_o,
         body_sha256, body_bytes, body)
      SELECT ?, connection_id, pk_hash, stamp_o, stamp_r, first_o,
             body_sha256, length(CAST(body AS BLOB)), body
        FROM records WHERE ${where}`,
        params,
      },
    ]);
    const done = { prefix, rows: changes[0]! };
    frozen.push(done);
    input.onFrozen?.(done);
  }
  return frozen;
}

type SpoolRow = Omit<FrozenRow, "body"> & { readonly body: string };

/**
 * Read one prefix of the frozen rows in key order, from the attempt's spool or
 * from a frozen view of `records`. A page is found by metadata first (key and
 * body size, no body, `META_ROWS` rows at a time), cut at `PAGE_BYTES` of
 * bodies (at least one row), and only then are its bodies read. Neither source changes
 * while the attempt runs, so a range read returns exactly the rows the
 * metadata named; fewer means the spool was emptied under the transfer.
 */
async function* readFrozen(
  deps: LocalSyncDeps,
  source: { readonly attempt: string; readonly view?: FrozenView },
  prefix: string,
): AsyncGenerator<readonly SpoolRow[]> {
  const range = keyRange(prefix);
  // A prefix is read after its batch committed, and nothing writes it again,
  // so the read connection sees all of it. It does not queue behind the
  // freeze of the next prefixes.
  const reader: SqlReader = source.view?.view ?? readerOf(deps.db);
  const frozen = source.view;
  // The two sources differ only in the table and its scope.
  let from: string;
  let scope: string;
  let scopeParams: SqlValue[];
  if (frozen) {
    from = "records";
    scope = "connection_id = ? AND stream = ?";
    scopeParams = [frozen.connectionId, frozen.stream];
    if (frozen.replaceBelow) {
      // Rows below the replacing run are left out, as the copy leaves them.
      scope += ` AND ${SEEN_PAIR} >= (?, ?)`;
      scopeParams.push(frozen.replaceBelow.o, frozen.replaceBelow.r);
    }
  } else {
    from = "publish_spool";
    scope = "attempt = ?";
    scopeParams = [source.attempt];
  }
  let meta: { pk_hash: string; body_bytes: number | null }[] = [];
  let at = 0;
  let more = true;
  for (;;) {
    if (at === meta.length) {
      if (!more) return;
      const after: string | undefined = meta[meta.length - 1]?.pk_hash;
      meta = await reader.query(
        `SELECT pk_hash, body_bytes FROM ${from}
          WHERE ${scope}${range.sql}${after === undefined ? "" : " AND pk_hash > ?"}
          ORDER BY pk_hash LIMIT ${META_ROWS}`,
        [
          ...scopeParams,
          ...range.params,
          ...(after === undefined ? [] : [after]),
        ],
      );
      at = 0;
      more = meta.length === META_ROWS;
      if (meta.length === 0) return;
      // A row from before `body_bytes` existed has no stored size: measure
      // the span of rows that holds them in one range read of the bodies.
      const unsized = meta.filter((row) => row.body_bytes === null);
      if (frozen && unsized.length > 0) {
        const measured = new Map(
          (
            await reader.query<{ pk_hash: string; n: number }>(
              `SELECT pk_hash, ${BODY_BYTES} AS n FROM records
                WHERE ${scope} AND pk_hash >= ? AND pk_hash <= ?`,
              [
                ...scopeParams,
                unsized[0]!.pk_hash,
                unsized[unsized.length - 1]!.pk_hash,
              ],
            )
          ).map((row) => [row.pk_hash, Number(row.n)]),
        );
        for (const row of unsized)
          row.body_bytes = measured.get(row.pk_hash) ?? 0;
      }
    }
    let take = 0;
    let bytes = 0;
    while (
      at + take < meta.length &&
      (take === 0 || bytes + Number(meta[at + take]!.body_bytes) <= PAGE_BYTES)
    ) {
      bytes += Number(meta[at + take]!.body_bytes);
      take += 1;
    }
    const first = meta[at]!.pk_hash;
    const last = meta[at + take - 1]!.pk_hash;
    const page: SpoolRow[] = await reader.query(
      `SELECT pk_hash, stamp_o, stamp_r, first_o, body_sha256, body
         FROM ${from}
        WHERE ${scope} AND pk_hash >= ? AND pk_hash <= ?
        ORDER BY pk_hash`,
      [...scopeParams, first, last],
    );
    if (page.length !== take) throw new FrozenRowsChanged(prefix);
    yield page;
    at += take;
  }
}

/**
 * C.2 step 4, after the freeze: read the attempt's spool page by page, encode
 * the rows as v3 frames (format 4 or later head) in parts of at most `partTargetBytes`,
 * STREAM-encrypted, and upload each part that does not exist. Identical rows
 * give an identical part, so a repeat run makes zero PUTs.
 *
 * Returns when every part is stored. `startFrozenParts` is the same work for a
 * caller that overlaps the uploads with its next step.
 */
export async function uploadFrozenParts(
  deps: LocalSyncDeps,
  input: {
    readonly attempt: string;
    readonly scope: string;
    readonly generation: number;
    readonly frozen: readonly FrozenPrefix[];
    /** Counts the blob calls and parts written; the bytes stay the same. */
    readonly meter?: PublishMeter;
    /** Called before each part is probed and again before it is uploaded; a throw stops the transfer. */
    readonly beforeUpload?: () => void;
  },
): Promise<readonly EncodedPart[]> {
  const wave = newUploadWave();
  try {
    const parts = await startFrozenParts(deps, { ...input, wave, probe: true });
    await wave.drain();
    return parts;
  } catch (error) {
    await wave.settle();
    throw error;
  }
}

/**
 * The encoding half of `uploadFrozenParts`: it starts each part's upload on
 * `wave` and returns the parts as soon as the last one is encoded, while the
 * uploads may still be running. The caller owns the wave: it must `drain` it
 * before anything that points at the parts, and `settle` it if it exits early.
 * A part's hash, size and count are known when it is encoded, so a head can be
 * built and uploaded without waiting for the parts it names.
 *
 * `probe` is whether to ask storage if a part exists before uploading it. A
 * stream with no registry row has nothing in storage worth finding, so its
 * transfer passes `false` and always uploads. A name is the hash of the clear
 * bytes, so an upload of a stored name keeps or replaces the object with
 * another encryption of the same clear bytes (storage does not promise which);
 * a probe skipped can cost a repeated upload and never a missing part. Never
 * skip a probe because this device uploaded the part before: storage can
 * delete or overwrite objects, and a remembered upload proves nothing.
 *
 * It needs no queue slot and holds no transaction: each page is its own read
 * of the spool, which no write to `records` reaches. Each prefix's row count
 * is checked against the spooled count before its last part is encoded; a
 * difference means the spool was emptied under the transfer and throws
 * `FrozenRowsChanged`, and the head is never built. Memory is one page (at most
 * `PAGE_BYTES` of bodies, or one row) and the parts the store's byte budget
 * allows (`holdMemory`), however large the stream. A stream has no upload
 * width of its own: the store's send gate decides how many parts are on the
 * wire.
 */
export async function startFrozenParts(
  deps: LocalSyncDeps,
  input: {
    readonly attempt: string;
    /** Read `records` through this view instead of the attempt's spool. */
    readonly view?: FrozenView;
    readonly scope: string;
    readonly generation: number;
    /**
     * The prefixes to encode, in key order. A feed delivers each one as the
     * snapshot finishes copying it.
     */
    readonly frozen: Iterable<FrozenPrefix> | AsyncIterable<FrozenPrefix>;
    readonly wave: UploadWave;
    readonly probe: boolean;
    /** Counts the blob calls and parts written; the bytes stay the same. */
    readonly meter?: PublishMeter;
    /** Called before each part is probed and again before it is uploaded; a throw stops the transfer. */
    readonly beforeUpload?: () => void;
  },
): Promise<readonly EncodedPart[]> {
  const target = partTarget(deps, input.generation);
  const blobs = input.meter ? meteredBlobs(deps, input.meter) : deps.blobs;
  // Memory budget (see `holdMemory`): two parts' worth, `2 * target` bytes, is
  // reserved before a page of rows is read for a part: the plain encoded part
  // and room for its ciphertext are both in memory until it is encrypted. When
  // the part is encoded its upload takes the reservation. It keeps only the
  // ciphertext once the part is encrypted (the plain bytes are dropped, and the
  // reservation shrinks to the ciphertext's size), and releases that once the
  // part is stored (or skipped), so the bytes of a part waiting for the send
  // gate stay counted but are one part's bytes, not two: the budget holds the
  // send gate's width in parts. The builder asks for the next reservation only
  // while it holds none, and an upload never asks for bytes, so a held
  // reservation always ends and reservations cannot wait on each other.
  let held: Reservation | undefined;
  const memory = {
    hold: async () => {
      held ??= await holdMemory(blobs, 2 * target, target);
    },
    /** Passes the reservation to the caller, who must release it. */
    take: (): Reservation => {
      const reservation = held ?? NO_RESERVATION;
      held = undefined;
      return reservation;
    },
    drop: () => memory.take()(),
  };
  try {
    return await encodeFrozenParts(deps, input, target, blobs, memory);
  } finally {
    memory.drop();
  }
}

async function encodeFrozenParts(
  deps: LocalSyncDeps,
  input: Parameters<typeof startFrozenParts>[1],
  target: number,
  blobs: ReturnType<typeof meteredBlobs>,
  memory: {
    readonly hold: () => Promise<void>;
    readonly take: () => Reservation;
    readonly drop: () => void;
  },
): Promise<readonly EncodedPart[]> {
  const result: EncodedPart[] = [];
  const port = deps.streamCrypto ?? nobleStreamCrypto;
  const hash = async (bytes: Uint8Array): Promise<Uint8Array> =>
    port.sha256(bytes);
  // The next prefix is awaited here, while no memory is held: `flush` has
  // dropped the last reservation and `hold` has not asked for the next.
  for await (const frozen of input.frozen) {
    const { prefix } = frozen;
    let seq = 0;
    const upload = async (part: Awaited<ReturnType<typeof encodePiece>>) => {
      const { hash: partHash, bytes, count } = part.entry;
      const blobName = `g${input.generation}-p-${partHash}`;
      const key = `${input.scope}/${blobName}`;
      const release = memory.take();
      // The task's own handle on the plain bytes, so it can drop them as soon
      // as they are encrypted: it must not read `part`, whose `data` it would
      // keep alive until the PUT settles.
      let plain: Uint8Array | undefined = part.data;
      try {
        input.wave.start(async () => {
          try {
            input.beforeUpload?.();
            if (!input.probe || !(await blobs.exists(key))) {
              const cipher = await deps.keys.encryptPart(input.scope, plain!);
              // Only the ciphertext is kept while the PUT waits and runs.
              plain = undefined;
              release.shrink(cipher.length);
              input.beforeUpload?.();
              await blobs.put(key, cipher, input.beforeUpload);
              if (input.meter) input.meter.partsUploaded += 1;
            }
          } finally {
            plain = undefined;
            release();
          }
        });
      } catch (error) {
        // The wave refused it: no upload took the reservation.
        release();
        throw error;
      }
      result.push({ prefix, seq, partHash, bytes, count, blobName });
      seq += 1;
    };
    let frames: FrameBytes[] = [];
    let bytes = 0;
    const flush = async () => {
      try {
        const part = await encodeFramePart(hash, prefix, frames);
        if (part) await upload(part);
        frames = [];
        bytes = 0;
      } finally {
        memory.drop();
      }
    };
    let seen = 0;
    const pages = readFrozen(deps, input, prefix);
    for (;;) {
      await memory.hold();
      const next = await pages.next();
      if (next.done) break;
      for (const row of next.value) {
        seen += 1;
        const body = new TextEncoder().encode(row.body);
        const frame = frameOfBody(
          {
            h: row.body_sha256,
            k: row.pk_hash,
            n: body.length,
            o: row.stamp_o,
            r: row.stamp_r,
            f: row.first_o ?? null,
          },
          body,
        );
        if (frame.length > target) {
          await flush();
          // A reader must see the entire envelope in the first piece.
          if (frame.indexOf(0x0a) + 1 > target) {
            throw new Error(
              "partTargetBytes is too small for a frame envelope",
            );
          }
          for (let at = 0; at < frame.length; at += target) {
            await memory.hold();
            await upload(
              await encodePiece(
                hash,
                prefix,
                frame.subarray(at, at + target),
                at === 0,
              ),
            );
          }
        } else {
          if (bytes + frame.length > target) await flush();
          await memory.hold();
          frames.push({ k: row.pk_hash, bytes: frame });
          bytes += frame.length;
        }
      }
    }
    if (frozen.rows !== null && seen !== frozen.rows)
      throw new FrozenRowsChanged(prefix);
    await flush();
  }
  return result;
}

/**
 * C.2 step 4: spool the changed prefixes, then encode and upload them. The
 * publisher calls the two halves apart (spool under the queue slot, upload
 * outside it); this composition is for a caller that holds the slot itself.
 * It drops its spool rows before returning, whether the upload succeeded or not.
 */
export async function encodePrefixes(
  deps: LocalSyncDeps,
  input: {
    readonly connectionId: string;
    readonly stream: string;
    readonly scope: string;
    readonly generation: number;
    readonly changedPrefixes: readonly string[];
    readonly upToSeq: number;
    readonly replaceBelow?: { readonly o: number; readonly r: string };
    readonly headExtras?: HeadExtras;
  },
): Promise<readonly EncodedPart[]> {
  partTarget(deps, input.generation);
  // upToSeq fences the publish watermark, not this snapshot of records.
  // HeadExtras belongs to the caller's head and is deliberately left opaque.
  const attempt = newSpoolAttempt();
  try {
    return await uploadFrozenParts(deps, {
      attempt,
      scope: input.scope,
      generation: input.generation,
      frozen: await freezePrefixRows(deps, { ...input, attempt }),
    });
  } finally {
    await dropSpool(deps, attempt, input.changedPrefixes);
  }
}
