import { sha256 } from "@noble/hashes/sha2";
import { SEEN_PAIR } from "./merge.js";
import {
  encodeFramePart,
  encodePiece,
  frameOfBody,
  PART_LIMIT_BYTES,
  type FrameBytes,
  type JsonValue,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { SqlValue } from "./driver.js";
import type { LocalSyncDeps } from "./deps.js";
import { meteredBlobs, type PublishMeter } from "./publish-meter.js";
import { newUploadWave, type UploadWave } from "./upload-wave.js";
import { holdMemory } from "./transfer-memory.js";

const hash = async (bytes: Uint8Array): Promise<Uint8Array> => sha256(bytes);

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
  readonly rows: number;
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
 * A transfer page holds at most this many rows and, when two or more rows
 * fit, at most `PAGE_BYTES` of bodies. A row larger than that is a page of
 * its own: one body is the floor, because a body is encoded whole.
 */
const PAGE_ROWS = 64;
const PAGE_BYTES = 2 * 1024 * 1024;

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
 */
export async function freezePrefixRows(
  deps: LocalSyncDeps,
  input: PrefixQuery & {
    readonly attempt: string;
    readonly changedPrefixes: readonly string[];
  },
): Promise<readonly FrozenPrefix[]> {
  const prefixes = checkedPrefixes(input.changedPrefixes);
  const frozen: FrozenPrefix[] = [];
  for (const prefix of prefixes) {
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
    frozen.push({ prefix, rows: changes[0]! });
  }
  return frozen;
}

type SpoolRow = Omit<FrozenRow, "body"> & { readonly body: string };

/**
 * Read one prefix of an attempt's spool in key order. A page is found by
 * metadata first (key and body size, no body), cut at `PAGE_ROWS` rows or
 * `PAGE_BYTES` of bodies (at least one row), and only then are its bodies
 * read. The spool does not change while the attempt runs, so a range read
 * returns exactly the rows the metadata named; fewer means the spool was
 * emptied under the transfer.
 */
async function* readSpool(
  deps: LocalSyncDeps,
  attempt: string,
  prefix: string,
): AsyncGenerator<readonly SpoolRow[]> {
  const range = keyRange(prefix);
  let after: string | null = null;
  for (;;) {
    const meta: { pk_hash: string; body_bytes: number }[] = await deps.db.query(
      `SELECT pk_hash, body_bytes FROM publish_spool
          WHERE attempt = ?${range.sql}${after === null ? "" : " AND pk_hash > ?"}
          ORDER BY pk_hash LIMIT ${PAGE_ROWS}`,
      [attempt, ...range.params, ...(after === null ? [] : [after])],
    );
    if (meta.length === 0) return;
    let take = 0;
    let bytes = 0;
    while (
      take < meta.length &&
      (take === 0 || bytes + Number(meta[take]!.body_bytes) <= PAGE_BYTES)
    ) {
      bytes += Number(meta[take]!.body_bytes);
      take += 1;
    }
    const first = meta[0]!.pk_hash;
    const last = meta[take - 1]!.pk_hash;
    const page: SpoolRow[] = await deps.db.query(
      `SELECT pk_hash, stamp_o, stamp_r, first_o, body_sha256, body
         FROM publish_spool
        WHERE attempt = ? AND pk_hash >= ? AND pk_hash <= ?
        ORDER BY pk_hash`,
      [attempt, first, last],
    );
    if (page.length !== take) throw new FrozenRowsChanged(prefix);
    yield page;
    if (take === meta.length && meta.length < PAGE_ROWS) return;
    after = last;
  }
}

/**
 * Parts one stream's transfer holds at once while they wait for the storage
 * client's turn (encoded bytes and ciphertext each). The storage client's own
 * limits decide how many go on the wire; this only bounds memory per stream.
 * Memory across streams is bounded by the store's byte budget (`holdMemory`).
 *
 * At least 2: a wave also carries the attachment upload, which can wait for
 * bytes, and a part upload must be able to run beside it.
 */
export const PARTS_IN_FLIGHT = 2;

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
  const wave = newUploadWave(PARTS_IN_FLIGHT);
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
 * `PAGE_BYTES` of bodies, or one row) and the `PARTS_IN_FLIGHT` parts of the
 * wave, however large the stream.
 */
export async function startFrozenParts(
  deps: LocalSyncDeps,
  input: {
    readonly attempt: string;
    readonly scope: string;
    readonly generation: number;
    readonly frozen: readonly FrozenPrefix[];
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
  // Memory budget (see `holdMemory`): one part's worth, `target` bytes, is
  // reserved before a page of rows is read for a part. When the part is
  // encoded its upload takes the reservation and releases it once the part is
  // stored (or skipped), so the bytes of a part waiting for the send gate stay
  // counted. The builder asks for the next reservation only while it holds
  // none, and an upload never asks for bytes, so a held reservation always
  // ends and reservations cannot wait on each other.
  let held: (() => void) | undefined;
  const memory = {
    hold: async () => {
      held ??= await holdMemory(blobs, target);
    },
    /** Passes the reservation to the caller, who must release it. */
    take: (): (() => void) => {
      const release = held ?? (() => {});
      held = undefined;
      return release;
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
    readonly take: () => () => void;
    readonly drop: () => void;
  },
): Promise<readonly EncodedPart[]> {
  const result: EncodedPart[] = [];
  for (const frozen of input.frozen) {
    const { prefix } = frozen;
    let seq = 0;
    const upload = async (part: Awaited<ReturnType<typeof encodePiece>>) => {
      const { hash: partHash, bytes, count } = part.entry;
      const blobName = `g${input.generation}-p-${partHash}`;
      const key = `${input.scope}/${blobName}`;
      const release = memory.take();
      try {
        await input.wave.start(async () => {
          try {
            input.beforeUpload?.();
            if (!input.probe || !(await blobs.exists(key))) {
              const cipher = await deps.keys.encryptPart(
                input.scope,
                part.data,
              );
              input.beforeUpload?.();
              await blobs.put(key, cipher, input.beforeUpload);
              if (input.meter) input.meter.partsUploaded += 1;
            }
          } finally {
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
    const pages = readSpool(deps, input.attempt, prefix);
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
    if (seen !== frozen.rows) throw new FrozenRowsChanged(prefix);
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
