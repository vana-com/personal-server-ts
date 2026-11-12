import { sha256 } from "@noble/hashes/sha2";
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
 * What the snapshot froze of one changed prefix: how many rows it held and a
 * digest of their identities, in key order. No row body is kept.
 *
 * A row's identity is (key, stamp, first checkpoint, body hash). The stamp and
 * the body hash change together, but `first_o` can change under an unchanged
 * stamp (an import or an older checkpoint lowers it, and logs nothing), and the
 * frame carries it, so it is part of the identity. Two reads of a prefix that
 * give the same digest therefore encode to the same bytes.
 */
export interface FrozenPrefix {
  readonly prefix: string;
  readonly rows: number;
  readonly digest: string;
}

/**
 * The rows a transfer read are not the rows the snapshot froze. The candidate
 * is stale: the caller discards it and snapshots again.
 */
export class FrozenRowsChanged extends Error {
  constructor(readonly prefix: string) {
    super(`rows of prefix "${prefix}" changed after the snapshot`);
    this.name = "FrozenRowsChanged";
  }
}

/** Rows read per query. Memory is a page of bodies plus the part in progress. */
const PAGE_ROWS = 64;

function partTarget(deps: LocalSyncDeps, generation: number): number {
  const target = deps.partTargetBytes ?? 4 * 1024 * 1024;
  if (
    !Number.isSafeInteger(target) ||
    target < 1 ||
    target > PART_LIMIT_BYTES
  ) {
    throw new Error("partTargetBytes must be between 1 and 16 MiB");
  }
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

/**
 * Read one prefix from `records` in key order, `PAGE_ROWS` rows per query. Each
 * query is its own read (no transaction spans pages, so none spans a network
 * await). Under replace (H), rows below `replaceBelow` are left out.
 */
async function* readPrefix(
  deps: LocalSyncDeps,
  input: PrefixQuery,
  prefix: string,
  columns: string,
): AsyncGenerator<readonly FrozenRow[]> {
  const params: SqlValue[] = [input.connectionId, input.stream];
  let where = "connection_id = ? AND stream = ?";
  if (prefix !== "") {
    const lo = parseInt(prefix.padEnd(16, "0"), 2);
    const hi = lo + 2 ** (16 - prefix.length);
    where += " AND pk_hash >= ? AND pk_hash < ?";
    params.push(
      lo.toString(16).padStart(4, "0").padEnd(64, "0"),
      hi === 65536 ? "g" : hi.toString(16).padStart(4, "0").padEnd(64, "0"),
    );
  }
  if (input.replaceBelow) {
    where += " AND (stamp_o > ? OR (stamp_o = ? AND stamp_r >= ?))";
    params.push(
      input.replaceBelow.o,
      input.replaceBelow.o,
      input.replaceBelow.r,
    );
  }
  let after: string | null = null;
  for (;;) {
    const page: FrozenRow[] = await deps.db.query<FrozenRow>(
      `SELECT ${columns} FROM records
        WHERE ${where}${after === null ? "" : " AND pk_hash > ?"}
        ORDER BY pk_hash LIMIT ${PAGE_ROWS}`,
      after === null ? params : [...params, after],
    );
    if (page.length === 0) return;
    yield page;
    if (page.length < PAGE_ROWS) return;
    after = page[page.length - 1]!.pk_hash;
  }
}

/** Running digest of row identities, in key order. */
function identityDigest() {
  const state = sha256.create();
  let rows = 0;
  return {
    add(row: Omit<FrozenRow, "body">) {
      state.update(
        new TextEncoder().encode(
          JSON.stringify([
            row.pk_hash,
            row.stamp_o,
            row.stamp_r,
            row.first_o ?? null,
            row.body_sha256,
          ]) + "\n",
        ),
      );
      rows += 1;
    },
    finish: () => ({
      rows,
      digest: Array.from(state.digest(), (b) =>
        b.toString(16).padStart(2, "0"),
      ).join(""),
    }),
  };
}

/**
 * Freeze the changed prefixes: read the identity columns of their rows (never
 * the bodies) and keep a count and a digest per prefix. Run under the queue
 * slot, so the digest is of one consistent state. Memory is one page, however
 * large the prefixes are; what is kept grows with the number of prefixes (at
 * most 65,536), not with the rows.
 */
export async function freezePrefixRows(
  deps: LocalSyncDeps,
  input: PrefixQuery & { readonly changedPrefixes: readonly string[] },
): Promise<readonly FrozenPrefix[]> {
  const frozen: FrozenPrefix[] = [];
  for (const prefix of checkedPrefixes(input.changedPrefixes)) {
    const digest = identityDigest();
    for await (const page of readPrefix(
      deps,
      input,
      prefix,
      "pk_hash, stamp_o, stamp_r, body_sha256, first_o",
    )) {
      for (const row of page) digest.add(row);
    }
    frozen.push({ prefix, ...digest.finish() });
  }
  return frozen;
}

/**
 * C.2 step 4, after the freeze: read the frozen prefixes page by page, encode
 * the rows as v3 frames (format 4 head) in parts of at most `partTargetBytes`,
 * STREAM-encrypted, and upload each part that does not exist. Identical rows
 * give an identical part, so a repeat run makes zero PUTs.
 *
 * It needs no queue slot and holds no transaction: each page is its own read.
 * The rows are not the snapshot's copy, so each prefix's rows are checked
 * against the frozen count and digest before its last part is uploaded; a
 * difference (a row changed, was added or removed) throws `FrozenRowsChanged`
 * and the head is never built. Memory is a page of rows and the part in
 * progress, however large the stream.
 */
export async function uploadFrozenParts(
  deps: LocalSyncDeps,
  input: PrefixQuery & {
    readonly scope: string;
    readonly generation: number;
    readonly frozen: readonly FrozenPrefix[];
  },
): Promise<readonly EncodedPart[]> {
  const target = partTarget(deps, input.generation);
  const result: EncodedPart[] = [];
  for (const frozen of input.frozen) {
    const { prefix } = frozen;
    let seq = 0;
    const upload = async (part: Awaited<ReturnType<typeof encodePiece>>) => {
      const { hash: partHash, bytes, count } = part.entry;
      const blobName = `g${input.generation}-p-${partHash}`;
      const key = `${input.scope}/${blobName}`;
      if ((await deps.blobs.get(key)) === null) {
        await deps.blobs.put(
          key,
          await deps.keys.encryptPart(input.scope, part.data),
        );
      }
      result.push({ prefix, seq, partHash, bytes, count, blobName });
      seq += 1;
    };
    let frames: FrameBytes[] = [];
    let bytes = 0;
    const flush = async () => {
      const part = await encodeFramePart(hash, prefix, frames);
      if (part) await upload(part);
      frames = [];
      bytes = 0;
    };
    const seen = identityDigest();
    for await (const page of readPrefix(
      deps,
      input,
      prefix,
      "pk_hash, stamp_o, stamp_r, body, body_sha256, first_o",
    )) {
      for (const row of page) {
        seen.add(row);
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
          frames.push({ k: row.pk_hash, bytes: frame });
          bytes += frame.length;
        }
      }
    }
    const read = seen.finish();
    if (read.rows !== frozen.rows || read.digest !== frozen.digest) {
      throw new FrozenRowsChanged(prefix);
    }
    await flush();
  }
  return result;
}

/**
 * C.2 step 4: freeze the changed prefixes, then encode and upload them. The
 * publisher calls the two halves apart (freeze under the queue slot, upload
 * outside it); this composition is for a caller that holds the slot itself.
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
  return uploadFrozenParts(deps, {
    connectionId: input.connectionId,
    stream: input.stream,
    replaceBelow: input.replaceBelow,
    scope: input.scope,
    generation: input.generation,
    frozen: await freezePrefixRows(deps, input),
  });
}
