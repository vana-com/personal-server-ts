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

/**
 * C.2 step 4: encode the changed prefixes of one stream from `records`
 * `ORDER BY pk_hash` (one prefix per query), as format-2 frames in parts of
 * at most `partTargetBytes`, STREAM-encrypted, and upload each part that does
 * not exist. Under replace (H), leave out rows below `replaceBelow`. Identical
 * rows give an identical part, so a repeat run makes zero PUTs.
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
  const target = deps.partTargetBytes ?? 4 * 1024 * 1024;
  if (!Number.isSafeInteger(target) || target < 1 || target > PART_LIMIT_BYTES) {
    throw new Error("partTargetBytes must be between 1 and 16 MiB");
  }
  if (!Number.isSafeInteger(input.generation) || input.generation < 1) {
    throw new Error("generation must be a positive safe integer");
  }
  const prefixes = [...new Set(input.changedPrefixes)].sort();
  for (let i = 0; i < prefixes.length; i += 1) {
    const prefix = prefixes[i]!;
    if (!/^[01]{0,16}$/.test(prefix)) throw new Error("invalid part prefix");
    if (i > 0 && prefix.startsWith(prefixes[i - 1]!)) {
      throw new Error("part prefixes must not overlap");
    }
  }

  const result: EncodedPart[] = [];
  // upToSeq fences the publish watermark, not this snapshot of records.
  // HeadExtras belongs to the caller's head and is deliberately left opaque.
  for (const prefix of prefixes) {
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
    const rows = await deps.db.query<{
      pk_hash: string;
      stamp_o: number;
      stamp_r: string;
      body: string;
      body_sha256: string;
    }>(
      `SELECT pk_hash, stamp_o, stamp_r, body, body_sha256 FROM records
       WHERE ${where} ORDER BY pk_hash`,
      params,
    );
    let seq = 0;
    const upload = async (part: Awaited<ReturnType<typeof encodePiece>>) => {
      const { hash: partHash, bytes, count } = part.entry;
      const blobName = `g${input.generation}-p-${partHash}`;
      const key = `${input.scope}/${blobName}`;
      if ((await deps.blobs.get(key)) === null) {
        await deps.blobs.put(key, await deps.keys.encryptPart(input.scope, part.data));
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
    for (const row of rows) {
      const body = new TextEncoder().encode(row.body);
      const frame = frameOfBody(
        {
          h: row.body_sha256,
          k: row.pk_hash,
          n: body.length,
          o: row.stamp_o,
          r: row.stamp_r,
        },
        body,
      );
      if (frame.length > target) {
        await flush();
        // A reader must see the entire envelope in the first piece.
        if (frame.indexOf(0x0a) + 1 > target) {
          throw new Error("partTargetBytes is too small for a frame envelope");
        }
        for (let at = 0; at < frame.length; at += target) {
          await upload(
            await encodePiece(hash, prefix, frame.subarray(at, at + target), at === 0),
          );
        }
      } else {
        if (bytes + frame.length > target) await flush();
        frames.push({ k: row.pk_hash, bytes: frame });
        bytes += frame.length;
      }
    }
    await flush();
  }
  return result;
}
