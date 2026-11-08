/**
 * Format-2 parts (§2.2 as amended): a part is whole frames, or one piece of a
 * frame too long to share a part. The parts of a head, read in order, are one
 * sequence of frames sorted by key hash.
 *
 *   small frames   : a part holds one or more complete frames (`count` = frames);
 *   a long frame   : cut into pieces of `FRAME_PIECE_BYTES`, each its own part,
 *                    alone in its run: the first piece has `count` 1, every
 *                    later piece `count` 0. Nothing else starts in the run.
 *
 * A reader needs at most one part in memory at a time.
 */

import { PART_LIMIT_BYTES, sha256Hex, type Sha256 } from "./bytes.js";
import { InvalidArgumentError, InvalidPartError } from "./errors.js";
import {
  decodeEnvelope,
  ENVELOPE_LIMIT_BYTES,
  type Envelope,
} from "./frames.js";
import type { EncodedPart, HeadPart } from "./parts.js";
import { inPrefix } from "./records.js";

const LF = 0x0a;

/** A frame as the host holds it before it chooses a part for it. */
export interface FrameBytes {
  readonly k: string;
  /** The complete frame: envelope, LF, body, LF. */
  readonly bytes: Uint8Array;
}

/** Encode complete small frames, sorted strictly by key hash, as one part. */
export async function encodeFramePart(
  sha256: Sha256,
  prefix: string,
  frames: readonly FrameBytes[],
): Promise<EncodedPart | null> {
  if (frames.length === 0) return null;
  let total = 0;
  let previous: string | null = null;
  for (const frame of frames) {
    if (previous !== null && frame.k <= previous) {
      throw new InvalidArgumentError("frames must be strictly sorted by key");
    }
    previous = frame.k;
    total += frame.bytes.length;
  }
  if (total > PART_LIMIT_BYTES) {
    throw new InvalidArgumentError("part exceeds the 16 MiB part limit");
  }
  const data = new Uint8Array(total);
  let at = 0;
  for (const frame of frames) {
    data.set(frame.bytes, at);
    at += frame.bytes.length;
  }
  return {
    data,
    entry: {
      bytes: total,
      count: frames.length,
      hash: await sha256Hex(sha256, data),
      prefix,
    },
  };
}

/** One piece of a long frame as a part. `first` pieces start the frame. */
export async function encodePiece(
  sha256: Sha256,
  prefix: string,
  data: Uint8Array,
  first: boolean,
): Promise<EncodedPart> {
  if (data.length === 0 || data.length > PART_LIMIT_BYTES) {
    throw new InvalidArgumentError("a piece must hold 1 byte up to 16 MiB");
  }
  return {
    data,
    entry: {
      bytes: data.length,
      count: first ? 1 : 0,
      hash: await sha256Hex(sha256, data),
      prefix,
    },
  };
}

/** Re-block a byte stream into pieces of exactly `size` bytes (the last may be shorter). */
export async function* cutPieces(
  source: AsyncIterable<Uint8Array>,
  size: number,
): AsyncGenerator<Uint8Array> {
  let fill = new Uint8Array(size);
  let used = 0;
  for await (const piece of source) {
    let at = 0;
    while (at < piece.length) {
      const take = Math.min(size - used, piece.length - at);
      fill.set(piece.subarray(at, at + take), used);
      used += take;
      at += take;
      if (used === size) {
        yield fill;
        fill = new Uint8Array(size);
        used = 0;
      }
    }
  }
  if (used > 0) yield fill.slice(0, used);
}

export interface PartFrame {
  readonly envelope: Envelope;
  /** Frame size in bytes: envelope, LF, body, LF. */
  readonly size: number;
  /** The whole frame when it sits inside one part; `null` for a long frame. */
  readonly raw: Uint8Array | null;
  /** The head entries that hold this frame, in order. */
  readonly parts: readonly HeadPart[];
  /** The body in pieces. For a long frame each piece costs one part load. */
  body(): AsyncGenerator<Uint8Array>;
}

/**
 * Read the frames of a head's parts in order. `load` returns the clear bytes
 * of one part; this function checks their size and SHA-256 against the head
 * entry, the key order and prefix of every frame, each part's frame count,
 * and that a long frame fills exactly its run of parts.
 *
 * A long frame's later parts are loaded only when its `body()` is read, so a
 * caller that needs only envelopes never loads them.
 */
export async function* framesOfParts(
  sha256: Sha256,
  parts: readonly HeadPart[],
  load: (part: HeadPart, index: number) => Promise<Uint8Array>,
): AsyncGenerator<PartFrame> {
  let previousKey: string | null = null;
  const checkKey = (envelope: Envelope, part: HeadPart) => {
    if (!inPrefix(envelope.k, part.prefix)) {
      throw new InvalidPartError("frame key is outside the part prefix");
    }
    if (previousKey !== null && envelope.k <= previousKey) {
      throw new InvalidPartError("frames are not strictly sorted by key");
    }
    previousKey = envelope.k;
  };
  const verified = async (part: HeadPart, index: number) => {
    const data = await load(part, index);
    if (data.length > PART_LIMIT_BYTES) {
      throw new InvalidPartError("part exceeds the 16 MiB decoder limit");
    }
    if (data.length !== part.bytes) {
      throw new InvalidPartError(
        `part has ${data.length} bytes, head says ${part.bytes}`,
      );
    }
    if ((await sha256Hex(sha256, data)) !== part.hash) {
      throw new InvalidPartError("part SHA-256 does not match the head");
    }
    return data;
  };

  let index = 0;
  while (index < parts.length) {
    const part = parts[index]!;
    if (part.count === 0) {
      throw new InvalidPartError("part continues a frame that never started");
    }
    const data = await verified(part, index);
    let at = 0;
    let started = 0;
    while (at < data.length) {
      const lf = data.subarray(at, at + ENVELOPE_LIMIT_BYTES + 1).indexOf(LF);
      if (lf === -1) throw new InvalidPartError("frame envelope is truncated");
      const envelope = decodeEnvelope(data.subarray(at, at + lf));
      checkKey(envelope, part);
      started += 1;
      const size = lf + 1 + envelope.n + 1;
      if (at + size <= data.length) {
        if (data[at + size - 1] !== LF) {
          throw new InvalidPartError("body is not followed by LF");
        }
        const raw = data.subarray(at, at + size);
        const bodyStart = lf + 1;
        yield {
          envelope,
          size,
          raw,
          parts: [part],
          async *body() {
            yield raw.subarray(bodyStart, bodyStart + envelope.n);
          },
        };
        at += size;
        continue;
      }
      // A long frame: it must open its part and fill its run exactly.
      if (at !== 0 || part.count !== 1) {
        throw new InvalidPartError("a long frame must be alone in its parts");
      }
      const run: HeadPart[] = [part];
      let covered = data.length;
      let last = index;
      while (covered < size) {
        last += 1;
        const next = parts[last];
        if (!next || next.count !== 0 || next.prefix !== part.prefix) {
          throw new InvalidPartError("long frame runs past its parts");
        }
        run.push(next);
        covered += next.bytes;
      }
      if (covered !== size) {
        throw new InvalidPartError("long frame does not fill its parts");
      }
      const firstIndex = index;
      yield {
        envelope,
        size,
        raw: null,
        parts: run,
        async *body() {
          let left = envelope.n;
          let seenEnd: number | undefined;
          for (let p = 0; p < run.length; p += 1) {
            const bytes =
              p === 0 ? data : await verified(run[p]!, firstIndex + p);
            const from = p === 0 ? lf + 1 : 0;
            const take = Math.min(left, bytes.length - from);
            if (take > 0) yield bytes.subarray(from, from + take);
            left -= take;
            if (p === run.length - 1) seenEnd = bytes[bytes.length - 1];
          }
          if (left !== 0 || seenEnd !== LF) {
            throw new InvalidPartError("long frame body is malformed");
          }
        },
      };
      index = last;
      at = data.length;
    }
    if (started !== part.count) {
      throw new InvalidPartError(
        `part has ${started} frames, head says ${part.count}`,
      );
    }
    index += 1;
  }
}
