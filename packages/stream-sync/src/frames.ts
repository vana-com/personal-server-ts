/**
 * Record frames (head format 2).
 *
 *   frame    = envelope LF body LF
 *   envelope = canonicalJson({"h": sha256(body), "k": pkHash, "n": body bytes,
 *                             "o": run start ms, "r": runId})
 *   body     = canonicalJson(record), exactly `n` bytes, with no raw LF
 *
 * Merge, overlay and delete read the envelope only. A body is opaque bytes:
 * it is written once, in pieces, and read in pieces. Nothing in this module
 * ever joins a body into one buffer.
 */

import { HEX64, toHex, utf8, type Sha256StreamFactory } from "./bytes.js";
import { InvalidPartError } from "./errors.js";
import { canonicalJson, isPlainObject } from "./json.js";

export interface Envelope {
  /** SHA-256 of the body bytes, 64 lowercase hex. */
  readonly h: string;
  /** pkHash of the record's primary key, 64 lowercase hex. */
  readonly k: string;
  /** Body length in bytes. */
  readonly n: number;
  /** Run start, in milliseconds since the epoch. */
  readonly o: number;
  /** Run id. */
  readonly r: string;
}

const LF = 0x0a;
/** An envelope is far smaller than this; a longer first line is corrupt. */
export const ENVELOPE_LIMIT_BYTES = 4096;

function checkEnvelope(e: unknown): asserts e is Envelope {
  if (!isPlainObject(e))
    throw new InvalidPartError("envelope is not an object");
  const keys = Object.keys(e).sort().join(",");
  if (keys !== "h,k,n,o,r") {
    throw new InvalidPartError("envelope fields must be exactly h, k, n, o, r");
  }
  if (typeof e.h !== "string" || !HEX64.test(e.h)) {
    throw new InvalidPartError("envelope h is not 64 lowercase hex");
  }
  if (typeof e.k !== "string" || !HEX64.test(e.k)) {
    throw new InvalidPartError("envelope k is not 64 lowercase hex");
  }
  if (typeof e.n !== "number" || !Number.isSafeInteger(e.n) || e.n < 0) {
    throw new InvalidPartError("envelope n is not a byte count");
  }
  if (typeof e.o !== "number" || !Number.isSafeInteger(e.o) || e.o < 0) {
    throw new InvalidPartError("envelope o is not a non-negative integer");
  }
  if (typeof e.r !== "string" || e.r === "") {
    throw new InvalidPartError("envelope r is not a non-empty string");
  }
}

/** Envelope bytes, without the LF. */
export function encodeEnvelope(envelope: Envelope): Uint8Array {
  checkEnvelope(envelope);
  return utf8(
    canonicalJson({
      h: envelope.h,
      k: envelope.k,
      n: envelope.n,
      o: envelope.o,
      r: envelope.r,
    }),
  );
}

const textDecoder = new TextDecoder("utf-8", { fatal: true });

/** Parse envelope bytes (no LF). Fails unless they are exactly canonical. */
export function decodeEnvelope(bytes: Uint8Array): Envelope {
  let text: string;
  let parsed: unknown;
  try {
    text = textDecoder.decode(bytes);
    parsed = JSON.parse(text);
  } catch {
    throw new InvalidPartError("envelope is not valid JSON");
  }
  checkEnvelope(parsed);
  if (canonicalJson(parsed) !== text) {
    throw new InvalidPartError("envelope is not in canonical form");
  }
  return parsed;
}

/** Total bytes of the frame: envelope, LF, body, LF. */
export function frameBytes(envelope: Envelope): number {
  return encodeEnvelope(envelope).length + 1 + envelope.n + 1;
}

/** Frame bytes as pieces: the envelope line, then the body pieces, then LF. */
export async function* frameChunks(
  envelope: Envelope,
  body: AsyncIterable<Uint8Array> | Iterable<Uint8Array>,
): AsyncGenerator<Uint8Array> {
  const head = encodeEnvelope(envelope);
  const line = new Uint8Array(head.length + 1);
  line.set(head);
  line[head.length] = LF;
  yield line;
  let seen = 0;
  for await (const piece of body) {
    seen += piece.length;
    yield piece;
  }
  if (seen !== envelope.n) {
    throw new InvalidPartError(
      `body has ${seen} bytes, envelope says ${envelope.n}`,
    );
  }
  yield Uint8Array.of(LF);
}

/** Hash and count a body that arrives in pieces. */
export async function measureBody(
  makeSha256: Sha256StreamFactory,
  body: AsyncIterable<Uint8Array> | Iterable<Uint8Array>,
): Promise<{ h: string; n: number }> {
  const hash = makeSha256();
  let n = 0;
  for await (const piece of body) {
    hash.update(piece);
    n += piece.length;
  }
  return { h: toHex(hash.digest()), n };
}

export interface Frame {
  readonly envelope: Envelope;
  /**
   * The body, in pieces. Drain it before asking for the next frame; if you do
   * not, the reader drains it for you. When `makeSha256` was given, the last
   * piece is followed by a hash check that throws on a mismatch.
   */
  readonly body: AsyncGenerator<Uint8Array>;
}

/** A pull reader over a byte stream that never joins pieces beyond one line. */
class ByteSource {
  private piece: Uint8Array = new Uint8Array(0);
  private at = 0;
  private readonly iterator: AsyncIterator<Uint8Array>;
  constructor(source: AsyncIterable<Uint8Array>) {
    this.iterator = source[Symbol.asyncIterator]();
  }
  private async fill(): Promise<boolean> {
    while (this.at >= this.piece.length) {
      const next = await this.iterator.next();
      if (next.done === true) return false;
      this.piece = next.value;
      this.at = 0;
    }
    return true;
  }
  /** True when no byte is left. */
  async atEnd(): Promise<boolean> {
    return !(await this.fill());
  }
  /** Bytes up to and excluding the next LF; consumes the LF. */
  async line(limit: number): Promise<Uint8Array> {
    const parts: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      if (!(await this.fill()))
        throw new InvalidPartError("frame is truncated");
      const rest = this.piece.subarray(this.at);
      const lf = rest.indexOf(LF);
      const take = lf === -1 ? rest.length : lf;
      total += take;
      if (total > limit)
        throw new InvalidPartError("envelope line is too long");
      parts.push(rest.subarray(0, take));
      this.at += take + (lf === -1 ? 0 : 1);
      if (lf !== -1) break;
    }
    if (parts.length === 1) return parts[0]!;
    const joined = new Uint8Array(total);
    let at = 0;
    for (const part of parts) {
      joined.set(part, at);
      at += part.length;
    }
    return joined;
  }
  /** Up to `max` bytes, never crossing a piece boundary. */
  async take(max: number): Promise<Uint8Array> {
    if (!(await this.fill())) throw new InvalidPartError("frame is truncated");
    const out = this.piece.subarray(this.at, this.at + max);
    this.at += out.length;
    return out;
  }
}

export async function* readFrames(
  source: AsyncIterable<Uint8Array>,
  makeSha256?: Sha256StreamFactory,
): AsyncGenerator<Frame> {
  const input = new ByteSource(source);
  while (!(await input.atEnd())) {
    const envelope = decodeEnvelope(await input.line(ENVELOPE_LIMIT_BYTES));
    let drained = false;
    const body = (async function* (): AsyncGenerator<Uint8Array> {
      const hash = makeSha256?.();
      let left = envelope.n;
      while (left > 0) {
        const piece = await input.take(left);
        left -= piece.length;
        hash?.update(piece);
        yield piece;
      }
      const end = await input.take(1);
      if (end[0] !== LF)
        throw new InvalidPartError("body is not followed by LF");
      if (hash !== undefined && toHex(hash.digest()) !== envelope.h) {
        throw new InvalidPartError("body SHA-256 does not match its envelope");
      }
      drained = true;
    })();
    yield { envelope, body };
    if (!drained) for await (const piece of body) void piece;
  }
}
