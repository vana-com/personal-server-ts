import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import {
  canonicalJson,
  decodeReplicaEnvelope,
  replicaEnvelopeSchema,
  type EnvelopeExpectation,
  type ReplicaEnvelope,
} from "./envelope.js";
import {
  toBase64,
  fromBase64,
  prepareReplicaFragment,
  replicaFragmentSchema,
  type ReplicaFragment,
  type PreparedFragment,
  type Predecessor,
} from "./transport.js";

const ENVELOPE_LIMIT = 192 * 1024;
const FRAME_LIMIT = 128 * 1024;
const BASE64_PIECE = 48 * 1024;
const encoder = new TextEncoder();
const digestOf = (hash: ReturnType<typeof sha256.create>) =>
  `sha256:${bytesToHex(hash.digest())}`;

function descriptors(envelope: ReplicaEnvelope) {
  return envelope.operations.flatMap((op) =>
    op.kind === "blob-claim" ? [op.blob] : op.kind === "upsert" ? op.blobs : [],
  );
}

/** Exact wire length without reading or materializing referenced binary bytes. */
export function replicaPayloadByteLength(envelope: ReplicaEnvelope): number {
  const blobs = [
    ...new Map(descriptors(envelope).map((d) => [d.blobId, d])).values(),
  ];
  const metadata = {
    envelope,
    blobs: blobs.map((blob) => ({ blobId: blob.blobId, bytes: "" })),
  };
  const length =
    encoder.encode(canonicalJson(metadata)).length +
    blobs.reduce((size, blob) => size + 4 * Math.ceil(blob.sizeBytes / 3), 0);
  if (!Number.isSafeInteger(length))
    throw new RangeError("replica payload length exhausted");
  return length;
}

/** Byte-identical to the Node payload, including descriptor order and deduplication. */
export async function* encodeReplicaPayload(
  envelope: ReplicaEnvelope,
  readBlob: (id: string) => AsyncIterable<Uint8Array>,
): AsyncIterable<Uint8Array> {
  const tail = encoder.encode(canonicalJson(envelope));
  if (tail.length > ENVELOPE_LIMIT)
    throw new RangeError("replica envelope too large");
  const unique = new Map(descriptors(envelope).map((d) => [d.blobId, d]));
  if (unique.size > 1000) throw new RangeError("too many replica blobs");
  for (const id of unique.keys())
    if (!id.length || id.length > 256)
      throw new RangeError("invalid replica blob id");
  yield encoder.encode('{"blobs":[');
  let first = true;
  for (const blob of unique.values()) {
    yield encoder.encode(
      `${first ? "" : ","}{"blobId":${JSON.stringify(blob.blobId)},"bytes":"`,
    );
    first = false;
    const hash = sha256.create();
    let size = 0;
    let carry = new Uint8Array(0);
    for await (const input of readBlob(blob.blobId)) {
      for (let offset = 0; offset < input.length; offset += BASE64_PIECE) {
        const piece = input.subarray(offset, offset + BASE64_PIECE);
        hash.update(piece);
        size += piece.length;
        const joined = new Uint8Array(carry.length + piece.length);
        joined.set(carry);
        joined.set(piece, carry.length);
        const aligned = joined.length - (joined.length % 3);
        if (aligned)
          yield encoder.encode(toBase64(joined.subarray(0, aligned)));
        carry = joined.slice(aligned);
      }
    }
    if (size !== blob.sizeBytes || digestOf(hash) !== blob.sha256)
      throw new Error("missing pinned replica bytes");
    if (carry.length) yield encoder.encode(toBase64(carry));
    yield encoder.encode('"}');
  }
  yield encoder.encode('],"envelope":');
  for (let offset = 0; offset < tail.length; offset += FRAME_LIMIT)
    yield tail.subarray(offset, offset + FRAME_LIMIT);
  yield encoder.encode("}");
}

export async function hashReplicaBytes(
  factory: () => AsyncIterable<Uint8Array>,
): Promise<{ digest: string; totalBytes: number }> {
  const hash = sha256.create();
  let totalBytes = 0;
  for await (const bytes of factory()) {
    hash.update(bytes);
    totalBytes += bytes.length;
    if (!Number.isSafeInteger(totalBytes))
      throw new RangeError("replica payload too large");
  }
  return { digest: digestOf(hash), totalBytes };
}

export async function* fragmentReplicaStream(input: {
  owner: string;
  writer: string;
  batch: string;
  sequence: number;
  previous: Predecessor | null;
  collectedAt: string;
  digest: string;
  totalBytes: number;
  bytes: () => AsyncIterable<Uint8Array>;
  encrypt: (scope: string, bytes: Uint8Array) => Promise<Uint8Array>;
  maxBlobBytes?: number;
  targetChunkBytes?: number;
}): AsyncIterable<PreparedFragment> {
  const cap = input.maxBlobBytes ?? FRAME_LIMIT;
  const chunkSize = input.targetChunkBytes ?? 32 * 1024;
  if (
    !Number.isSafeInteger(cap) ||
    cap < 1 ||
    cap > FRAME_LIMIT ||
    !Number.isSafeInteger(chunkSize) ||
    chunkSize < 1 ||
    chunkSize > FRAME_LIMIT ||
    !Number.isSafeInteger(input.totalBytes) ||
    input.totalBytes < 1
  )
    throw new RangeError("invalid replica size limit");
  const count = Math.ceil(input.totalBytes / chunkSize);
  if (count > 100000) throw new RangeError("too many replica fragments");
  const hash = sha256.create();
  let offset = 0;
  let index = 0;
  let used = 0;
  let chunk = new Uint8Array(Math.min(chunkSize, input.totalBytes));
  for await (const piece of input.bytes()) {
    if (offset + used + piece.length > input.totalBytes)
      throw new Error("invalid replica batch length");
    for (let position = 0; position < piece.length;) {
      const size = Math.min(chunk.length - used, piece.length - position);
      chunk.set(piece.subarray(position, position + size), used);
      used += size;
      position += size;
      if (used === chunk.length) {
        hash.update(chunk);
        const prepared = await prepareReplicaFragment({
          ...input,
          count,
          index,
          offset,
          chunk,
        });
        if (prepared.encrypted.length > cap)
          throw new RangeError("encrypted fragment exceeds storage cap");
        yield prepared;
        offset += used;
        index++;
        used = 0;
        chunk = new Uint8Array(Math.min(chunkSize, input.totalBytes - offset));
      }
    }
  }
  if (offset !== input.totalBytes || digestOf(hash) !== input.digest)
    throw new Error("corrupt replica batch");
}

function commonFragment(f: ReplicaFragment): string {
  return canonicalJson({
    owner: f.owner,
    writer: f.writer,
    batch: f.batch,
    sequence: f.sequence,
    previous: f.previous,
    collectedAt: f.collectedAt,
    digest: f.digest,
    totalBytes: f.totalBytes,
    count: f.count,
  });
}

/** Consume to completion before importing: the final digest is checked at EOF. */
export async function* assembleReplicaStream(
  fragments: () => AsyncIterable<ReplicaFragment>,
): AsyncIterable<Uint8Array> {
  let first: ReplicaFragment | undefined;
  let common = "";
  let index = 0;
  let offset = 0;
  const hash = sha256.create();
  for await (const value of fragments()) {
    const f = replicaFragmentSchema.parse(value);
    if (!first) {
      first = f;
      common = commonFragment(f);
    }
    if (
      commonFragment(f) !== common ||
      f.index !== index ||
      f.index >= f.count ||
      f.offset !== offset ||
      (f.sequence === 1) !== (f.previous === null) ||
      !f.content.length
    )
      throw new Error("inconsistent replica fragments");
    const chunkHash = sha256.create();
    for (let position = 0; position < f.content.length; position += 64 * 1024) {
      const encoded = f.content.slice(position, position + 64 * 1024);
      if (position + encoded.length < f.content.length && encoded.includes("="))
        throw new Error("noncanonical base64");
      const chunk = fromBase64(encoded);
      offset += chunk.length;
      if (offset > f.totalBytes)
        throw new Error("invalid replica batch length");
      chunkHash.update(chunk);
      hash.update(chunk);
      yield chunk;
    }
    if (digestOf(chunkHash) !== f.chunkDigest)
      throw new Error("corrupt replica fragment");
    index++;
  }
  if (!first || index !== first.count || offset !== first.totalBytes)
    throw new Error("incomplete replica batch");
  if (digestOf(hash) !== first.digest) throw new Error("corrupt replica batch");
}

// Decode bounded input windows; a caller may supply arbitrarily large source frames.
async function* textWindows(
  input: AsyncIterable<Uint8Array>,
): AsyncIterable<string> {
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  for await (const frame of input) {
    for (let offset = 0; offset < frame.length; offset += 16 * 1024) {
      const text = decoder.decode(frame.subarray(offset, offset + 16 * 1024), {
        stream: true,
      });
      if (text) yield text;
    }
  }
  const tail = decoder.decode();
  if (tail) yield tail;
}

/** A cursor over the fixed canonical grammar, rather than a general JSON DOM. */
class PayloadCursor {
  private readonly iterator: AsyncIterator<string>;
  private window = "";
  private position = 0;
  constructor(input: AsyncIterable<Uint8Array>) {
    this.iterator = textWindows(input)[Symbol.asyncIterator]();
  }
  async peek(): Promise<string> {
    while (this.position === this.window.length) {
      const next = await this.iterator.next();
      if (next.done) return "";
      this.window = next.value;
      this.position = 0;
    }
    return this.window[this.position]!;
  }
  async literal(value: string): Promise<void> {
    for (const character of value) {
      if ((await this.peek()) !== character)
        throw new Error("invalid canonical replica payload");
      this.position++;
    }
  }
  async blobId(): Promise<string> {
    await this.literal('"');
    let raw = '"';
    let escaped = false;
    while (true) {
      const char = await this.peek();
      if (!char || raw.length > 256 * 6 + 2)
        throw new Error("invalid replica blob id");
      this.position++;
      raw += char;
      if (char === '"' && !escaped) break;
      escaped = char === "\\" && !escaped;
    }
    const value: unknown = JSON.parse(raw);
    if (
      typeof value !== "string" ||
      value.length < 1 ||
      value.length > 256 ||
      JSON.stringify(value) !== raw
    )
      throw new Error("invalid canonical replica blob id");
    return value;
  }
  async *base64(): AsyncIterable<Uint8Array> {
    await this.literal('"');
    let carry = "";
    let padded = false;
    while (true) {
      if (!(await this.peek())) throw new Error("truncated replica binary");
      const quote = this.window.indexOf('"', this.position);
      const end = quote === -1 ? this.window.length : quote;
      const piece = this.window.slice(this.position, end);
      this.position = end;
      if (padded && piece.length) throw new Error("noncanonical base64");
      const joined = carry + piece;
      const aligned = joined.length - (joined.length % 4);
      if (aligned) {
        const encoded = joined.slice(0, aligned);
        const bytes = fromBase64(encoded);
        padded = encoded.includes("=");
        yield bytes;
      }
      carry = joined.slice(aligned);
      if (padded && carry.length) throw new Error("noncanonical base64");
      if (quote !== -1) {
        if (carry.length) throw new Error("noncanonical base64");
        this.position++;
        return;
      }
    }
  }
  async envelopeTail(): Promise<string> {
    let result = "";
    let size = 0;
    while (await this.peek()) {
      const rest = this.window.slice(this.position);
      size += encoder.encode(rest).length;
      if (size > ENVELOPE_LIMIT + 1)
        throw new RangeError("replica envelope too large");
      result += rest;
      this.position = this.window.length;
    }
    if (!result.endsWith("}")) throw new Error("truncated replica payload");
    return result.slice(0, -1);
  }
  async close(): Promise<void> {
    await this.iterator.return?.();
  }
}

type BlobMetadata = { blobId: string; sha256: string; sizeBytes: number };
type PayloadInspection = { envelope: ReplicaEnvelope; blobs: BlobMetadata[] };
type PayloadEvent =
  | { kind: "bytes"; blobId: string; bytes: Uint8Array }
  | { kind: "verified"; payload: PayloadInspection };

/** Shared parser for inspection and second-pass staged blob reads. No whole binary retention. */
async function* parsePayload(
  input: AsyncIterable<Uint8Array>,
  expected?: EnvelopeExpectation,
): AsyncIterable<PayloadEvent> {
  const cursor = new PayloadCursor(input);
  const blobs: BlobMetadata[] = [];
  const ids = new Set<string>();
  try {
    await cursor.literal('{"blobs":[');
    if ((await cursor.peek()) !== "]") {
      while (true) {
        if (blobs.length >= 1000)
          throw new RangeError("too many replica blobs");
        await cursor.literal('{"blobId":');
        const blobId = await cursor.blobId();
        if (ids.has(blobId)) throw new Error("duplicate replica binary");
        ids.add(blobId);
        await cursor.literal(',"bytes":');
        const hash = sha256.create();
        let sizeBytes = 0;
        for await (const bytes of cursor.base64()) {
          sizeBytes += bytes.length;
          if (!Number.isSafeInteger(sizeBytes))
            throw new RangeError("replica binary too large");
          hash.update(bytes);
          yield { kind: "bytes", blobId, bytes };
        }
        blobs.push({ blobId, sha256: digestOf(hash), sizeBytes });
        await cursor.literal("}");
        if ((await cursor.peek()) !== ",") break;
        await cursor.literal(",");
      }
    }
    await cursor.literal('],"envelope":');
    const encoded = await cursor.envelopeTail();
    const envelope = expected
      ? decodeReplicaEnvelope(encoded, expected)
      : replicaEnvelopeSchema.parse(JSON.parse(encoded));
    if (canonicalJson(envelope) !== encoded)
      throw new Error("noncanonical replica envelope");
    const declared = descriptors(envelope);
    for (const blob of blobs) {
      if (
        !declared.some(
          (d) =>
            d.blobId === blob.blobId &&
            d.sha256 === blob.sha256 &&
            d.sizeBytes === blob.sizeBytes,
        )
      )
        throw new Error("unbound replica binary");
    }
    yield { kind: "verified", payload: { envelope, blobs } };
  } finally {
    await cursor.close();
  }
}

export async function inspectReplicaPayload(
  factory: () => AsyncIterable<Uint8Array>,
  expected: EnvelopeExpectation,
): Promise<PayloadInspection> {
  for await (const event of parsePayload(factory(), expected))
    if (event.kind === "verified") return event.payload;
  throw new Error("incomplete replica payload");
}

/** Inspect first, then consume this same immutable source to completion into staging. */
export async function* readReplicaPayloadBlob(
  factory: () => AsyncIterable<Uint8Array>,
  id: string,
): AsyncIterable<Uint8Array> {
  let found = false;
  for await (const event of parsePayload(factory())) {
    if (event.kind === "bytes" && event.blobId === id) yield event.bytes;
    if (event.kind === "verified")
      found = event.payload.blobs.some((blob) => blob.blobId === id);
  }
  if (!found) throw new Error("missing replica binary");
}
