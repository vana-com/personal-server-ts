import { sha256Hex } from "../contracts/binary.js";

/**
 * An immutable, in-process batch. Only this module can associate item text
 * with a batch; callers cannot substitute text after signing its digest.
 */
export interface PreparedScopeUploadBatch {
  readonly byteLength: number;
  readonly bodySha256: string;
  readonly items: number;
}

const bodies = new WeakMap<PreparedScopeUploadBatch, string>();
const encoder = new TextEncoder();
const FRAME_BYTES = 12; // {"items":[]}

/** Internal consumer: rejects fabricated or copied batch descriptors. */
export function preparedScopeUploadText(
  batch: PreparedScopeUploadBatch,
): string {
  const text = bodies.get(batch);
  if (text === undefined)
    throw new TypeError("Unrecognized scope upload batch");
  return text;
}

/** Count UTF-8 bytes without allocating a temporary Uint8Array per item. */
function utf8Length(text: string): number {
  let bytes = text.length;
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit < 0x80) continue;
    if (unit < 0x800) {
      bytes += 1;
    } else if (
      unit >= 0xd800 &&
      unit <= 0xdbff &&
      i + 1 < text.length &&
      text.charCodeAt(i + 1) >= 0xdc00 &&
      text.charCodeAt(i + 1) <= 0xdfff
    ) {
      bytes += 2;
      i += 1;
    } else {
      bytes += 2;
    }
  }
  return bytes;
}

async function prepare(texts: string[]): Promise<PreparedScopeUploadBatch> {
  const text = texts.join(",");
  // The replay digest is still over the exact HTTP batch body. This buffer
  // is never put in a Request, parsed, or kept after hashing.
  const bytes = encoder.encode(`{"items":[${text}]}`);
  const batch = Object.freeze({
    byteLength: bytes.byteLength,
    bodySha256: await sha256Hex(bytes),
    items: texts.length,
  });
  bodies.set(batch, text);
  return batch;
}

/**
 * Serialize once, retaining only the current batch plus one look-ahead item.
 * Keep the SDK's conservative one-comma-per-item batching boundary, including
 * sending a single oversized item alone for the server to accept or reject.
 */
export async function* prepareScopeUploadBatches(
  items: readonly unknown[],
  targetBytes: number,
): AsyncGenerator<PreparedScopeUploadBatch> {
  let texts: string[] = [];
  let bytes = FRAME_BYTES;
  for (const item of items) {
    const text = JSON.stringify(item) ?? "null";
    const size = utf8Length(text) + 1;
    if (texts.length > 0 && bytes + size > targetBytes) {
      yield await prepare(texts);
      texts = [];
      bytes = FRAME_BYTES;
    }
    texts.push(text);
    bytes += size;
  }
  if (texts.length > 0) yield await prepare(texts);
}
