/**
 * Bounded, digest-checked reads of stored envelope bytes, for the grantee
 * read port. Browser-safe: SHA-256 is computed incrementally in JavaScript,
 * one chunk at a time, so no read holds more than a chunk to hash it.
 */
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";

/**
 * A stored envelope read that stopped: more bytes than the read may take
 * (`too_large`), or bytes that are not the version the read was authorized
 * for (`generation_mismatch`).
 */
export class StoredEnvelopeReadError extends Error {
  constructor(
    readonly code: "too_large" | "generation_mismatch",
    message: string,
  ) {
    super(message);
    this.name = "StoredEnvelopeReadError";
  }
}

function tooLarge(maxBytes: number): StoredEnvelopeReadError {
  return new StoredEnvelopeReadError(
    "too_large",
    `The stored envelope is larger than ${maxBytes} bytes`,
  );
}

function changed(): StoredEnvelopeReadError {
  return new StoredEnvelopeReadError(
    "generation_mismatch",
    "The stored version changed after the read was authorized",
  );
}

/**
 * Pass `source` through unchanged. The stream fails, and stops reading
 * `source`, as soon as more than `maxBytes` arrive. When `sha256Hex` is
 * given, it fails at the end unless the bytes hash to it, so a consumer that
 * releases nothing until the stream closes never releases other bytes.
 */
export function verifiedStream(
  source: ReadableStream<Uint8Array>,
  limits: { maxBytes: number; sha256Hex?: string },
): ReadableStream<Uint8Array> {
  const hash = sha256.create();
  let total = 0;
  return source.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        total += chunk.byteLength;
        if (total > limits.maxBytes) {
          controller.error(tooLarge(limits.maxBytes));
          return;
        }
        hash.update(chunk);
        controller.enqueue(chunk);
      },
      flush(controller) {
        if (
          limits.sha256Hex !== undefined &&
          bytesToHex(hash.digest()) !== limits.sha256Hex
        ) {
          controller.error(changed());
        }
      },
    }),
  );
}

/**
 * Read all of `source` as text, at most `maxBytes` of it, with the SHA-256
 * of the bytes read. The bytes are decoded as they arrive and not kept.
 */
export async function readBoundedText(
  source: ReadableStream<Uint8Array>,
  maxBytes: number,
): Promise<{ text: string; sha256Hex: string; byteLength: number }> {
  const hash = sha256.create();
  const decoder = new TextDecoder();
  const parts: string[] = [];
  let total = 0;
  const reader = source.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) throw tooLarge(maxBytes);
      hash.update(value);
      parts.push(decoder.decode(value, { stream: true }));
    }
  } catch (error) {
    await reader.cancel(error).catch(() => undefined);
    throw error;
  }
  parts.push(decoder.decode());
  return {
    text: parts.join(""),
    sha256Hex: bytesToHex(hash.digest()),
    byteLength: total,
  };
}

/** The error for bytes that are not the version a read was authorized for. */
export function generationMismatch(): StoredEnvelopeReadError {
  return changed();
}
