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

/** UTF-8 length of a JSON string literal, without serializing it. */
function jsonStringLength(text: string): number {
  let bytes = 2;
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit === 0x22 || unit === 0x5c) bytes += 2;
    else if (unit < 0x20) {
      bytes += [8, 9, 10, 12, 13].includes(unit) ? 2 : 6;
    } else if (unit < 0x80) bytes += 1;
    else if (unit < 0x800) bytes += 2;
    else if (
      unit >= 0xd800 &&
      unit <= 0xdbff &&
      text.charCodeAt(i + 1) >= 0xdc00 &&
      text.charCodeAt(i + 1) <= 0xdfff
    ) {
      bytes += 4;
      i += 1;
    } else if (unit >= 0xd800 && unit <= 0xdfff) bytes += 6;
    else bytes += 3;
  }
  return bytes;
}

/**
 * `JSON.stringify(value)` as UTF-8, built piece by piece and refused as soon
 * as it would pass `maxBytes`: a value whose serialization expands (one
 * large string referenced many times) never allocates more than the cap.
 * Same output as `JSON.stringify` for JSON data (objects, arrays, strings,
 * numbers, booleans, null, `toJSON`); a cycle throws, as it does there.
 */
export function boundedJsonBytes(value: unknown, maxBytes: number): Uint8Array {
  const pieces: string[] = [];
  let total = 0;
  const ancestors = new Set<object>();
  const reserve = (bytes: number) => {
    total += bytes;
    if (total > maxBytes) {
      throw new StoredEnvelopeReadError(
        "too_large",
        `The served envelope is larger than ${maxBytes} bytes`,
      );
    }
  };
  // Punctuation and scalar JSON other than strings are ASCII.
  const emit = (piece: string) => {
    reserve(piece.length);
    pieces.push(piece);
  };
  const emitString = (text: string) => {
    reserve(jsonStringLength(text));
    pieces.push(JSON.stringify(text));
  };
  // `toJSON` applied, as JSON.stringify applies it before deciding to omit.
  const resolve = (key: string, item: unknown): unknown =>
    item !== null &&
    typeof item === "object" &&
    typeof (item as { toJSON?: unknown }).toJSON === "function"
      ? (item as { toJSON(key: string): unknown }).toJSON(key)
      : item;
  // What JSON.stringify omits from an object and writes as null in an array.
  const omitted = (item: unknown) =>
    item === undefined ||
    typeof item === "function" ||
    typeof item === "symbol";
  const write = (item: unknown): void => {
    if (typeof item === "string") {
      emitString(item);
      return;
    }
    if (item === null || typeof item !== "object") {
      emit(JSON.stringify(item));
      return;
    }
    if (ancestors.has(item)) {
      throw new TypeError("Converting circular structure to JSON");
    }
    ancestors.add(item);
    if (Array.isArray(item)) {
      emit("[");
      for (let index = 0; index < item.length; index += 1) {
        if (index > 0) emit(",");
        const resolved = resolve(String(index), item[index]);
        if (omitted(resolved)) emit("null");
        else write(resolved);
      }
      emit("]");
    } else {
      emit("{");
      let first = true;
      for (const name of Object.keys(item)) {
        const resolved = resolve(name, (item as Record<string, unknown>)[name]);
        if (omitted(resolved)) continue;
        if (!first) emit(",");
        emitString(name);
        emit(":");
        first = false;
        write(resolved);
      }
      emit("}");
    }
    ancestors.delete(item);
  };
  const root = resolve("", value);
  if (omitted(root)) {
    throw new TypeError("The value has no JSON serialization");
  }
  write(root);
  return new TextEncoder().encode(pieces.join(""));
}
