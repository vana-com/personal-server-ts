/**
 * Canonical JSON: the one serialization every byte and hash in this package
 * derives from. Object keys sort by UTF-16 code unit, numbers print the way
 * ECMAScript prints them (so -0 is `0` and 1e21 is `1e+21`), strings use
 * JSON escaping, and there is no insignificant whitespace.
 *
 * Only the JSON data model is accepted. Anything else fails with a typed error
 * instead of being coerced.
 */

import { NonCanonicalValueError } from "./errors.js";

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

export type JsonObject = { readonly [key: string]: JsonValue };

const MAX_DEPTH = 256;

export function canonicalJson(value: unknown): string {
  return write(value, 0);
}

export function isPlainObject(value: unknown): value is JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/** Own-property test that ignores inherited names such as `constructor`. */
export function hasOwn(object: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function write(value: unknown, depth: number): string {
  if (depth > MAX_DEPTH) {
    throw new NonCanonicalValueError("value nests too deeply");
  }
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) {
        throw new NonCanonicalValueError(`non-finite number: ${String(value)}`);
      }
      return JSON.stringify(value);
    case "object":
      return Array.isArray(value)
        ? writeArray(value, depth)
        : writeObject(value, depth);
    default:
      throw new NonCanonicalValueError(
        `unsupported value of type ${typeof value}`,
      );
  }
}

function writeArray(value: readonly unknown[], depth: number): string {
  const parts: string[] = [];
  for (let i = 0; i < value.length; i += 1) {
    parts.push(write(value[i], depth + 1));
  }
  return `[${parts.join(",")}]`;
}

function writeObject(value: object, depth: number): string {
  if (!isPlainObject(value)) {
    throw new NonCanonicalValueError("only plain objects are allowed");
  }
  const parts: string[] = [];
  for (const key of Object.keys(value).sort()) {
    parts.push(`${JSON.stringify(key)}:${write(value[key], depth + 1)}`);
  }
  return `{${parts.join(",")}}`;
}

/** Source slice size, in UTF-16 units, that {@link canonicalJsonChunks} yields. */
export const JSON_CHUNK_UNITS = 32 * 1024;

/**
 * The same text as {@link canonicalJson}, as a sequence of pieces of at most
 * about `JSON_CHUNK_UNITS` UTF-16 units each (escapes can make a piece up to
 * six times longer; a piece is never cut inside a
 * surrogate pair, and a short token may join the piece before it). The whole
 * text never exists as one string, so the caller can hash and encode it
 * piece by piece. `chunks.join("") === canonicalJson(value)` always holds.
 */
export function* canonicalJsonChunks(value: unknown): Generator<string> {
  const out = new ChunkBuffer();
  yield* writeChunks(value, 0, out);
  if (out.text !== "") yield out.text;
}

class ChunkBuffer {
  text = "";
  /** Add a short token; returns a full piece when the buffer is ready. */
  add(token: string): string | null {
    this.text += token;
    if (this.text.length < JSON_CHUNK_UNITS) return null;
    const full = this.text;
    this.text = "";
    return full;
  }
}

function* writeChunks(
  value: unknown,
  depth: number,
  out: ChunkBuffer,
): Generator<string> {
  if (depth > MAX_DEPTH) {
    throw new NonCanonicalValueError("value nests too deeply");
  }
  if (typeof value === "string") {
    yield* stringChunks(value, out);
    return;
  }
  if (typeof value === "object" && value !== null) {
    if (Array.isArray(value)) {
      yield* token("[", out);
      for (let i = 0; i < value.length; i += 1) {
        if (i > 0) yield* token(",", out);
        yield* writeChunks(value[i], depth + 1, out);
      }
      yield* token("]", out);
      return;
    }
    if (!isPlainObject(value)) {
      throw new NonCanonicalValueError("only plain objects are allowed");
    }
    yield* token("{", out);
    let first = true;
    for (const key of Object.keys(value).sort()) {
      if (!first) yield* token(",", out);
      first = false;
      yield* stringChunks(key, out);
      yield* token(":", out);
      yield* writeChunks(value[key], depth + 1, out);
    }
    yield* token("}", out);
    return;
  }
  // null, boolean, number and the error cases are short: reuse `write`.
  yield* token(write(value, depth), out);
}

function* token(text: string, out: ChunkBuffer): Generator<string> {
  const full = out.add(text);
  if (full !== null) yield full;
}

function* stringChunks(text: string, out: ChunkBuffer): Generator<string> {
  if (text.length <= JSON_CHUNK_UNITS) {
    yield* token(JSON.stringify(text), out);
    return;
  }
  yield* token('"', out);
  let at = 0;
  while (at < text.length) {
    let end = Math.min(at + JSON_CHUNK_UNITS, text.length);
    // Do not cut between the two halves of a surrogate pair.
    const last = text.charCodeAt(end - 1);
    if (end < text.length && last >= 0xd800 && last <= 0xdbff) end -= 1;
    const quoted = JSON.stringify(text.slice(at, end));
    yield* token(quoted.slice(1, -1), out);
    at = end;
  }
  yield* token('"', out);
}
