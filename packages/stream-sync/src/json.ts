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
