/**
 * RFC 8785 JSON Canonicalization Scheme (JCS), the subset the E2EE v2 and
 * ACI protocols need: object members sorted by UTF-16 code units, no
 * whitespace, ES number-to-string serialization, JSON.stringify string
 * escaping (which is the RFC 8785 escaping: the two-character forms for
 * control characters that have them, `\u00xx` lowercase otherwise, no
 * escaping of non-ASCII).
 *
 * Only JSON data is accepted: `undefined`, functions, symbols, bigints and
 * non-finite numbers throw instead of being silently dropped, since a
 * canonical form that differs from the peer's would only show up as an
 * AEAD failure.
 */

export function canonicalizeJson(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) {
        throw new TypeError("JCS: non-finite number");
      }
      // ES Number::toString, which JSON.stringify uses; -0 serializes as 0.
      return JSON.stringify(value);
    case "string":
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) {
        return `[${value.map((item) => canonicalizeJson(item)).join(",")}]`;
      }
      const record = value as Record<string, unknown>;
      // Array.prototype.sort with no comparator orders by UTF-16 code units,
      // which is exactly the RFC 8785 member ordering.
      const keys = Object.keys(record).sort();
      const members: string[] = [];
      for (const key of keys) {
        const member = record[key];
        if (member === undefined) {
          throw new TypeError(`JCS: undefined member "${key}"`);
        }
        members.push(`${JSON.stringify(key)}:${canonicalizeJson(member)}`);
      }
      return `{${members.join(",")}}`;
    }
    default:
      throw new TypeError(`JCS: unsupported value of type ${typeof value}`);
  }
}

const encoder = new TextEncoder();

/** UTF-8 bytes of the canonical form. */
export function canonicalJsonBytes(value: unknown): Uint8Array {
  return encoder.encode(canonicalizeJson(value));
}
