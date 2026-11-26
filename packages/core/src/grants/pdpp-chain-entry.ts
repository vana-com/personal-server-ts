/**
 * The design-2 chain entry for one PDPP grant: a salted fingerprint of the
 * grant document, listed in the PermissionsV2 slot of (owner, app builder).
 *
 * Wire contract (data-gateway `lib/pdpp-grants.ts`, branch
 * `maciej/pdpp-design2`, and `db/migrations/README.md` "0077 PDPP grant
 * entries"):
 *
 *   entry = "pdpp:sha256:" + hex(sha256(utf8(JCS({ domain, grant, salt }))))
 *
 * - `domain` is `vana.pdpp-grant-entry.v1`;
 * - `grant` is the PDPP grant document exactly as this AS issued it;
 * - `salt` is 32 random bytes as 64 lowercase hex chars, chosen per grant and
 *   kept with the grant;
 * - JCS is RFC 8785 over I-JSON (RFC 7493) values: numbers are IEEE 754
 *   doubles, strings are well-formed UTF-16, member names are unique.
 *
 * The gateway recomputes the entry from the `(grant, salt)` the PS attaches to
 * `POST /v1/grants` and refuses a mismatch (`PDPP_GRANT_HASH_MISMATCH`), so
 * the two implementations must agree byte for byte. The golden vector in the
 * test was produced by the gateway's own implementation.
 *
 * Pure: no IO, no logging. Grant documents and salts must never be logged.
 */

import { createHash, randomBytes } from "node:crypto";

export const PDPP_ENTRY_PREFIX = "pdpp:sha256:";
export const PDPP_ENTRY_DOMAIN = "vana.pdpp-grant-entry.v1";
const SALT = /^[0-9a-f]{64}$/;
const ENTRY = /^pdpp:sha256:[0-9a-f]{64}$/;
const MAX_DEPTH = 32;

export class PdppCanonicalJsonError extends Error {}

function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function canonicalString(s: string): string {
  // RFC 8785 §3.2.2.2: JSON.stringify's escaping is exactly the JCS rule.
  if (hasLoneSurrogate(s))
    throw new PdppCanonicalJsonError("string contains a lone surrogate");
  return JSON.stringify(s);
}

function canonicalize(value: unknown, depth: number): string {
  if (depth > MAX_DEPTH)
    throw new PdppCanonicalJsonError("JSON nesting too deep");
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      // RFC 8785 §3.2.2.3: ECMAScript Number serialization; -0 → "0". The
      // value is already a double here, the same value the gateway parses
      // from the JSON this PS sends, so both sides hash the same digits.
      if (!Number.isFinite(value))
        throw new PdppCanonicalJsonError("non-finite number");
      return JSON.stringify(value);
    case "string":
      return canonicalString(value);
    case "object": {
      if (Array.isArray(value))
        return `[${value.map((v) => canonicalize(v, depth + 1)).join(",")}]`;
      const proto = Object.getPrototypeOf(value) as unknown;
      if (proto !== Object.prototype && proto !== null)
        throw new PdppCanonicalJsonError(
          "only plain JSON objects can be canonicalized",
        );
      // RFC 8785 §3.2.3: member names sorted by UTF-16 code units. A member
      // whose value is undefined is not JSON and is refused, as the gateway
      // does, so no member silently drops out of the fingerprint.
      const keys = Object.keys(value).sort();
      return `{${keys
        .map((k) => {
          const v = (value as Record<string, unknown>)[k];
          if (v === undefined)
            throw new PdppCanonicalJsonError(
              `member ${JSON.stringify(k)} is undefined`,
            );
          return `${canonicalString(k)}:${canonicalize(v, depth + 1)}`;
        })
        .join(",")}}`;
    }
    default:
      throw new PdppCanonicalJsonError(
        `unsupported JSON value type: ${typeof value}`,
      );
  }
}

/** RFC 8785 JSON Canonicalization Scheme over I-JSON values. */
export function pdppCanonicalJson(value: unknown): string {
  return canonicalize(value, 0);
}

/** A fresh per-grant salt: 32 random bytes, 64 lowercase hex chars. */
export function newPdppGrantSalt(): string {
  return randomBytes(32).toString("hex");
}

export function isPdppGrantEntry(entry: string): boolean {
  return ENTRY.test(entry);
}

/** The slot entry for `(grant, salt)`; see the module doc for the formula. */
export function computePdppGrantEntry(grant: unknown, salt: string): string {
  if (!SALT.test(salt))
    throw new PdppCanonicalJsonError("salt must be 64 lowercase hex chars");
  const canonical = pdppCanonicalJson({
    domain: PDPP_ENTRY_DOMAIN,
    grant,
    salt,
  });
  return (
    PDPP_ENTRY_PREFIX +
    createHash("sha256").update(canonical, "utf8").digest("hex")
  );
}
