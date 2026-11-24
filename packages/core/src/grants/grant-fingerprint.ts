/**
 * The salted fingerprint of one PDPP grant, as it appears on chain.
 *
 * A member and a builder share one on-chain permission slot. The slot holds a
 * list of opaque strings (1 to 64 entries, 1 to 128 bytes each, no
 * duplicates) and the contract never reads them. Under the "one fingerprint
 * per permission" decision (23 Nov 2026), each entry is the fingerprint of one
 * PDPP grant, so a member can hold several grants with the same builder and
 * revoke one by removing its entry.
 *
 * The grant's terms stay off chain, with the member's Personal Server and the
 * builder. The random salt keeps anyone without the grant document from
 * confirming a guess about its terms. Anyone given the document and its salt
 * can recompute the fingerprint and compare it with the chain's history.
 *
 * Format: `gf1:` followed by 64 lowercase hex digits, the SHA-256 of the RFC
 * 8785 canonical JSON of `{ domain, salt, grant }`. The prefix keeps a
 * fingerprint distinct from a scope name such as `chatgpt.conversations`, so
 * a slot can hold both while old grants are migrated. The `domain` member
 * pins the meaning of the bytes, so a hash computed for another purpose can
 * never equal a grant fingerprint.
 *
 * Test vectors shared with other implementations (gateway, SDK, clients) are
 * in `__fixtures__/grant-fingerprint-vectors.json`.
 */

import { sha256Hex } from "../contracts/binary.js";
import { canonicalJsonBytes } from "../derivatives/e2ee/jcs.js";
import type { Grant } from "../pdpp/types.js";

export const GRANT_FINGERPRINT_DOMAIN = "vana.grant-fingerprint.v1";
export const GRANT_FINGERPRINT_PREFIX = "gf1:";

const SALT = /^[0-9a-f]{64}$/;
const FINGERPRINT = /^gf1:[0-9a-f]{64}$/;

/** A fresh 32-byte salt as 64 lowercase hex digits. One per grant, never reused. */
export function newGrantSalt(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function isGrantSalt(value: unknown): value is string {
  return typeof value === "string" && SALT.test(value);
}

/** True for a string in fingerprint form. Says nothing about which grant it is. */
export function isGrantFingerprint(value: unknown): value is string {
  return typeof value === "string" && FINGERPRINT.test(value);
}

/**
 * The fingerprint of `grant` under `salt`.
 *
 * The grant is hashed as its JSON form, after a `JSON.stringify` round trip:
 * members whose value is `undefined` are left out, so an optional member that
 * is absent and one that is `undefined` give the same fingerprint. The input
 * must be plain Grant JSON. The round trip does not reject other values; it
 * converts them as `JSON.stringify` does (a Date becomes its ISO string).
 *
 * Recompute against the grant document exactly as it was issued, not one
 * rebuilt from current data: a changed display name, timestamp spelling or
 * array order gives a different fingerprint. Text is not Unicode-normalized.
 */
export async function grantFingerprint(
  grant: Grant,
  salt: string,
): Promise<string> {
  if (!isGrantSalt(salt)) {
    throw new TypeError("grant salt must be 64 lowercase hex digits");
  }
  const json: unknown = JSON.parse(JSON.stringify(grant));
  const digest = await sha256Hex(
    canonicalJsonBytes({ domain: GRANT_FINGERPRINT_DOMAIN, salt, grant: json }),
  );
  return GRANT_FINGERPRINT_PREFIX + digest.slice(2);
}

/** True when `entry` is the fingerprint of `grant` under `salt`. */
export async function grantMatchesFingerprint(
  grant: Grant,
  salt: string,
  entry: string,
): Promise<boolean> {
  if (!isGrantFingerprint(entry) || !isGrantSalt(salt)) return false;
  return (await grantFingerprint(grant, salt)) === entry;
}
