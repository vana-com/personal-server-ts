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
 * The fingerprint also covers the grant's data scopes: the exact data-point
 * scope names (such as `pdpp.chatgpt.messages`) a builder pays to read under
 * it. The Personal Server names its data, so it computes this list when it
 * issues the grant; the gateway's payment check then compares names and needs
 * no rule of its own for turning a grant's source into a scope name. Because
 * the member signs the slot that lists the fingerprint, the list cannot be
 * widened after approval.
 *
 * Format: `gf1:` followed by 64 lowercase hex digits, the SHA-256 of the RFC
 * 8785 canonical JSON of `{ domain, salt, grant, data_scopes }`, with
 * `data_scopes` sorted and without duplicates. The prefix keeps a
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
/** Printable ASCII without spaces, so every implementation sorts the same way. */
const DATA_SCOPE = /^[\x21-\x7e]{1,128}$/;

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

/**
 * `scopes` sorted and without duplicates, or null when it is empty or holds a
 * name that is not 1 to 128 printable ASCII characters without spaces. The
 * sort is by character code (ordinal), never by locale; for printable ASCII
 * that is also byte order, so other languages get the same list.
 */
export function canonicalDataScopes(scopes: unknown): string[] | null {
  if (!Array.isArray(scopes) || scopes.length === 0) return null;
  for (const scope of scopes) {
    if (typeof scope !== "string" || !DATA_SCOPE.test(scope)) return null;
  }
  return [...new Set(scopes as string[])].sort();
}

/** True for a string in fingerprint form. Says nothing about which grant it is. */
export function isGrantFingerprint(value: unknown): value is string {
  return typeof value === "string" && FINGERPRINT.test(value);
}

/**
 * The fingerprint of `grant`, paying for `dataScopes`, under `salt`.
 *
 * `dataScopes` may come in any order and with duplicates; the fingerprint
 * uses the sorted list without them. An empty list, or a name that is not 1
 * to 128 printable ASCII characters without spaces, is a TypeError.
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
  dataScopes: readonly string[],
  salt: string,
): Promise<string> {
  if (!isGrantSalt(salt)) {
    throw new TypeError("grant salt must be 64 lowercase hex digits");
  }
  const scopes = canonicalDataScopes(dataScopes);
  if (scopes === null) {
    throw new TypeError(
      "data scopes must be a non-empty list of printable ASCII names",
    );
  }
  const json: unknown = JSON.parse(JSON.stringify(grant));
  const digest = await sha256Hex(
    canonicalJsonBytes({
      domain: GRANT_FINGERPRINT_DOMAIN,
      salt,
      grant: json,
      data_scopes: scopes,
    }),
  );
  return GRANT_FINGERPRINT_PREFIX + digest.slice(2);
}

/** True when `entry` is the fingerprint of `grant`, paying for `dataScopes`, under `salt`. */
export async function grantMatchesFingerprint(
  grant: Grant,
  dataScopes: readonly string[],
  salt: string,
  entry: string,
): Promise<boolean> {
  if (!isGrantFingerprint(entry) || !isGrantSalt(salt)) return false;
  if (canonicalDataScopes(dataScopes) === null) return false;
  return (await grantFingerprint(grant, dataScopes, salt)) === entry;
}
