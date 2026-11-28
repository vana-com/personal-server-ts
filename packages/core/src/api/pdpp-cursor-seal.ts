import { PdppError } from "../errors/pdpp-catalog.js";
import { decodeBase64Url, encodeBase64Url } from "../encoding/base64url.js";

/**
 * Sealed page cursors and `changes_since` tokens (spec-core §4 "Incremental
 * sync", §8 "List records", §9 RS item 21).
 *
 * Every backend mints its own position token. Those tokens are readable
 * (base64url JSON with a field value, a horizon and an offset, or a raw
 * change sequence) and are bound only to the stream. The spec requires that a
 * token "MUST NOT reveal a readable position, time, or field value", that its
 * equality or ordering signals no change outside the grant, and that it is
 * bound to the grant (owner: subject and effective scope), the query context
 * and the selected `PDPP-Version` contract, with a mismatch rejected as
 * `invalid_cursor`.
 *
 * This module meets all of that at the one boundary every backend shares: it
 * wraps the backend token in AES-256-GCM with a fresh random IV, so two
 * tokens for the same position are distinct and opaque, and it authenticates
 * a digest of the binding context with the token. A token that fails to open,
 * names another kind, or carries another context is `invalid_cursor`. The
 * backend never sees a token it did not mint for this context.
 */

/** An unsealed token this RS issued before sealing: base64url JSON or a sequence. */
function isLegacySyncToken(token: string): boolean {
  if (/^(0|[1-9][0-9]*)$/.test(token)) return true;
  try {
    const parsed = JSON.parse(new TextDecoder().decode(decodeBase64Url(token)));
    return parsed?.kind === "changes_since";
  } catch {
    return false;
  }
}

/** The two token spaces never mix (spec-core §4 "Two distinct cursor spaces"). */
export type SealedTokenKind = "page" | "sync";

const PREFIX: Record<SealedTokenKind, string> = { page: "pc_", sync: "cs_" };
const IV_BYTES = 12;
const TAG_BYTES = 16;

export interface CursorSeal {
  seal(kind: SealedTokenKind, context: unknown, inner: string): Promise<string>;
  /** Rejects with `invalid_cursor` for anything this seal did not mint for `context`. */
  open(kind: SealedTokenKind, context: unknown, token: string): Promise<string>;
}

/**
 * A seal under `key` (32 bytes), on WebCrypto so Node and the browser (Lite)
 * runtime share it. Without a key the seal draws a random one, which lives as
 * long as this object: tokens then stop opening on restart. Hosts pass a
 * persisted key so a stored `next_changes_since` survives one.
 */
export function createCursorSeal(key?: Uint8Array): CursorSeal {
  const subtle = globalThis.crypto.subtle;
  const raw = key
    ? new Uint8Array(key)
    : globalThis.crypto.getRandomValues(new Uint8Array(32));
  if (raw.byteLength !== 32) {
    throw new Error("Cursor seal key must be 32 bytes");
  }
  const secret = subtle.importKey("raw", raw, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
  const encoder = new TextEncoder();
  const digest = async (context: unknown) =>
    encodeBase64Url(
      new Uint8Array(
        await subtle.digest("SHA-256", encoder.encode(JSON.stringify(context))),
      ),
    );
  const invalid = () =>
    new PdppError(
      "invalid_cursor",
      "Cursor token is malformed, unrecognized, or was used with a different grant or query context",
    );
  return {
    async seal(kind, context, inner) {
      const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_BYTES));
      const body = new Uint8Array(
        await subtle.encrypt(
          { name: "AES-GCM", iv, additionalData: encoder.encode(kind) },
          await secret,
          encoder.encode(
            JSON.stringify({ c: await digest(context), t: inner }),
          ),
        ),
      );
      const out = new Uint8Array(iv.byteLength + body.byteLength);
      out.set(iv, 0);
      out.set(body, iv.byteLength);
      return PREFIX[kind] + encodeBase64Url(out);
    },
    async open(kind, context, token) {
      if (!token.startsWith(PREFIX[kind])) {
        // A stored `next_changes_since` from before tokens were sealed is a
        // position this RS no longer accepts: 410, so the client restarts
        // from `beginning` (spec-core §4 "Cursor expiry") instead of reading
        // a 400 as a permanent failure.
        if (kind === "sync" && isLegacySyncToken(token)) {
          throw new PdppError(
            "cursor_expired",
            "changes_since token predates this server's token format; start again from beginning",
          );
        }
        throw invalid();
      }
      const text = token.slice(PREFIX[kind].length);
      if (!/^[A-Za-z0-9_-]+$/.test(text)) throw invalid();
      const bytes = new Uint8Array(decodeBase64Url(text));
      if (bytes.byteLength < IV_BYTES + TAG_BYTES + 1) throw invalid();
      let plain: { c?: unknown; t?: unknown };
      try {
        plain = JSON.parse(
          new TextDecoder().decode(
            await subtle.decrypt(
              {
                name: "AES-GCM",
                iv: bytes.subarray(0, IV_BYTES),
                additionalData: encoder.encode(kind),
              },
              await secret,
              bytes.subarray(IV_BYTES),
            ),
          ),
        );
      } catch {
        throw invalid();
      }
      if (plain.c !== (await digest(context)) || typeof plain.t !== "string")
        throw invalid();
      return plain.t;
    },
  };
}
