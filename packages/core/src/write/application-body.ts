import { sha256 } from "@noble/hashes/sha2";
import { toHex } from "@opendatalabs/personal-server-ts-stream-sync";
import { canonicalizeJson } from "../derivatives/e2ee/jcs.js";
import { ProtocolError } from "../errors/catalog.js";

/** Validate the wire profile using the existing JCS serializer, then hash only
 * the original bytes. Canonical output is a validation oracle, never hash input.
 */
export function readApplicationBody(bytes: Uint8Array): {
  readonly text: string;
  readonly value: unknown;
  readonly requestHash: string;
} {
  try {
    const text = new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: true,
    }).decode(bytes);
    const value: unknown = JSON.parse(text);
    const pending: unknown[] = [value];
    while (pending.length) {
      const item = pending.pop();
      if (typeof item === "string") {
        for (const character of item) {
          const point = character.codePointAt(0)!;
          if (point >= 0xd800 && point <= 0xdfff)
            throw new TypeError("unpaired surrogate");
        }
      } else if (typeof item === "number") {
        if (!Number.isFinite(item)) throw new TypeError("non-finite number");
      } else if (item !== null && typeof item === "object") {
        pending.push(...Object.keys(item), ...Object.values(item));
      }
    }
    // Duplicate keys, whitespace, rounded numbers and other alternate
    // spellings cannot equal the canonical bytes of their parsed value.
    if (canonicalizeJson(value) !== text) throw new TypeError("non-JCS body");
    return { text, value, requestHash: toHex(sha256(bytes)) };
  } catch {
    throw new ProtocolError(
      400,
      "APPLICATION_BODY_NOT_JCS",
      "Application writes require an RFC 8785 JCS UTF-8 envelope",
    );
  }
}
