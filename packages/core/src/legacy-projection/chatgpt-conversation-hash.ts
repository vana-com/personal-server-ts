import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";

/** Full hash binds receipts unambiguously; callers display only its first 12 hex. */
export function chatgptConversationIdHash(id: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(id)));
}
