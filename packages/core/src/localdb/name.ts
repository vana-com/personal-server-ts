import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";

/** One database file per (owner, network); every host derives the same name. */
export function localDatabaseName(owner: string, network: string): string {
  const hash = bytesToHex(sha256(utf8ToBytes(owner.toLowerCase())));
  return `vana-${network}-${hash.slice(0, 32)}`;
}
