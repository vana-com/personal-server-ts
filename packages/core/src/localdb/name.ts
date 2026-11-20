import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";

/** One database file per (owner, network); every host derives the same name. */
export function localDatabaseName(owner: string, network: string): string {
  const hash = bytesToHex(sha256(utf8ToBytes(owner.toLowerCase())));
  return `vana-${network}-${hash.slice(0, 32)}`;
}

/**
 * The shape of a logical database name: `vana-<network>-<32 hex>`. The network
 * is the stream-sync network identity (`vana:14800:https://host`), so it holds
 * `:` and `/`. A host that opens the database by this name checks it against
 * this pattern (from the generated host contract) before touching a file.
 */
export const LOCAL_DATABASE_NAME_PATTERN =
  /^vana-[A-Za-z0-9:/._-]+-[0-9a-f]{32}$/;
