import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";
import type { ImportFingerprint } from "./legacy-import-types.js";

/** Hash unique sorted SQL digest rows without retaining them. Callers own
 * external sorting/deduplication; rejecting disorder prevents silent drift. */
export async function importFingerprint(
  rows: AsyncIterable<{ pk_hash: string; body_sha256: string }>,
): Promise<ImportFingerprint> {
  const hash = sha256.create();
  let previous: string | null = null;
  let count = 0;
  for await (const row of rows) {
    if (
      !/^[0-9a-f]{64}$/.test(row.pk_hash) ||
      !/^[0-9a-f]{64}$/.test(row.body_sha256) ||
      (previous !== null && row.pk_hash <= previous)
    ) {
      throw new Error("invalid_import_fingerprint_rows");
    }
    for (const value of [row.pk_hash, row.body_sha256]) {
      const bytes = utf8ToBytes(value);
      const length = new Uint8Array(4);
      new DataView(length.buffer).setUint32(0, bytes.length, false);
      hash.update(length).update(bytes);
    }
    count++;
    previous = row.pk_hash;
  }
  return { rows: count, fingerprint: bytesToHex(hash.digest()) };
}
