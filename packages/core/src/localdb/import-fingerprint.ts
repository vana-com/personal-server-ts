import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";
import type { ImportFingerprint } from "./legacy-import-types.js";

/** Hash unique sorted SQL digest rows without retaining them. Callers own
 * external sorting/deduplication; rejecting disorder prevents silent drift. */
export async function importFingerprint(
  rows: AsyncIterable<{ pk_hash: string; body_sha256: string }>,
): Promise<ImportFingerprint> {
  const hash = sha256.create();
  // Every validated digest is 64 ASCII bytes. Reuse its length-prefixed
  // encoding instead of allocating two buffers and a DataView per field.
  const framed = new Uint8Array(68);
  framed[3] = 64;
  const update = (value: string) => {
    for (let i = 0; i < 64; i++) framed[i + 4] = value.charCodeAt(i);
    hash.update(framed);
  };
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
    update(row.pk_hash);
    update(row.body_sha256);
    count++;
    previous = row.pk_hash;
    // Resolved SQL promises alone never yield to host tasks. Keep a long
    // digest scan from starving I/O and the collector between source pages.
    if (count % 128 === 0)
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }
  return { rows: count, fingerprint: bytesToHex(hash.digest()) };
}
