import { sha256 } from "@noble/hashes/sha2";
import {
  canonicalJson,
  isPlainObject,
  pkHash,
  primaryKeyValues,
  toHex,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  computeRecordKeyFromData,
  keyMatchesData,
} from "../storage/pdpp-records/record-key.js";

/** Normalize a producer's record into the identity and bytes used by local merge. */
export async function mutationIdentity(
  data: unknown,
  primaryKey: string[],
  key?: string | string[],
): Promise<{
  keyValues: string;
  recordKey: string;
  body: string;
  bodySha256: string;
  hash: string;
}> {
  if (!isPlainObject(data)) throw new Error("invalid record");
  const keyValues = canonicalJson(primaryKeyValues(data, primaryKey));
  const recordKey = computeRecordKeyFromData(data, primaryKey);
  if (key !== undefined && !keyMatchesData(key, data, primaryKey))
    throw new Error("record key does not match data");
  const body = canonicalJson(data);
  return {
    keyValues,
    recordKey,
    body,
    bodySha256: toHex(sha256(new TextEncoder().encode(body))),
    hash: await pkHash(async (bytes) => sha256(bytes), data, primaryKey),
  };
}
