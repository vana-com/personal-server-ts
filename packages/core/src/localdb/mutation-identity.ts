import type { SqlStatement, SqlValue } from "./driver.js";
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

/** A producer's record plus its mutation stamp, staged for the shared merge.
 * A fixed stamp is used by run intake. An operation stamp is allocated inside
 * the caller's transaction, so a run-independent write cannot move backwards.
 */
export function stageMutation(input: {
  readonly operation: string;
  readonly stream: string;
  readonly row: {
    readonly pkHash: string;
    readonly recordKey: string;
    readonly body: string;
    readonly bodySha256: string;
  };
  readonly stamp:
    | {
        readonly observedAt: number;
        readonly id: string;
        readonly ordinal: number;
      }
    | { readonly operation: string; readonly id: string };
  readonly guard?: {
    readonly sql: string;
    readonly params: SqlStatement["params"];
  };
}): SqlStatement {
  const fixed = "observedAt" in input.stamp;
  const time = fixed ? "?" : "o";
  const stamp = input.stamp;
  const params: SqlValue[] = [
    input.operation,
    input.stream,
    input.row.pkHash,
    input.row.recordKey,
  ];
  if ("observedAt" in stamp) params.push(stamp.observedAt);
  params.push(stamp.id, input.row.body, input.row.bodySha256);
  if ("observedAt" in stamp) params.push(stamp.observedAt, stamp.ordinal);
  else params.push(stamp.operation);
  params.push(...(input.guard?.params ?? []));
  return {
    sql: `INSERT OR REPLACE INTO incoming(op,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256,first_o,stamp_n)
      SELECT ?,?,?,?,${time},?,?,?,${time},${fixed ? "?" : "0"}
      ${fixed ? "" : "FROM mutation_stamps WHERE op=? AND"} ${fixed ? "WHERE" : ""} ${input.guard?.sql ?? "1"}`,
    params,
  };
}
