import {
  isPlainObject,
  type JsonValue,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { ProtocolError } from "../errors/catalog.js";
import { prepareBlob } from "./blobs.js";
import type { SqlStatement } from "./driver.js";
import type { ApplicationEnvelope } from "./application-intake.js";

/** Validate/copy file bytes before yielding; bind every ref in the record batch. */
export function prepareApplicationBlobs(
  input: ApplicationEnvelope,
): (target: {
  readonly op: string;
  readonly connection: string;
  readonly generation: number;
  readonly stream: string;
  readonly pkHash: string;
}) => SqlStatement[] {
  const refuse = (message: string): never => {
    throw new ProtocolError(400, "INVALID_APPLICATION_BLOB", message);
  };
  const refs = new Map<string, { mime: string; size: number }>();
  const pending: JsonValue[] = [input.record.data];
  while (pending.length) {
    const value = pending.pop()!;
    if (Array.isArray(value)) {
      pending.push(...value);
      continue;
    }
    if (!isPlainObject(value)) continue;
    if ("blob_ref" in value) {
      const ref = value.blob_ref;
      if (
        !isPlainObject(ref) ||
        typeof ref.sha256 !== "string" ||
        !/^[a-f0-9]{64}$/.test(ref.sha256) ||
        ref.blob_id !== `sha256:${ref.sha256}` ||
        typeof ref.mime_type !== "string" ||
        !/^[a-z]+\/[a-zA-Z0-9!#$&^_.+\-]+$/.test(ref.mime_type) ||
        typeof ref.size_bytes !== "number" ||
        !Number.isSafeInteger(ref.size_bytes) ||
        ref.size_bytes < 0
      )
        refuse("Invalid content-addressed blob reference");
      const valid = ref as {
        sha256: string;
        mime_type: string;
        size_bytes: number;
      };
      const prior = refs.get(valid.sha256);
      if (
        prior &&
        (prior.mime !== valid.mime_type || prior.size !== valid.size_bytes)
      )
        refuse("Conflicting blob references");
      refs.set(valid.sha256, { mime: valid.mime_type, size: valid.size_bytes });
    }
    pending.push(...Object.values(value));
  }
  const supplied = new Map<
    string,
    { bytes: Uint8Array; statements: ReturnType<typeof prepareBlob> }
  >();
  for (const blob of input.blobs ?? []) {
    const ref = refs.get(blob.sha256);
    if (
      !ref ||
      ref.mime !== blob.mimeType ||
      ref.size !== blob.bytes?.length ||
      !Array.isArray(blob.bytes) ||
      blob.bytes.some((b) => !Number.isInteger(b) || b < 0 || b > 255) ||
      supplied.has(blob.sha256)
    )
      refuse("File bytes do not match a declared record reference");
    const bytes = new Uint8Array(blob.bytes);
    supplied.set(blob.sha256, {
      bytes,
      statements: prepareBlob({ ...blob, bytes }),
    });
  }
  if (input.record.op === "delete") {
    if (supplied.size) refuse("A deletion cannot attach files");
    return () => [];
  }
  return (target) => {
    const statements: SqlStatement[] = [
      {
        sql: "CREATE TEMP TABLE IF NOT EXISTS application_blob_guard(op TEXT, blob TEXT, ok INTEGER NOT NULL CONSTRAINT application_blob_ready CHECK(ok=1), PRIMARY KEY(op,blob))",
      },
    ];
    for (const [hash, ref] of refs) {
      const body = supplied.get(hash);
      if (body) statements.push(...body.statements(target.generation));
      statements.push(
        {
          sql: `INSERT INTO application_blob_guard SELECT ?,?,CASE WHEN EXISTS(SELECT 1 FROM blobs WHERE blob_id=? AND mime_type=? AND size_bytes=? AND bytes IS NOT NULL${body ? " AND bytes=?" : ""}) THEN 1 ELSE 0 END`,
          params: [
            target.op,
            hash,
            hash,
            ref.mime,
            ref.size,
            ...(body ? [body.bytes] : []),
          ],
        },
        {
          sql: "INSERT INTO blob_refs(blob_id,connection_id,stream,pk_hash) VALUES (?,?,?,?)",
          params: [hash, target.connection, target.stream, target.pkHash],
        },
      );
    }
    statements.push({
      sql: "DELETE FROM application_blob_guard WHERE op=?",
      params: [target.op],
    });
    return statements;
  };
}
