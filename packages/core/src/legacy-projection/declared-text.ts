import type {
  PdppRecord,
  ProjectionDiagnostic,
  ProjectionError,
} from "./types.js";
import type { PdppBlobMeta } from "../storage/pdpp-records/types.js";

export type StreamSchemas = Readonly<Record<string, Record<string, unknown>>>;
type ObjectValue = Record<string, unknown>;
const object = (value: unknown): ObjectValue | undefined =>
  value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as ObjectValue)
    : undefined;

export class DeclaredTextError extends Error {
  constructor(
    readonly kind:
      "invalid_encoded_text" | "message_content_omitted" | "unresolved_blob",
    readonly stream: string,
    readonly field: string,
  ) {
    super(kind);
  }
  projectionError(scope: string): ProjectionError {
    return { kind: this.kind, scope, stream: this.stream, field: this.field };
  }
}

/**
 * data-connectors ChatGPT 0.2.53 codec, supplied with the implementation
 * assignment. This is one replacement pass, never recursive unescaping.
 * Ordinary and unmatched backslash-u text is valid source text.
 */
export function decodePdppSafeText(text: string): string {
  if (
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(
      text,
    )
  ) {
    throw new Error("raw_forbidden_code_unit");
  }
  return text.replace(/\\u([0-9a-fA-F]{4})/g, (escape, hex: string) => {
    const unit = Number.parseInt(hex, 16);
    return unit === 0x5c ||
      unit <= 8 ||
      unit === 11 ||
      unit === 12 ||
      (unit >= 14 && unit <= 31) ||
      (unit >= 127 && unit <= 159) ||
      (unit >= 0xd800 && unit <= 0xdfff)
      ? String.fromCharCode(unit)
      : escape;
  });
}

export function declaredBlobField(
  schema: ObjectValue | undefined,
): string | undefined {
  const properties = object(schema?.properties);
  const ref = object(properties?.blob_ref);
  const field = ref?.x_pdpp_blob_projects_field;
  return ref?.x_pdpp_blob_codec === "json-string-v1" &&
    typeof field === "string" &&
    field.length > 0 &&
    field !== "blob_ref" &&
    properties &&
    Object.hasOwn(properties, field)
    ? field
    : undefined;
}

/** Decode content strings and keys once, copying only changed containers. */
function decodeDeclaredValue(value: unknown): unknown {
  if (typeof value === "string") return decodePdppSafeText(value);
  if (Array.isArray(value)) {
    const decoded = value.map(decodeDeclaredValue);
    return decoded.some((item, index) => item !== value[index])
      ? decoded
      : value;
  }
  const row = object(value);
  if (!row) return value;
  const keys = new Set<string>();
  let changed = false;
  const entries = Object.entries(row).map(([key, item]) => {
    const decodedKey = decodePdppSafeText(key);
    if (keys.has(decodedKey)) throw new Error("decoded_key_collision");
    keys.add(decodedKey);
    const decoded = decodeDeclaredValue(item);
    changed ||= decodedKey !== key || decoded !== item;
    return [decodedKey, decoded] as const;
  });
  // CreateDataProperty preserves __proto__/constructor as ordinary own keys.
  return changed ? Object.fromEntries(entries) : value;
}

/** Copies only changed rows. Blob-derived source text must never enter this decoder. */
export function decodeDeclaredRecords(
  records: PdppRecord[],
  schemas: StreamSchemas = {},
  allowUnresolvedBlobs = false,
): PdppRecord[] {
  return records.map((record) =>
    decodeDeclaredRecord(record, schemas, allowUnresolvedBlobs),
  );
}

function decodeDeclaredRecord(
  record: PdppRecord,
  schemas: StreamSchemas,
  allowUnresolvedBlobs: boolean,
): PdppRecord {
  const schema = schemas[record.stream];
  const properties = object(schema?.properties);
  if (!properties || !object(record.data)) return record;
  let data = record.data;
  const blobField = declaredBlobField(schema);
  if (blobField && Object.hasOwn(data, "blob_ref") && !allowUnresolvedBlobs) {
    throw new DeclaredTextError("unresolved_blob", record.stream, blobField);
  }
  if (
    blobField &&
    Array.isArray(schema?.required) &&
    schema.required.includes(blobField) &&
    !Object.hasOwn(data, blobField) &&
    !Object.hasOwn(data, "blob_ref")
  ) {
    throw new DeclaredTextError(
      "message_content_omitted",
      record.stream,
      blobField,
    );
  }
  for (const [field, declaration] of Object.entries(properties)) {
    if (
      object(declaration)?.x_pdpp_text_encoding !== "pdpp-safe-escape-v1" ||
      !Object.hasOwn(data, field) ||
      data[field] === null
    )
      continue;
    let decoded: unknown;
    try {
      decoded = decodeDeclaredValue(data[field]);
    } catch {
      throw new DeclaredTextError("invalid_encoded_text", record.stream, field);
    }
    if (decoded !== data[field]) data = { ...data, [field]: decoded };
  }
  return data === record.data ? record : { ...record, data };
}

/**
 * A bad encoded row follows the projector's drop-and-count policy. Missing
 * blob resolution is still a caller error. Each rejected row counts once,
 * under the first failing field, without exposing its contents.
 */
export function decodeDeclaredRecordsForProjection(
  records: PdppRecord[],
  schemas: StreamSchemas | undefined,
  scope: string,
  allowUnresolvedBlobs = false,
): { records: PdppRecord[]; diagnostics: ProjectionDiagnostic[] } {
  const decoded: PdppRecord[] = [];
  const dropped = new Map<
    string,
    Extract<ProjectionDiagnostic, { kind: "records_dropped" }>
  >();
  for (const record of records) {
    try {
      decoded.push(
        decodeDeclaredRecord(record, schemas ?? {}, allowUnresolvedBlobs),
      );
    } catch (error) {
      if (
        !(error instanceof DeclaredTextError) ||
        error.kind === "unresolved_blob"
      )
        throw error;
      const reason = `${error.kind}: ${error.field}`;
      const key = JSON.stringify([error.stream, reason]);
      const diagnostic = dropped.get(key);
      if (diagnostic) diagnostic.count += 1;
      else
        dropped.set(key, {
          kind: "records_dropped",
          scope,
          stream: error.stream,
          count: 1,
          reasons: [reason],
        });
    }
  }
  return { records: decoded, diagnostics: [...dropped.values()] };
}

export function declaredBlobReference(
  data: ObjectValue,
  field: string,
): {
  blobId: string;
  sha256: string;
  size: number;
} {
  const ref = object(data.blob_ref);
  if (
    (Object.hasOwn(data, field) && data[field] !== null) ||
    !ref ||
    typeof ref.blob_id !== "string" ||
    !/^sha256:[0-9a-f]{64}$/.test(ref.blob_id) ||
    ref.sha256 !== ref.blob_id.slice(7) ||
    ref.mime_type !== "application/json" ||
    !Number.isSafeInteger(ref.size_bytes) ||
    (ref.size_bytes as number) < 2
  ) {
    throw new Error("invalid_blob_reference");
  }
  return {
    blobId: ref.blob_id,
    sha256: ref.sha256 as string,
    size: ref.size_bytes as number,
  };
}

/** UTF-8 JSON string bytes contain exact source text, with no PDPP escaping. */
export async function decodeDeclaredBlob(
  data: ObjectValue,
  field: string,
  contents: {
    meta: PdppBlobMeta | undefined;
    bytes: Uint8Array<ArrayBuffer> | undefined;
  },
): Promise<ObjectValue> {
  const ref = declaredBlobReference(data, field);
  const { meta, bytes } = contents;
  if (!meta || !bytes) throw new Error("blob_missing_or_corrupt");
  if (
    meta.blobId !== ref.blobId ||
    meta.sha256 !== ref.sha256 ||
    meta.mimeType !== "application/json" ||
    meta.sizeBytes !== ref.size ||
    bytes.length !== ref.size
  ) {
    throw new Error("blob_metadata_mismatch");
  }
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  if (
    [...digest].map((b) => b.toString(16).padStart(2, "0")).join("") !==
    ref.sha256
  ) {
    throw new Error("blob_digest_mismatch");
  }
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error("invalid_blob_json_string");
  }
  if (typeof value !== "string") throw new Error("invalid_blob_json_string");
  const { blob_ref: _ref, ...rest } = data;
  return { ...rest, [field]: value };
}
