import type {
  PdppBlobMeta,
  PdppStoredRecord,
} from "../storage/pdpp-records/types.js";
import type { PdppRecord } from "./types.js";

// Matches the bounded native/renderer source-record transport, not an external URL.
export const MAX_CLAUDE_SOURCE_BYTES = 32 * 1024 * 1024;
type ObjectValue = Record<string, unknown>;
type ParentStream = "conversations" | "projects";
export interface ClaudeBlobContents {
  meta: PdppBlobMeta | undefined;
  bytes: Uint8Array<ArrayBuffer> | undefined;
}
export class ClaudeSourceRecordError extends Error {}

function reject(detail: string): never {
  throw new ClaudeSourceRecordError(detail);
}
function object(value: unknown): ObjectValue | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as ObjectValue)
    : null;
}
function string(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}
function identity(value: ObjectValue): string {
  const uuid = string(value.uuid),
    id = string(value.id);
  if (uuid && id && uuid !== id) reject("ambiguous_source_identity");
  return uuid ?? id ?? reject("missing_source_identity");
}
function safeText(value: unknown, limit: number): string | null {
  const text = string(value)?.slice(0, limit) ?? null;
  if (
    text !== null &&
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(
      text,
    )
  ) {
    reject("unsafe_source_text");
  }
  return text;
}
function time(value: unknown): string | null {
  const text = string(value);
  return text && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(text)
    ? text
    : null;
}
function boolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

/** Shape validation runs before loading potentially large bytes into the snapshot. */
export function claudeBlobReference(data: ObjectValue): {
  blobId: string;
  sha256: string;
  size: number;
} {
  const ref = object(data.blob_ref);
  if (
    !ref ||
    Object.keys(ref).sort().join(",") !==
      "blob_id,mime_type,sha256,size_bytes" ||
    typeof ref.blob_id !== "string" ||
    !/^sha256:[0-9a-f]{64}$/.test(ref.blob_id) ||
    ref.sha256 !== ref.blob_id.slice(7) ||
    ref.sha256 === "0".repeat(64) ||
    ref.mime_type !== "application/json" ||
    !Number.isSafeInteger(ref.size_bytes) ||
    (ref.size_bytes as number) < 1 ||
    (ref.size_bytes as number) > MAX_CLAUDE_SOURCE_BYTES
  ) {
    reject("invalid_blob_reference");
  }
  return {
    blobId: ref.blob_id,
    sha256: ref.sha256 as string,
    size: ref.size_bytes as number,
  };
}

/** Only the reviewed source envelope and mapped Claude fields are accepted. No source I/O. */
export async function decodeClaudeSourceRecord(
  row: PdppStoredRecord,
  contents: ClaudeBlobContents,
): Promise<PdppRecord[]> {
  if (row.stream !== "conversations" && row.stream !== "projects")
    reject("unsupported_blob_stream");
  const stream: ParentStream = row.stream;
  const ref = claudeBlobReference(row.data);
  const { meta, bytes } = contents;
  if (!meta || !bytes) reject("blob_missing_or_corrupt");
  if (
    meta.blobId !== ref.blobId ||
    meta.mimeType !== "application/json" ||
    meta.sha256 !== ref.sha256 ||
    meta.sizeBytes !== ref.size ||
    bytes.byteLength !== ref.size
  )
    reject("blob_metadata_mismatch");
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  if (
    [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("") !==
    ref.sha256
  )
    reject("blob_digest_mismatch");
  let envelope: ObjectValue | null;
  try {
    envelope = object(
      JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)),
    );
  } catch {
    return reject("invalid_source_json");
  }
  if (
    !envelope ||
    envelope.format !== "anthropic-source-record-v1" ||
    envelope.stream !== stream ||
    envelope.record_key !== row.recordKey ||
    row.data.id !== row.recordKey
  )
    reject("source_envelope_mismatch");
  const payload = object(envelope.payload);
  if (!payload || identity(payload) !== row.recordKey)
    reject("source_identity_mismatch");
  const childKey = stream === "conversations" ? "chat_messages" : "docs";
  // Multipart project metadata can omit docs; the canonical document stream
  // then supplies the detail. A missing conversation body is not an empty chat.
  const separateDocuments = stream === "projects" && payload.docs === undefined;
  if (!separateDocuments && !Array.isArray(payload[childKey]))
    reject("source_children_unknown");
  const rawChildren = separateDocuments ? [] : (payload[childKey] as unknown[]);
  const children: PdppRecord[] = [];
  const childIds = new Set<string>();
  for (const raw of rawChildren) {
    const child = object(raw);
    if (!child) reject("malformed_source_child");
    const id = identity(child);
    if (stream === "conversations" && !string(child.uuid))
      reject("missing_source_identity");
    if (childIds.has(id)) reject("duplicate_source_child");
    childIds.add(id);
    children.push({
      stream: stream === "conversations" ? "messages" : "project_documents",
      data:
        stream === "conversations"
          ? message(child, id, row.recordKey)
          : document(child, id, row.recordKey),
    });
  }
  const parent =
    stream === "conversations"
      ? conversation(payload, row.recordKey, children.length)
      : project(
          payload,
          row.recordKey,
          separateDocuments ? undefined : rawChildren,
        );
  // The inline summary must describe these same bytes, never a different parent revision.
  for (const key of Object.keys(parent)) {
    if (Object.hasOwn(row.data, key) && !sameJson(row.data[key], parent[key]))
      reject("parent_blob_conflict");
  }
  return [{ stream, data: parent }, ...children];
}

function flattenMessage(raw: ObjectValue): string {
  if (typeof raw.text === "string" && raw.text.length > 0) return raw.text;
  if (typeof raw.content === "string") return raw.content;
  if (Array.isArray(raw.content))
    return raw.content
      .map((part) => {
        if (typeof part === "string") return part;
        const block = object(part);
        return typeof block?.text === "string"
          ? block.text
          : typeof block?.content === "string"
            ? block.content
            : "";
      })
      .filter(Boolean)
      .join("\n");
  return typeof object(raw.content)?.text === "string"
    ? (object(raw.content)!.text as string)
    : "";
}
function safeAttachmentJson(value: unknown, depth = 0): boolean {
  if (depth > 64) reject("source_attachment_too_deep");
  if (typeof value === "string") {
    safeText(value, Number.MAX_SAFE_INTEGER);
    return true;
  }
  if (typeof value === "number") return Number.isFinite(value);
  if (value === null || typeof value === "boolean") return true;
  if (Array.isArray(value))
    return value.every((item) => safeAttachmentJson(item, depth + 1));
  const record = object(value);
  return (
    !!record &&
    Object.entries(record).every(([key, item]) => {
      safeText(key, Number.MAX_SAFE_INTEGER);
      return safeAttachmentJson(item, depth + 1);
    })
  );
}
function message(
  raw: ObjectValue,
  id: string,
  conversationId: string,
): ObjectValue {
  const attachments =
    raw.attachments === undefined || raw.attachments === null
      ? null
      : raw.attachments;
  if (
    attachments !== null &&
    (!Array.isArray(attachments) ||
      attachments.some((item) => !object(item) || !safeAttachmentJson(item)))
  )
    reject("invalid_source_attachments");
  return {
    id,
    conversation_id: conversationId,
    role: string(raw.sender),
    parent_id: string(raw.parent_message_uuid),
    content: safeText(flattenMessage(raw), 10_000_000),
    model: null,
    create_time: time(raw.created_at),
    update_time: time(raw.updated_at),
    attachments,
  };
}
function conversation(
  raw: ObjectValue,
  id: string,
  count: number,
): ObjectValue {
  return {
    id,
    title: safeText(string(raw.name) ?? string(raw.summary), 4000),
    create_time: time(raw.created_at),
    update_time: time(raw.updated_at),
    project_id: string(raw.project_uuid),
    model: null,
    message_count: count,
    is_starred: boolean(raw.is_starred),
  };
}
function document(
  raw: ObjectValue,
  id: string,
  projectId: string,
): ObjectValue {
  return {
    id,
    project_id: projectId,
    filename: safeText(
      string(raw.filename) ??
        string(raw.file_name) ??
        string(raw.name) ??
        string(raw.title),
      1024,
    ),
    content: safeText(
      string(raw.content) ??
        string(raw.text) ??
        string(raw.body) ??
        string(raw.filedata),
      10_000_000,
    ),
    create_time: time(raw.created_at),
    update_time: time(raw.updated_at),
  };
}
function project(
  raw: ObjectValue,
  id: string,
  docs: unknown[] | undefined,
): ObjectValue {
  const creator = object(raw.creator);
  if (raw.creator !== undefined && raw.creator !== null && !creator)
    reject("invalid_source_creator");
  const name = safeText(string(raw.name) ?? "Untitled project", 2000)!;
  return {
    id,
    name,
    description: safeText(raw.description, 65_000),
    create_time: time(raw.created_at),
    update_time: time(raw.updated_at),
    is_archived: raw.archived_at != null,
    prompt_template: safeText(raw.prompt_template, 65_000),
    creator: creator
      ? Object.fromEntries(
          [
            ["uuid", string(creator.uuid)],
            ["full_name", safeText(creator.full_name, 2000)],
          ].filter(([, value]) => value !== null),
        )
      : null,
    is_private: boolean(raw.is_private),
    is_starter_project: boolean(raw.is_starter_project),
    archived_at: safeText(raw.archived_at, 128),
    ...(docs === undefined
      ? {}
      : {
          raw_docs: docs.map((rawDoc) => {
            const doc = object(rawDoc)!;
            return Object.fromEntries(
              [
                ["uuid", safeText(doc.uuid, 128)],
                ["filename", safeText(doc.filename, 1024)],
                ["content", safeText(doc.content, 10_000_000)],
                ["created_at", safeText(doc.created_at, 128)],
                ["updated_at", safeText(doc.updated_at, 128)],
              ].filter(([, value]) => value !== null),
            );
          }),
        }),
  };
}

/** JSON object field order is irrelevant; array order is part of the source value. */
function sameJson(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (Array.isArray(left) && Array.isArray(right))
    return (
      left.length === right.length &&
      left.every((value, index) => sameJson(value, right[index]))
    );
  const a = object(left),
    b = object(right);
  return (
    !!a &&
    !!b &&
    Object.keys(a).length === Object.keys(b).length &&
    Object.keys(a).every(
      (key) => Object.hasOwn(b, key) && sameJson(a[key], b[key]),
    )
  );
}

/** Deduplicate matching inline detail, but never conceal a conflicting body or relationship. */
export function mergeClaudeSourceRecords(
  records: PdppRecord[],
  expanded: PdppRecord[],
): PdppRecord[] {
  const merged = new Map<string, PdppRecord>();
  const blobParents = new Set(
    expanded
      .filter(
        (record) =>
          record.stream === "projects" || record.stream === "conversations",
      )
      .map((record) => String(record.data.id)),
  );
  for (const record of records) {
    if (
      record.stream === "project_documents" &&
      blobParents.has(String(record.data.project_id))
    ) {
      const data = record.data;
      if (
        !string(data.id) ||
        ["filename", "content", "create_time", "update_time"].some(
          (field) =>
            !Object.hasOwn(data, field) ||
            !(typeof data[field] === "string" || data[field] === null),
        )
      )
        reject("invalid_inline_document");
      safeText(data.filename, 1024);
      safeText(data.content, 10_000_000);
    }
    const key = `${record.stream}\u0000${String(record.data.id)}`;
    if (merged.has(key)) reject("duplicate_inline_identity");
    merged.set(key, record);
  }
  const sourceIdentities = new Set<string>();
  for (const record of expanded) {
    const key = `${record.stream}\u0000${String(record.data.id)}`;
    if (sourceIdentities.has(key)) reject("duplicate_source_identity");
    sourceIdentities.add(key);
    const existing = merged.get(key);
    if (
      (record.stream === "messages" || record.stream === "project_documents") &&
      !existing
    )
      reject("source_child_missing_inline");
    if (existing) {
      const required =
        record.stream === "messages"
          ? [
              "id",
              "conversation_id",
              "role",
              "parent_id",
              "content",
              "create_time",
              "update_time",
              "attachments",
            ]
          : record.stream === "project_documents"
            ? [
                "id",
                "project_id",
                "filename",
                "content",
                "create_time",
                "update_time",
              ]
            : [];
      if (required.some((field) => !Object.hasOwn(existing.data, field)))
        reject("inline_child_fields_missing");
      for (const field of Object.keys(record.data)) {
        if (
          Object.hasOwn(existing.data, field) &&
          !sameJson(existing.data[field], record.data[field])
        )
          reject("inline_blob_conflict");
      }
    }
    merged.set(key, record);
  }
  // Inline children of a blob parent must occur in its explicit source list.
  const parentIds = new Set(
    expanded
      .filter(
        (record) =>
          (record.stream === "projects" &&
            Object.hasOwn(record.data, "raw_docs")) ||
          record.stream === "conversations",
      )
      .map((record) => String(record.data.id)),
  );
  for (const record of records) {
    if (
      ((record.stream === "messages" &&
        parentIds.has(String(record.data.conversation_id))) ||
        (record.stream === "project_documents" &&
          parentIds.has(String(record.data.project_id)))) &&
      !sourceIdentities.has(`${record.stream}\u0000${String(record.data.id)}`)
    )
      reject("inline_child_absent_from_blob");
  }
  return [...merged.values()];
}
