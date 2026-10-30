/**
 * Shared import job vectors: a spool builder and a mixed record set that
 * every adapter (in-memory, Node SQLite, native) should publish identically.
 */

import {
  PDPP_IMPORT_SPOOL_FORMAT,
  type ImportDeclarations,
  type ImportSpoolHandle,
  type ImportSpoolRecord,
} from "./contract.js";
import { sha256HexOf } from "./engine.js";

export const IMPORT_VECTOR_INSTANCE = "conn-chatgpt-1";
export const IMPORT_VECTOR_SOURCE = "https://source.invalid/chatgpt";
export const IMPORT_VECTOR_METHOD = "chatgpt-browser";
export const IMPORT_VECTOR_OWNER = "0xowner";

/** `conversations` and `messages` are mutable_state; `events` is append_only. */
export const importVectorDeclarations: ImportDeclarations = {
  forInstance(instance, stream) {
    if (instance !== IMPORT_VECTOR_INSTANCE) return undefined;
    if (stream === "conversations" || stream === "messages")
      return { semantics: "mutable_state", primaryKey: ["id"] };
    if (stream === "events")
      return { semantics: "append_only", primaryKey: ["id"] };
    return undefined;
  },
  validateData: (_stream, _instance, data) =>
    typeof data.id === "string" ? null : "id must be a string",
};

/** Mixed vectors: re-upserts, deletes, append-only rewrites, non-ASCII, a rejected line. */
export function importVectorRecords(): ImportSpoolRecord[] {
  const at = (n: number) =>
    new Date(Date.UTC(2026, 9, 28, 0, 0, n)).toISOString();
  return [
    {
      stream: "conversations",
      key: "c1",
      data: { id: "c1", title: "Grüße 👋" },
      emitted_at: at(1),
    },
    {
      stream: "messages",
      key: "m1",
      data: { id: "m1", conversation_id: "c1", text: "こんにちは" },
      emitted_at: at(2),
    },
    {
      stream: "messages",
      key: "m2",
      data: { id: "m2", conversation_id: "c1", text: "first" },
      emitted_at: at(3),
    },
    {
      stream: "messages",
      key: "m2",
      data: { id: "m2", conversation_id: "c1", text: "edited" },
      emitted_at: at(4),
    },
    {
      stream: "messages",
      key: "m3",
      data: { id: "m3", conversation_id: "c1", text: "gone" },
      emitted_at: at(5),
    },
    { stream: "messages", key: "m3", op: "delete", emitted_at: at(6) },
    {
      stream: "events",
      key: "e1",
      data: { id: "e1", kind: "first" },
      emitted_at: at(7),
    },
    {
      stream: "events",
      key: "e1",
      data: { id: "e1", kind: "rewritten" },
      emitted_at: at(8),
    },
    // Rejected: key does not match data.
    {
      stream: "messages",
      key: "m9",
      data: { id: "other" },
      emitted_at: at(9),
    },
    {
      stream: "conversations",
      key: "c2",
      data: { id: "c2", title: "second" },
      emitted_at: at(10),
    },
  ];
}

export async function buildImportSpool(
  records: readonly unknown[],
  id = "spool-1",
): Promise<{ bytes: Uint8Array; handle: ImportSpoolHandle }> {
  const bytes = new TextEncoder().encode(
    records.map((record) => JSON.stringify(record) + "\n").join(""),
  );
  return {
    bytes,
    handle: {
      id,
      format: PDPP_IMPORT_SPOOL_FORMAT,
      byteLength: bytes.byteLength,
      sha256: await sha256HexOf(bytes),
    },
  };
}
