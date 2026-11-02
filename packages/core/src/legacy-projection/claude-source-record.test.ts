import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { PdppStoredRecord } from "../storage/pdpp-records/types.js";
import {
  claudeBlobReference,
  decodeClaudeSourceRecord,
  MAX_CLAUDE_SOURCE_BYTES,
  mergeClaudeSourceRecords,
} from "./claude-source-record.js";

const stamp = "2026-09-01T00:00:00Z";
function source(payload: Record<string, unknown>, stream = "conversations") {
  const bytes = new TextEncoder().encode(
    JSON.stringify({
      format: "anthropic-source-record-v1",
      stream,
      record_key: payload.uuid,
      payload,
    }),
  );
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const meta = {
    blobId: `sha256:${sha256}`,
    sha256,
    sizeBytes: bytes.length,
    mimeType: "application/json",
  };
  const row: PdppStoredRecord = {
    instance: "selected",
    stream,
    recordKey: String(payload.uuid),
    data: {
      id: payload.uuid,
      blob_ref: {
        blob_id: meta.blobId,
        sha256,
        size_bytes: meta.sizeBytes,
        mime_type: meta.mimeType,
      },
    },
    version: 1,
    emittedAt: stamp,
    deleted: false,
  };
  return { row, contents: { bytes, meta } };
}
const message = (id: string, extra = {}) => ({
  uuid: id,
  sender: "human",
  parent_message_uuid: null,
  created_at: stamp,
  content: [{ type: "text", text: "hello" }],
  attachments: [],
  ...extra,
});
const conversation = (children: unknown[] = []) => ({
  uuid: "chat",
  name: "Synthetic chat",
  chat_messages: children,
});

it("maps nonempty messages with content precedence, attachments, timestamps and relationship", async () => {
  const input = source(
    conversation([
      message("m1", {
        text: "preferred",
        attachments: [{ filename: "notes.txt" }],
      }),
      message("m2", {
        parent_message_uuid: "m1",
        content: ["part", { content: "two" }],
      }),
    ]),
  );
  const records = await decodeClaudeSourceRecord(input.row, input.contents);
  expect(records).toMatchObject([
    {
      stream: "conversations",
      data: { id: "chat", title: "Synthetic chat", message_count: 2 },
    },
    {
      stream: "messages",
      data: {
        id: "m1",
        conversation_id: "chat",
        content: "preferred",
        attachments: [{ filename: "notes.txt" }],
        create_time: stamp,
      },
    },
    {
      stream: "messages",
      data: { id: "m2", parent_id: "m1", content: "part\ntwo" },
    },
  ]);
});

it("maps declared project fields and documents, excluding arbitrary raw fields", async () => {
  const input = source(
    {
      uuid: "p",
      name: "Project",
      creator: { uuid: "u", full_name: "Person", private_token: "excluded" },
      is_private: true,
      archived_at: stamp,
      docs: [
        { uuid: "d", filename: "file", content: "body", created_at: stamp },
      ],
      other: "excluded",
    },
    "projects",
  );
  const records = await decodeClaudeSourceRecord(input.row, input.contents);
  expect(records).toMatchObject([
    {
      stream: "projects",
      data: {
        id: "p",
        name: "Project",
        is_private: true,
        is_archived: true,
        creator: { uuid: "u", full_name: "Person" },
        raw_docs: [{ uuid: "d", filename: "file", content: "body" }],
      },
    },
    {
      stream: "project_documents",
      data: { id: "d", project_id: "p", filename: "file", content: "body" },
    },
  ]);
  expect(records[0]?.data).not.toHaveProperty("other");
  expect(records[0]?.data.creator).not.toHaveProperty("private_token");
});

describe("verified byte and parent identity boundary", () => {
  it.each([
    [
      "wrong MIME",
      (ref: Record<string, unknown>) => {
        ref.mime_type = "text/plain";
      },
    ],
    [
      "oversized",
      (ref: Record<string, unknown>) => {
        ref.size_bytes = MAX_CLAUDE_SOURCE_BYTES + 1;
      },
    ],
    [
      "zero size",
      (ref: Record<string, unknown>) => {
        ref.size_bytes = 0;
      },
    ],
    [
      "fractional size",
      (ref: Record<string, unknown>) => {
        ref.size_bytes = 1.5;
      },
    ],
    [
      "wrong digest",
      (ref: Record<string, unknown>) => {
        ref.sha256 = "f".repeat(64);
      },
    ],
    [
      "sentinel",
      (ref: Record<string, unknown>) => {
        ref.sha256 = "0".repeat(64);
        ref.blob_id = `sha256:${ref.sha256}`;
        ref.size_bytes = 1;
      },
    ],
    [
      "extra shape",
      (ref: Record<string, unknown>) => {
        ref.url = "https://example.invalid/never-fetch";
      },
    ],
  ])("refuses %s references before byte access", (_label, mutate) => {
    const input = source(conversation());
    mutate(input.row.data.blob_ref as Record<string, unknown>);
    expect(() => claudeBlobReference(input.row.data)).toThrow(
      "invalid_blob_reference",
    );
  });
  it("refuses missing bytes and MIME metadata that disagrees with the reference", async () => {
    const input = source(conversation());
    await expect(
      decodeClaudeSourceRecord(input.row, {
        ...input.contents,
        bytes: undefined,
      }),
    ).rejects.toThrow("blob_missing_or_corrupt");
    await expect(
      decodeClaudeSourceRecord(input.row, {
        ...input.contents,
        meta: { ...input.contents.meta, mimeType: "text/plain" },
      }),
    ).rejects.toThrow("blob_metadata_mismatch");
  });
  it("checks the exact byte digest, not merely its stated metadata", async () => {
    const input = source(conversation());
    const bytes = input.contents.bytes.slice();
    bytes[5] ^= 1;
    await expect(
      decodeClaudeSourceRecord(input.row, { ...input.contents, bytes }),
    ).rejects.toThrow("blob_digest_mismatch");
  });
  it.each(["stream", "recordKey", "id"])(
    "refuses a parent %s that disagrees with the verified envelope",
    async (field) => {
      const input = source(conversation());
      if (field === "stream") input.row.stream = "projects";
      else if (field === "id") input.row.data.id = "different";
      else input.row.recordKey = "different";
      await expect(
        decodeClaudeSourceRecord(input.row, input.contents),
      ).rejects.toThrow("source_envelope_mismatch");
    },
  );
  it("refuses parent summary conflicts instead of choosing one version", async () => {
    const input = source(conversation());
    input.row.data.title = "Other revision";
    await expect(
      decodeClaudeSourceRecord(input.row, input.contents),
    ).rejects.toThrow("parent_blob_conflict");
  });
});

describe("source child lists", () => {
  it.each([
    ["omitted", { uuid: "chat", name: "Chat" }, "source_children_unknown"],
    ["null", { uuid: "chat", chat_messages: null }, "source_children_unknown"],
    [
      "nonarray",
      { uuid: "chat", chat_messages: {} },
      "source_children_unknown",
    ],
    ["malformed child", conversation([null]), "malformed_source_child"],
    [
      "missing child identity",
      conversation([{ sender: "human" }]),
      "missing_source_identity",
    ],
    [
      "ambiguous child identity",
      conversation([message("a", { id: "b" })]),
      "ambiguous_source_identity",
    ],
    [
      "duplicate child",
      conversation([message("a"), message("a")]),
      "duplicate_source_child",
    ],
    [
      "bad attachment",
      conversation([message("a", { attachments: [1] })]),
      "invalid_source_attachments",
    ],
    [
      "unsafe text",
      conversation([message("a", { text: "bad\u0000text" })]),
      "unsafe_source_text",
    ],
  ])(
    "refuses %s without fabricating empty detail",
    async (_label, payload, detail) => {
      const input = source(payload);
      await expect(
        decodeClaudeSourceRecord(input.row, input.contents),
      ).rejects.toThrow(detail);
    },
  );
  it("distinguishes explicit empty lists from separately collected project metadata", async () => {
    const input = source(conversation());
    expect(
      await decodeClaudeSourceRecord(input.row, input.contents),
    ).toMatchObject([{ data: { message_count: 0 } }]);
    const project = source({ uuid: "p", name: "Project" }, "projects");
    const records = await decodeClaudeSourceRecord(
      project.row,
      project.contents,
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.data).not.toHaveProperty("raw_docs");
  });
});

it("merges identical inline children, rejecting conflicts, duplicate identities and extra children", async () => {
  const input = source(conversation([message("a")]));
  const expanded = await decodeClaudeSourceRecord(input.row, input.contents);
  const child = expanded[1]!;
  expect(mergeClaudeSourceRecords([child], expanded)).toHaveLength(2);
  expect(() => mergeClaudeSourceRecords([], expanded)).toThrow(
    "source_child_missing_inline",
  );
  expect(() =>
    mergeClaudeSourceRecords(
      [{ ...child, data: { id: child.data.id } }],
      expanded,
    ),
  ).toThrow("inline_child_fields_missing");
  expect(() =>
    mergeClaudeSourceRecords(
      [{ ...child, data: { ...child.data, content: "different" } }],
      expanded,
    ),
  ).toThrow("inline_blob_conflict");
  expect(() =>
    mergeClaudeSourceRecords(
      [{ ...child, data: { ...child.data, conversation_id: "other" } }],
      expanded,
    ),
  ).toThrow("inline_blob_conflict");
  expect(() => mergeClaudeSourceRecords([child, child], expanded)).toThrow(
    "duplicate_inline_identity",
  );
  expect(() => mergeClaudeSourceRecords([child], [...expanded, child])).toThrow(
    "duplicate_source_identity",
  );
  expect(() =>
    mergeClaudeSourceRecords(
      [child, { ...child, data: { ...child.data, id: "extra" } }],
      expanded,
    ),
  ).toThrow("inline_child_absent_from_blob");
});

it.each(["invalid JSON", "invalid UTF-8", "wrong format", "nonobject payload"])(
  "refuses %s even with a valid byte digest",
  async (kind) => {
    const input = source(conversation());
    let bytes: Uint8Array<ArrayBuffer>;
    if (kind === "invalid JSON") bytes = new TextEncoder().encode("{");
    else if (kind === "invalid UTF-8") bytes = new Uint8Array([0xff]);
    else {
      const parsed = JSON.parse(new TextDecoder().decode(input.contents.bytes));
      if (kind === "wrong format") parsed.format = "unreviewed-v2";
      else parsed.payload = [];
      bytes = new TextEncoder().encode(JSON.stringify(parsed));
    }
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    const meta = {
      blobId: `sha256:${sha256}`,
      sha256,
      sizeBytes: bytes.length,
      mimeType: "application/json",
    };
    input.row.data.blob_ref = {
      blob_id: meta.blobId,
      sha256,
      size_bytes: meta.sizeBytes,
      mime_type: meta.mimeType,
    };
    await expect(
      decodeClaudeSourceRecord(input.row, { bytes, meta }),
    ).rejects.toThrow(
      kind.startsWith("invalid")
        ? "invalid_source_json"
        : kind === "wrong format"
          ? "source_envelope_mismatch"
          : "source_identity_mismatch",
    );
  },
);
