import { describe, expect, it } from "vitest";
import { readCanonicalLegacyScope, type CanonicalLegacyReadStore } from "./canonical-legacy-projection.js";
import { createStreamDeclarationRegistry } from "./pdpp-records/stream-declaration.js";
import type { PdppBlobMeta, PdppStoredRecord } from "./pdpp-records/types.js";
import { projectPdppRecordsToLegacyPayload } from "../legacy-projection/index.js";
import { compareLegacyCoverage, type LegacyCoverageVerdict } from "./legacy-scope-coverage.js";
import { createLegacyScopeView, type LegacyScopeAuthority } from "./legacy-scope-view.js";

const schema = {
  properties: {
    content: { type: ["string", "null"], x_pdpp_text_encoding: "pdpp-safe-escape-v1" },
    blob_ref: { x_pdpp_blob_projects_field: "content", x_pdpp_blob_codec: "json-string-v1" },
  },
};
const declarations = createStreamDeclarationRegistry([{
  name: "messages", semantics: "append_only", primaryKey: ["id"],
  cursorField: "create_time", requiredFields: ["id"], schema,
}]);
const now = "2026-10-16T00:00:00.000Z";
const selection = { instance: "test", sourceId: "https://registry.pdpp.dev/sources/chatgpt", method: "chatgpt" };
function records(contents: Record<string, unknown>[]) {
  return [{
    stream: "conversations",
    data: { id: "c", current_node: String(contents.length), message_count_on_current_branch: contents.length },
  }, ...contents.map((content, i) => ({
    stream: "messages",
    data: { id: String(i + 1), conversation_id: "c", parent_id: i ? String(i) : null,
      role: "user", content_type: "text", on_current_branch: true, ...content },
  }))];
}
function storeFor(input: ReturnType<typeof records>, blob?: { meta: PdppBlobMeta; bytes?: Uint8Array<ArrayBuffer> }): CanonicalLegacyReadStore {
  const rows: PdppStoredRecord[] = input.map((row) => ({
    ...row, instance: "test", recordKey: row.data.id as string,
    version: 1, emittedAt: now, deleted: false,
  }));
  const binding = { ...selection, deletedAt: null, generation: 1, resetClock: 0 };
  return {
    getInstanceBinding: () => binding, listConnections: () => [binding],
    readSnapshot: (read) => read(),
    listArrivalOrder: () => [], listStreamCompletions: () => [],
    listStreams: () => ["conversations", "messages"].map((stream) => ({
      stream, recordCount: rows.filter((row) => row.stream === stream).length, lastUpdated: now,
    })),
    listRecords: (stream, options) => {
      const data = rows.filter((row) => row.stream === stream);
      const offset = Number(options.cursor ?? 0);
      return { data: data.slice(offset, offset + options.limit),
        hasMore: offset + options.limit < data.length, nextCursor: String(offset + options.limit), horizon: "1" };
    },
    getBlobMeta: (id) => blob?.meta.blobId === id ? blob.meta : undefined,
    getBlobBytes: (id) => blob?.meta.blobId === id ? blob.bytes : undefined,
  };
}
async function blobFor(value: unknown) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const sha256 = [...hash].map((b) => b.toString(16).padStart(2, "0")).join("");
  const meta = { blobId: "sha256:" + sha256, sha256, sizeBytes: bytes.length, mimeType: "application/json" };
  return { bytes, meta, ref: { blob_id: meta.blobId, sha256, size_bytes: bytes.length, mime_type: meta.mimeType } };
}
function project(content: unknown, declared = true) {
  return projectPdppRecordsToLegacyPayload("chatgpt.conversations", records([{ content }]), {
    fetchedStreams: ["conversations", "messages"], now,
    ...(declared ? { streamSchemas: { messages: schema } } : {}),
  });
}
function payloadContent(result: ReturnType<typeof project>) {
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error("projection failed");
  return (result.payload.conversations as { messages: { content: string }[] }[])[0]!.messages[0]!.content;
}

describe("declared lossless text projection", () => {
  it("decodes every escaped code unit, both hex cases, without rescanning", () => {
    const units = [...Array.from({ length: 32 }, (_, i) => i).filter((i) => ![9, 10, 13].includes(i)),
      ...Array.from({ length: 33 }, (_, i) => 127 + i), ...Array.from({ length: 2048 }, (_, i) => 0xd800 + i)];
    const encoded = units.map((i) => "\\u" + i.toString(16).padStart(4, "0")).join("|");
    expect(payloadContent(project(encoded))).toBe(units.map((i) => String.fromCharCode(i)).join("|"));
    expect(payloadContent(project(encoded.toUpperCase().replace(/\\U/g, "\\u")))).toBe(units.map((i) => String.fromCharCode(i)).join("|"));
    expect(payloadContent(project("\\u005Cu0000"))).toBe("\\u0000");
  });
  it.each(["\\u0041", "\\u00G0", "\\u12", "normal\\path", "😀\ufffe\n\t\r"])(
    "preserves literal and valid text %s", (text) => expect(payloadContent(project(text))).toBe(text),
  );
  it("does not decode undeclared old data", () => {
    expect(payloadContent(project("\\u0000", false))).toBe("\\u0000");
  });
  it.each(["\u0000", "\ud800", "\udc00", 42, {}])("rejects malformed encoded value %j with a typed error", (content) => {
    expect(project(content)).toMatchObject({ ok: false, error: { kind: "invalid_encoded_text", stream: "messages", field: "content" } });
  });
  it("preserves declared null without a blob", () => {
    expect(project(null).ok).toBe(true);
  });
});

describe("canonical declared blob projection", () => {
  it.each([null, undefined])("restores JSON-string content for %s and retains mixed branch order/count", async (inline) => {
    const raw = "long\u0000\ud800" + "\\u0000";
    const blob = await blobFor(raw);
    const source = records([{ content: "first" }, { ...(inline === null ? { content: null } : {}), blob_ref: blob.ref }, { content: "last\\u0000" }]);
    const result = await readCanonicalLegacyScope({
      store: storeFor(source, blob), selection, scope: "chatgpt.conversations", declarations, pageSize: 1,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const conversation = (result.envelope.data.conversations as { message_count: number; messages: { id: string; content: string }[] }[])[0]!;
    expect(conversation.message_count).toBe(3);
    expect(conversation.messages.map((m) => [m.id, m.content])).toEqual([["1", "first"], ["2", raw], ["3", "last\u0000"]]);
    expect(result.diagnostics.sourceRowCounts).toEqual({ conversations: 1, messages: 3 });
    const legacy = projectPdppRecordsToLegacyPayload("chatgpt.conversations", records([{ content: "first" }, { content: raw }, { content: "last\u0000" }]), { fetchedStreams: ["conversations", "messages"], now });
    if (!legacy.ok) throw new Error("legacy fixture invalid");
    expect(compareLegacyCoverage(legacy.payload, result.envelope.data, {
      entityKeys: { "$.conversations": ["id"], "$.conversations[].messages": ["id"] },
    }).covered).toBe(true);
  });
  it.each(["absent", "unreadable"])("refuses %s blob with missing_raw_blob", async (state) => {
    const blob = await blobFor("text");
    const result = await readCanonicalLegacyScope({
      store: storeFor(records([{ content: null, blob_ref: blob.ref }]), state === "absent" ? undefined : { meta: blob.meta }),
      selection, scope: "chatgpt.conversations", declarations,
    });
    expect(result).toMatchObject({ ok: false, reason: "missing_raw_blob", recordCount: 1 });
  });
  it("rejects non-string JSON blob payload", async () => {
    const blob = await blobFor({ text: "not a JSON string" });
    expect(await readCanonicalLegacyScope({
      store: storeFor(records([{ content: null, blob_ref: blob.ref }]), blob),
      selection, scope: "chatgpt.conversations", declarations,
    })).toMatchObject({ ok: false, reason: "blob_backed_record_invalid" });
  });
  it("refuses omitted text rather than silently losing a message", async () => {
    expect(await readCanonicalLegacyScope({
      store: storeFor(records([{}])), selection, scope: "chatgpt.conversations", declarations,
    })).toMatchObject({ ok: false, reason: "projection_rejected", error: { kind: "message_content_omitted" } });
  });
  it("includes declaration changes in the revision", async () => {
    const store = storeFor(records([{ content: "\\u0000" }]));
    const old = await readCanonicalLegacyScope({ store, selection, scope: "chatgpt.conversations" });
    const current = await readCanonicalLegacyScope({ store, selection, scope: "chatgpt.conversations", declarations });
    expect(old.ok && current.ok && old.revision !== current.revision).toBe(true);
  });
});

function viewFixture(store: CanonicalLegacyReadStore, legacyContents: Record<string, unknown>[],
  registry = declarations) {
  const expected = projectPdppRecordsToLegacyPayload("chatgpt.conversations", records(legacyContents), {
    fetchedStreams: ["conversations", "messages"], now,
  });
  if (!expected.ok) throw new Error("invalid legacy fixture");
  let covered = false;
  const verdicts: LegacyCoverageVerdict[] = [];
  const cache = new Map<string, LegacyCoverageVerdict>();
  const authority: LegacyScopeAuthority = {
    listMethodConnections: () => [store.getInstanceBinding("test")],
    hasHeldData: () => true, readSnapshot: (read) => read(),
    writeClock: () => 1, arrivalRevision: () => 1,
    hasTakeover: () => covered, hasCoveredHead: () => covered, isReset: () => false,
    cachedVerdict: (_scope, _instance, _generation, _head, cursor) => cache.get(cursor) ?? null,
    verdictFor: () => [], resetTakeover: () => { covered = false; },
    eligibleLegacyHead: () => ({ id: 1, path: "test", version: 1, casRevision: 1, collectedAt: now }),
    confirmRead: (_scope, _head, current, verdict) => {
      if (!current()) return false;
      if (verdict) {
        verdicts.push(verdict.coverage);
        cache.set(verdict.canonicalCursor, verdict.coverage);
        covered ||= verdict.coverage.covered;
      }
      return true;
    },
  };
  const view = createLegacyScopeView({
    authority, records: store, declarations: registry,
    configuredMethods: () => ["chatgpt"],
    readLegacyHead: async () => ({
      version: "1.0", scope: "chatgpt.conversations", collectedAt: now, data: expected.payload,
    }),
  });
  return { view, verdicts };
}

describe("declared projection takeover", () => {
  it("takes over only using decoded inline and blob content", async () => {
    const blob = await blobFor("blob\u0000\\u0000");
    const { view, verdicts } = viewFixture(
      storeFor(records([{ content: "inline\\u0000" }, { content: null, blob_ref: blob.ref }]), blob),
      [{ content: "inline\u0000" }, { content: "blob\u0000\\u0000" }],
    );
    expect((await view.readLatest("chatgpt.conversations")).kind).toBe("canonical");
    expect(verdicts.at(-1)).toMatchObject({ covered: true, reason: null });
  });
  it("records missing blob as not covered and keeps the legacy head", async () => {
    const blob = await blobFor("long");
    const { view, verdicts } = viewFixture(
      storeFor(records([{ content: null, blob_ref: blob.ref }])), [{ content: "long" }],
    );
    expect((await view.readLatest("chatgpt.conversations")).kind).toBe("file");
    expect(verdicts.at(-1)).toMatchObject({ covered: false, reason: "missing_raw_blob" });
  });
  it("invalidates covered payload and verdict caches on a declaration-only change", async () => {
    const declaration = { name: "messages", semantics: "append_only" as const, primaryKey: ["id"],
      cursorField: "create_time", requiredFields: ["id"], schema: {} as Record<string, unknown> };
    const registry = createStreamDeclarationRegistry([declaration]);
    const { view, verdicts } = viewFixture(
      storeFor(records([{ content: "\\u0000" }])), [{ content: "\\u0000" }], registry,
    );
    expect((await view.readLatest("chatgpt.conversations")).kind).toBe("canonical");
    declaration.schema = schema;
    expect((await view.readLatest("chatgpt.conversations")).kind).toBe("refused");
    expect(verdicts.at(-1)?.covered).toBe(false);
  });
});

describe("declared blob safety", () => {
  it("rejects blob/inline conflict", async () => {
    const blob = await blobFor("blob");
    expect(await readCanonicalLegacyScope({
      store: storeFor(records([{ content: "inline", blob_ref: blob.ref }]), blob),
      selection, scope: "chatgpt.conversations", declarations,
    })).toMatchObject({ ok: false, reason: "blob_backed_record_invalid" });
  });
  it("preflights the byte budget before reading bytes", async () => {
    const blob = await blobFor("blob");
    const store = storeFor(records([{ content: null, blob_ref: blob.ref }]), blob);
    store.getBlobBytes = () => { throw new Error("must not read"); };
    expect(await readCanonicalLegacyScope({
      store, selection, scope: "chatgpt.conversations", declarations, blobByteBudget: 0,
    })).toMatchObject({ ok: false, reason: "blob_read_budget_exceeded" });
  });
  it("redacts blob store read errors and reports missing_raw_blob", async () => {
    const blob = await blobFor("blob");
    const store = storeFor(records([{ content: null, blob_ref: blob.ref }]), blob);
    store.getBlobBytes = () => { throw new Error("secret storage details"); };
    expect(await readCanonicalLegacyScope({
      store, selection, scope: "chatgpt.conversations", declarations,
    })).toEqual({ ok: false, status: "unavailable", reason: "missing_raw_blob", recordCount: 1 });
  });
  it("does not interpret a blob without declaration annotations", async () => {
    const blob = await blobFor("blob");
    expect(await readCanonicalLegacyScope({
      store: storeFor(records([{ content: null, blob_ref: blob.ref }]), blob),
      selection, scope: "chatgpt.conversations",
    })).toMatchObject({ ok: false, reason: "blob_backed_records_unsupported" });
  });
});
