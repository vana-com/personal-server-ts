import { describe, expect, it } from "vitest";
import {
  readCanonicalLegacyScope,
  type CanonicalLegacyReadStore,
} from "./canonical-legacy-projection.js";
import { createStreamDeclarationRegistry } from "./pdpp-records/stream-declaration.js";
import type { PdppBlobMeta, PdppStoredRecord } from "./pdpp-records/types.js";
import { decodeDeclaredRecords } from "../legacy-projection/declared-text.js";
import { projectPdppRecordsToLegacyPayload } from "../legacy-projection/index.js";
import {
  compareLegacyCoverage,
  type LegacyCoverageVerdict,
} from "./legacy-scope-coverage.js";
import {
  createLegacyScopeView,
  type LegacyScopeAuthority,
} from "./legacy-scope-view.js";

const schema = {
  properties: {
    content: {
      type: ["string", "null"],
      x_pdpp_text_encoding: "pdpp-safe-escape-v1",
    },
    blob_ref: {
      x_pdpp_blob_projects_field: "content",
      x_pdpp_blob_codec: "json-string-v1",
    },
  },
};
const declarations = createStreamDeclarationRegistry([
  {
    name: "messages",
    semantics: "append_only",
    primaryKey: ["id"],
    cursorField: "create_time",
    requiredFields: ["id"],
    schema,
  },
]);
const now = "2026-10-16T00:00:00.000Z";
const selection = {
  instance: "test",
  sourceId: "https://registry.pdpp.dev/sources/chatgpt",
  method: "chatgpt",
};
function records(contents: Record<string, unknown>[]) {
  return [
    {
      stream: "conversations",
      data: {
        id: "c",
        current_node: String(contents.length),
        message_count_on_current_branch: contents.length,
      },
    },
    ...contents.map((content, i) => ({
      stream: "messages",
      data: {
        id: String(i + 1),
        conversation_id: "c",
        parent_id: i ? String(i) : null,
        role: "user",
        content_type: "text",
        on_current_branch: true,
        ...content,
      },
    })),
  ];
}
function storeFor(
  input: ReturnType<typeof records>,
  blob?: { meta: PdppBlobMeta; bytes?: Uint8Array<ArrayBuffer> },
): CanonicalLegacyReadStore {
  const rows: PdppStoredRecord[] = input.map((row) => ({
    ...row,
    instance: "test",
    recordKey: row.data.id as string,
    version: 1,
    emittedAt: now,
    deleted: false,
  }));
  const binding = {
    ...selection,
    deletedAt: null,
    generation: 1,
    resetClock: 0,
  };
  return {
    getInstanceBinding: () => binding,
    listConnections: () => [binding],
    readSnapshot: (read) => read(),
    listArrivalOrder: () => [],
    listStreamCompletions: () => [],
    listStreams: () =>
      ["conversations", "messages"].map((stream) => ({
        stream,
        recordCount: rows.filter((row) => row.stream === stream).length,
        lastUpdated: now,
      })),
    listRecords: (stream, options) => {
      const data = rows.filter((row) => row.stream === stream);
      const offset = Number(options.cursor ?? 0);
      return {
        data: data.slice(offset, offset + options.limit),
        hasMore: offset + options.limit < data.length,
        nextCursor: String(offset + options.limit),
        horizon: "1",
      };
    },
    getBlobMeta: (id) => (blob?.meta.blobId === id ? blob.meta : undefined),
    getBlobBytes: (id) => (blob?.meta.blobId === id ? blob.bytes : undefined),
  };
}
async function blobFor(value: unknown) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const sha256 = [...hash].map((b) => b.toString(16).padStart(2, "0")).join("");
  const meta = {
    blobId: "sha256:" + sha256,
    sha256,
    sizeBytes: bytes.length,
    mimeType: "application/json",
  };
  return {
    bytes,
    meta,
    ref: {
      blob_id: meta.blobId,
      sha256,
      size_bytes: bytes.length,
      mime_type: meta.mimeType,
    },
  };
}
function project(content: unknown, declared = true) {
  return projectPdppRecordsToLegacyPayload(
    "chatgpt.conversations",
    records([{ content }]),
    {
      fetchedStreams: ["conversations", "messages"],
      now,
      ...(declared ? { streamSchemas: { messages: schema } } : {}),
    },
  );
}
function payloadContent(result: ReturnType<typeof project>) {
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error("projection failed");
  return (
    result.payload.conversations as { messages: { content: string }[] }[]
  )[0]!.messages[0]!.content;
}

describe("declared lossless text projection", () => {
  it("decodes every escaped code unit, both hex cases, without rescanning", () => {
    const units = [
      ...Array.from({ length: 32 }, (_, i) => i).filter(
        (i) => ![9, 10, 13].includes(i),
      ),
      ...Array.from({ length: 33 }, (_, i) => 127 + i),
      ...Array.from({ length: 2048 }, (_, i) => 0xd800 + i),
    ];
    const encoded = units
      .map((i) => "\\u" + i.toString(16).padStart(4, "0"))
      .join("|");
    expect(payloadContent(project(encoded))).toBe(
      units.map((i) => String.fromCharCode(i)).join("|"),
    );
    expect(
      payloadContent(project(encoded.toUpperCase().replace(/\\U/g, "\\u"))),
    ).toBe(units.map((i) => String.fromCharCode(i)).join("|"));
    expect(payloadContent(project("\\u005Cu0000"))).toBe("\\u0000");
  });
  it.each(["\\u0041", "\\u00G0", "\\u12", "normal\\path", "😀\ufffe\n\t\r"])(
    "preserves literal and valid text %s",
    (text) => expect(payloadContent(project(text))).toBe(text),
  );
  it.each([
    "  leading and trailing  ",
    "\n\n\tindented\n",
    "\u00A0nbsp edges\u00A0",
    "\n  \t",
  ])("keeps edge whitespace exactly in %j", (text) => {
    expect(payloadContent(project(text))).toBe(text);
    expect(payloadContent(project(text, false))).toBe(text);
  });
  it("keeps edge whitespace around a decoded control character", () => {
    expect(payloadContent(project("\n  a\\u0000b \t\n"))).toBe(
      "\n  a\u0000b \t\n",
    );
  });
  it("does not decode undeclared old data", () => {
    expect(payloadContent(project("\\u0000", false))).toBe("\\u0000");
  });
  it.each(["\u0000", "\ud800", "\udc00"])(
    "rejects malformed encoded value %j with a typed error",
    (content) => {
      expect(() =>
        decodeDeclaredRecords(records([{ content }]), { messages: schema }),
      ).toThrowError(
        expect.objectContaining({
          kind: "invalid_encoded_text",
          stream: "messages",
          field: "content",
        }),
      );
    },
  );
  it("preserves declared null without a blob", () => {
    expect(project(null).ok).toBe(true);
  });
});

describe("canonical declared blob projection", () => {
  it.each([null, undefined])(
    "restores JSON-string content for %s and retains mixed branch order/count",
    async (inline) => {
      const raw = "long\u0000\ud800" + "\\u0000";
      const blob = await blobFor(raw);
      const source = records([
        { content: "first" },
        { ...(inline === null ? { content: null } : {}), blob_ref: blob.ref },
        { content: "last\\u0000" },
      ]);
      const result = await readCanonicalLegacyScope({
        store: storeFor(source, blob),
        selection,
        scope: "chatgpt.conversations",
        declarations,
        pageSize: 1,
      });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      const conversation = (
        result.envelope.data.conversations as {
          message_count: number;
          messages: { id: string; content: string }[];
        }[]
      )[0]!;
      expect(conversation.message_count).toBe(3);
      expect(conversation.messages.map((m) => [m.id, m.content])).toEqual([
        ["1", "first"],
        ["2", raw],
        ["3", "last\u0000"],
      ]);
      expect(result.diagnostics.sourceRowCounts).toEqual({
        conversations: 1,
        messages: 3,
      });
      const legacy = projectPdppRecordsToLegacyPayload(
        "chatgpt.conversations",
        records([
          { content: "first" },
          { content: raw },
          { content: "last\u0000" },
        ]),
        { fetchedStreams: ["conversations", "messages"], now },
      );
      if (!legacy.ok) throw new Error("legacy fixture invalid");
      expect(
        compareLegacyCoverage(legacy.payload, result.envelope.data, {
          entityKeys: {
            "$.conversations": ["id"],
            "$.conversations[].messages": ["id"],
          },
        }).covered,
      ).toBe(true);
    },
  );
  it.each(["absent", "unreadable"])(
    "refuses %s blob with missing_raw_blob",
    async (state) => {
      const blob = await blobFor("text");
      const result = await readCanonicalLegacyScope({
        store: storeFor(
          records([{ content: null, blob_ref: blob.ref }]),
          state === "absent" ? undefined : { meta: blob.meta },
        ),
        selection,
        scope: "chatgpt.conversations",
        declarations,
      });
      expect(result).toMatchObject({
        ok: false,
        reason: "missing_raw_blob",
        recordCount: 1,
      });
    },
  );
  it("rejects non-string JSON blob payload", async () => {
    const blob = await blobFor({ text: "not a JSON string" });
    expect(
      await readCanonicalLegacyScope({
        store: storeFor(records([{ content: null, blob_ref: blob.ref }]), blob),
        selection,
        scope: "chatgpt.conversations",
        declarations,
      }),
    ).toMatchObject({ ok: false, reason: "blob_backed_record_invalid" });
  });
  it("keeps optional content absent without a blob reference", async () => {
    const source = records([{ role: "tool", content_type: "code" }]);
    const decoded = decodeDeclaredRecords(source, { messages: schema });
    expect(Object.hasOwn(decoded[1]!.data, "content")).toBe(false);
    expect(
      await readCanonicalLegacyScope({
        store: storeFor(source),
        selection,
        scope: "chatgpt.conversations",
        declarations,
      }),
    ).toMatchObject({
      ok: true,
      complete: true,
      diagnostics: { omissions: [] },
    });
  });
  it("includes declaration changes in the revision", async () => {
    const store = storeFor(records([{ content: "\\u0000" }]));
    const old = await readCanonicalLegacyScope({
      store,
      selection,
      scope: "chatgpt.conversations",
    });
    const current = await readCanonicalLegacyScope({
      store,
      selection,
      scope: "chatgpt.conversations",
      declarations,
    });
    expect(old.ok && current.ok && old.revision !== current.revision).toBe(
      true,
    );
  });
});

function viewFixture(
  store: CanonicalLegacyReadStore,
  legacyContents: Record<string, unknown>[],
  registry = declarations,
) {
  const expected = projectPdppRecordsToLegacyPayload(
    "chatgpt.conversations",
    records(legacyContents),
    {
      fetchedStreams: ["conversations", "messages"],
      now,
    },
  );
  if (!expected.ok) throw new Error("invalid legacy fixture");
  let covered = false;
  const verdicts: LegacyCoverageVerdict[] = [];
  const cache = new Map<string, LegacyCoverageVerdict>();
  const authority: LegacyScopeAuthority = {
    listMethodConnections: () => [store.getInstanceBinding("test")],
    hasHeldData: () => true,
    readSnapshot: (read) => read(),
    writeClock: () => 1,
    arrivalRevision: () => 1,
    hasTakeover: () => covered,
    hasMethodTakeover: () => covered,
    hasCoveredHead: () => covered,
    isReset: () => false,
    cachedVerdict: (_scope, _instance, _generation, _head, cursor) =>
      cache.get(cursor) ?? null,
    verdictFor: () => [],
    resetTakeover: () => {
      covered = false;
    },
    eligibleLegacyHead: () => ({
      id: 1,
      path: "test",
      version: 1,
      casRevision: 1,
      collectedAt: now,
    }),
    confirmRead: (_scope, _head, current, _method, verdict) => {
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
    authority,
    records: store,
    declarations: registry,
    configuredMethods: () => ["chatgpt"],
    readLegacyHead: async () => ({
      version: "1.0",
      scope: "chatgpt.conversations",
      collectedAt: now,
      data: expected.payload,
    }),
  });
  return { view, verdicts };
}

describe("declared projection takeover", () => {
  it("takes over only using decoded inline and blob content", async () => {
    const blob = await blobFor("blob\u0000\\u0000");
    const { view, verdicts } = viewFixture(
      storeFor(
        records([
          { content: "inline\\u0000" },
          { content: null, blob_ref: blob.ref },
        ]),
        blob,
      ),
      [{ content: "inline\u0000" }, { content: "blob\u0000\\u0000" }],
    );
    expect((await view.readLatest("chatgpt.conversations")).kind).toBe(
      "canonical",
    );
    expect(verdicts.at(-1)).toMatchObject({ covered: true, reason: null });
  });
  it("records missing blob as not covered and keeps the legacy head", async () => {
    const blob = await blobFor("long");
    const { view, verdicts } = viewFixture(
      storeFor(records([{ content: null, blob_ref: blob.ref }])),
      [{ content: "long" }],
    );
    expect((await view.readLatest("chatgpt.conversations")).kind).toBe("file");
    expect(verdicts.at(-1)).toMatchObject({
      covered: false,
      reason: "missing_raw_blob",
    });
  });
  it("invalidates covered payload and verdict caches on a declaration-only change", async () => {
    const declaration = {
      name: "messages",
      semantics: "append_only" as const,
      primaryKey: ["id"],
      cursorField: "create_time",
      requiredFields: ["id"],
      schema: {} as Record<string, unknown>,
    };
    const registry = createStreamDeclarationRegistry([declaration]);
    const { view, verdicts } = viewFixture(
      storeFor(records([{ content: "\\u0000" }])),
      [{ content: "\\u0000" }],
      registry,
    );
    expect((await view.readLatest("chatgpt.conversations")).kind).toBe(
      "canonical",
    );
    declaration.schema = schema;
    expect((await view.readLatest("chatgpt.conversations")).kind).toBe(
      "refused",
    );
    expect(verdicts.at(-1)?.covered).toBe(false);
  });
});

describe("declared blob safety", () => {
  it("rejects blob/inline conflict", async () => {
    const blob = await blobFor("blob");
    expect(
      await readCanonicalLegacyScope({
        store: storeFor(
          records([{ content: "inline", blob_ref: blob.ref }]),
          blob,
        ),
        selection,
        scope: "chatgpt.conversations",
        declarations,
      }),
    ).toMatchObject({ ok: false, reason: "blob_backed_record_invalid" });
  });
  it("preflights the byte budget before reading bytes", async () => {
    const blob = await blobFor("blob");
    const store = storeFor(
      records([{ content: null, blob_ref: blob.ref }]),
      blob,
    );
    store.getBlobBytes = () => {
      throw new Error("must not read");
    };
    expect(
      await readCanonicalLegacyScope({
        store,
        selection,
        scope: "chatgpt.conversations",
        declarations,
        blobByteBudget: 0,
      }),
    ).toMatchObject({ ok: false, reason: "blob_read_budget_exceeded" });
  });
  it("redacts blob store read errors and reports missing_raw_blob", async () => {
    const blob = await blobFor("blob");
    const store = storeFor(
      records([{ content: null, blob_ref: blob.ref }]),
      blob,
    );
    store.getBlobBytes = () => {
      throw new Error("secret storage details");
    };
    expect(
      await readCanonicalLegacyScope({
        store,
        selection,
        scope: "chatgpt.conversations",
        declarations,
      }),
    ).toEqual({
      ok: false,
      status: "unavailable",
      reason: "missing_raw_blob",
      recordCount: 1,
    });
  });
  it("does not interpret a blob without declaration annotations", async () => {
    const blob = await blobFor("blob");
    expect(
      await readCanonicalLegacyScope({
        store: storeFor(records([{ content: null, blob_ref: blob.ref }]), blob),
        selection,
        scope: "chatgpt.conversations",
      }),
    ).toMatchObject({ ok: false, reason: "blob_backed_records_unsupported" });
  });
});

describe("real ChatGPT nested declarations", () => {
  // Real ChatGPT declaration shapes: content/blob_ref are optional and the
  // encoding applies to every string and object key inside tool_calls.
  const schema = {
    type: "object",
    required: ["id", "conversation_id"],
    properties: {
      content: {
        type: ["string", "null"],
        x_pdpp_text_encoding: "pdpp-safe-escape-v1",
      },
      tool_calls: {
        type: "array",
        x_pdpp_text_encoding: "pdpp-safe-escape-v1",
      },
      blob_ref: {
        x_pdpp_blob_projects_field: "content",
        x_pdpp_blob_codec: "json-string-v1",
      },
    },
  };
  const declarations = createStreamDeclarationRegistry([
    {
      name: "messages",
      semantics: "append_only",
      primaryKey: ["id"],
      cursorField: "create_time",
      requiredFields: ["id", "conversation_id"],
      schema,
    },
  ]);
  const now = "2026-10-17T00:00:00.000Z";
  const selection = {
    instance: "test",
    sourceId: "https://registry.pdpp.dev/sources/chatgpt",
    method: "chatgpt",
  };
  function conversation(id: string, content: Record<string, unknown> = {}) {
    return [
      {
        stream: "conversations",
        data: {
          id,
          current_node: id + "-m",
          message_count_on_current_branch: 1,
        },
      },
      {
        stream: "messages",
        data: {
          id: id + "-m",
          conversation_id: id,
          parent_id: null,
          on_current_branch: true,
          role: "user",
          content_type: "text",
          content: "hello\\u0000",
          tool_calls: [],
          ...content,
        },
      },
    ];
  }
  function storeFor(
    input: ReturnType<typeof conversation>,
  ): CanonicalLegacyReadStore {
    const rows: PdppStoredRecord[] = input.map((row) => ({
      ...row,
      instance: "test",
      recordKey: row.data.id as string,
      version: 1,
      emittedAt: now,
      deleted: false,
    }));
    const binding = {
      ...selection,
      deletedAt: null,
      generation: 1,
      resetClock: 0,
    };
    return {
      getInstanceBinding: () => binding,
      listConnections: () => [binding],
      readSnapshot: (read) => read(),
      listArrivalOrder: () => [],
      listStreamCompletions: () => [],
      listStreams: () =>
        ["conversations", "messages"].map((stream) => ({
          stream,
          recordCount: rows.filter((row) => row.stream === stream).length,
          lastUpdated: now,
        })),
      listRecords: (stream, options) => {
        const data = rows.filter((row) => row.stream === stream);
        const offset = Number(options.cursor ?? 0);
        return {
          data: data.slice(offset, offset + options.limit),
          hasMore: offset + options.limit < data.length,
          nextCursor: String(offset + options.limit),
          horizon: "1",
        };
      },
    };
  }
  const project = (input: ReturnType<typeof conversation>) =>
    projectPdppRecordsToLegacyPayload("chatgpt.conversations", input, {
      fetchedStreams: ["conversations", "messages"],
      streamSchemas: { messages: schema },
      now,
    });

  describe("recursive declared ChatGPT values", () => {
    it("decodes nested array values and object keys once, preserving primitives and source rows", () => {
      const toolCalls = [
        {
          ["key\\u0000"]: [
            "value\\uD800",
            {
              ["path\\u005C"]: "literal\\u005Cu0000",
              body: { text_ref: "content" },
            },
          ],
          number: 42,
          boolean: false,
          nullable: null,
        },
      ];
      const input = conversation("valid", { tool_calls: toolCalls });
      const original = structuredClone(input);
      const decoded = decodeDeclaredRecords(input, { messages: schema });
      expect(decoded[1]!.data.tool_calls).toEqual([
        {
          ["key\u0000"]: [
            "value\uD800",
            { ["path\\"]: "literal\\u0000", body: { text_ref: "content" } },
          ],
          number: 42,
          boolean: false,
          nullable: null,
        },
      ]);
      expect(input).toEqual(original);
      expect(decoded[0]).toBe(input[0]);
      const result = project(input);
      expect(result).toMatchObject({ ok: true, payload: { total: 1 } });
      if (result.ok) expect(result.diagnostics).toBeUndefined();
    });

    it.each([42, false, null, {}, []].map((value) => [value]))(
      "leaves non-string values %j unchanged",
      (value) => {
        const input = conversation("valid", { tool_calls: value });
        const decoded = decodeDeclaredRecords(input, { messages: schema });
        expect(decoded[1]!.data.tool_calls).toBe(value);
      },
    );

    it("preserves prototype-named keys as own data properties without pollution", () => {
      const nested = JSON.parse(
        '{"__proto__":{"polluted":"safe\\\\u0000"},"constructor":{"prototype":"value\\\\u005C"},"hasOwnProperty":"own"}',
      );
      const decoded = decodeDeclaredRecords(
        conversation("valid", { tool_calls: [nested] }),
        { messages: schema },
      );
      const value = (
        decoded[1]!.data.tool_calls as Record<string, unknown>[]
      )[0]!;
      expect(Object.getPrototypeOf(value)).toBe(Object.prototype);
      expect(Object.hasOwn(value, "__proto__")).toBe(true);
      expect(value.__proto__).toEqual({ polluted: "safe\u0000" });
      expect(value.constructor).toEqual({ prototype: "value\\" });
      expect(value.hasOwnProperty).toBe("own");
      expect(Object.hasOwn(Object.prototype, "polluted")).toBe(false);
    });

    it("rejects decoded key collisions instead of overwriting either value", () => {
      const tool_calls = [{ ["key\\u005C"]: 1, ["key\\"]: 2 }];
      expect(() =>
        decodeDeclaredRecords(conversation("bad", { tool_calls }), {
          messages: schema,
        }),
      ).toThrowError(
        expect.objectContaining({
          kind: "invalid_encoded_text",
          field: "tool_calls",
        }),
      );
    });

    it("still diagnoses explicitly required absent content", () => {
      const input = conversation("required");
      delete (input[1]!.data as Record<string, unknown>).content;
      expect(() =>
        decodeDeclaredRecords(input, {
          messages: { ...schema, required: ["content"] },
        }),
      ).toThrowError(
        expect.objectContaining({
          kind: "message_content_omitted",
          field: "content",
        }),
      );
    });

    it("counts each malformed row once even when several fields are bad", async () => {
      const input = [
        ...conversation("good"),
        ...conversation("bad1", {
          content: "\u0000",
          tool_calls: [{ text: "\u0000" }],
        }),
        ...conversation("bad2", { content: "\u0000" }),
      ];
      const result = await readCanonicalLegacyScope({
        store: storeFor(input),
        selection,
        scope: "chatgpt.conversations",
        declarations,
      });
      expect(result).toMatchObject({ ok: true, complete: false });
      if (!result.ok) return;
      expect(result.diagnostics.omissions).toContainEqual({
        stream: "messages",
        count: 2,
        reasons: ["invalid_encoded_text: content"],
      });
      expect(
        result.diagnostics.omissions.filter(
          (entry) => entry.stream === "messages",
        ),
      ).toHaveLength(1);
    });

    it("does not decode undeclared nested values", () => {
      const input = conversation("old", {
        tool_calls: [{ ["key\\u0000"]: "value\\u0000" }],
      });
      expect(decodeDeclaredRecords(input)).toEqual(input);
    });

    it("keeps absent optional tool-message content absent and preserves branch evidence", async () => {
      const input = conversation("tool", {
        role: "tool",
        content_type: "code",
        tool_calls: [{ text_ref: "content" }],
      });
      delete (input[1]!.data as Record<string, unknown>).content;
      const decoded = decodeDeclaredRecords(input, { messages: schema });
      expect(Object.hasOwn(decoded[1]!.data, "content")).toBe(false);
      const result = await readCanonicalLegacyScope({
        store: storeFor(input),
        selection,
        scope: "chatgpt.conversations",
        declarations,
        pageSize: 1,
      });
      expect(result).toMatchObject({
        ok: true,
        complete: true,
        envelope: {
          data: {
            total: 1,
            conversations: [{ message_count: 0, messages: [] }],
          },
        },
        diagnostics: {
          omissions: [],
          partialRows: [],
          sourceRowCounts: { conversations: 1, messages: 1 },
        },
      });
    });

    it.each(
      [
        [{ text: "\u0000" }],
        [{ ["\ud800"]: "invalid key" }],
        [{ ["key\\u005C"]: 1, ["key\\"]: 2 }],
      ].map((tool_calls) => [tool_calls]),
    )(
      "isolates one malformed record and retains valid peer conversations (%j)",
      async (tool_calls) => {
        const input = [
          ...conversation("first"),
          ...conversation("bad", { tool_calls }),
          ...conversation("last"),
        ];
        const pure = project(input);
        expect(pure.ok).toBe(true);
        if (!pure.ok) return;
        expect(
          (pure.payload.conversations as { id: string }[]).map((c) => c.id),
        ).toEqual(["first", "last"]);
        expect(pure.diagnostics).toContainEqual({
          kind: "records_dropped",
          scope: "chatgpt.conversations",
          stream: "messages",
          count: 1,
          reasons: ["invalid_encoded_text: tool_calls"],
        });
        const canonical = await readCanonicalLegacyScope({
          store: storeFor(input),
          selection,
          scope: "chatgpt.conversations",
          declarations,
          pageSize: 1,
        });
        expect(canonical).toMatchObject({
          ok: true,
          complete: false,
          diagnostics: { sourceRowCounts: { conversations: 3, messages: 3 } },
        });
        if (!canonical.ok) return;
        expect(canonical.envelope.data).toEqual(pure.payload);
        expect(canonical.diagnostics.omissions).toContainEqual({
          stream: "messages",
          count: 1,
          reasons: ["invalid_encoded_text: tool_calls"],
        });
        expect(canonical.diagnostics.omissions).toContainEqual({
          stream: "conversations",
          count: 1,
          reasons: ["Current branch message count does not match conversation"],
        });
      },
    );

    it("never claims an entirely malformed history is a successful empty result", async () => {
      const input = conversation("bad", { tool_calls: [{ text: "\u0000" }] });
      expect(
        await readCanonicalLegacyScope({
          store: storeFor(input),
          selection,
          scope: "chatgpt.conversations",
          declarations,
        }),
      ).toMatchObject({
        ok: false,
        reason: "all_rows_rejected",
        stream: "conversations",
        sourceRows: 1,
        dropped: 1,
      });
    });
  });
});
