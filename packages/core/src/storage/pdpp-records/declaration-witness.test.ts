import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  DeclarationWitnessCursorError,
  DeclarationWitnessInputError,
  DeclarationWitnessReadError,
  DeclarationWitnessSchemaError,
  witnessDeclarationUpgrade,
} from "./index.js";
import { createMemoryRecordStore } from "./memory-store.js";
import { fromSyncRecordStore } from "./read-port.js";
import { createRecordDataValidator } from "./schema.js";
import { createStreamDeclarationRegistry } from "./stream-declaration.js";
import type { PdppRecordEnvelopeInput } from "./types.js";

const sourceKey = "claude-account-1";
const stream = "messages";
const nextSchema = {
  type: "object",
  properties: {
    id: { type: "string" },
    model_source: { type: ["string", "null"] },
  },
  required: ["id"],
};

function fixture() {
  const store = createMemoryRecordStore();
  const readPort = fromSyncRecordStore({
    ...store,
    forInstance: () => undefined,
  });
  const list = vi.spyOn(readPort, "listRecords");
  function insert(
    key: string,
    data: Record<string, unknown> = {},
    instance = sourceKey,
    rowStream = stream,
  ) {
    const input: PdppRecordEnvelopeInput = {
      instance,
      stream: rowStream,
      key,
      data: { id: key, ...data },
      emitted_at: "2026-04-01T00:00:00.000Z",
    };
    expect(
      store.ingestBatch(
        [input],
        () => "mutable_state",
        () => ["id"],
      ).accepted,
    ).toBe(1);
  }
  const run = (
    overrides: Partial<Parameters<typeof witnessDeclarationUpgrade>[0]> = {},
  ) =>
    witnessDeclarationUpgrade({
      readPort,
      sourceKey,
      stream,
      nextSchema,
      limit: 2,
      ...overrides,
    });
  return { store, readPort, list, insert, run };
}

describe("witnessDeclarationUpgrade", () => {
  it("passes only at the verified end of multiple bounded pages", async () => {
    const { insert, run, list } = fixture();
    insert("a");
    insert("b", { model_source: null });
    insert("c", { model_source: "claude" });
    insert("d");
    insert("e");
    const first = await run();
    expect(first).toEqual({
      verdict: "partial",
      checked: 2,
      nextCursor: expect.any(String),
    });
    const second = await run({ cursor: first.nextCursor! });
    expect(second).toEqual({
      verdict: "partial",
      checked: 2,
      nextCursor: expect.any(String),
    });
    const third = await run({ cursor: second.nextCursor! });
    expect(third).toEqual({ verdict: "pass", checked: 1, nextCursor: null });
    expect(list).toHaveBeenCalledTimes(3);
    for (const [requestedStream, options] of list.mock.calls) {
      expect(requestedStream).toBe(stream);
      expect(options).toMatchObject({
        instanceIds: [sourceKey],
        order: "asc",
        limit: 2,
      });
      expect(options.fields).toBeUndefined();
    }
    const seen = await Promise.all(
      list.mock.results.map((result) => result.value),
    );
    expect(
      seen.flatMap((page) =>
        page.data.map((row: { recordKey: string }) => row.recordKey),
      ),
    ).toEqual(["a", "b", "c", "d", "e"]);
  });

  it("resumes a partial page at the next row and permits a different positive limit", async () => {
    const { insert, run } = fixture();
    insert("a");
    insert("b");
    insert("c", { model_source: 42 });
    const first = await run({ limit: 1 });
    expect(first.verdict).toBe("partial");
    const resumed = await run({ cursor: first.nextCursor!, limit: 2 });
    expect(resumed).toEqual({
      verdict: "fail",
      checked: 2,
      nextCursor: null,
      failure: {
        recordKeyDigest: createHash("sha256").update("c").digest("hex"),
        instancePath: "/model_source",
        keyword: "type",
      },
    });
  });

  it("fails at the first invalid row without returning or logging record values", async () => {
    const { insert, run } = fixture();
    insert("a");
    insert("private-record-key", { model_source: 42, secret: "private-value" });
    insert("z", { model_source: 43 });
    const log = vi.spyOn(console, "log");
    const warn = vi.spyOn(console, "warn");
    const error = vi.spyOn(console, "error");
    try {
      const result = await run({ limit: 3 });
      expect(result).toEqual({
        verdict: "fail",
        checked: 2,
        nextCursor: null,
        failure: {
          recordKeyDigest: createHash("sha256")
            .update("private-record-key")
            .digest("hex"),
          instancePath: "/model_source",
          keyword: "type",
        },
      });
      expect(JSON.stringify(result)).not.toContain("private-record-key");
      expect(JSON.stringify(result)).not.toContain("private-value");
      expect(log).not.toHaveBeenCalled();
      expect(warn).not.toHaveBeenCalled();
      expect(error).not.toHaveBeenCalled();
    } finally {
      log.mockRestore();
      warn.mockRestore();
      error.mockRestore();
    }
  });

  it("redacts data-derived JSON pointer segments and keeps the root pointer empty", async () => {
    const { insert, run } = fixture();
    insert("a", { contacts: { "private@example.com": 42 } });
    const result = await run({
      nextSchema: {
        type: "object",
        properties: {
          contacts: {
            type: "object",
            additionalProperties: { type: "string" },
          },
        },
      },
    });
    expect(result.failure?.instancePath).toBe("/contacts/*");
    expect(JSON.stringify(result)).not.toContain("private@example.com");
    const root = await run({ nextSchema: { type: "array" } });
    expect(root.failure?.instancePath).toBe("");
  });

  it("passes an empty stream", async () => {
    const { run } = fixture();
    expect(await run()).toEqual({
      verdict: "pass",
      checked: 0,
      nextCursor: null,
    });
  });

  it("skips tombstones and deleted rows and never requests other streams or sources", async () => {
    const { store, insert, run, list } = fixture();
    insert("a");
    insert("bad-deleted", { model_source: 42 });
    expect(
      store.deleteRecord(
        sourceKey,
        stream,
        "bad-deleted",
        "2026-04-02T00:00:00.000Z",
        "mutable_state",
      ),
    ).toBe(true);
    insert("bad-other-source", { model_source: 42 }, "other-source");
    insert("bad-other-stream", { model_source: 42 }, sourceKey, "other-stream");
    expect(await run()).toEqual({
      verdict: "pass",
      checked: 1,
      nextCursor: null,
    });
    expect(list).toHaveBeenCalledOnce();
    expect(list).toHaveBeenCalledWith(stream, {
      instanceIds: [sourceKey],
      limit: 2,
      order: "asc",
    });
  });

  for (const schema of [
    { type: "invalid-type" },
    { $schema: "http://json-schema.org/draft-07/schema#", type: "object" },
    { $ref: "https://example.invalid/remote-schema" },
  ]) {
    it(`rejects a schema rejected by the write validator: ${JSON.stringify(schema)}`, async () => {
      const registry = createStreamDeclarationRegistry([
        {
          name: stream,
          semantics: "mutable_state",
          primaryKey: ["id"],
          cursorField: "emitted_at",
          requiredFields: ["id"],
          schema,
        },
      ]);
      expect(() => createRecordDataValidator(registry)).toThrow();
      const { run, list } = fixture();
      await expect(run({ nextSchema: schema })).rejects.toBeInstanceOf(
        DeclarationWitnessSchemaError,
      );
      expect(list).not.toHaveBeenCalled();
    });
  }

  it("uses the write validator's 2020-12, local reference, format and annotation behavior", async () => {
    const { insert, run } = fixture();
    insert("a", { tuple: ["ok", null], model_source: "not-an-email" });
    const schema = {
      type: "object",
      properties: {
        tuple: {
          type: "array",
          prefixItems: [{ type: "string" }, { type: "null" }],
          items: false,
        },
        model_source: { $ref: "#/$defs/model" },
      },
      $defs: {
        model: { type: "string", format: "email", customAnnotation: true },
      },
    };
    expect((await run({ nextSchema: schema })).verdict).toBe("pass");
  });

  it("rejects asynchronous schemas rather than treating a promise as a pass", async () => {
    const { run, list } = fixture();
    await expect(
      run({ nextSchema: { $async: true, type: "object" } }),
    ).rejects.toBeInstanceOf(DeclarationWitnessSchemaError);
    expect(list).not.toHaveBeenCalled();
  });

  it("fails closed on unknown, truncated and syntactically valid tampered cursors", async () => {
    const { insert, run, list, store } = fixture();
    insert("a");
    insert("b");
    const first = await run({ limit: 1 });
    const token = first.nextCursor!;
    const raw = store.listRecords(stream, {
      instanceIds: [sourceKey],
      limit: 1,
      order: "asc",
    }).nextCursor!;
    const changed =
      token.slice(0, -2) + (token.at(-2) === "A" ? "B" : "A") + token.slice(-1);
    list.mockClear();
    for (const cursor of ["", "unknown", token.slice(0, -1), changed, raw]) {
      await expect(run({ cursor })).rejects.toBeInstanceOf(
        DeclarationWitnessCursorError,
      );
    }
    expect(list).not.toHaveBeenCalled();
  });

  it("binds a continuation to its source, stream, schema and read-port identity", async () => {
    const { insert, run, list } = fixture();
    insert("a");
    insert("b");
    const { nextCursor } = await run({ limit: 1 });
    list.mockClear();
    for (const changed of [
      { sourceKey: "other-source" },
      { stream: "other-stream" },
      { nextSchema: { type: "object" } },
      { readPort: fixture().readPort },
    ]) {
      await expect(
        run({ cursor: nextCursor!, ...changed }),
      ).rejects.toBeInstanceOf(DeclarationWitnessCursorError);
    }
    expect(list).not.toHaveBeenCalled();
  });

  for (const limit of [
    0,
    -1,
    1.5,
    NaN,
    Infinity,
    Number.MAX_SAFE_INTEGER + 1,
  ]) {
    it(`rejects invalid limit ${limit} before reading`, async () => {
      const { run, list } = fixture();
      await expect(run({ limit })).rejects.toBeInstanceOf(
        DeclarationWitnessInputError,
      );
      expect(list).not.toHaveBeenCalled();
    });
  }

  it("fails closed instead of passing an incomplete or oversized page", async () => {
    const { insert, run, list } = fixture();
    insert("a");
    list.mockResolvedValueOnce({ data: [], hasMore: true });
    await expect(run()).rejects.toBeInstanceOf(DeclarationWitnessReadError);
    list.mockResolvedValueOnce({
      data: [],
      hasMore: undefined as unknown as boolean,
    });
    await expect(run()).rejects.toBeInstanceOf(DeclarationWitnessReadError);
    const row = {
      instance: sourceKey,
      stream,
      recordKey: "a",
      data: { id: "a" },
      version: 1,
      emittedAt: "2026-04-01T00:00:00.000Z",
      deleted: false as const,
    };
    list.mockResolvedValueOnce({ data: [row, row], hasMore: false });
    await expect(run({ limit: 1 })).rejects.toBeInstanceOf(
      DeclarationWitnessReadError,
    );
    list.mockResolvedValueOnce({
      data: [{ ...row, instance: "wrong-source" }],
      hasMore: false,
    });
    await expect(run()).rejects.toBeInstanceOf(DeclarationWitnessReadError);
  });
});
