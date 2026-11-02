import { describe, expect, it } from "vitest";
import { createMemoryRecordStore } from "./memory-store.js";
import { fromSyncRecordStore } from "./read-port.js";
import {
  createSourceStreamDeclarationRegistry,
  type StreamDeclaration,
} from "./stream-declaration.js";
import type { ListRecordsOptions, ListRecordsPage } from "./types.js";

const stream = "messages";
const instanceIds = ["inst_1", "inst_2"];
const declaration: StreamDeclaration = {
  name: stream,
  semantics: "mutable_state",
  primaryKey: ["id"],
  cursorField: "emitted_at",
  requiredFields: ["id"],
};

function fixture() {
  const store = createMemoryRecordStore();
  const registry = createSourceStreamDeclarationRegistry([
    { sourceId: "source_1", instance: "inst_1", streams: [declaration] },
    {
      sourceId: "source_2",
      instance: "inst_2",
      streams: [{ ...declaration, requiredFields: ["id", "content"] }],
    },
  ]);
  const result = store.ingestBatch(
    ["d", "b", "e", "a", "c"].map((key, index) => ({
      instance: index % 2 === 0 ? "inst_1" : "inst_2",
      stream,
      key,
      data: { id: key, content: key.toUpperCase() },
      emitted_at: "2026-04-01T00:00:00.000Z",
    })),
    () => "mutable_state",
    () => ["id"],
  );
  expect(result.accepted).toBe(5);
  expect(result.rejected).toEqual([]);
  return {
    store,
    registry,
    port: fromSyncRecordStore({ ...store, forInstance: registry.forInstance }),
  };
}

describe("fromSyncRecordStore", () => {
  for (const order of ["asc", "desc"] as const) {
    for (const fields of [undefined, ["id"]]) {
      it(`preserves complete ${order} pages with fields=${String(fields)}`, async () => {
        const { store, port } = fixture();
        const options: ListRecordsOptions = {
          instanceIds,
          order,
          limit: 2,
          ...(fields === undefined ? {} : { fields }),
        };
        const syncPages: ListRecordsPage[] = [];
        const asyncPages: ListRecordsPage[] = [];
        let syncCursor: string | undefined;
        let asyncCursor: string | undefined;

        // A bound makes a non-terminating adapter fail instead of hanging.
        for (let index = 0; index < 10; index += 1) {
          const expected = store.listRecords(stream, {
            ...options,
            ...(syncCursor === undefined ? {} : { cursor: syncCursor }),
          });
          const actual = await port.listRecords(stream, {
            ...options,
            ...(asyncCursor === undefined ? {} : { cursor: asyncCursor }),
          });
          syncPages.push(expected);
          asyncPages.push(actual);
          expect(actual).toEqual(expected);
          expect(JSON.stringify(actual)).toBe(JSON.stringify(expected));
          if (!expected.hasMore && !actual.hasMore) break;
          expect(actual.nextCursor).toBeDefined();
          expect(actual.nextCursor).not.toBe(asyncCursor);
          syncCursor = expected.nextCursor;
          asyncCursor = actual.nextCursor;
        }

        expect(asyncPages).toEqual(syncPages);
        expect(asyncPages).toHaveLength(3);
        expect(asyncPages.map((page) => page.data.length)).toEqual([2, 2, 1]);
        expect(asyncPages[2]?.hasMore).toBe(false);
        expect(asyncPages[2]?.nextCursor).toBeUndefined();
        const keys = asyncPages.flatMap((page) =>
          page.data.map((record) => record.recordKey),
        );
        expect(keys).toEqual(
          order === "asc"
            ? ["a", "b", "c", "d", "e"]
            : ["e", "d", "c", "b", "a"],
        );
        expect(new Set(keys).size).toBe(5);
      });
    }
  }

  it("preserves empty pages and instance filtering", async () => {
    const { store, port } = fixture();
    for (const ids of [[], ["inst_1"], ["unknown"]]) {
      const options: ListRecordsOptions = {
        instanceIds: ids,
        order: "asc",
        limit: 10,
      };
      expect(await port.listRecords(stream, options)).toEqual(
        store.listRecords(stream, options),
      );
    }
  });

  it("preserves getRecord results, missing records, and deleted records", async () => {
    const { store, port } = fixture();
    for (const [instance, key] of [
      ["inst_1", "d"],
      ["inst_2", "b"],
      ["inst_1", "missing"],
      ["inst_2", "d"],
    ] as const) {
      expect(await port.getRecord(instance, stream, key)).toBe(
        store.getRecord(instance, stream, key),
      );
    }
    expect(await port.getRecord("inst_1", stream, "missing")).toBeUndefined();
    store.deleteRecord(
      "inst_1",
      stream,
      "d",
      "2026-04-02T00:00:00.000Z",
      "mutable_state",
    );
    expect(await port.getRecord("inst_1", stream, "d")).toBeUndefined();
  });

  it("preserves stream listings", async () => {
    const { store, port } = fixture();
    for (const ids of [instanceIds, ["inst_1"], [], ["unknown"]]) {
      expect(await port.listStreams(ids)).toEqual(store.listStreams(ids));
    }
  });

  it("looks up declarations by instance without confusing argument order", async () => {
    const { registry, port } = fixture();
    for (const instance of [...instanceIds, "unknown"]) {
      expect(await port.getStreamDeclaration(stream, instance)).toBe(
        registry.forInstance(instance, stream),
      );
    }
    expect(await port.getStreamDeclaration(stream, "inst_1")).toBe(declaration);
    expect(
      await port.getStreamDeclaration("unknown", "inst_1"),
    ).toBeUndefined();
    expect(await port.getStreamDeclaration(stream, "unknown")).toBeUndefined();
  });

  it("preserves the receiver and turns each sync throw into a rejection", async () => {
    const error = new Error("sync read failed");
    const source = {
      fail(): never {
        throw error;
      },
      listRecords(): never {
        return this.fail();
      },
      getRecord(): never {
        return this.fail();
      },
      listStreams(): never {
        return this.fail();
      },
      forInstance(): never {
        return this.fail();
      },
    };
    const port = fromSyncRecordStore(source);
    const calls = [
      () => port.listRecords(stream, { instanceIds, limit: 2, order: "asc" }),
      () => port.getRecord("inst_1", stream, "d"),
      () => port.listStreams(instanceIds),
      () => port.getStreamDeclaration(stream, "inst_1"),
    ];
    for (const call of calls) {
      // A synchronous throw here fails the test before .rejects is reached.
      const promise = call();
      expect(promise).toBeInstanceOf(Promise);
      await expect(promise).rejects.toBe(error);
    }
  });
});
