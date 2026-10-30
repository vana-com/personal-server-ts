import { describe, expect, it } from "vitest";
import {
  binding,
  identity,
  registration,
  upsert,
} from "@opendatalabs/personal-server-ts-core/replication/fixtures";
import type { ReplicaOperation } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  createLiteCanonicalStore,
  type LiteOperationDraft,
} from "./canonical-store.js";
import {
  createFakeCanonicalPersistence,
  fakeCanonicalDisk,
  storagePage,
} from "./test-support/canonical-persistence.js";
import {
  createLiteCanonicalImportEncoder,
  encodeLiveSnapshotDigestInput,
  LITE_IMPORT_READ_MANY_MAX,
  planIngest,
  type ImportStagedOperation,
  type LiteCanonicalReadView,
} from "./import-job.js";

const context = () => ({
  owner: identity.owner,
  declarations: [
    { sourceId: identity.sourceId, binding, validateData: () => true },
  ],
});
const ids = (prefix: string) => {
  let n = 0;
  return () => `${prefix}-${n++}`;
};
const draft = (op: ReplicaOperation): LiteOperationDraft => {
  const { revision: _, ...value } = op;
  return value;
};

/** A provisioned, registered connection: the state an import starts from. */
async function registeredDisk() {
  const disk = fakeCanonicalDisk();
  const store = createLiteCanonicalStore({
    persistence: createFakeCanonicalPersistence(disk).port,
    enabled: true,
    context,
    authenticateReplica: () => undefined,
    newId: ids("setup"),
  });
  await store.provisionConnection(identity.connectionId, {
    sourceId: identity.sourceId,
    methodId: identity.methodId,
  });
  await store.commitLocal("register", [draft(registration)]);
  return disk;
}

function viewOf(rows: Map<string, string>): LiteCanonicalReadView {
  return {
    get: async (key) => rows.get(key),
    scan: async (prefix, after) =>
      storagePage(
        [...rows]
          .filter(([key]) => key.startsWith(prefix))
          .map(([key, value]) => ({ key, value })),
        after,
      ),
  };
}

/** About 300 KiB of mixed operations: re-upserts, an unchanged repeat, deletes, non-ASCII. */
function importOperations(): ImportStagedOperation[] {
  const operations: ImportStagedOperation[] = [];
  const add = (key: string, data: Record<string, unknown> | null) =>
    operations.push({
      order: operations.length,
      stream: binding.stream,
      recordKey: key,
      keyJson: JSON.stringify(key),
      op: data ? "upsert" : "delete",
      dataJson: data ? JSON.stringify(data) : null,
      emittedAt: `2026-10-28T00:00:${String(operations.length % 60).padStart(2, "0")}Z`,
      keep: "last",
      digest: "0".repeat(64),
    });
  for (let i = 0; i < 260; i++)
    add(`m${i}`, { id: `m${i}`, text: `こんにちは ${i} ${"·".repeat(400)}` });
  add("m1", { id: "m1", text: "edited 👋" });
  add("m2", { id: "m2", text: `こんにちは 2 ${"·".repeat(400)}` });
  for (let i = 10; i < 40; i++) add(`m${i}`, null);
  add("absent", null);
  return operations;
}

/** `operation` with a text field of about `chars` UTF-8 bytes. */
const large = (operation: ImportStagedOperation, chars: number) => ({
  ...operation,
  dataJson: JSON.stringify({
    id: operation.recordKey,
    text: "é·x".repeat(Math.ceil(chars / 5)),
  }),
});

/** A view over `rows` that counts its calls; optionally with the batched reads. */
function countingView(
  rows: Map<string, string>,
  options: { batched?: boolean; answer?: number } = {},
) {
  const calls = { get: 0, scan: 0, getMany: 0, scanMany: 0 };
  const page = (prefix: string, after?: string) =>
    storagePage(
      [...rows]
        .filter(([key]) => key.startsWith(prefix))
        .map(([key, value]) => ({ key, value })),
      after,
    );
  // A host may answer a leading part of a batched read.
  const leading = <T>(items: T[]) => items.slice(0, options.answer);
  const view: LiteCanonicalReadView = {
    get: async (key) => (calls.get++, rows.get(key)),
    scan: async (prefix, after) => (calls.scan++, page(prefix, after)),
    ...(options.batched
      ? {
          getMany: async (keys: string[]) => {
            calls.getMany++;
            expect(keys.length).toBeLessThanOrEqual(LITE_IMPORT_READ_MANY_MAX);
            return leading(keys).map((key) => rows.get(key));
          },
          scanMany: async (scans: { prefix: string; after?: string }[]) => {
            calls.scanMany++;
            expect(scans.length).toBeLessThanOrEqual(LITE_IMPORT_READ_MANY_MAX);
            return leading(scans).map((scan) => page(scan.prefix, scan.after));
          },
        }
      : {}),
  };
  return { view, calls };
}

const importJob = {
  jobId: "job-1",
  binding: {
    owner: identity.owner,
    instance: identity.connectionId,
    sourceId: identity.sourceId,
    method: identity.methodId,
    generation: identity.generation,
  },
};

/** Three batches: new records, then edits and deletes of earlier ones. */
function importBatches(): ImportStagedOperation[][] {
  const all = importOperations();
  const edits = all.slice(0, 120).map((operation, i) => ({
    ...operation,
    dataJson:
      i % 3 === 0
        ? operation.dataJson
        : JSON.stringify({ id: operation.recordKey, text: `edit ${i}` }),
  }));
  return [all.slice(0, 150), all.slice(150), edits];
}

/** Applies a batch's entries the way a native staged copy does. */
function applyEntries(
  rows: Map<string, string>,
  entries: { key: string; value: string | null }[],
) {
  for (const entry of entries)
    if (entry.value === null) rows.delete(entry.key);
    else rows.set(entry.key, entry.value);
}

describe("Lite canonical import encoder", () => {
  it("re-exports the shared rules a native copy must not re-implement", () => {
    expect(typeof planIngest).toBe("function");
    expect(typeof encodeLiveSnapshotDigestInput).toBe("function");
  });

  it("encodes an import batch to the exact entries commitLocal writes", async () => {
    const before = await registeredDisk();
    const job = {
      jobId: "job-1",
      binding: {
        owner: identity.owner,
        instance: identity.connectionId,
        sourceId: identity.sourceId,
        method: identity.methodId,
        generation: identity.generation,
      },
    };
    const encoder = createLiteCanonicalImportEncoder({
      context,
      newId: ids("op"),
    });
    const parts = encoder.importBatchParts({
      job,
      seq: 0,
      operations: importOperations(),
      bindingFor: (stream) => (stream === binding.stream ? binding : undefined),
    });
    expect(parts.length).toBeGreaterThan(1);

    // The existing Lite write path.
    const written = { rows: new Map(before.rows), blobs: new Map() };
    const store = createLiteCanonicalStore({
      persistence: createFakeCanonicalPersistence(written).port,
      enabled: true,
      context,
      authenticateReplica: () => undefined,
      newId: ids("op"),
    });
    const receipts = [];
    for (const part of parts)
      receipts.push(await store.commitLocal(part.id, part.operations));

    // The encoder over the same starting state, applied as a native copy would.
    const base = new Map(before.rows);
    const encoded = await encoder.encode(viewOf(base), parts);
    const copied = new Map(base);
    for (const entry of encoded.entries)
      if (entry.value === null) copied.delete(entry.key);
      else copied.set(entry.key, entry.value);

    expect(encoded.parts.map((part) => part.receipt)).toEqual(receipts);
    expect([...copied].sort()).toEqual([...written.rows].sort());
    expect(base).toEqual(before.rows);
    const keys = encoded.entries.map((entry) => entry.key);
    for (const prefix of ["rows/", "log/"])
      expect(keys.some((key) => key.startsWith(prefix))).toBe(true);
    // Log entries point at the retained operation; they carry no record bytes.
    for (const entry of encoded.entries.filter((e) => e.key.startsWith("log/")))
      expect(Object.keys(JSON.parse(entry.value!)).sort()).toEqual([
        "batchId",
        "operationKey",
        "rowVersion",
        "sequence",
      ]);
  });

  it.each([
    { name: "whole answers", answer: undefined },
    { name: "one item per batched answer", answer: 1 },
  ])(
    "encodes consecutive batches with batched reads, byte-identical to commitLocal ($name)",
    async ({ answer }) => {
      const before = await registeredDisk();
      const batches = importBatches();
      const bindingFor = () => binding;

      // The existing Lite write path, every part of every batch in order.
      const written = { rows: new Map(before.rows), blobs: new Map() };
      const store = createLiteCanonicalStore({
        persistence: createFakeCanonicalPersistence(written).port,
        enabled: true,
        context,
        authenticateReplica: () => undefined,
        newId: ids("op"),
      });
      const encoder = createLiteCanonicalImportEncoder({
        context,
        newId: ids("op"),
      });
      const plain = createLiteCanonicalImportEncoder({
        context,
        newId: ids("op"),
      });
      const staged = new Map(before.rows);
      const plainStaged = new Map(before.rows);
      const batchedCalls = { get: 0, scan: 0, getMany: 0, scanMany: 0 };
      let plainCalls = 0;
      for (const [seq, operations] of batches.entries()) {
        const parts = encoder.importBatchParts({
          job: importJob,
          seq,
          operations,
          bindingFor,
        });
        const receipts = [];
        for (const part of parts)
          receipts.push(await store.commitLocal(part.id, part.operations));

        const batched = countingView(staged, { batched: true, answer });
        const encoded = await encoder.encode(batched.view, parts);
        expect(encoded.parts.map((part) => part.receipt)).toEqual(receipts);
        applyEntries(staged, encoded.entries);
        for (const key of Object.keys(
          batchedCalls,
        ) as (keyof typeof batchedCalls)[])
          batchedCalls[key] += batched.calls[key];

        const reference = countingView(plainStaged);
        applyEntries(
          plainStaged,
          (await plain.encode(reference.view, parts)).entries,
        );
        plainCalls += reference.calls.get + reference.calls.scan;
      }
      expect([...staged].sort()).toEqual([...written.rows].sort());
      expect([...plainStaged].sort()).toEqual([...written.rows].sort());
      // Reads go through the batched ops, not one call per key.
      expect(batchedCalls.get + batchedCalls.scan).toBe(0);
      if (answer === undefined)
        expect(batchedCalls.getMany + batchedCalls.scanMany).toBeLessThan(
          plainCalls / 20,
        );
    },
  );

  it("re-encodes over the true answers when a canonical write lands between batches", async () => {
    const before = await registeredDisk();
    const [first, second] = importBatches();
    const bindingFor = () => binding;
    const written = { rows: new Map(before.rows), blobs: new Map() };
    const store = createLiteCanonicalStore({
      persistence: createFakeCanonicalPersistence(written).port,
      enabled: true,
      context,
      authenticateReplica: () => undefined,
      newId: ids("op"),
    });
    const other = (disk: { rows: Map<string, string> }) =>
      createLiteCanonicalStore({
        persistence: createFakeCanonicalPersistence({
          rows: disk.rows,
          blobs: new Map(),
        }).port,
        enabled: true,
        context,
        authenticateReplica: () => undefined,
        newId: ids("other"),
      });
    // A live write of a record the second batch also writes, plus a new one.
    const intervening = [
      draft(upsert("other-op", 1, "written meanwhile")),
      draft({
        ...upsert("other-m200", 2),
        recordKey: "m200",
        data: { id: "m200", text: "live m200" },
      }),
    ];
    const encoder = createLiteCanonicalImportEncoder({
      context,
      newId: ids("op"),
    });
    const staged = new Map(before.rows);
    for (const [seq, operations] of [first, second].entries()) {
      if (seq === 1) {
        await other(written).commitLocal("live", intervening);
        await other({ rows: staged }).commitLocal("live", intervening);
      }
      const parts = encoder.importBatchParts({
        job: importJob,
        seq,
        operations,
        bindingFor,
      });
      const receipts = [];
      for (const part of parts)
        receipts.push(await store.commitLocal(part.id, part.operations));
      const encoded = await encoder.encode(
        countingView(staged, { batched: true }).view,
        parts,
      );
      expect(encoded.parts.map((part) => part.receipt)).toEqual(receipts);
      expect(encoded.fence.value).toBe(staged.get("clock"));
      applyEntries(staged, encoded.entries);
    }
    expect([...staged].sort()).toEqual([...written.rows].sort());
  });

  it("pages a prefix the batch itself filled past one page, as commitLocal does", async () => {
    const before = await registeredDisk();
    // Many versions of one record keep its revision prefix over 100 entries.
    const operations = Array.from({ length: 105 }, (_, i) => ({
      ...importOperations()[0]!,
      order: i,
      dataJson: JSON.stringify({ id: "m0", text: `version ${i}` }),
    }));
    const written = { rows: new Map(before.rows), blobs: new Map() };
    const store = createLiteCanonicalStore({
      persistence: createFakeCanonicalPersistence(written).port,
      enabled: true,
      context,
      authenticateReplica: () => undefined,
      newId: ids("op"),
    });
    const encoder = createLiteCanonicalImportEncoder({
      context,
      newId: ids("op"),
    });
    const staged = new Map(before.rows);
    {
      const parts = encoder.importBatchParts({
        job: importJob,
        seq: 0,
        operations,
        bindingFor: () => binding,
      });
      const receipts = [];
      for (const part of parts)
        receipts.push(await store.commitLocal(part.id, part.operations));
      const encoded = await encoder.encode(
        countingView(staged, { batched: true }).view,
        parts,
      );
      expect(encoded.parts.map((part) => part.receipt)).toEqual(receipts);
      applyEntries(staged, encoded.entries);
      // The record's revision prefix outgrew one 100-entry page.
      const revisions = encoded.entries.filter((entry) =>
        /^entries\/[^/]+\/records\//.test(entry.key),
      );
      expect(revisions.length).toBeGreaterThan(100);
    }
    expect([...staged].sort()).toEqual([...written.rows].sort());
  });

  it("fences the batch on the clock it encoded against", async () => {
    const before = await registeredDisk();
    const job = {
      jobId: "job-1",
      binding: {
        owner: identity.owner,
        instance: identity.connectionId,
        sourceId: identity.sourceId,
        method: identity.methodId,
        generation: identity.generation,
      },
    };
    const encoder = createLiteCanonicalImportEncoder({
      context,
      newId: ids("op"),
    });
    const parts = encoder.importBatchParts({
      job,
      seq: 0,
      operations: importOperations().slice(0, 5),
      bindingFor: () => binding,
    });
    const encoded = await encoder.encode(viewOf(before.rows), parts);
    expect(encoded.fence).toEqual({
      key: "clock",
      value: before.rows.get("clock"),
    });
    // Any canonical commit before publication moves the clock, so a native
    // copy that compares it refuses the stale entries.
    const store = createLiteCanonicalStore({
      persistence: createFakeCanonicalPersistence(before).port,
      enabled: true,
      context,
      authenticateReplica: () => undefined,
      newId: ids("other"),
    });
    await store.commitLocal("intervening", [
      draft(upsert("other-op", 1, "written meanwhile")),
    ]);
    expect(before.rows.get("clock")).not.toBe(encoded.fence.value);
  });

  it("bounds what it carries between batches when one key changes in every batch", async () => {
    const before = await registeredDisk();
    const written = { rows: new Map(before.rows), blobs: new Map() };
    const store = createLiteCanonicalStore({
      persistence: createFakeCanonicalPersistence(written).port,
      enabled: true,
      context,
      authenticateReplica: () => undefined,
      newId: ids("op"),
    });
    const limit = 32 * 1024;
    const bounded = createLiteCanonicalImportEncoder({
      context,
      newId: ids("op"),
      carryUnits: limit,
    });
    const unbounded = createLiteCanonicalImportEncoder({
      context,
      newId: ids("op"),
    });
    const stagedBounded = new Map(before.rows);
    const stagedUnbounded = new Map(before.rows);
    const [mutable, ...others] = importOperations();
    const carried: number[] = [];
    for (let seq = 0; seq < 40; seq++) {
      const parts = bounded.importBatchParts({
        job: importJob,
        seq,
        operations: [
          {
            ...mutable!,
            dataJson: JSON.stringify({
              id: mutable!.recordKey,
              text: `${seq} ${"·".repeat(2_000)}`,
            }),
          },
          ...others.slice(seq * 5, seq * 5 + 5),
        ],
        bindingFor: () => binding,
      });
      const receipts = [];
      for (const part of parts)
        receipts.push(await store.commitLocal(part.id, part.operations));
      for (const [encoder, staged] of [
        [bounded, stagedBounded],
        [unbounded, stagedUnbounded],
      ] as const) {
        const encoded = await encoder.encode(
          countingView(staged, { batched: true }).view,
          parts,
        );
        expect(encoded.parts.map((part) => part.receipt)).toEqual(receipts);
        applyEntries(staged, encoded.entries);
      }
      expect(bounded.carriedUnits()).toBeLessThanOrEqual(limit);
      carried.push(unbounded.carriedUnits());
    }
    // The key's retained variants make every batch read more; the cap holds.
    expect(carried.at(-1)!).toBeGreaterThan(2 * limit);
    expect(carried.at(-1)!).toBeGreaterThan(carried[4]! + 60_000);
    expect([...stagedBounded].sort()).toEqual([...written.rows].sort());
    expect([...stagedUnbounded].sort()).toEqual([...written.rows].sort());
  });

  it("puts an operation over 192 KiB alone in its own part", () => {
    const encoder = createLiteCanonicalImportEncoder({ context });
    const [a, b, c] = importOperations();
    const parts = encoder.importBatchParts({
      job: importJob,
      seq: 0,
      operations: [a!, large(b!, 300_000), c!],
      bindingFor: () => binding,
    });
    expect(
      parts.map((part) => part.operations.map((op) => op.recordKey)),
    ).toEqual([["m0"], ["m1"], ["m2"]]);
  });

  it("refuses an operation over the 17 MiB a canonical part can hold", () => {
    const encoder = createLiteCanonicalImportEncoder({ context });
    expect(() =>
      encoder.importBatchParts({
        job: importJob,
        seq: 0,
        operations: [large(importOperations()[0]!, 17 * 1024 * 1024)],
        bindingFor: () => binding,
      }),
    ).toThrow(expect.objectContaining({ code: "record_too_large" }));
  });

  it.each([{ batched: true }, { batched: false }])(
    "encodes records over 192 KiB and 512 KiB byte-identical to commitLocal (batched $batched)",
    async ({ batched }) => {
      const before = await registeredDisk();
      const small = importOperations().slice(0, 6);
      const batches = [
        [
          small[0]!,
          large(small[1]!, 300_000),
          small[2]!,
          large(small[3]!, 700_000),
          small[4]!,
        ],
        // Edit both large records (one grows, one shrinks) and add one.
        [large(small[3]!, 900_000), small[1]!, small[5]!],
      ];
      const written = { rows: new Map(before.rows), blobs: new Map() };
      const store = createLiteCanonicalStore({
        persistence: createFakeCanonicalPersistence(written).port,
        enabled: true,
        context,
        authenticateReplica: () => undefined,
        newId: ids("op"),
      });
      const encoder = createLiteCanonicalImportEncoder({
        context,
        newId: ids("op"),
      });
      const staged = new Map(before.rows);
      let operations = 0;
      for (const [seq, batch] of batches.entries()) {
        const parts = encoder.importBatchParts({
          job: importJob,
          seq,
          operations: batch,
          bindingFor: () => binding,
        });
        const receipts = [];
        for (const part of parts)
          receipts.push(await store.commitLocal(part.id, part.operations));
        const encoded = await encoder.encode(
          countingView(staged, { batched }).view,
          parts,
        );
        expect(encoded.parts.map((part) => part.receipt)).toEqual(receipts);
        applyEntries(staged, encoded.entries);
        operations += batch.length;
      }
      expect([...staged].sort()).toEqual([...written.rows].sort());
      const sizes = [...staged.values()].map(
        (value) => new TextEncoder().encode(value).byteLength,
      );
      expect(sizes.filter((size) => size > 512 * 1024).length).toBeGreaterThan(
        0,
      );

      // The outbox pages past each large operation instead of stalling on it.
      const reader = createLiteCanonicalStore({
        persistence: createFakeCanonicalPersistence({
          rows: staged,
          blobs: new Map(),
        }).port,
        enabled: true,
        context,
        authenticateReplica: () => undefined,
      });
      const sequences: number[] = [];
      for (let after = 0, pages = 0; pages < 50; pages++) {
        const page = await reader.readOutboxPage(after);
        sequences.push(...page.entries.map((entry) => entry.sequence));
        if (!page.hasMore) break;
        after = page.nextAfterSequence;
      }
      // The registration plus every imported operation, in order.
      expect(sequences).toEqual(
        Array.from({ length: operations + 1 }, (_, i) => i + 1),
      );
    },
  );

  it("encodes an 8.5 MiB record byte-identically to commitLocal and reads it back", async () => {
    const before = await registeredDisk();
    const operation = large(importOperations()[0]!, 8_500_000);
    const encoder = createLiteCanonicalImportEncoder({
      context,
      newId: ids("op"),
    });
    const parts = encoder.importBatchParts({
      job: importJob,
      seq: 0,
      operations: [operation],
      bindingFor: () => binding,
    });
    expect(parts).toHaveLength(1);

    const written = { rows: new Map(before.rows), blobs: new Map() };
    const store = createLiteCanonicalStore({
      persistence: createFakeCanonicalPersistence(written).port,
      enabled: true,
      context,
      authenticateReplica: () => undefined,
      newId: ids("op"),
    });
    const receipts = [];
    for (const part of parts)
      receipts.push(await store.commitLocal(part.id, part.operations));

    const base = new Map(before.rows);
    const encoded = await encoder.encode(viewOf(base), parts);
    const copied = new Map(base);
    for (const entry of encoded.entries)
      if (entry.value === null) copied.delete(entry.key);
      else copied.set(entry.key, entry.value);

    // Exact key/value equality includes the operation digest path and row.
    expect(encoded.parts.map((part) => part.receipt)).toEqual(receipts);
    expect([...copied].sort()).toEqual([...written.rows].sort());
    expect(
      (
        await store.readRecord(
          identity.connectionId,
          binding.stream,
          operation.recordKey,
        )
      )?.data,
    ).toEqual(JSON.parse(operation.dataJson!));
  });
});
