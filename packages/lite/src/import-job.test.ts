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
    for (const prefix of ["rows/", "journal/", "outbox/", "mutations/"])
      expect(keys.some((key) => key.startsWith(prefix))).toBe(true);
    // Outbox entries point at the retained operation; they carry no record bytes.
    for (const entry of encoded.entries.filter((e) =>
      e.key.startsWith("outbox/"),
    ))
      expect(Object.keys(JSON.parse(entry.value!)).sort()).toEqual([
        "batchId",
        "operationKey",
        "sequence",
      ]);
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

  it("refuses an operation that cannot fit one canonical part", () => {
    const encoder = createLiteCanonicalImportEncoder({ context });
    const big = importOperations()[0];
    expect(() =>
      encoder.importBatchParts({
        job: {
          jobId: "job-1",
          binding: {
            owner: identity.owner,
            instance: identity.connectionId,
            sourceId: identity.sourceId,
            method: identity.methodId,
            generation: identity.generation,
          },
        },
        seq: 0,
        operations: [
          {
            ...big,
            dataJson: JSON.stringify({ id: "m0", text: "x".repeat(200_000) }),
          },
        ],
        bindingFor: () => binding,
      }),
    ).toThrow(expect.objectContaining({ code: "record_too_large" }));
  });
});
