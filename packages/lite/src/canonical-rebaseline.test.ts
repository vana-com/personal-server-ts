import { describe, expect, it } from "vitest";
import {
  binding,
  identity,
  registration,
} from "@opendatalabs/personal-server-ts-core/replication/fixtures";
import {
  canonicalJson,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import { operationDigest } from "@opendatalabs/personal-server-ts-core/replication/completion";
import { encodeLiveSnapshotDigestInput } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records/completion";
import { sha256 } from "viem";
import {
  createLiteCanonicalStore,
  LiteCanonicalRefusal,
} from "./canonical-store.js";
import { LITE_CANONICAL_MAX_OPERATION_BYTES } from "./canonical-persistence.js";
import {
  createFakeCanonicalPersistence,
  fakeCanonicalDisk,
} from "./test-support/canonical-persistence.js";

const trusted = [
  { sourceId: identity.sourceId, binding, validateData: () => true },
];

function device() {
  const disk = fakeCanonicalDisk();
  let declarations = trusted;
  const store = createLiteCanonicalStore({
    persistence: createFakeCanonicalPersistence(disk).port,
    enabled: true,
    context: () => ({ owner: identity.owner, declarations }),
    authenticateReplica: (credential) =>
      credential === "replica" ? identity.owner : undefined,
  });
  return {
    disk,
    store,
    /** The host stops declaring the stream (Lite keeps no binding history). */
    retire() {
      declarations = [];
    },
  };
}
const record = (key: string, text: string) => ({
  ...identity,
  kind: "upsert" as const,
  declaration: binding,
  recordKey: key,
  emittedAt: "2026-10-20T00:00:00Z",
  data: { id: key, text },
  blobs: [],
});
const { revision: _, ...register } = registration;
const envelope = (operations: ReplicaOperation[]) => ({
  format: "vana-pdpp-replica",
  version: 1,
  owner: identity.owner,
  batchId: "peer",
  operations,
});
const peer = {
  ...record("p", "from peer"),
  revision: { counter: 50, writerId: "device-b", operationId: "peer-p" },
};

/** Local writes (one record edited) and one record a peer wrote. */
async function written() {
  const d = device();
  await d.store.provisionConnection(identity.connectionId, {
    sourceId: identity.sourceId,
    methodId: identity.methodId,
  });
  await d.store.commitLocal("one", [
    register,
    record("a", "first"),
    record("b", "b"),
  ]);
  await d.store.commitLocal("two", [record("a", "second")]);
  await d.store.import({
    id: "peer",
    credential: "replica",
    envelope: envelope([peer]),
  });
  return d;
}
const outbox = async (
  store: ReturnType<typeof createLiteCanonicalStore>,
  after = 0,
) => (await store.readOutboxPage(after)).entries;
const byText = (entries: { operation: ReplicaOperation }[]) =>
  new Map(
    entries.map(({ operation }) => [
      operation.kind === "upsert"
        ? String(operation.data.text)
        : operation.kind,
      operation,
    ]),
  );

describe("Lite canonical rebaseline", () => {
  it("re-exports current state under the new writer in the order of the operations it copies", async () => {
    const { store } = await written();
    const original = byText(await outbox(store));
    expect(await store.rebaseline("writer-2")).toEqual({
      reissued: 4,
      skipped: 0,
    });
    const entries = await outbox(store);
    const copies = byText(entries);
    // Current state only: the edited record once, at its current value.
    expect([...copies.keys()].sort()).toEqual([
      "b",
      "connection-register",
      "from peer",
      "second",
    ]);
    expect(
      entries.every((e) => e.operation.revision.writerId === "writer-2"),
    ).toBe(true);
    for (const text of ["second", "b"]) {
      const source = original.get(text)!.revision;
      expect(copies.get(text)!.revision).toMatchObject({
        counter: source.counter,
        origin: { writerId: source.writerId, operationId: source.operationId },
      });
    }
    expect(copies.get("from peer")!.revision).toMatchObject({
      counter: 50,
      origin: { writerId: "device-b", operationId: "peer-p" },
    });
    // A new lifecycle operation takes a new counter, above every retained one.
    expect(copies.get("connection-register")!.revision.counter).toBeGreaterThan(
      50,
    );
    // The same writer again changes nothing.
    expect(await store.rebaseline("writer-2")).toBeUndefined();
    expect(await outbox(store)).toEqual(entries);
    // Canonical reads do not change.
    expect(
      await store.readRecord(identity.connectionId, binding.stream, "a"),
    ).toMatchObject({ data: { text: "second" } });
  });

  it("re-exports a certified completion that a new receiver certifies", async () => {
    const { store, disk } = await written();
    const rows = [
      ["a", "second"],
      ["b", "b"],
      ["p", "from peer"],
    ].map(([id, text]) => ({
      recordKey: id!,
      dataJson: canonicalJson({ id, text }),
    }));
    const snapshot = sha256(
      encodeLiveSnapshotDigestInput(
        {
          sourceId: identity.sourceId,
          instance: identity.connectionId,
          method: identity.methodId,
          generation: 1,
          stream: binding.stream,
        },
        binding.primaryKey,
        rows,
      ),
    );
    const complete: ReplicaOperation = {
      ...identity,
      kind: "stream-complete",
      declaration: binding,
      sourceCollectedAt: "2026-10-20T00:00:00Z",
      liveCount: 3,
      snapshotSha256: `sha256:${snapshot.slice(2)}`,
      proof: {
        kind: "producer-asserted",
        snapshotSha256: null,
        collectionTimeBasis: null,
      },
      dependencies: [
        {
          writerId: "device-b",
          operationId: "peer-p",
          digest: operationDigest(peer),
        },
      ],
      revision: { counter: 70, writerId: "device-b", operationId: "peer-c" },
    };
    await store.import({
      id: "peer-complete",
      credential: "replica",
      envelope: envelope([complete]),
    });
    const certified = (keys: Iterable<string>) =>
      [...keys].filter((key) => key.startsWith("stream-completions/")).length;
    expect(certified(disk.rows.keys())).toBe(1);

    await store.rebaseline("writer-2");
    const operations = (await outbox(store)).map((e) => e.operation);
    const copy = operations.find((op) => op.kind === "stream-complete")!;
    expect(copy.revision).toMatchObject({
      counter: 70,
      origin: { writerId: "device-b", operationId: "peer-c" },
    });
    // It depends on the new writer's own operations only.
    expect(copy.kind === "stream-complete" && copy.dependencies).toEqual(
      operations
        .filter((op) => op.kind !== "stream-complete")
        .map((op) => ({
          writerId: "writer-2",
          operationId: op.revision.operationId,
          digest: operationDigest(op),
        })),
    );

    // A receiver that gets only the new writer's batch certifies it.
    const fresh = device();
    await fresh.store.provisionConnection(identity.connectionId, {
      sourceId: identity.sourceId,
      methodId: identity.methodId,
    });
    await fresh.store.import({
      id: "writer-2",
      credential: "replica",
      envelope: envelope(operations),
    });
    expect(certified(fresh.disk.rows.keys())).toBe(1);
    expect(
      await fresh.store.readRecord(identity.connectionId, binding.stream, "p"),
    ).toMatchObject({ data: { text: "from peer" } });
  });

  it("skips a certified completion whose rewrite outgrows one operation, and re-exports its records", async () => {
    const d = device();
    await d.store.provisionConnection(identity.connectionId, {
      sourceId: identity.sourceId,
      methodId: identity.methodId,
    });
    await d.store.commitLocal("one", [register]);
    const records = Array.from({ length: 1_700 }, (_, i) => ({
      ...record(`r${String(i).padStart(4, "0")}`, "r"),
      revision: {
        counter: 100 + i,
        writerId: "device-b",
        operationId: `r${i}`,
      },
    }));
    await d.store.import({
      id: "peer-records",
      credential: "replica",
      envelope: envelope(records),
    });
    const snapshot = sha256(
      encodeLiveSnapshotDigestInput(
        {
          sourceId: identity.sourceId,
          instance: identity.connectionId,
          method: identity.methodId,
          generation: 1,
          stream: binding.stream,
        },
        binding.primaryKey,
        records.map((op) => ({
          recordKey: op.recordKey,
          dataJson: canonicalJson(op.data),
        })),
      ),
    );
    const complete: ReplicaOperation = {
      ...identity,
      kind: "stream-complete",
      declaration: binding,
      sourceCollectedAt: "2026-10-20T00:00:00Z",
      liveCount: records.length,
      snapshotSha256: `sha256:${snapshot.slice(2)}`,
      proof: {
        kind: "producer-asserted",
        snapshotSha256: null,
        collectionTimeBasis: null,
      },
      dependencies: records.map((op) => ({
        writerId: "device-b",
        operationId: op.revision.operationId,
        digest: operationDigest(op),
      })),
      revision: { counter: 9_000, writerId: "device-b", operationId: "peer-c" },
    };
    // The peer's completion fits one operation; its rewrite would not.
    const originalCompletionBytes = new TextEncoder().encode(
      canonicalJson(complete),
    ).byteLength;
    expect(originalCompletionBytes).toBeLessThan(
      LITE_CANONICAL_MAX_OPERATION_BYTES,
    );
    await d.store.import({
      id: "peer-complete",
      credential: "replica",
      envelope: envelope([complete]),
    });
    expect(
      [...d.disk.rows.keys()].filter((key) =>
        key.startsWith("stream-completions/"),
      ),
    ).toHaveLength(1);

    // Each dependency repeats this valid nonempty writer ID. Keep the record
    // count fixed while crossing the real operation cap, not a mocked limit.
    const writerId = "w".repeat(
      Math.ceil(LITE_CANONICAL_MAX_OPERATION_BYTES / records.length),
    );
    expect(await d.store.rebaseline(writerId)).toEqual({
      reissued: 1 + records.length,
      skipped: 1,
    });
    const operations: ReplicaOperation[] = [];
    for (let after = 0; ;) {
      const page = await outbox(d.store, after);
      if (!page.length) break;
      operations.push(...page.map((e) => e.operation));
      after = page.at(-1)!.sequence;
    }
    const { revision: _revision, ...draft } = complete;
    // The actual emitted lifecycle/record operations are exactly the dependencies
    // reexport() would put in this completion draft (before its revision margin).
    const projectedRewrite = {
      ...draft,
      dependencies: operations.map((op) => ({
        writerId: op.revision.writerId,
        operationId: op.revision.operationId,
        digest: operationDigest(op),
      })),
    };
    const projectedRewriteBytes = new TextEncoder().encode(
      canonicalJson(projectedRewrite),
    ).byteLength;
    const maxReissuedOperationBytes = Math.max(
      ...operations.map(
        (op) => new TextEncoder().encode(canonicalJson(op)).byteLength,
      ),
    );
    expect(projectedRewriteBytes).toBeGreaterThan(
      LITE_CANONICAL_MAX_OPERATION_BYTES,
    );
    expect(maxReissuedOperationBytes).toBeLessThanOrEqual(
      LITE_CANONICAL_MAX_OPERATION_BYTES,
    );
    console.info("REBASELINE_BOUNDARY_BYTES", {
      originalCompletionBytes,
      projectedRewriteBytes,
      maxReissuedOperationBytes,
      writerIdBytes: new TextEncoder().encode(writerId).byteLength,
      limit: LITE_CANONICAL_MAX_OPERATION_BYTES,
    });
    expect(operations.some((op) => op.kind === "stream-complete")).toBe(false);
    expect(operations.filter((op) => op.kind === "upsert")).toHaveLength(
      records.length,
    );
  }, 60_000);

  it("moves the outbox past published operations and keeps them in the log", async () => {
    const { store, disk } = await written();
    await store.rebaseline("writer-2");
    const entries = await outbox(store);
    await store.acknowledgePublished(entries[1]!.sequence);
    expect(await outbox(store)).toEqual(entries.slice(2));
    await store.acknowledgePublished(entries.at(-1)!.sequence);
    // Lower and repeated acknowledgments are no-ops.
    await store.acknowledgePublished(entries[0]!.sequence);
    expect(await outbox(store)).toEqual([]);
    // Layout 2: the log keeps history; compaction is a separate rule.
    expect(
      [...disk.rows.keys()].filter((key) => key.startsWith("reexported/")),
    ).toHaveLength(entries.length);
    await expect(
      store.acknowledgePublished(entries.at(-1)!.sequence + 1),
    ).rejects.toThrow("outbox acknowledgment conflict");
  });

  it("skips a record the merge no longer explains once its stream is undeclared", async () => {
    const d = await written();
    d.retire();
    expect(await d.store.rebaseline("writer-2")).toEqual({
      reissued: 1,
      skipped: 3,
    });
  });

  it("imports a received batch over 192 KiB and refuses an operation over the value bound", async () => {
    const { store } = await written();
    const large = Array.from({ length: 4 }, (_, i) => ({
      ...record(`x${i}`, "x".repeat(60_000)),
      revision: { counter: 60 + i, writerId: "device-b", operationId: `x${i}` },
    }));
    await expect(
      store.import({
        id: "large",
        credential: "replica",
        envelope: envelope(large),
      }),
    ).resolves.toBeDefined();
    const oversized = {
      ...record("y", "y".repeat(LITE_CANONICAL_MAX_OPERATION_BYTES)),
      revision: { counter: 70, writerId: "device-b", operationId: "y" },
    };
    const refusal = await store
      .import({
        id: "oversized",
        credential: "replica",
        envelope: envelope([oversized]),
      })
      .catch((error: unknown) => error);
    expect(refusal).toBeInstanceOf(LiteCanonicalRefusal);
    expect(refusal).toMatchObject({ reason: "operation_too_large" });
  });
});
