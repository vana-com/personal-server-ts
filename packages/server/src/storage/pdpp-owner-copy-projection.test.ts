import { expect, it } from "vitest";
import {
  binding,
  identity,
  registration,
} from "@opendatalabs/personal-server-ts-core/replication/fixtures";
import { copyReadFixture } from "./pdpp-replica-copy-reads.test-utils.js";
import type { ReplicaOperation } from "@opendatalabs/personal-server-ts-core/replication/envelope";

it("uses one whole-copy scope for owner counts and complete diagnostic values", () => {
  const f = copyReadFixture();
  const other = "conn-other";
  f.store.registerConnection({
    instance: other,
    sourceId: identity.sourceId,
    method: identity.methodId,
    label: other,
  });
  const seed = f.copy("local", 1);
  const deletion = {
    ...identity,
    kind: "connection-delete" as const,
    revision: { counter: 30, writerId: "device-a", operationId: "delete" },
  };
  const local = f.copy("local", 1, [...seed.envelope.operations, deletion]);
  const cross = f.copy("cross", 2, [
    ...f.copy("cross", 2).envelope.operations,
    { ...registration, connectionId: other },
  ]);
  f.stage(local);
  f.stage(cross);
  const owner = f.receiver.readStore({ reader: "owner" });
  expect(owner.listStreams([identity.connectionId])).toMatchObject([
    { stream: "messages", copyConflicts: 1 },
  ]);
  const page = owner.readCopyConflicts(local.id, [identity.connectionId]);
  expect(page.data).toEqual([
    {
      id: local.id,
      copyKey: local.copyKey,
      reason: "copy_conflict",
      visibility: "conflicted",
      status: "copy conflict",
      connections: [identity.connectionId],
      streams: ["messages"],
      values: local.envelope.operations,
    },
  ]);
  expect(page.hasMore).toBe(false);
});

it("projects connection-level copies onto every declared stream and keeps every operation kind", () => {
  const sourceId = identity.sourceId;
  const other = {
    ...binding,
    stream: "notes",
    digest: `sha256:${"c".repeat(64)}`,
  };
  const f = copyReadFixture({
    declarations: [
      { sourceId, binding, validateData: () => true },
      { sourceId, binding: other, validateData: () => true },
    ],
  });
  const invalidate = {
    ...identity,
    kind: "stream-invalidate" as const,
    declaration: binding,
    revision: { counter: 21, writerId: "device-a", operationId: "invalidate" },
  };
  const deletion = {
    ...identity,
    kind: "connection-delete" as const,
    revision: { counter: 22, writerId: "device-a", operationId: "delete" },
  };
  const a = f.copy("invalidate", 1, [invalidate]),
    b = f.copy("delete", 2, [deletion]);
  f.stage(a);
  f.stage(b);
  const owner = f.receiver.readStore({ reader: "owner" });
  const catalog = owner.listCopyConflicts({
    instanceIds: [identity.connectionId],
  });
  expect(catalog.data).toHaveLength(2);
  const connectionCopy = catalog.data.find(
    (copy) => copy.copyKey === b.copyKey,
  )!;
  expect(connectionCopy.streams).toEqual(["messages", "notes"]);
  expect(owner.listStreams([identity.connectionId])).toEqual([
    { stream: "messages", recordCount: 0, lastUpdated: null, copyConflicts: 2 },
    { stream: "notes", recordCount: 0, lastUpdated: null, copyConflicts: 1 },
  ]);
  const values = owner.readCopyConflicts(a.id, [identity.connectionId]).data;
  expect(values.find((copy) => copy.copyKey === a.copyKey)?.values).toEqual([
    invalidate,
  ]);
  expect(values.find((copy) => copy.copyKey === b.copyKey)?.values).toEqual([
    deletion,
  ]);
  expect(
    owner
      .listCopyConflicts({
        instanceIds: [identity.connectionId],
        stream: "notes",
      })
      .data.map((copy) => copy.copyKey),
  ).toEqual([b.copyKey]);
  const before = owner.listStreams([identity.connectionId]);
  f.reopen();
  expect(
    f.receiver
      .readStore({ reader: "owner" })
      .listStreams([identity.connectionId]),
  ).toEqual(before);
});

it("keeps connection-level copies discoverable when that connection has no declared streams", () => {
  const f = copyReadFixture({ declarations: [] });
  const del = {
    ...identity,
    kind: "connection-delete" as const,
    revision: { counter: 22, writerId: "device-a", operationId: "delete" },
  };
  const a = f.copy("register", 1, [registration]),
    b = f.copy("delete", 2, [del]);
  f.stage(a);
  f.stage(b);
  const owner = f.receiver.readStore({ reader: "owner" });
  expect(owner.listStreams([identity.connectionId])).toEqual([]);
  const page = owner.listCopyConflicts({
    instanceIds: [identity.connectionId],
    connection: identity.connectionId,
  });
  expect(page.data).toHaveLength(2);
  expect(
    page.data.every(
      (copy) => copy.connections.length === 1 && copy.streams.length === 0,
    ),
  ).toBe(true);
});

it("keysets discovery across reasons and restarts, and rejects cursor reuse for a different scope or query", () => {
  const f = copyReadFixture();
  const a = f.copy("A", 1),
    b = f.copy("B", 2),
    c = f.copy("C", 3);
  f.stage(a);
  f.stage(b);
  f.stage(c);
  const query = {
    instanceIds: [identity.connectionId],
    connection: identity.connectionId,
    stream: "messages",
    limit: 1,
  };
  const first = f.receiver
    .readStore({ reader: "owner" })
    .listCopyConflicts(query);
  expect(first.hasMore).toBe(true);
  f.reopen();
  const owner = f.receiver.readStore({ reader: "owner" });
  const second = owner.listCopyConflicts({
    ...query,
    cursor: first.nextCursor,
  });
  expect(second.data).toHaveLength(1);
  expect(second.data[0].copyKey).not.toBe(first.data[0].copyKey);
  expect(() =>
    owner.listCopyConflicts({
      ...query,
      stream: "other",
      cursor: first.nextCursor,
    }),
  ).toThrow();
  expect(() =>
    owner.listCopyConflicts({
      ...query,
      instanceIds: [],
      cursor: first.nextCursor,
    }),
  ).toThrow();
  expect(() =>
    owner.readCopyConflicts(a.id, query.instanceIds, {
      cursor: first.nextCursor,
    }),
  ).toThrow();
  expect(() =>
    owner.listCopyConflicts({ ...query, cursor: "x".repeat(5000) }),
  ).toThrow();
  f.receiver.copies.terminate({
    credential: "test",
    id: a.id,
    reason: "finalized_conflict",
  });
  const terminal = owner.listCopyConflicts({ ...query, limit: 100 });
  expect(terminal.data).toHaveLength(3);
  expect(
    terminal.data.every((copy) => copy.status === "integrity conflict"),
  ).toBe(true);
});

it("matches connection and stream filters as a pair without narrowing a wide token's authority", () => {
  const other = "other";
  const notes = {
    ...binding,
    stream: "notes",
    digest: `sha256:${"c".repeat(64)}`,
  };
  const declarations = [
    { sourceId: identity.sourceId, binding, validateData: () => true },
    { sourceId: identity.sourceId, binding: notes, validateData: () => true },
  ];
  const f = copyReadFixture({ declarations });
  f.store.registerConnection({
    instance: other,
    sourceId: identity.sourceId,
    method: identity.methodId,
    label: other,
  });
  const ops = [
    f.copy("message", 1).record,
    { ...f.copy("note", 2).record, connectionId: other, declaration: notes },
  ];
  const a = f.copy("A", 1, ops),
    b = f.copy("B", 2, [
      ...ops.map((op) => ({
        ...op,
        revision: {
          ...op.revision,
          operationId: `other-${op.revision.operationId}`,
        },
      })),
    ]);
  f.stage(a);
  f.stage(b);
  const owner = f.receiver.readStore({ reader: "owner" }),
    instanceIds = [identity.connectionId, other];
  expect(
    owner.listCopyConflicts({
      instanceIds,
      connection: identity.connectionId,
      stream: "notes",
    }).data,
  ).toEqual([]);
  expect(
    owner.listCopyConflicts({
      instanceIds,
      connection: identity.connectionId,
      stream: "messages",
    }).data,
  ).toHaveLength(2);
  expect(
    owner.listCopyConflicts({
      instanceIds: [identity.connectionId],
      connection: other,
    }).data,
  ).toEqual([]);
  expect(
    owner
      .listStreams(instanceIds)
      .map((row) => [row.stream, row.copyConflicts]),
  ).toEqual([
    ["messages", 2],
    ["notes", 2],
  ]);
  expect(owner.listStreams([identity.connectionId])).toEqual([]);
});

it("uses current declarations for connection-level counts and metadata and expires prior declaration cursors", () => {
  const declarations = [
    { sourceId: identity.sourceId, binding, validateData: () => true },
  ];
  const f = copyReadFixture({ declarations });
  const a = f.copy("A", 1, [registration]),
    b = f.copy("B", 2, [registration]);
  f.stage(a);
  f.stage(b);
  const owner = f.receiver.readStore({ reader: "owner" }),
    query = { instanceIds: [identity.connectionId], limit: 1 };
  const first = owner.listCopyConflicts(query);
  declarations.push({
    sourceId: identity.sourceId,
    binding: {
      ...binding,
      stream: "notes",
      digest: `sha256:${"c".repeat(64)}`,
    },
    validateData: () => true,
  });
  f.receiver.reconcileDeclarations({ credential: "test" });
  expect(() =>
    owner.listCopyConflicts({ ...query, cursor: first.nextCursor }),
  ).toThrow();
  expect(
    owner
      .listStreams(query.instanceIds)
      .map((row) => [row.stream, row.copyConflicts]),
  ).toEqual([
    ["messages", 2],
    ["notes", 2],
  ]);
  expect(
    owner
      .listCopyConflicts({ ...query, limit: 100 })
      .data.every((copy) => copy.streams.join(",") === "messages,notes"),
  ).toBe(true);
  declarations.pop();
  f.receiver.reconcileDeclarations({ credential: "test" });
  f.reopen();
  expect(
    f.receiver.readStore({ reader: "owner" }).listStreams(query.instanceIds),
  ).toEqual([
    { stream: "messages", recordCount: 0, lastUpdated: null, copyConflicts: 2 },
  ]);
});

it("decodes every operation kind without materializing conflicting values", () => {
  const f = copyReadFixture();
  f.stage(f.copy("first", 1));
  const revision = {
    counter: 30,
    writerId: "device-a",
    operationId: "operation",
  };
  const record = f.copy("value", 2).record;
  const operations: ReplicaOperation[] = [
    registration,
    {
      ...identity,
      kind: "connection-reset",
      generation: 2,
      previousGeneration: 1,
      revision,
    },
    {
      ...identity,
      kind: "connection-delete",
      revision: { ...revision, operationId: "remove-connection" },
    },
    {
      ...identity,
      kind: "blob-claim",
      revision: { ...revision, operationId: "claim" },
      blob: {
        blobId: "blob",
        sha256: `sha256:${"0".repeat(64)}`,
        mimeType: "text/plain",
        sizeBytes: 1,
      },
    },
    {
      ...identity,
      kind: "stream-invalidate",
      declaration: binding,
      revision: { ...revision, operationId: "invalidate" },
    },
    {
      ...identity,
      kind: "stream-complete",
      declaration: binding,
      revision: { ...revision, operationId: "complete" },
      sourceCollectedAt: "2026-10-21T00:00:00Z",
      liveCount: 0,
      snapshotSha256: `sha256:${"0".repeat(64)}`,
      proof: {
        kind: "producer-asserted",
        snapshotSha256: null,
        collectionTimeBasis: null,
      },
      dependencies: [],
    },
    record,
    {
      ...identity,
      kind: "delete",
      declaration: binding,
      revision: { ...revision, operationId: "remove-record" },
      recordKey: "a",
      emittedAt: record.emittedAt,
      deletedAt: record.emittedAt,
    },
  ];
  const copy = f.copy("all kinds", 2, operations);
  f.stage(copy);
  const owner = f.receiver.readStore({ reader: "owner" });
  expect(
    owner
      .readCopyConflicts(copy.id)
      .data.find((row) => row.copyKey === copy.copyKey)?.values,
  ).toEqual(operations);
  expect(owner.listStreams([identity.connectionId])).toEqual([
    { stream: "messages", recordCount: 0, lastUpdated: null, copyConflicts: 2 },
  ]);
  expect(
    owner.getRecord(identity.connectionId, "messages", "a"),
  ).toBeUndefined();
  expect(
    f.receiver
      .readStore({ reader: "grant" })
      .getRecord(identity.connectionId, "messages", "a"),
  ).toBeUndefined();
});

it("walks different batch ids with the same copy keys and a normalized token scope", () => {
  const f = copyReadFixture();
  const copies = ["alpha", "beta"].flatMap((batch) =>
    [1, 2].map((seed) => f.copy(`copy-${seed}`, seed, undefined, batch)),
  );
  copies.forEach((copy) => f.stage(copy));
  const owner = f.receiver.readStore({ reader: "owner" });
  const seen: string[] = [];
  let cursor: string | undefined;
  do {
    const page = owner.listCopyConflicts({
      instanceIds: seen.length
        ? [identity.connectionId]
        : [identity.connectionId, identity.connectionId],
      limit: 1,
      cursor,
    });
    expect(page.data).toHaveLength(1);
    seen.push(JSON.stringify([page.data[0].id, page.data[0].copyKey]));
    cursor = page.nextCursor;
    expect(page.hasMore).toBe(cursor !== undefined);
  } while (cursor && seen.length < 5);
  expect(seen).toEqual(
    copies.map((copy) => JSON.stringify([copy.id, copy.copyKey])).sort(),
  );
  expect(owner.listStreams([identity.connectionId])[0].copyConflicts).toBe(4);
});

it("keeps continuation cursors bounded even for a long retained batch id", () => {
  const f = copyReadFixture();
  const a = f.copy("A", 1, undefined, "batch-" + "x".repeat(5000));
  const b = f.copy("B", 2, undefined, a.batch);
  f.stage(a);
  f.stage(b);
  const owner = f.receiver.readStore({ reader: "owner" });
  const first = owner.listCopyConflicts({ limit: 1 });
  expect(Buffer.byteLength(first.nextCursor!)).toBeLessThanOrEqual(4096);
  f.reopen();
  const second = f.receiver
    .readStore({ reader: "owner" })
    .listCopyConflicts({ limit: 1, cursor: first.nextCursor });
  expect(second.hasMore).toBe(false);
  expect(
    new Set([...first.data, ...second.data].map((copy) => copy.copyKey)).size,
  ).toBe(2);
});
