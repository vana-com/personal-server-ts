import { expect, it } from "vitest";
import {
  upsert,
  registration,
  identity,
} from "@opendatalabs/personal-server-ts-core/replication/fixtures";
import { copyReadFixture } from "./pdpp-replica-copy-reads.test-utils.js";
import { COPY_CONFLICT_READ_LIMITS } from "./pdpp-replication-receiver.js";

it("owners read both marked copies separately while page and point reads retain the confirmed predecessor, across promotion and restart", () => {
  const f = copyReadFixture();
  const prior = {
    ...upsert("prior", 5),
    data: { id: "a", text: "prior" },
    recordKey: "a",
  };
  f.receiver.import({
    credential: "test",
    envelope: {
      ...f.copy("prior", 10).envelope,
      batchId: "prior",
      operations: [registration, prior],
    },
  });
  const a = f.copy("A", 1),
    b = f.copy("B", 2);
  f.stage(a);
  f.stage(b);
  const check = (winner: string, keys = [a.copyKey, b.copyKey]) => {
    const owner = f.receiver.readStore({ reader: "owner" });
    const grant = f.receiver.readStore({ reader: "grant" });
    expect("readCopyConflicts" in grant).toBe(false);
    expect("listCopyConflicts" in grant).toBe(false);
    expect(owner.readCopyConflicts(a.id).data).toEqual(
      keys.sort().map((copyKey) => ({
        id: a.id,
        copyKey,
        connections: [identity.connectionId],
        streams: ["messages"],
        reason: "copy_conflict",
        visibility: "conflicted",
        status: "copy conflict",
        values:
          copyKey === a.copyKey ? a.envelope.operations : b.envelope.operations,
      })),
    );
    for (const read of [owner, grant]) {
      expect(
        read.getRecord(identity.connectionId, "messages", "a")?.data.text,
      ).toBe(winner);
      expect(
        read
          .listRecords("messages", {
            instanceIds: [identity.connectionId],
            limit: 100,
            order: "asc",
          })
          .data.map((r) => r.data.text),
      ).toEqual([winner]);
    }
  };
  check("prior");
  f.reopen();
  check("prior");
  f.prove(b);
  f.receiver.copies.promote({
    credential: "test",
    id: b.id,
    copyKey: b.copyKey,
  });
  check("B", [a.copyKey]);
  f.reopen();
  check("B", [a.copyKey]);
  f.prove(b, "2", 101n);
  f.receiver.copies.apply({
    credential: "test",
    id: b.id,
    decision: f.receiver.copies.decide(b.id, { attempts: 0, budget: 5 }),
  });
  const terminal = () => {
    expect(
      f.receiver.readStore({ reader: "owner" }).readCopyConflicts(a.id).data,
    ).toEqual(
      [a.copyKey, b.copyKey].sort().map((copyKey) => ({
        id: a.id,
        copyKey,
        connections: [identity.connectionId],
        streams: ["messages"],
        reason: "finalized_conflict",
        visibility: "conflicted",
        status: "integrity conflict",
      })),
    );
    for (const reader of ["owner", "grant"] as const)
      expect(
        f.receiver
          .readStore({ reader })
          .getRecord(identity.connectionId, "messages", "a"),
      ).toBeUndefined();
  };
  terminal();
  f.reopen();
  terminal();
});

it("counts distinct conflicting copies per stream at write time, including copies touching multiple requested connections", () => {
  const f = copyReadFixture();
  const other = "conn-other";
  f.store.registerConnection({
    instance: other,
    sourceId: identity.sourceId,
    method: identity.methodId,
    label: "other",
  });
  const a = f.copy("A", 1),
    b = f.copy("B", 2);
  a.envelope.operations.push(
    { ...registration, connectionId: other },
    { ...a.record, connectionId: other },
  );
  // Staging computes its own canonical digest and rejects a stale input digest.
  const copies = [f.copy("A", 1, a.envelope.operations), b];
  f.stage(copies[0]);
  f.stage(b);
  const check = () => {
    const owner = f.receiver.readStore({ reader: "owner" });
    expect(owner.listStreams([identity.connectionId, other])).toEqual([
      {
        stream: "messages",
        recordCount: 0,
        lastUpdated: null,
        copyConflicts: 2,
      },
    ]);
    // A copy also touching another connection is outside this token's scope.
    expect(owner.listStreams([other])).toEqual([]);
    expect(
      f.receiver
        .readStore({ reader: "grant" })
        .listStreams([identity.connectionId, other]),
    ).toEqual([]);
  };
  check();
  f.reopen();
  check();
  f.prove(b);
  f.receiver.copies.promote({
    credential: "test",
    id: b.id,
    copyKey: b.copyKey,
  });
  expect(
    f.receiver
      .readStore({ reader: "owner" })
      .listStreams([identity.connectionId, other]),
  ).toEqual([
    {
      stream: "messages",
      recordCount: 1,
      lastUpdated: b.record.emittedAt,
      copyConflicts: 1,
    },
  ]);
  expect(
    f.receiver
      .readStore({ reader: "grant" })
      .listStreams([identity.connectionId, other])[0],
  ).not.toHaveProperty("copyConflicts");
});

it("includes a normal Node batch of fifty 6 KiB records with every operation", () => {
  const f = copyReadFixture();
  const records = Array.from({ length: 50 }, (_, i) => ({
    ...upsert(`op-${i}`, i + 10),
    recordKey: `key-${i}`,
    data: { id: `key-${i}`, text: "x".repeat(6 * 1024) },
  }));
  const a = f.copy("normal", 1, [registration, ...records]);
  f.stage(a);
  f.stage(f.copy("small", 2));
  const page = f.receiver
    .readStore({ reader: "owner" })
    .readCopyConflicts(a.id);
  expect(page.data.find((copy) => copy.copyKey === a.copyKey)?.values).toEqual(
    a.envelope.operations,
  );
  expect(page.data.every((copy) => !("valuesOmitted" in copy))).toBe(true);
});

it("keeps owner conflict counts when pending preview is disabled and rebuilds them from retained copies on a view upgrade", () => {
  const f = copyReadFixture();
  f.stage(f.copy("A", 1));
  f.stage(f.copy("B", 2));
  f.receiver.setPendingEnabled(false);
  expect(
    f.receiver
      .readStore({ reader: "owner" })
      .listStreams([identity.connectionId]),
  ).toEqual([
    { stream: "messages", recordCount: 0, lastUpdated: null, copyConflicts: 2 },
  ]);
  f.db.exec("UPDATE pdpp_replica_view_schema SET version=7");
  f.reopen();
  expect(
    f.receiver
      .readStore({ reader: "owner" })
      .listStreams([identity.connectionId])[0].copyConflicts,
  ).toBe(2);
});

it("hides corrupt rejects while valid scoped diagnostics survive reopening", () => {
  const f = copyReadFixture();
  const a = f.copy("A", 1),
    b = f.copy("B", 2);
  f.stage({ ...a, fragments: [{ dataHash: "0xZZ", metadataHash: "0x00" }] });
  expect(
    f.receiver.readStore({ reader: "owner" }).readCopyConflicts(a.id).data,
  ).toEqual([]);
  f.stage(a);
  f.stage(b);
  const before = f.receiver
    .readStore({ reader: "owner" })
    .readCopyConflicts(a.id, [identity.connectionId]);
  f.reopen();
  expect(
    f.receiver
      .readStore({ reader: "owner" })
      .readCopyConflicts(a.id, [identity.connectionId]),
  ).toEqual(before);
});

it("omits an over-limit copy's operations without hiding its normal sibling", () => {
  const f = copyReadFixture();
  const many = Array.from({ length: 513 }, (_, i) => ({
    ...upsert(`op-${i}`, i + 10),
    recordKey: `key-${i}`,
  }));
  const a = f.copy("large", 1, [registration, ...many]),
    b = f.copy("small", 2);
  f.stage(a);
  f.stage(b);
  const page = f.receiver
    .readStore({ reader: "owner" })
    .readCopyConflicts(a.id);
  expect(page.data).toHaveLength(2);
  expect(page.data.find((copy) => copy.copyKey === a.copyKey)).toMatchObject({
    valuesOmitted: true,
    valuesOmittedReason: "operation_limit",
  });
  expect(
    page.data.find((copy) => copy.copyKey === a.copyKey),
  ).not.toHaveProperty("values");
  expect(page.data.find((copy) => copy.copyKey === b.copyKey)?.values).toEqual(
    b.envelope.operations,
  );
});

it.each([5, 9])(
  "omits a %i MiB copy's values but retains its scoped finalized marker",
  (mib) => {
    const f = copyReadFixture();
    const a = f.copy("large", 1, [
      registration,
      {
        ...upsert("large", 10),
        data: { id: "a", text: "x".repeat(mib * 1024 * 1024) },
      },
    ]);
    f.stage(a);
    f.stage(f.copy("small", 2));
    const owner = f.receiver.readStore({ reader: "owner" });
    expect(
      owner
        .readCopyConflicts(a.id)
        .data.find((copy) => copy.copyKey === a.copyKey),
    ).toMatchObject({ valuesOmitted: true, valuesOmittedReason: "byte_limit" });
    f.receiver.copies.terminate({
      credential: "test",
      id: a.id,
      reason: "finalized_conflict",
    });
    for (const scope of [undefined, [identity.connectionId]]) {
      const markers = owner.readCopyConflicts(a.id, scope).data;
      expect(markers).toHaveLength(2);
      expect(
        markers.every(
          (copy) =>
            copy.reason === "finalized_conflict" &&
            !("values" in copy) &&
            !("valuesOmitted" in copy),
        ),
      ).toBe(true);
    }
  },
);

it("pages complete diagnostic values within a total byte budget without skipping a copy", () => {
  const f = copyReadFixture();
  for (let seed = 1; seed <= 3; seed++)
    f.stage(
      f.copy("page", seed, [
        registration,
        {
          ...upsert(`page-${seed}`, seed + 10),
          data: { id: "a", text: "x".repeat(3 * 1024 * 1024) },
        },
      ]),
    );
  const owner = f.receiver.readStore({ reader: "owner" });
  const first = owner.readCopyConflicts(f.copy("page", 1).id);
  expect(first.hasMore).toBe(true);
  expect(first.data).toHaveLength(2);
  const second = owner.readCopyConflicts(f.copy("page", 1).id, undefined, {
    cursor: first.nextCursor,
  });
  expect(second.hasMore).toBe(false);
  expect(second.data).toHaveLength(1);
  expect(
    new Set([...first.data, ...second.data].map((copy) => copy.copyKey)).size,
  ).toBe(3);
  expect(
    [...first.data, ...second.data].every(
      (copy) => copy.values?.length === 2 && !copy.valuesOmitted,
    ),
  ).toBe(true);
});

it("pages more than a hundred markers while preserving exact scoped counts", () => {
  const f = copyReadFixture();
  for (let seed = 1; seed <= 101; seed++) f.stage(f.copy(`copy-${seed}`, seed));
  const owner = f.receiver.readStore({ reader: "owner" });
  const id = f.copy("A", 1).id;
  const first = owner.readCopyConflicts(id, undefined, { limit: 100 });
  expect(first.data).toHaveLength(100);
  expect(first.hasMore).toBe(true);
  const second = owner.readCopyConflicts(id, undefined, {
    limit: 100,
    cursor: first.nextCursor,
  });
  expect(second.data).toHaveLength(1);
  expect(second.hasMore).toBe(false);
  expect(owner.listStreams([identity.connectionId])[0].copyConflicts).toBe(101);
  expect(owner.readCopyConflicts(id, ["out-of-scope"]).data).toEqual([]);
});

it("includes page metadata and cursors in the response byte budget", () => {
  const f = copyReadFixture();
  const targetEntryBytes = COPY_CONFLICT_READ_LIMITS.totalBytes / 2 - 10;
  const copies = [1, 2].map((seed) => {
    const empty = f.copy("page", seed);
    const entry = {
      id: empty.id,
      copyKey: empty.copyKey,
      reason: "copy_conflict",
      visibility: "conflicted",
      status: "copy conflict",
      connections: [identity.connectionId],
      streams: ["messages"],
      values: empty.envelope.operations,
    };
    const text = "x".repeat(
      targetEntryBytes -
        Buffer.byteLength(JSON.stringify(entry)) +
        empty.record.data.text.length,
    );
    return f.copy("page", seed, [
      registration,
      { ...empty.record, data: { id: "a", text } },
    ]);
  });
  copies.forEach((copy) => f.stage(copy));
  const owner = f.receiver.readStore({ reader: "owner" });
  const first = owner.readCopyConflicts(copies[0].id);
  expect(Buffer.byteLength(JSON.stringify(first))).toBeLessThanOrEqual(
    COPY_CONFLICT_READ_LIMITS.totalBytes,
  );
  expect(first.hasMore).toBe(true);
  const second = owner.readCopyConflicts(copies[0].id, undefined, {
    cursor: first.nextCursor,
  });
  expect(Buffer.byteLength(JSON.stringify(second))).toBeLessThanOrEqual(
    COPY_CONFLICT_READ_LIMITS.totalBytes,
  );
  expect(second.hasMore).toBe(false);
  expect(
    [...first.data, ...second.data].map((copy) => copy.copyKey).sort(),
  ).toEqual(copies.map((copy) => copy.copyKey).sort());
});
