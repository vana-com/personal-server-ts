import { expect, it } from "vitest";
import {
  upsert,
  registration,
  identity,
} from "@opendatalabs/personal-server-ts-core/replication/fixtures";
import { copyReadFixture } from "./pdpp-replica-copy-reads.test-utils.js";

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
    // @ts-expect-error Grant readers have no owner diagnostic capability.
    if (false) grant.readCopyConflicts(a.id);
    expect(owner.readCopyConflicts(a.id)).toEqual(
      keys.sort().map((copyKey) => ({
        copyKey,
        reason: "copy_conflict",
        visibility: "conflicted",
        status: "copy conflict",
        values: [copyKey === a.copyKey ? a.record : b.record],
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
      f.receiver.readStore({ reader: "owner" }).readCopyConflicts(a.id),
    ).toEqual(
      [a.copyKey, b.copyKey].sort().map((copyKey) => ({
        copyKey,
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
    expect(owner.listStreams([other])).toEqual([
      {
        stream: "messages",
        recordCount: 0,
        lastUpdated: null,
        copyConflicts: 1,
      },
    ]);
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

it("refuses oversized values without returning a partial conflict list", () => {
  const f = copyReadFixture();
  const a = f.copy("A".repeat(300_000), 1),
    b = f.copy("B", 2);
  f.stage(a);
  f.stage(b);
  expect(() =>
    f.receiver.readStore({ reader: "owner" }).readCopyConflicts(a.id),
  ).toThrow("Copy conflict diagnostics exceed the read limit");
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

it("hides corrupt rejects and reads copy diagnostics inside one snapshot", () => {
  const f = copyReadFixture();
  const a = f.copy("A", 1),
    b = f.copy("B", 2);
  f.stage({ ...a, fragments: [{ dataHash: "0xZZ", metadataHash: "0x00" }] });
  expect(
    f.receiver.readStore({ reader: "owner" }).readCopyConflicts(a.id),
  ).toEqual([]);
  f.stage(a);
  f.stage(b);
  const prepare = f.db.prepare.bind(f.db);
  const queries: string[] = [];
  f.db.prepare = ((sql: string) => {
    if (sql.includes("pdpp_replica_copies")) {
      expect(f.db.inTransaction).toBe(true);
      queries.push(sql);
    }
    return prepare(sql);
  }) as typeof f.db.prepare;
  try {
    expect(
      f.receiver.readStore({ reader: "owner" }).readCopyConflicts(a.id),
    ).toHaveLength(2);
    expect(queries.length).toBeGreaterThan(0);
  } finally {
    f.db.prepare = prepare;
  }
});

it("limits record operations and envelopes per copy, total bytes, and marker rows without partial output", () => {
  const operations = copyReadFixture();
  const many = Array.from({ length: 257 }, (_, i) => ({
    ...upsert(`op-${i}`, i + 10),
    recordKey: `key-${i}`,
  }));
  const a = operations.copy("A", 1, [registration, ...many]);
  operations.stage(a);
  operations.stage(operations.copy("B", 2));
  expect(() =>
    operations.receiver.readStore({ reader: "owner" }).readCopyConflicts(a.id),
  ).toThrow("Copy conflict diagnostics exceed the read limit");

  const envelope = copyReadFixture();
  const large = envelope.copy("A", 1, [
    registration,
    { ...upsert("large", 10), data: { id: "a", text: "x".repeat(1_100_000) } },
  ]);
  envelope.stage(large);
  envelope.stage(envelope.copy("B", 2));
  expect(() =>
    envelope.receiver
      .readStore({ reader: "owner" })
      .readCopyConflicts(large.id),
  ).toThrow("Copy conflict diagnostics exceed the read limit");
  envelope.receiver.copies.terminate({
    credential: "test",
    id: large.id,
    reason: "finalized_conflict",
  });
  // Terminal diagnostics never read values, so large envelopes do not hide markers.
  expect(
    envelope.receiver
      .readStore({ reader: "owner" })
      .readCopyConflicts(large.id),
  ).toHaveLength(2);
  expect(
    envelope.receiver
      .readStore({ reader: "owner" })
      .readCopyConflicts(large.id, [identity.connectionId]),
  ).toHaveLength(2);

  const total = copyReadFixture();
  for (let seed = 1; seed <= 21; seed++)
    total.stage(
      total.copy("A", seed, [
        registration,
        {
          ...upsert(`total-${seed}`, seed + 10),
          data: { id: "a", text: "x".repeat(210_000) },
        },
      ]),
    );
  expect(() =>
    total.receiver
      .readStore({ reader: "owner" })
      .readCopyConflicts(total.copy("A", 1).id),
  ).toThrow("Copy conflict diagnostics exceed the read limit");

  const count = copyReadFixture();
  for (let seed = 1; seed <= 101; seed++)
    count.stage(count.copy(`copy-${seed}`, seed));
  expect(() =>
    count.receiver
      .readStore({ reader: "owner" })
      .readCopyConflicts(count.copy("A", 1).id),
  ).toThrow("Copy conflict diagnostics exceed the read limit");
  expect(
    count.receiver
      .readStore({ reader: "owner" })
      .listStreams([identity.connectionId])[0].copyConflicts,
  ).toBe(101);
  expect(
    count.receiver
      .readStore({ reader: "owner" })
      .readCopyConflicts(count.copy("A", 1).id, ["out-of-scope"]),
  ).toEqual([]);
});
