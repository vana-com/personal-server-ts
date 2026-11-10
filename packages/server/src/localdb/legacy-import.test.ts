import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";
import { afterEach, expect, it, vi } from "vitest";
import { importLegacySource } from "../../../core/src/localdb/legacy-import.js";
import { createImportLedger } from "../../../core/src/localdb/import-ledger.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { ImportSource } from "../../../core/src/localdb/legacy-import-types.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const dbs: SqlDriver[] = [];
const dirs: string[] = [];
afterEach(async () => {
  for (const db of dbs.splice(0)) await db.close();
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});
async function fixture(path = ":memory:") {
  const db = await openLocalDb(openBetterSqlite3(path), {
    owner: "0xabc",
    network: "test",
    deviceId: "device",
  });
  dbs.push(db);
  await db.batch([
    {
      sql: "INSERT OR IGNORE INTO connections (connection_id, connector, ns, generation, control_state) VALUES ('connection', 'fixture', 'known', 1, 'active')",
    },
  ]);
  const unused = vi.fn(async (): Promise<never> => {
    throw new Error("unexpected network");
  });
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    queue: connectionQueue(),
    ownerAddress: "0xabc",
    registry: {
      read: unused,
      post: unused,
      listControlRows: unused,
      listStreamRows: unused,
    },
    blobs: { get: unused, put: unused },
    keys: {
      namespaceHmac: unused,
      encrypt: unused,
      encryptPart: unused,
      decrypt: unused,
    },
    signer: { signAddData: unused },
    logger: { info() {}, warn() {} },
    now: () => 123,
    newOp: () => `op-${++op}`,
  };
  let values: Record<string, unknown>[] = [
    { id: "b", text: "two" },
    { id: "a", text: "one" },
  ];
  const source: ImportSource = {
    source: "fixture-revision",
    owner: "0xabc",
    network: "test",
    revision: "revision",
    target: {
      connectionId: "connection",
      connector: "fixture",
      stream: "items",
      primaryKey: ["id"],
      semantics: "mutable_state",
      incremental: true,
    },
    exclusions: [],
    async *records() {
      yield* values;
    },
  };
  const ledger = createImportLedger(db);
  return {
    db,
    deps,
    source,
    ledger,
    unused,
    setValues: (next: typeof values) => {
      values = next;
    },
    run: () => importLegacySource(deps, ledger, source),
  };
}
it("import-stamp-zero-first-o-null", async () => {
  const f = await fixture();
  expect((await f.run()).kind).toBe("imported");
  expect(
    await f.db.query(
      "SELECT record_key, stamp_o, stamp_r, first_o FROM records ORDER BY record_key",
    ),
  ).toEqual([
    { record_key: "a", stamp_o: 0, stamp_r: "seed", first_o: null },
    { record_key: "b", stamp_o: 0, stamp_r: "seed", first_o: null },
  ]);
  expect(
    await f.db.query("SELECT DISTINCT origin FROM record_changes"),
  ).toEqual([{ origin: "import" }]);
});

it("import-already-imported-idempotent", async () => {
  const f = await fixture();
  const first = await f.run();
  expect(first.kind).toBe("imported");
  const before = await f.db.query("SELECT * FROM record_changes");
  expect((await f.run()).kind).toBe("already-imported");
  expect(await f.db.query("SELECT * FROM record_changes")).toEqual(before);
  expect(await f.db.query("SELECT highest_seq FROM import_ledger")).toEqual([
    { highest_seq: 2 },
  ]);
});
it("import-after-local-delete-refuses", async () => {
  for (const sql of [
    "UPDATE connections SET control_state = 'deleted'",
    "UPDATE connections SET deleted_at = 1",
    "INSERT INTO delete_intents VALUES ('fixture','delete','{}')",
  ]) {
    const f = await fixture();
    const id = controlScope("fixture", "");
    await f.db.batch([
      {
        sql: "UPDATE connections SET connection_id = ?, ns = ''",
        params: [id],
      },
    ]);
    Object.assign(f.source.target, { connectionId: id });
    await f.db.batch([{ sql }]);
    expect(await f.run()).toEqual({
      kind: "refused",
      reason: "connection_deleted",
    });
    expect(f.unused).not.toHaveBeenCalled();
    expect(await f.db.query("SELECT * FROM records")).toEqual([]);
  }
});
it("import-generation-one-only", async () => {
  const f = await fixture();
  await f.db.batch([{ sql: "UPDATE connections SET generation = 2" }]);
  expect(await f.run()).toEqual({
    kind: "refused",
    reason: "generation_not_one",
  });
});
it("import-newer-row-wins", async () => {
  const f = await fixture();
  await f.run();
  await f.db.batch([
    {
      sql: 'UPDATE records SET stamp_o = 9, stamp_r = \'new\', body = \'{"id":"a","text":"new"}\' WHERE record_key = \'a\'',
    },
  ]);
  const before = await f.db.query("SELECT count(*) AS n FROM record_changes");
  await f.run();
  expect(
    await f.db.query(
      "SELECT body, stamp_o, first_o FROM records WHERE record_key = 'a'",
    ),
  ).toEqual([{ body: '{"id":"a","text":"new"}', stamp_o: 9, first_o: null }]);
  expect(await f.db.query("SELECT count(*) AS n FROM record_changes")).toEqual(
    before,
  );
});
it("import-batch-4mib", async () => {
  const f = await fixture();
  f.setValues(
    Array.from({ length: 3 }, (_, i) => ({
      id: String(i),
      text: "é".repeat(600_000),
    })),
  );
  const batch = f.db.batch.bind(f.db);
  f.db.batch = async (statements) => {
    expect(Buffer.byteLength(JSON.stringify(statements))).toBeLessThanOrEqual(
      4 * 1024 * 1024,
    );
    return batch(statements);
  };
  expect((await f.run()).kind).toBe("imported");
  f.setValues([{ id: "oversize", text: "x".repeat(4 * 1024 * 1024) }]);
  expect(await f.run()).toEqual({ kind: "refused", reason: "invalid_record" });
});
it("import-crash-resume-idempotent", async () => {
  const f = await fixture();
  const batch = f.db.batch.bind(f.db);
  let merges = 0;
  f.db.batch = async (statements) => {
    if (
      statements.some((s) => s.sql.startsWith("INSERT INTO records")) &&
      ++merges === 2
    )
      throw new Error("crash");
    return batch(statements);
  };
  await expect(f.run()).rejects.toThrow("crash");
  expect(await f.db.query("SELECT count(*) AS n FROM records")).toEqual([
    { n: 1 },
  ]);
  expect(await f.db.query("SELECT * FROM import_ledger")).toEqual([]);
  f.db.batch = batch;
  expect((await f.run()).kind).toBe("imported");
  expect(await f.db.query("SELECT count(*) AS n FROM record_changes")).toEqual([
    { n: 2 },
  ]);
  expect(await f.db.query("SELECT highest_seq FROM import_ledger")).toEqual([
    { highest_seq: 2 },
  ]);
});
it("import-delete-between-batches-refuses", async () => {
  const f = await fixture();
  const batch = f.db.batch.bind(f.db);
  let deleted = false;
  f.db.batch = async (statements) => {
    const result = await batch(statements);
    if (
      !deleted &&
      statements.some((s) => s.sql.startsWith("INSERT INTO records"))
    ) {
      deleted = true;
      await batch([
        { sql: "INSERT INTO delete_intents VALUES ('fixture','delete','{}')" },
      ]);
    }
    return result;
  };
  expect(await f.run()).toEqual({
    kind: "refused",
    reason: "connection_deleted",
  });
  expect(await f.db.query("SELECT count(*) AS n FROM record_changes")).toEqual([
    { n: 1 },
  ]);
  expect(await f.db.query("SELECT * FROM import_ledger")).toEqual([]);
});
it("import-source-revision-changed-refuses", async () => {
  const f = await fixture();
  let passes = 0;
  f.source.records = async function* () {
    if (++passes > 1) throw new Error("source_changed");
    yield { id: "a" };
  };
  expect(await f.run()).toEqual({ kind: "refused", reason: "source_changed" });
  expect(await f.db.query("SELECT * FROM import_ledger")).toEqual([]);
});

it("import-owner-network-unknown-and-exclusions-refuse", async () => {
  for (const field of ["owner", "network"] as const) {
    const f = await fixture();
    expect(
      await importLegacySource(f.deps, f.ledger, {
        ...f.source,
        [field]: "other",
      }),
    ).toEqual({ kind: "refused", reason: "owner_mismatch" });
    expect(await f.db.query("SELECT * FROM records")).toEqual([]);
  }
  const f = await fixture();
  expect(
    await importLegacySource(f.deps, f.ledger, {
      ...f.source,
      target: { ...f.source.target, connectionId: "unknown" },
    }),
  ).toEqual({ kind: "refused", reason: "unknown_control" });
  expect(
    await importLegacySource(f.deps, f.ledger, {
      ...f.source,
      exclusions: [{ reason: "unmapped", rows: 1 }],
    }),
  ).toEqual({ kind: "refused", reason: "invalid_record" });
  expect(f.unused).not.toHaveBeenCalled();
});
it("import-stream-delete-floor-refuses", async () => {
  const f = await fixture();
  await f.run();
  await f.db.batch([
    {
      sql: "UPDATE stream_state SET floor_o = 1, floor_r = 'delete', floor_version = '1'",
    },
  ]);
  expect(await f.run()).toEqual({
    kind: "refused",
    reason: "connection_deleted",
  });
});
it("import-atomic-final-receipt-failure-is-retryable", async () => {
  const f = await fixture();
  const statements = f.ledger.statements;
  f.ledger.statements = (receipt) => [
    ...statements(receipt),
    { sql: "INSERT INTO write_ctx (id, origin) VALUES (1, 'import')" },
  ];
  await expect(f.run()).rejects.toThrow();
  expect(await f.db.query("SELECT * FROM import_ledger")).toEqual([]);
  expect(await f.db.query("SELECT origin FROM write_ctx")).toEqual([
    { origin: "local" },
  ]);
  f.ledger.statements = statements;
  expect((await f.run()).kind).toBe("imported");
  expect(await f.db.query("SELECT count(*) AS n FROM record_changes")).toEqual([
    { n: 2 },
  ]);
});
it("import-reopen-replay-preserves-receipt-and-sequence", async () => {
  const dir = mkdtempSync(join(process.cwd(), ".legacy-import-test-"));
  dirs.push(dir);
  const path = join(dir, "db.sqlite");
  const first = await fixture(path);
  await first.run();
  await first.db.close();
  dbs.splice(dbs.indexOf(first.db), 1);
  const reopened = await fixture(path);
  expect((await reopened.run()).kind).toBe("already-imported");
  expect(
    await reopened.db.query("SELECT highest_seq FROM import_ledger"),
  ).toEqual([{ highest_seq: 2 }]);
  expect(
    await reopened.db.query("SELECT count(*) AS n FROM record_changes"),
  ).toEqual([{ n: 2 }]);
});
it("import-conflicting-duplicates-refuse-and-identical-deduplicate", async () => {
  const f = await fixture();
  f.setValues([
    { id: "a", value: 1 },
    { id: "a", value: 2 },
  ]);
  expect(await f.run()).toEqual({ kind: "refused", reason: "invalid_record" });
  expect(await f.db.query("SELECT * FROM records")).toEqual([]);
  f.setValues([
    { id: "a", value: 1 },
    { id: "a", value: 1 },
  ]);
  expect((await f.run()).kind).toBe("imported");
  expect(await f.db.query("SELECT rows FROM import_ledger")).toEqual([
    { rows: 1 },
  ]);
});
it("import-transaction-fence-closes-check-commit-race", async () => {
  const f = await fixture();
  const batch = f.db.batch.bind(f.db);
  let changed = false;
  f.db.batch = async (statements) => {
    if (
      !changed &&
      statements.some((s) => s.sql.startsWith("INSERT INTO records"))
    ) {
      changed = true;
      await batch([
        { sql: "UPDATE connections SET control_state = 'deleted'" },
      ]);
    }
    return batch(statements);
  };
  expect(await f.run()).toEqual({
    kind: "refused",
    reason: "connection_deleted",
  });
  expect(await f.db.query("SELECT * FROM records")).toEqual([]);
  expect(await f.db.query("SELECT * FROM import_ledger")).toEqual([]);
});
it("import-declaration-drift-refuses", async () => {
  const f = await fixture();
  await f.run();
  const changed = {
    ...f.source,
    target: { ...f.source.target, primaryKey: ["other"] },
  };
  f.setValues([{ id: "c", other: "new" }]);
  expect(await importLegacySource(f.deps, f.ledger, changed)).toEqual({
    kind: "refused",
    reason: "invalid_record",
  });
  expect(await f.db.query("SELECT count(*) AS n FROM records")).toEqual([
    { n: 2 },
  ]);
});
it("import-typed-key-collision-refuses", async () => {
  const f = await fixture();
  f.setValues([{ id: 1 }, { id: "1" }]);
  expect(await f.run()).toEqual({ kind: "refused", reason: "invalid_record" });
  expect(await f.db.query("SELECT * FROM import_ledger")).toEqual([]);
});

it("import-independent-key-body-and-fingerprint-oracle", async () => {
  const f = await fixture();
  const result = await f.run();
  const hash = (text: string) =>
    createHash("sha256").update(text).digest("hex");
  const expected = [
    { record_key: "a", body: '{"id":"a","text":"one"}' },
    { record_key: "b", body: '{"id":"b","text":"two"}' },
  ]
    .map((row) => ({
      ...row,
      pk_hash: hash(JSON.stringify([row.record_key])),
      body_sha256: hash(row.body),
    }))
    .sort((a, b) => (a.pk_hash < b.pk_hash ? -1 : 1));
  expect(
    await f.db.query(
      "SELECT record_key, body, pk_hash, body_sha256 FROM records ORDER BY pk_hash",
    ),
  ).toEqual(expected);
  const digest = createHash("sha256");
  for (const row of expected)
    for (const value of [row.pk_hash, row.body_sha256])
      digest.update(Buffer.from([0, 0, 0, 64])).update(value, "ascii");
  expect(result).toMatchObject({
    receipt: { rows: 2, fingerprint: digest.digest("hex") },
  });
});
it("import-preserves-unrelated-operation-staging", async () => {
  const f = await fixture();
  await f.db.batch([
    {
      sql: "INSERT INTO incoming (op, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o) VALUES ('unrelated','elsewhere','hash','key',1,'run','{}','body-hash',NULL)",
    },
  ]);
  await f.run();
  expect(await f.db.query("SELECT op FROM incoming")).toEqual([
    { op: "unrelated" },
  ]);
  expect(await f.db.query("SELECT * FROM import_snapshot")).toEqual([]);
});
