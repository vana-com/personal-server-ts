import { afterEach, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import { createImportLedger } from "../../../core/src/localdb/import-ledger.js";
import { importLegacySource } from "../../../core/src/localdb/legacy-import.js";
import { readBackLegacyImport } from "../../../core/src/localdb/import-readback.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { ImportSource } from "../../../core/src/localdb/legacy-import-types.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
const dbs = new Set<SqlDriver>();
const dirs: string[] = [];
afterEach(async () => {
  for (const db of dbs) await db.close();
  dbs.clear();
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});
const payload = {
  id: "account",
  display_name: "Example",
  uri: "uri",
  followers: 1,
  following: 2,
  images: [],
};
async function fixture(path = ":memory:") {
  const db = await openLocalDb(openBetterSqlite3(path), {
    owner: "0xabc",
    network: "test",
    deviceId: "fixture",
  });
  dbs.add(db);
  await db.batch([
    {
      sql: "INSERT OR IGNORE INTO connections (connection_id,connector,ns,generation,control_state) VALUES ('connection','profile-source','known',1,'active')",
    },
  ]);
  const unexpected = async (): Promise<never> => {
    throw new Error("unexpected external call");
  };
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    queue: connectionQueue(),
    ownerAddress: "0xabc",
    registry: {
      read: unexpected,
      post: unexpected,
      listControlRows: unexpected,
      listStreamRows: unexpected,
    },
    blobs: { get: unexpected, put: unexpected },
    keys: {
      namespaceHmac: unexpected,
      encrypt: unexpected,
      encryptPart: unexpected,
      decrypt: unexpected,
    },
    signer: { signAddData: unexpected },
    logger: { info() {}, warn() {} },
    now: () => 1,
    newOp: () => `proof-${++op}`,
  };
  const source: ImportSource = {
    source: "fixture",
    owner: "0xabc",
    network: "test",
    revision: "revision",
    target: {
      connectionId: "connection",
      connector: "profile-source",
      stream: "profile",
      primaryKey: ["id"],
      semantics: "mutable_state",
      incremental: true,
    },
    exclusions: [],
    async *records() {
      yield { ...payload };
    },
  };
  const run = () => readBackLegacyImport(deps, source);
  return {
    db,
    deps,
    source,
    run,
    import: () => importLegacySource(deps, createImportLedger(db), source),
  };
}
it("readback verifies the seed without a projection or file proof", async () => {
  const f = await fixture();
  await f.import();
  expect((await f.run()).pass).toBe(true);
  await f.db.batch([
    { sql: "UPDATE records SET body_sha256 = ?", params: ["f".repeat(64)] },
  ]);
  expect(await f.run()).toMatchObject({
    pass: false,
    reason: "stored_row_invalid",
  });
});
it("readback-newer-different-row-succeeds", async () => {
  const f = await fixture();
  await f.import();
  const { canonicalImportRow } =
    await import("../../../core/src/localdb/import-snapshot.js");
  const row = await canonicalImportRow(
    { ...payload, display_name: "Changed" },
    ["id"],
  );
  await f.db.batch([
    {
      sql: "UPDATE records SET body = ?, body_sha256 = ?, stamp_o = 99",
      params: [row.body, row.body_sha256],
    },
  ]);
  expect((await f.run()).pass).toBe(true);
});

it("readback reports missing receipts and rows as bugs", async () => {
  const f = await fixture();
  expect(await f.run()).toMatchObject({
    pass: false,
    reason: "missing_receipt",
  });
  await f.import();
  await f.db.batch([{ sql: "DELETE FROM records" }]);
  expect(await f.run()).toMatchObject({
    pass: false,
    reason: "record_mismatch",
  });
});
it("a different valid database value succeeds regardless of its stamp", async () => {
  const f = await fixture();
  await f.import();
  const { canonicalImportRow } =
    await import("../../../core/src/localdb/import-snapshot.js");
  const row = await canonicalImportRow(
    { ...payload, display_name: "authoritative database value" },
    ["id"],
  );
  await f.db.batch([
    {
      sql: "UPDATE records SET body = ?, body_sha256 = ?",
      params: [row.body, row.body_sha256],
    },
  ]);
  expect((await f.run()).pass).toBe(true);
});
it("readback does not write proof status and survives reopen", async () => {
  const dir = mkdtempSync(join(process.cwd(), ".import-readback-test-"));
  dirs.push(dir);
  const path = join(dir, "db.sqlite");
  const first = await fixture(path);
  await first.import();
  await first.db.close();
  dbs.delete(first.db);
  const f = await fixture(path);
  const before = await f.db.query("SELECT * FROM import_ledger");
  expect((await f.run()).pass).toBe(true);
  expect(await f.db.query("SELECT * FROM import_ledger")).toEqual(before);
  expect(await f.db.query("SELECT * FROM import_snapshot")).toEqual([]);
});
it("readback detects a changed immutable source", async () => {
  const f = await fixture();
  await f.import();
  f.source.records = async function* () {
    yield { ...payload, extra: 1 };
  };
  expect(await f.run()).toMatchObject({
    pass: false,
    reason: "source_changed",
  });
});
