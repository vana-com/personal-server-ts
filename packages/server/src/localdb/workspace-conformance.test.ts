import { openWorkspace } from "../../../core/dist/localdb/workspace.js";
import { afterEach, expect, it } from "vitest";
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { migrate } from "../../../core/src/localdb/migrate.js";
import {
  createSqlWorkspaceValues,
  runtimeAdmission,
  setWorkspaceAuthority,
  type WorkspaceBinding,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
const b: WorkspaceBinding = {
  owner: "o",
  databaseIncarnation: "db",
  connection: "c",
  generation: 1,
  keyCheck: "key",
  operation: "job",
  expectedHead: "h",
  codecVersion: 1,
};
const cleanup: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const f of cleanup.splice(0).reverse()) await f();
});
async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), "workspace-"));
  cleanup.push(() => rm(dir, { recursive: true, force: true }));
  const db = openBetterSqlite3(join(dir, "db"));
  cleanup.push(() => db.close());
  await migrate(db);
  await db.batch([
    {
      sql: "INSERT INTO db_meta(id,owner,network,device_id,created_at) VALUES(1,'o','test','d',0)",
    },
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,control_state) VALUES('c','test','','active')",
    },
  ]);
  return db;
}
it.each([
  { host: "web", label: "browser host" },
  { host: "phone", label: "phone host" },
] as const)(
  "$label contract persists chunks in main tables; memory databases refuse capability",
  async ({ host }) => {
    const db = await fixture();
    const facade: SqlDriver = { ...db, info: { ...db.info, host } };
    expect(() =>
      createSqlWorkspaceValues(
        { ...facade, info: { ...facade.info, persistent: false } },
        randomUUID,
      ),
    ).toThrow("persistent");
    const ws = await openWorkspace(facade, b),
      values = createSqlWorkspaceValues(facade, randomUUID, 4096);
    const data = Buffer.from([0, 0xff, 0x80, 0x22]);
    const digest = createHash("sha256").update(data).digest("hex");
    const token = await values.begin(b, data.length, digest, "binary");
    const lease = await runtimeAdmission.acquire(b.operation, 65536);
    await values.append(token, 0, data, lease);
    await lease.release();
    const sealed = await values.seal(token);
    expect(sealed.bytes).toBe(data.length);
    expect(
      await db.query("SELECT name FROM sqlite_temp_master WHERE type='table'"),
    ).toEqual([]);
    await setWorkspaceAuthority(db, { ...b, keyCheck: "new-key" });
    await expect(values.status(token)).rejects.toThrow();
    await expect(ws.stage("u", "fold", "k", "v")).rejects.toThrow();
  },
);
it("rolls back receipt and fold when the disk fills during unit promotion", async () => {
  const db = await fixture(),
    ws = await openWorkspace(db, b);
  // Force allocation inside the promotion transaction, not in a fake SQL port.
  for (let i = 0; i < 40; i++)
    await ws.stage("u", "fold", String(i).padStart(4, "0"), "x".repeat(60000));
  const [{ page_count }] = await db.query<{ page_count: number }>(
    "PRAGMA page_count",
  );
  await db.batch([{ sql: `PRAGMA max_page_count=${page_count}` }]);
  await expect(ws.commitUnit("u", "digest", 0)).rejects.toThrow(/full/i);
  expect(await ws.position()).toBe(0);
  expect(await db.query("SELECT * FROM workspace_receipts")).toEqual([]);
  expect(await db.query("SELECT * FROM workspace_cells")).toEqual([]);
  await db.batch([{ sql: "PRAGMA max_page_count=2147483646" }]);
  await ws.commitUnit("u", "digest", 0);
  expect(await ws.position()).toBe(1);
});
it("never sends a candidate with an unreceipted output or accepts a local phase as authority", async () => {
  const db = await fixture(),
    ws = await openWorkspace(db, b);
  await ws.stage("u", "outputs", "object", "digest");
  await ws.commitUnit("u", "d", 0);
  await ws.transition("collect", "folded");
  await ws.transition("folded", "sealed");
  await expect(ws.transition("sealed", "ready")).rejects.toThrow();
  await expect(ws.transition("sent", "accepted")).rejects.toThrow("authority");
  expect((await db.query("SELECT phase FROM workspaces"))[0]).toEqual({
    phase: "sealed",
  });
});
it("fences all subsequent writes after canonical deletion", async () => {
  const db = await fixture(),
    ws = await openWorkspace(db, b);
  await ws.stage("u", "fold", "k", "v");
  await db.batch([{ sql: "UPDATE connections SET control_state='deleted'" }]);
  await expect(ws.commitUnit("u", "d", 0)).rejects.toThrow();
  expect(await ws.position()).toBe(0);
});
it("migration preserves canonical bodies, cursors and pending changes and is idempotent", async () => {
  const { MIGRATIONS } = await import("../../../core/src/localdb/schema.js");
  const dir = await mkdtemp(join(tmpdir(), "workspace-upgrade-"));
  cleanup.push(() => rm(dir, { recursive: true, force: true }));
  const db = openBetterSqlite3(join(dir, "db"));
  cleanup.push(() => db.close());
  for (let i = 0; i < MIGRATIONS.length - 1; i++)
    await db.batch([
      ...MIGRATIONS[i]!.map((sql) => ({ sql })),
      { sql: `PRAGMA user_version=${i + 1}` },
    ]);
  await db.batch([
    {
      sql: "INSERT INTO db_meta(id,owner,network,device_id,created_at) VALUES(1,'o','test','d',0)",
    },
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,control_state) VALUES('c','test','','active')",
    },
    {
      sql: "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES('c','s','hash','[1]',1,'r','{\"id\":1}','digest')",
    },
    { sql: "INSERT INTO log_state VALUES('c',17,0,'[]',NULL)" },
  ]);
  const records = await db.query("SELECT * FROM records"),
    changes = await db.query("SELECT * FROM record_changes"),
    state = await db.query("SELECT * FROM log_state");
  await migrate(db);
  await migrate(db);
  expect(await db.query("SELECT * FROM records")).toEqual(records);
  expect(await db.query("SELECT * FROM record_changes")).toEqual(changes);
  expect(await db.query("SELECT * FROM log_state")).toEqual(state);
});
it("retains sent CAS work after an authority read or local fence; it may still land", async () => {
  const db = await fixture(),
    ws = await openWorkspace(db, b);
  await ws.stage("u", "outputs", "object", "sealed-digest");
  await ws.stage("u", "uploads", "object", "sealed-digest");
  await ws.commitUnit("u", "d", 0);
  await ws.transition("collect", "folded");
  await ws.transition("folded", "sealed");
  await ws.transition("sealed", "ready");
  await ws.markSent(2, "old-head", "candidate-head");
  // A read of the old head cannot prove that the sent CAS will not land later.
  await setWorkspaceAuthority(db, b);
  await expect(ws.discard()).rejects.toThrow();
  // A changed local key or head cannot revoke the request at the remote registry.
  await setWorkspaceAuthority(db, {
    ...b,
    keyCheck: "new",
    expectedHead: "other",
  });
  await expect(ws.discard()).rejects.toThrow();
  await expect(ws.cleanupOne()).rejects.toThrow();
  expect(await db.query("SELECT phase FROM workspaces")).toEqual([
    { phase: "sent" },
  ]);
  expect(
    await db.query(
      "SELECT payload FROM workspace_cells WHERE relation='outputs'",
    ),
  ).toEqual([{ payload: "sealed-digest" }]);
});
