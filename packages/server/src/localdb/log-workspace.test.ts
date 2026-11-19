import { afterEach, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { migrate } from "../../../core/src/localdb/migrate.js";
import {
  openWorkspace,
  runtimeAdmission,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { createWorkspaceValues } from "./workspace-values.js";
import type { WorkspaceBinding } from "../../../core/src/localdb/index.js";

const binding: WorkspaceBinding = {
  owner: "owner",
  databaseIncarnation: "db-1",
  connection: "c",
  generation: 1,
  keyCheck: "key",
  operation: "op",
  expectedHead: "head",
  codecVersion: 1,
};
const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const close of cleanups.splice(0).reverse()) await close();
});
async function fixture() {
  const path = await mkdtemp(join(tmpdir(), "workspace-"));
  cleanups.push(() => rm(path, { recursive: true, force: true }));
  const db = openBetterSqlite3(join(path, "db.sqlite"));
  cleanups.push(() => db.close());
  await migrate(db);
  await db.batch([
    {
      sql: "INSERT INTO db_meta(id,owner,network,device_id,created_at) VALUES(1,'owner','test','device',0)",
    },
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state) VALUES('c','test','',1,'active')",
    },
  ]);
  const ws = await openWorkspace(db, binding);
  return { db, ws };
}
it("commits fold data and receipt together, refuses gaps and conflicting replay", async () => {
  const { db, ws } = await fixture();
  await ws.stage("u1", "fold", "s/key/up", '{"first_o":null}');
  await expect(ws.commitUnit("u1", "digest", 1)).rejects.toThrow();
  expect(await ws.position()).toBe(0);
  await ws.commitUnit("u1", "digest", 0);
  expect(await ws.position()).toBe(1);
  await ws.commitUnit("u1", "digest", 0);
  await expect(ws.commitUnit("u1", "other", 0)).rejects.toThrow();
  expect(await db.query("SELECT payload FROM workspace_cells")).toEqual([
    { payload: '{"first_o":null}' },
  ]);
});
it("refuses live cleanup and fences deletion and generation changes", async () => {
  const { db, ws } = await fixture();
  await ws.stage("u", "fold", "key", "winner");
  await ws.commitUnit("u", "d", 0);
  await expect(ws.cleanupOne()).rejects.toThrow();
  await db.batch([
    { sql: "UPDATE connections SET generation=2 WHERE connection_id='c'" },
  ]);
  await expect(ws.stage("v", "fold", "key", "stale")).rejects.toThrow();
  await expect(
    openWorkspace(db, { ...binding, keyCheck: "changed" }),
  ).rejects.toThrow();
  expect(await ws.position()).toBe(1);
  await ws.discard();
  while (await ws.cleanupOne()) {
    /* indexed one-row cleanup */
  }
  expect(await db.query("SELECT * FROM workspace_cells")).toEqual([]);
});
it("owns one cursor row until release and uses an indexed keyset", async () => {
  const { db, ws } = await fixture();
  for (const key of ["b", "a", "c"])
    await ws.stage("u", "membership", key, key);
  await ws.commitUnit("u", "d", 0);
  const lease = await runtimeAdmission.acquire("op", 2097152);
  try {
    const cursor = ws.cursor("membership");
    const first = await cursor.next(lease);
    expect(first?.value.key).toBe("a");
    await expect(cursor.next(lease)).rejects.toThrow();
    await expect(lease.release()).rejects.toThrow("owned");
    await first!.release();
    expect((await cursor.next(lease))?.value.key).toBe("b");
    await cursor.close();
    const plans = await db.query<{ detail: string }>(
      "EXPLAIN QUERY PLAN SELECT key,payload FROM workspace_cells WHERE operation=? AND relation=? AND key>? ORDER BY key LIMIT 1",
      ["op", "membership", ""],
    );
    expect(plans.some((p) => p.detail.includes("TEMP B-TREE"))).toBe(false);
  } finally {
    await lease.release();
  }
});
it("keeps waiters as durable ids and admits only one runtime job", async () => {
  const { db } = await fixture();
  await runtimeAdmission.enqueue(db, "first");
  await runtimeAdmission.enqueue(db, "second");
  const lease = await runtimeAdmission.acquire("first", 4096);
  await expect(runtimeAdmission.acquire("second", 4096)).rejects.toThrow(
    "busy",
  );
  expect(await runtimeAdmission.nextWaiting(db, 0)).toMatchObject({
    job: "first",
  });
  await lease.release();
  await runtimeAdmission.finish(db, "first");
  expect(await runtimeAdmission.nextWaiting(db, 0)).toMatchObject({
    job: "second",
  });
});
it("spools split UTF-8, retries exact chunks, seals by digest and bounds reads", async () => {
  const { db } = await fixture();
  const values = createWorkspaceValues(db, 4096);
  const bytes = Buffer.from('é\\"hello');
  const hash = createHash("sha256").update(bytes).digest("hex");
  const token = await values.begin(binding, bytes.length, hash, "utf8");
  const lease = await runtimeAdmission.acquire("op", 2097152);
  try {
    await values.append(token, 0, bytes.subarray(0, 1), lease);
    await values.append(token, 0, bytes.subarray(0, 1), lease);
    await expect(
      values.append(token, 0, Buffer.from("x"), lease),
    ).rejects.toThrow();
    await expect(values.seal(token)).rejects.toThrow();
    await values.append(token, 1, bytes.subarray(1), lease);
    await lease.release();
    const sealed = await values.seal(token);
    const readLease = await runtimeAdmission.acquire("op", 2097152);
    expect((await values.status(token)).sealed).toEqual(sealed);
    const chunk = await values.read(sealed, 0, readLease);
    expect([...chunk.value]).toEqual([...bytes.subarray(0, 1)]);
    await expect(values.read(sealed, 1, readLease)).rejects.toThrow();
    await chunk.release();
    await expect(values.abort(token)).rejects.toThrow();
    await readLease.release();
  } finally {
    await lease.release();
  }
});
