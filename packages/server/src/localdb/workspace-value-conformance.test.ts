import { afterEach, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { migrate } from "../../../core/src/localdb/migrate.js";
import {
  openLogWorkspace,
  runtimeAdmission,
  type WorkspaceBinding,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { createWorkspaceValues } from "./workspace-values.js";
const b: WorkspaceBinding = {
  owner: "o",
  databaseIncarnation: "db",
  connection: "c",
  generation: 1,
  keyCheck: "k",
  operation: "op",
  expectedHead: "h",
  codecVersion: 1,
};
const cleanup: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const f of cleanup.splice(0).reverse()) await f();
});
async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), "workspace-values-"));
  cleanup.push(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "db"),
    db = openBetterSqlite3(path);
  cleanup.push(() => db.close().catch(() => {}));
  await db.query("PRAGMA journal_mode=WAL");
  await db.query("PRAGMA synchronous=NORMAL");
  await migrate(db);
  await db.batch([
    {
      sql: "INSERT INTO db_meta(id,owner,network,device_id,created_at) VALUES(1,'o','t','d',0)",
    },
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,control_state) VALUES('c','t','','active')",
    },
  ]);
  await openLogWorkspace(db, b);
  return { db, path };
}
const digest = (v: Uint8Array) => createHash("sha256").update(v).digest("hex");
it("restart resumes append tokens, seals idempotently, and reads an older larger chunk under a smaller frame", async () => {
  const { db, path } = await fixture(),
    values = createWorkspaceValues(db, 1024 * 1024),
    bytes = Buffer.alloc(50000, 0x80);
  const writer = await values.begin(b, bytes.length, digest(bytes), "binary");
  let lease = await runtimeAdmission.acquire("op", 1024 * 1024);
  await values.append(writer, 0, bytes, lease);
  await lease.release();
  await db.close();
  const reopened = openBetterSqlite3(path);
  cleanup.push(() => reopened.close());
  const next = createWorkspaceValues(reopened, 4096);
  expect(await next.status(writer)).toMatchObject({
    offset: 50000,
    sealed: null,
  });
  const token = await next.seal(writer);
  expect(await next.seal(writer)).toEqual(token);
  const hash = createHash("sha256");
  lease = await runtimeAdmission.acquire("op", 65536);
  try {
    for (let at = 0; at < token.bytes;) {
      const unit = await next.read(token, at, lease);
      expect(unit.value.length).toBeLessThanOrEqual(
        Math.floor((4096 - 2048) / 6),
      );
      hash.update(unit.value);
      at += unit.value.length;
      await unit.release();
    }
  } finally {
    await lease.release();
  }
  expect(hash.digest("hex")).toBe(token.sha256);
});
it.each(["digest", "utf8"])(
  "corrupt %s never seals or advances the workspace",
  async (kind) => {
    const { db } = await fixture(),
      values = createWorkspaceValues(db),
      bytes = Buffer.from([0xc3]);
    const writer = await values.begin(
        b,
        1,
        kind === "digest" ? "0".repeat(64) : digest(bytes),
        kind === "utf8" ? "utf8" : "binary",
      ),
      lease = await runtimeAdmission.acquire("op", 65536);
    await values.append(writer, 0, bytes, lease);
    await lease.release();
    await expect(values.seal(writer)).rejects.toThrow();
    expect(await values.status(writer)).toMatchObject({
      offset: 1,
      sealed: null,
    });
    expect(await db.query("SELECT position FROM workspaces")).toEqual([
      { position: 0 },
    ]);
  },
);
it("empty values seal; abort invalidates writers; invalid offsets and stale incarnations reject", async () => {
  const { db } = await fixture(),
    values = createWorkspaceValues(db),
    empty = await values.begin(b, 0, digest(new Uint8Array()), "binary"),
    token = await values.seal(empty),
    lease = await runtimeAdmission.acquire("op", 65536);
  try {
    const unit = await values.read(token, 0, lease);
    expect(unit.value.length).toBe(0);
    await unit.release();
    await expect(values.read(token, -1, lease)).rejects.toThrow();
  } finally {
    await lease.release();
  }
  const writer = await values.begin(b, 1, "0".repeat(64), "binary");
  await values.abort(writer);
  await expect(values.status(writer)).rejects.toThrow();
  await expect(
    values.status({
      ...empty,
      binding: { ...b, databaseIncarnation: "other" },
    }),
  ).rejects.toThrow();
});
it("aggregate durable staging exceeds 64 MiB while every admitted chunk remains bounded", async () => {
  const { db } = await fixture(),
    values = createWorkspaceValues(db, 1024 * 1024),
    part = Buffer.alloc(65536, 7),
    hash = createHash("sha256"),
    count = 1025;
  for (let i = 0; i < count; i++) hash.update(part);
  const writer = await values.begin(
      b,
      count * part.length,
      hash.digest("hex"),
      "binary",
    ),
    lease = await runtimeAdmission.acquire("op", 1024 * 1024);
  try {
    await expect(values.append(writer, 1, part, lease)).rejects.toThrow();
    for (let i = 0; i < count; i++)
      await values.append(writer, i * part.length, part, lease);
  } finally {
    await lease.release();
  }
  const sealed = await values.seal(writer);
  expect(sealed.bytes).toBeGreaterThan(64 * 1024 * 1024);
  expect(
    (
      await db.query("SELECT MAX(length(body)) AS bytes FROM body_value_chunks")
    )[0],
  ).toEqual({ bytes: 65536 });
}, 120000);
