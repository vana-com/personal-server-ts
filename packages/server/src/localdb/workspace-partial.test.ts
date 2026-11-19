import { afterEach, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { openLocalDb } from "../../../core/src/localdb/index.js";
import { openLogWorkspace } from "../../../core/src/localdb/workspace-consumer.js";
import { setWorkspaceAuthority } from "../../../core/src/localdb/workspace.js";

const cleanup: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const close of cleanup.splice(0).reverse()) await close();
});
export async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), "workspace-partial-"));
  cleanup.push(() => rm(dir, { recursive: true, force: true }));
  const db = await openLocalDb(openBetterSqlite3(join(dir, "db")), {
    owner: "o",
    network: "test",
    deviceId: "d",
  });
  cleanup.push(() => db.close());
  await db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,control_state) VALUES('c','test','','active')",
    },
  ]);
  const binding = {
    owner: "o",
    databaseIncarnation: "db",
    connection: "c",
    generation: 1,
    keyCheck: "key",
    operation: "partial",
    expectedHead: "head",
    codecVersion: 1,
  };
  const ws = await openLogWorkspace(db, binding);
  return { db, binding, ws };
}
it("indexed removal facts survive eviction, preserve the last removal, and reject a new lineage", async () => {
  const { db, binding, ws } = await fixture();
  await ws.partial.noteKey(0, "s", "k", ["k"], null);
  await ws.partial.noteKey(2, "s", "k", ["k"], { o: 2, r: "r" });
  await ws.partial.noteKey(3, "s", "k", ["k"], null);
  await ws.partial.noteKey(1, "s", "k", ["k"], { o: 1, r: "r" });
  const reopened = await openLogWorkspace(db, binding);
  expect(await reopened.partial.key("s", "k")).toMatchObject({
    lastNamingUnit: 3,
    lastRemovalUnit: 2,
  });
  expect(await reopened.partial.held("s", "k", 0)).toBe(true);
  expect(await reopened.partial.held("s", "k", 2)).toBe(false);
  expect(await reopened.partial.held("s", "k", 3)).toBe(false);
  await setWorkspaceAuthority(db, { ...binding, expectedHead: "other" });
  await expect(reopened.partial.key("s", "k")).rejects.toThrow();
});

it("commits bodies, holdback, markers and receipts together, keeping the snapshot cursor until its last part", async () => {
  const { db, binding, ws } = await fixture();
  const { pkHash } =
    await import("@opendatalabs/personal-server-ts-stream-sync");
  const { sha256 } = await import("@noble/hashes/sha2");
  const hash = await pkHash(async (bytes) => sha256(bytes), { id: "k" }, [
    "id",
  ]);
  const identity = { dataHash: "hash", blobName: "blob" };
  const meta = {
    stream: "s",
    primaryKey: ["id"],
    profile: { key: null, version: "1" },
    complete: true,
  };
  const batch = {
    generation: 1,
    observedAt: 0,
    streams: [meta],
    operations: [
      {
        kind: "upsert" as const,
        stream: "s",
        pkHash: hash,
        stamp: { o: 1, r: "r" },
        firstSeen: null,
        value: { id: "k" },
      },
    ],
  };
  await ws.partial.initialize({
    start: 0,
    snapshot: true,
    total: 3,
    finalIdentity: identity,
    observedAt: 0,
  });
  await ws.partial.name(2, meta, batch, identity, true);
  await ws.partial.noteKey(1, "s", hash, ["k"], { o: 2, r: "r" });
  for (let i = 0; i < 3; i++) await ws.partial.scanned(i, identity);
  const lease = await ws.acquire(128 * 1024 * 1024);
  try {
    await ws.partial.commitPart(0, batch, identity, () => "apply", lease);
    expect(
      await db.query("SELECT parts_applied,parts_total FROM stream_partial"),
    ).toEqual([{ parts_applied: 1, parts_total: 3 }]);
    expect(await db.query("SELECT pk_hash FROM partial_hidden")).toEqual([
      { pk_hash: hash },
    ]);
    expect(await db.query("SELECT position FROM log_state")).toEqual([]);
    const actual = db.batch.bind(db);
    db.batch = async (statements) => {
      if (
        statements.some((s) =>
          s.sql.startsWith("INSERT INTO workspace_receipts"),
        )
      )
        throw new Error("commit refused");
      return actual(statements);
    };
    await expect(
      ws.partial.commitPart(
        1,
        { ...batch, operations: [] },
        identity,
        () => "apply",
        lease,
      ),
    ).rejects.toThrow("commit refused");
    expect(await db.query("SELECT position FROM workspace_receipts")).toEqual([
      { position: 1 },
    ]);
    expect(await db.query("SELECT parts_applied FROM stream_partial")).toEqual([
      { parts_applied: 1 },
    ]);
    db.batch = actual;
    await ws.partial.commitPart(
      1,
      { ...batch, operations: [] },
      identity,
      () => "apply",
      lease,
    );
    const reopened = await openLogWorkspace(db, binding);
    expect(await reopened.partial.applied(0, identity)).toBe(true);
    await reopened.partial.commitPart(
      2,
      {
        ...batch,
        operations: [{ ...batch.operations[0]!, stamp: { o: 3, r: "r" } }],
      },
      identity,
      () => "apply",
      lease,
      { position: 3, base: 3, refs: [], snapshot: null },
    );
    expect(await db.query("SELECT * FROM stream_partial")).toEqual([]);
    expect(await db.query("SELECT * FROM partial_hidden")).toEqual([]);
    expect(await db.query("SELECT position FROM log_state")).toEqual([
      { position: 3 },
    ]);
    expect(
      await db.query("SELECT complete,head_version FROM stream_state"),
    ).toEqual([{ complete: 1, head_version: 1 }]);
  } finally {
    await lease.release();
  }
});

it("holds only later removals of the same stream and durably refuses an oversized referenced record", async () => {
  const { db, ws } = await fixture();
  await ws.partial.noteKeys(3, [
    { stream: "a", pkHash: "k1", key: ["k1"], removal: { o: 1, r: "r" } },
    { stream: "a", pkHash: "k2", key: ["k2"], removal: { o: 2, r: "r" } },
    { stream: "b", pkHash: "k1", key: ["k1"], removal: { o: 3, r: "r" } },
  ]);
  expect(await ws.partial.held("a", "k1", 1)).toBe(true);
  expect(await ws.partial.held("a", "k1", 3)).toBe(false);
  expect(await ws.partial.held("a", "k1", 5)).toBe(false);
  expect(await ws.partial.held("b", "k2", 1)).toBe(false);
  expect(await ws.partial.held("a", "missing", 1)).toBe(false);
  const lease = await ws.acquire(128 * 1024 * 1024);
  try {
    await expect(
      ws.partial.admitRecord(65 * 1024 * 1024, lease),
    ).rejects.toMatchObject({ reason: "admission", retryable: true });
    expect(
      await db.query(
        "SELECT state,reason FROM workspace_attempts WHERE unit='record'",
      ),
    ).toEqual([{ state: "failed", reason: "admission" }]);
    expect(await db.query("SELECT position FROM workspace_receipts")).toEqual(
      [],
    );
  } finally {
    await lease.release();
  }
});

it("rejects a gap in the preliminary scan without certifying completion", async () => {
  const { db, ws } = await fixture();
  await expect(
    ws.partial.scanned(1, { dataHash: "h1", blobName: "b1" }),
  ).rejects.toThrow();
  expect(
    await db.query(
      "SELECT key FROM workspace_cells WHERE relation='partial-parts'",
    ),
  ).toEqual([]);
});

it("last naming stores batch identity scalars without serializing the batch body", async () => {
  const { db, ws } = await fixture();
  const identity = { dataHash: "hash", blobName: "blob" };
  await ws.partial.initialize({
    start: 0,
    snapshot: false,
    total: 1,
    finalIdentity: identity,
    observedAt: 0,
  });
  const batch = {
    generation: 1,
    observedAt: 42,
    operations: [{ value: { pad: "x".repeat(1024 * 1024) } }],
  };
  await ws.partial.name(
    0,
    {
      stream: "s",
      primaryKey: ["id"],
      profile: { key: null, version: "1" },
      complete: true,
    },
    batch,
    identity,
    true,
  );
  const row = (
    await db.query<{ payload: string }>(
      "SELECT payload FROM workspace_partial_streams",
    )
  )[0]!;
  expect(JSON.parse(row.payload).batch).toEqual({
    generation: 1,
    observedAt: 42,
  });
  expect(row.payload.length).toBeLessThan(1024);
});

it("updates an already complete stream without creating first-load holdback", async () => {
  const { db, ws } = await fixture();
  const { pkHash } =
    await import("@opendatalabs/personal-server-ts-stream-sync");
  const { sha256 } = await import("@noble/hashes/sha2");
  const hash = await pkHash(async (b) => sha256(b), { id: "k" }, ["id"]);
  await db.batch([
    {
      sql: "INSERT INTO stream_state(connection_id,stream,primary_key,semantics,incremental,complete,head_generation,head_version) VALUES('c','s','[\"id\"]','mutable_state',1,1,1,1)",
    },
  ]);
  const identity = { dataHash: "head", blobName: "blob" },
    meta = {
      stream: "s",
      primaryKey: ["id"],
      profile: { key: null, version: "1" },
      complete: true,
    };
  await ws.partial.initialize({
    start: 0,
    snapshot: false,
    total: 2,
    finalIdentity: identity,
    observedAt: 0,
  });
  await ws.partial.name(
    1,
    meta,
    { generation: 1, observedAt: 0 },
    identity,
    true,
  );
  await ws.partial.noteKey(1, "s", hash, ["k"], { o: 2, r: "r" });
  await ws.partial.scanned(0, identity);
  await ws.partial.scanned(1, identity);
  const lease = await ws.acquire(128 * 1024 * 1024);
  try {
    await ws.partial.commitPart(
      0,
      {
        generation: 1,
        observedAt: 0,
        streams: [meta],
        operations: [
          {
            kind: "upsert",
            stream: "s",
            pkHash: hash,
            stamp: { o: 1, r: "r" },
            firstSeen: null,
            value: { id: "k" },
          },
        ],
      },
      identity,
      () => "u",
      lease,
    );
    expect(await db.query("SELECT * FROM partial_hidden")).toEqual([]);
  } finally {
    await lease.release();
  }
});
