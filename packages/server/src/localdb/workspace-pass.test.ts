import { afterEach, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { openLocalDb } from "../../../core/src/localdb/index.js";
import { openProgressiveLogWorkspace } from "../../../core/src/localdb/workspace-consumer.js";
const cleanup: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const close of cleanup.splice(0).reverse()) await close();
});
it("resumes the durable pass owner but gives completed work a fresh id and preserves the replacement during cleanup", async () => {
  const dir = await mkdtemp(join(tmpdir(), "workspace-pass-"));
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
    expectedHead: "head",
    codecVersion: 1,
  };
  let id = 0;
  const allocate = () => String(++id);
  const ws = await openProgressiveLogWorkspace(db, binding, allocate);
  expect(
    (await openProgressiveLogWorkspace(db, binding, allocate)).binding
      .operation,
  ).toBe(ws.binding.operation);
  const identity = { dataHash: "head", blobName: "blob" },
    meta = {
      stream: "s",
      primaryKey: ["id"],
      profile: { key: null, version: "1" },
      complete: true,
    };
  await ws.partial.initialize({
    start: 0,
    snapshot: true,
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
  await ws.partial.scanned(0, identity);
  await ws.partial.scanned(1, identity);
  const lease = await ws.acquire(128 * 1024 * 1024);
  try {
    await ws.partial.commitPart(
      0,
      { generation: 1, observedAt: 0, streams: [meta], operations: [] },
      identity,
      allocate,
      lease,
    );
    expect(
      (await openProgressiveLogWorkspace(db, binding, allocate)).binding
        .operation,
    ).toBe(ws.binding.operation);
    await ws.partial.commitPart(
      1,
      { generation: 1, observedAt: 0, streams: [meta], operations: [] },
      identity,
      allocate,
      lease,
      { position: 2, base: 2, refs: [], snapshot: null },
    );
  } finally {
    await lease.release();
  }
  // A lost final reply can leave phase=collect even though all parts committed.
  const replacement = await openProgressiveLogWorkspace(db, binding, allocate);
  expect(replacement.binding.operation).not.toBe(ws.binding.operation);
  expect(
    await db.query("SELECT job FROM workspace_jobs WHERE job=?", [
      ws.binding.operation,
    ]),
  ).toEqual([]);
  await expect(ws.unit("stale", "d", 0)).rejects.toThrow();
  while (await ws.cleanupOne()) {
    /* Aborted facts only; the new pointer survives. */
  }
  expect(
    (await openProgressiveLogWorkspace(db, binding, allocate)).binding
      .operation,
  ).toBe(replacement.binding.operation);
});
