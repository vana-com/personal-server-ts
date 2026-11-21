import { mkdtempSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createMemoryStreamSyncBlobs,
  createMemoryStreamSyncRegistry,
} from "../stream-sync/index.js";
import type { SqlDriver, SqlStatement, SqlValue } from "./driver.js";
import { openLocalDb } from "./open.js";
import { connectionQueue } from "./queue.js";
import { createLocalSync } from "./sync.js";

const owner = `0x${"11".repeat(20)}` as const;

function driver(path: string): SqlDriver {
  const db = new Database(path);
  const execute = (sql: string, params: readonly SqlValue[] = []) => {
    const stmt = db.prepare(sql);
    return stmt.reader ? stmt.all(...params) : stmt.run(...params);
  };
  return {
    info: {
      sqliteVersion: db.prepare("select sqlite_version() as v").get()
        .v as string,
      host: "node",
      persistent: true,
    },
    async query(sql, params) {
      return execute(sql, params) as never;
    },
    async batch(statements: readonly SqlStatement[]) {
      const changes = db.transaction(() =>
        statements.map(({ sql, params }) => {
          const result = execute(sql, params);
          return Array.isArray(result) ? 0 : result.changes;
        }),
      )();
      return { changes };
    },
    async close() {
      db.close();
    },
  };
}

const observed = (liveRecord: boolean) => ({
  liveRecord,
  explicitDelete: false,
  retryableSkip: false,
  otherSkip: false,
  preflightExclusion: false,
  detailGap: "none" as const,
  invalidDetailCoverage: false,
  failedInDone: false,
});

describe("connection checkpoint read", () => {
  const roots: string[] = [];
  afterEach(() => {
    for (const root of roots.splice(0)) {
      rmSync(root, { recursive: true, force: true });
    }
  });

  async function open(version = "1") {
    const root = mkdtempSync(join(homedir(), ".tmp", "connection-checkpoint-"));
    roots.push(root);
    const db = await openLocalDb(driver(join(root, "data.db")), {
      owner,
      network: "test",
      deviceId: "device",
    });
    let op = 0;
    const resolveArtifact = vi.fn(() => ({
      connector: "fixture",
      version,
      streams: [
        {
          name: "items",
          semantics: "mutable_state" as const,
          primaryKey: ["id"],
          coverageStrategy: "checkpoint_window" as const,
        },
        {
          name: "notes",
          semantics: "mutable_state" as const,
          primaryKey: ["id"],
          coverageStrategy: "checkpoint_window" as const,
        },
      ],
    }));
    const sync = createLocalSync(
      {
        db,
        queue: connectionQueue(),
        ownerAddress: owner,
        registry: createMemoryStreamSyncRegistry(),
        blobs: createMemoryStreamSyncBlobs(),
        keys: {
          namespaceHmac: async () => new Uint8Array(32),
          encrypt: async (_s, b) => b,
          encryptPart: async (_s, b) => b,
          decrypt: async (_s, b) => b,
        },
        signer: { signAddData: async () => "0x00" },
        logger: { info: vi.fn(), warn: vi.fn() },
        now: () => 1000,
        newOp: () => `op-${++op}`,
      },
      { resolveArtifact },
    );
    return { db, sync, resolveArtifact };
  }

  const request = {
    connector: "fixture",
    artifactDigest: "fixture",
    owner: { address: owner, leaseId: null },
    connect: true as const,
  };

  it("is null before any run, and for a connector with no connection", async () => {
    const { sync } = await open();
    try {
      expect(await sync.intake.checkpoint?.("fixture")).toBeNull();
      expect(await sync.intake.checkpoint?.("nothing-here")).toBeNull();
    } finally {
      await sync.close();
    }
  });

  it("returns each stream's saved cursor with the connector version that wrote it, without resolving an artifact", async () => {
    const { sync, resolveArtifact } = await open("1.2.0");
    try {
      await sync.intake.begin("run-1", request);
      await sync.intake.batch("run-1", {
        batch: 0,
        records: [
          { stream: "items", data: { id: "one" } },
          { stream: "notes", data: { id: "n1" } },
        ],
      });
      const ended = await sync.intake.end("run-1", {
        finish: "completed",
        streams: { items: observed(true), notes: observed(true) },
        checkpoints: {
          items: { synced_through: "2026-11-20", fingerprints: { one: "h1" } },
          notes: { seen: 1 },
        },
        lastBatch: 0,
      });
      expect(ended.outcome).toBe("succeeded");
      // The cursor travels with the publication; the checkpoint takes it then.
      await sync.publish();
      resolveArtifact.mockClear();

      const checkpoint = await sync.intake.checkpoint?.("fixture");
      expect(checkpoint).toEqual({
        connectionId: expect.any(String),
        streams: {
          items: {
            state: {
              synced_through: "2026-11-20",
              fingerprints: { one: "h1" },
            },
            cursorVersion: "1.2.0",
          },
          notes: { state: { seen: 1 }, cursorVersion: "1.2.0" },
        },
      });
      expect(resolveArtifact).not.toHaveBeenCalled();
      // A read: the next begin still works as before (it replays the same START state).
      const again = await sync.intake.begin("run-2", {
        ...request,
        connect: false,
      });
      expect(again.start.state).toEqual({
        items: { synced_through: "2026-11-20", fingerprints: { one: "h1" } },
        notes: { seen: 1 },
      });
    } finally {
      await sync.close();
    }
  });

  it("leaves out a stream that must be read in full next, and is null once the checkpoint is cleared", async () => {
    const { db, sync } = await open();
    try {
      await sync.intake.begin("run-1", request);
      await sync.intake.batch("run-1", {
        batch: 0,
        records: [
          { stream: "items", data: { id: "one" } },
          { stream: "notes", data: { id: "n1" } },
        ],
      });
      await sync.intake.end("run-1", {
        finish: "completed",
        streams: { items: observed(true), notes: observed(true) },
        checkpoints: { items: { cursor: "a" }, notes: { cursor: "b" } },
        lastBatch: 0,
      });
      await sync.publish();
      const before = await sync.intake.checkpoint?.("fixture");
      expect(Object.keys(before?.streams ?? {}).sort()).toEqual([
        "items",
        "notes",
      ]);
      await db.batch([
        {
          sql: "UPDATE stream_state SET needs_full = 1 WHERE stream = 'items'",
          params: [],
        },
      ]);
      const partial = await sync.intake.checkpoint?.("fixture");
      expect(partial?.streams).toEqual({
        notes: { state: { cursor: "b" }, cursorVersion: "1" },
      });
      await db.batch([
        { sql: "UPDATE connections SET checkpoint = NULL", params: [] },
      ]);
      expect(await sync.intake.checkpoint?.("fixture")).toBeNull();
    } finally {
      await sync.close();
    }
  });
});
