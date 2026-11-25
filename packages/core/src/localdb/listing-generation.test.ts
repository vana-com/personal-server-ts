import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, expect, it, vi } from "vitest";
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

const observed = {
  liveRecord: true,
  explicitDelete: false,
  retryableSkip: false,
  otherSkip: false,
  preflightExclusion: false,
  detailGap: "none" as const,
  invalidDetailCoverage: false,
  failedInDone: false,
};

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

async function open() {
  mkdirSync(join(homedir(), ".tmp"), { recursive: true });
  const root = mkdtempSync(join(homedir(), ".tmp", "listing-generation-"));
  roots.push(root);
  const db = await openLocalDb(driver(join(root, "data.db")), {
    owner,
    network: "test",
    deviceId: "device",
  });
  let op = 0;
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
    {
      resolveArtifact: () => ({
        connector: "fixture",
        version: "1",
        streams: [
          {
            name: "items",
            semantics: "mutable_state" as const,
            primaryKey: ["id"],
            coverageStrategy: "checkpoint_window" as const,
          },
        ],
      }),
    },
  );
  return sync;
}

it("plain owner status distinguishes a reconnect with identical stream head and record count", async () => {
  const sync = await open();
  const request = {
    connector: "fixture",
    artifactDigest: "fixture",
    owner: { address: owner, leaseId: null },
    connect: true as const,
  };
  const importOne = async (run: string) => {
    await sync.intake.begin(run, request);
    await sync.intake.batch(run, {
      batch: 0,
      records: [{ stream: "items", data: { id: "one" } }],
    });
    await sync.intake.end(run, {
      finish: "completed",
      streams: { items: observed },
      checkpoints: { items: { cursor: "a" } },
      lastBatch: 0,
    });
    await sync.publish();
  };
  try {
    await importOne("run-1");
    const first = await sync.listing.status();
    expect(first.connections).toHaveLength(1);
    const before = first.connections[0]!;
    expect(before.control).toBe("active");
    expect(before.streams.items).toMatchObject({ live: true, records: 1 });

    await sync.deleter.requestConnectionDelete("fixture");
    await sync.cycle();
    await importOne("run-2");

    const after = (await sync.listing.status()).connections[0]!;
    // The reconnect is a new generation, yet the stream head and count match.
    expect(after.generation).toBeTypeOf("number");
    expect(after.generation).not.toBe(before.generation);
    expect({ ...after, generation: undefined }).toEqual({
      ...before,
      generation: undefined,
    });
    // No-op reads change nothing.
    const again = await sync.listing.status();
    expect(await sync.listing.status()).toEqual(again);
    // Only the plain status carries it.
    const audited = await sync.listing.status({ audit: true });
    for (const connection of audited.connections)
      expect(Object.hasOwn(connection, "generation")).toBe(false);
  } finally {
    await sync.close();
  }
});
