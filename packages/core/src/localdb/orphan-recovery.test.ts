import { mkdtempSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { describe, expect, it, vi } from "vitest";
import { streamSyncFlagsOn } from "../stream-sync/design-flags.js";
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

const modes = [false, true].flatMap((log) =>
  [false, true].flatMap((publish) =>
    [false, true].map((progressive) => ({ log, publish, progressive })),
  ),
);

describe.each(modes)("orphan recovery %j", ({ log, publish, progressive }) => {
  it("ends a lost producer but preserves a live producer", async () => {
    const root = mkdtempSync(join(homedir(), ".tmp", "orphan-recovery-"));
    const path = join(root, "data.db");
    const flags = streamSyncFlagsOn(log ? "logProtocol" : undefined);
    const open = async () => {
      const db = await openLocalDb(driver(path), {
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
          publishWhileCollecting: publish || flags.publishWhileCollecting,
          progressiveFirstLoad: progressive || flags.progressiveFirstLoad,
        },
        {
          resolveArtifact: () => ({
            connector: "fixture",
            version: "1",
            streams: [
              {
                name: "items",
                semantics: "mutable_state",
                primaryKey: ["id"],
                coverageStrategy: "checkpoint_window",
              },
            ],
          }),
        },
      );
      return { db, sync };
    };
    const request = {
      connector: "fixture",
      artifactDigest: "fixture",
      owner: { address: owner, leaseId: null },
    };
    let current: Awaited<ReturnType<typeof open>> | undefined;
    try {
      current = await open();
      await current.sync.intake.begin("lost", request);
      await current.sync.intake.batch("lost", {
        batch: 0,
        records: [{ stream: "items", data: { id: "one" } }],
      });
      await current.sync.close();
      current = await open();
      await current.sync.intake.begin("live", request);
      expect(
        await current.db.query(
          "SELECT run_id, state FROM runs ORDER BY run_id",
        ),
      ).toEqual([
        { run_id: "live", state: "collecting" },
        { run_id: "lost", state: "ended" },
      ]);
      expect(
        await current.db.query(
          "SELECT decision, reason FROM run_streams WHERE run_id = 'lost'",
        ),
      ).toEqual([{ decision: "discarded", reason: "failed" }]);
      expect(await current.sync.intake.end("lost", {})).toMatchObject({
        result: "aborted",
      });
      await current.sync.intake.begin("later", request);
      expect(
        await current.db.query("SELECT state FROM runs WHERE run_id = 'live'"),
      ).toEqual([{ state: "collecting" }]);
      await expect(
        current.sync.intake.batch("live", {
          batch: 0,
          records: [{ stream: "items", data: { id: "live" } }],
        }),
      ).resolves.toBeDefined();
    } finally {
      await current?.sync.close();
      rmSync(root, { recursive: true, force: true });
    }
  });
});
