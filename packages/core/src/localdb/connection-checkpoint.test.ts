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

  async function open(
    version = "1",
    shared: {
      registry?: ReturnType<typeof createMemoryStreamSyncRegistry>;
      blobs?: ReturnType<typeof createMemoryStreamSyncBlobs>;
    } = {},
  ) {
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
        registry: shared.registry ?? createMemoryStreamSyncRegistry(),
        blobs: shared.blobs ?? createMemoryStreamSyncBlobs(),
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

  it("sees a connection another device deleted, through the registry, instead of its own stale checkpoint", async () => {
    const registry = createMemoryStreamSyncRegistry();
    const blobs = createMemoryStreamSyncBlobs();
    const here = await open("1", { registry, blobs });
    const elsewhere = await open("1", { registry, blobs });
    try {
      await here.sync.intake.begin("run-1", request);
      await here.sync.intake.batch("run-1", {
        batch: 0,
        records: [
          { stream: "items", data: { id: "one" } },
          { stream: "notes", data: { id: "n1" } },
        ],
      });
      await here.sync.intake.end("run-1", {
        finish: "completed",
        streams: { items: observed(true), notes: observed(true) },
        checkpoints: { items: { cursor: "a" }, notes: { cursor: "b" } },
        lastBatch: 0,
      });
      await here.sync.publish();
      expect(await here.sync.intake.checkpoint?.("fixture")).not.toBeNull();
      // The other device joins the connection and deletes it.
      await elsewhere.sync.cycle();
      await elsewhere.sync.deleter.requestConnectionDelete("fixture");
      await elsewhere.sync.cycle();
      // The local row still holds yesterday's checkpoint until the registry is read.
      expect(await here.db.query("SELECT checkpoint FROM connections")).toEqual(
        [{ checkpoint: expect.any(String) }],
      );
      expect(await here.sync.intake.checkpoint?.("fixture")).toBeNull();
    } finally {
      await here.sync.close();
      await elsewhere.sync.close();
    }
  });

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

  it("has no cursors while any stream must be read in full next (begin reads the whole connection then), and none once the checkpoint is cleared", async () => {
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
      expect(await sync.intake.checkpoint?.("fixture")).toBeNull();
      await db.batch([
        { sql: "UPDATE stream_state SET needs_full = 0", params: [] },
      ]);
      expect(
        Object.keys(
          (await sync.intake.checkpoint?.("fixture"))?.streams ?? {},
        ).sort(),
      ).toEqual(["items", "notes"]);
      await db.batch([
        { sql: "UPDATE connections SET checkpoint = NULL", params: [] },
      ]);
      expect(await sync.intake.checkpoint?.("fixture")).toBeNull();
    } finally {
      await sync.close();
    }
  });

  /**
   * The end a host sends for a run that selected the streams it writes (the
   * raw dialect `selectedStreams` requires): one stream, its records in the
   * batch, its cursor, nothing else claimed.
   */
  const selectedEnd = (stream: string, cursor: Record<string, unknown>) => ({
    wireDialect: "connector-end-evidence/1" as const,
    lastBatch: 0,
    selectedStreams: [stream],
    covered: [stream],
    done: { status: "succeeded" as const },
    errors: [],
    checkpoints: { [stream]: cursor },
    preflightExcludedStreams: [],
    detailCoverage: {},
    invalidDetailCoverageStreams: [],
    wholeStreamEvidence: [],
  });

  it("saves and reads the cursor of a stream a run selected and wrote, whatever the connector declares besides; later keys' runs add theirs", async () => {
    const { db, sync } = await open("1.2.0");
    try {
      // The host writes one key per run, selecting its stream: the connector
      // also declares `notes`, which this grant does not cover.
      await sync.intake.begin("run-items", {
        ...request,
        selectedStreams: ["items"],
      });
      await sync.intake.batch("run-items", {
        batch: 0,
        records: [{ stream: "items", data: { id: "one" } }],
      });
      const ended = await sync.intake.end(
        "run-items",
        selectedEnd("items", { cursor: "a" }),
      );
      expect(ended.outcome).toBe("succeeded");
      await sync.publish();
      expect((await sync.intake.checkpoint?.("fixture"))?.streams).toEqual({
        items: { state: { cursor: "a" }, cursorVersion: "1.2.0" },
      });
      // The unselected stream has no state of its own.
      expect(
        await db.query("SELECT stream FROM stream_state ORDER BY stream"),
      ).toEqual([{ stream: "items" }]);
      // A later key's run, on the same connection, adds its stream's cursor.
      await sync.intake.begin("run-notes", {
        ...request,
        selectedStreams: ["notes"],
      });
      await sync.intake.batch("run-notes", {
        batch: 0,
        records: [{ stream: "notes", data: { id: "n1" } }],
      });
      await sync.intake.end("run-notes", selectedEnd("notes", { cursor: "b" }));
      await sync.publish();
      expect((await sync.intake.checkpoint?.("fixture"))?.streams).toEqual({
        items: { state: { cursor: "a" }, cursorVersion: "1.2.0" },
        notes: { state: { cursor: "b" }, cursorVersion: "1.2.0" },
      });
      // A resumed run of the first key advances its cursor and keeps the other.
      await sync.intake.begin("run-items-2", {
        ...request,
        selectedStreams: ["items"],
        streams: [{ name: "items", resumed: true }],
      });
      await sync.intake.batch("run-items-2", {
        batch: 0,
        records: [{ stream: "items", data: { id: "two" } }],
      });
      await sync.intake.end(
        "run-items-2",
        selectedEnd("items", { cursor: "c" }),
      );
      await sync.publish();
      expect((await sync.intake.checkpoint?.("fixture"))?.streams).toEqual({
        items: { state: { cursor: "c" }, cursorVersion: "1.2.0" },
        notes: { state: { cursor: "b" }, cursorVersion: "1.2.0" },
      });
      expect(
        (
          await db.query<{ record_key: string }>(
            "SELECT record_key FROM records WHERE stream='items' ORDER BY record_key",
          )
        ).map((r) => r.record_key),
      ).toEqual(["one", "two"]);
    } finally {
      await sync.close();
    }
  });

  it("reads the cursor a selecting run saved although an earlier run that selected nothing left the unwritten stream an empty, incomplete head", async () => {
    const { db, sync } = await open("1.2.0");
    try {
      // The earlier host wrote one stream without selecting it: the run also
      // covered `notes` with nothing, publishing an empty incomplete head for
      // it, and saved no cursor (the run was not complete as a whole).
      await sync.intake.begin("run-legacy", request);
      await sync.intake.batch("run-legacy", {
        batch: 0,
        records: [{ stream: "items", data: { id: "one" } }],
      });
      await sync.intake.end("run-legacy", {
        finish: "completed",
        streams: { items: observed(true) },
        checkpoints: { items: { cursor: "a" } },
        lastBatch: 0,
      });
      await sync.publish();
      expect(await sync.intake.checkpoint?.("fixture")).toBeNull();
      expect(
        await db.query(
          "SELECT stream, complete FROM stream_state ORDER BY stream",
        ),
      ).toEqual([
        { stream: "items", complete: 1 },
        { stream: "notes", complete: 0 },
      ]);
      // A run that selects the stream it writes saves its cursor, and the
      // read hands it out: the never-written stream has none to withhold.
      await sync.intake.begin("run-items", {
        ...request,
        selectedStreams: ["items"],
      });
      await sync.intake.batch("run-items", {
        batch: 0,
        records: [{ stream: "items", data: { id: "two" } }],
      });
      await sync.intake.end("run-items", selectedEnd("items", { cursor: "c" }));
      await sync.publish();
      expect((await sync.intake.checkpoint?.("fixture"))?.streams).toEqual({
        items: { state: { cursor: "c" }, cursorVersion: "1.2.0" },
      });
    } finally {
      await sync.close();
    }
  });
});
