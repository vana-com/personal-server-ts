// A run that resumes a stream from a cursor read before the run (the
// connection's checkpoint, `intake.checkpoint()`, handed to a remote collector
// as its start state) is begun by the collector's host with `connect: true`,
// which asks for a full collection. The stream's rows are only those after the
// cursor, so the begin says so per stream (`streams[].resumed`), and the
// publication treats the stream as an incremental read: over the connection the
// cursor was read from it publishes and saves the cursor as usual; over a
// connection deleted and reconnected in between, or a stream flagged for a full
// read in between, the head stays incomplete and the cursor is not saved, so
// the rows the resumed read skipped are read in full by the next run.

import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createMemoryStreamSyncBlobs,
  createMemoryStreamSyncRegistry,
} from "../stream-sync/index.js";
import { RunIntakeError } from "../stream-sync/intake.js";
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

describe("a run resumed from a cursor read before it began", () => {
  const roots: string[] = [];
  afterEach(() => {
    for (const root of roots.splice(0)) {
      rmSync(root, { recursive: true, force: true });
    }
  });

  async function open(
    shared: {
      registry?: ReturnType<typeof createMemoryStreamSyncRegistry>;
      blobs?: ReturnType<typeof createMemoryStreamSyncBlobs>;
      /** The connector's streams; the sheet writes one of them per run. */
      streams?: readonly ("items" | "notes")[];
    } = {},
  ) {
    // The runner has no `~/.tmp` of its own: make it before the first run.
    mkdirSync(join(homedir(), ".tmp"), { recursive: true });
    const root = mkdtempSync(join(homedir(), ".tmp", "resumed-run-"));
    roots.push(root);
    const db = await openLocalDb(driver(join(root, "data.db")), {
      owner,
      network: "test",
      deviceId: "device",
    });
    let op = 0;
    const names = shared.streams ?? ["items", "notes"];
    const resolveArtifact = vi.fn(() => ({
      connector: "fixture",
      version: "1.2.0",
      streams: names.map((name) => ({
        name,
        semantics: "mutable_state" as const,
        primaryKey: ["id"],
        coverageStrategy: "checkpoint_window" as const,
      })),
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
    return { db, sync, names, resolveArtifact };
  }

  type Opened = Awaited<ReturnType<typeof open>>;

  /** The host's begin for a remote write: an explicit connect, as the sheet sends. */
  const connect = {
    connector: "fixture",
    artifactDigest: "fixture",
    owner: { address: owner, leaseId: null },
    connect: true as const,
  };

  /** A first full run that leaves a cursor for both streams and publishes it. */
  async function seeded({ sync, names }: Opened) {
    const rows = { items: { id: "one" }, notes: { id: "n1" } };
    const cursors = { items: { cursor: "a" }, notes: { cursor: "b" } };
    await sync.intake.begin("run-1", connect);
    await sync.intake.batch("run-1", {
      batch: 0,
      records: names.map((stream) => ({ stream, data: rows[stream] })),
    });
    await sync.intake.end("run-1", {
      finish: "completed",
      streams: Object.fromEntries(names.map((n) => [n, observed(true)])),
      checkpoints: Object.fromEntries(names.map((n) => [n, cursors[n]])),
      lastBatch: 0,
    });
    await sync.publish();
    // What the sheet reads at plan time and hands the remote run as its start.
    const checkpoint = await sync.intake.checkpoint?.("fixture");
    expect(checkpoint?.streams.items?.state).toEqual({ cursor: "a" });
    return checkpoint!;
  }

  /**
   * The remote run's result written back as the sheet does: one stream, begun
   * with `connect`, the rows after the cursor, ended with the new cursor.
   */
  async function writeBack(
    { sync }: Opened,
    runId: string,
    options: { resumed: boolean; publish?: false },
    record: Record<string, unknown> = { id: "two" },
  ) {
    const begun = await sync.intake.begin(runId, {
      ...connect,
      ...(options.resumed
        ? { streams: [{ name: "items", resumed: true }] }
        : {}),
    });
    await sync.intake.batch(runId, {
      batch: 0,
      records: [{ stream: "items", data: record }],
    });
    const ended = await sync.intake.end(runId, {
      finish: "completed",
      streams: { items: observed(true) },
      checkpoints: { items: { cursor: "c" } },
      lastBatch: 0,
    });
    if (options.publish !== false) await sync.publish();
    return { begun, ended };
  }

  const itemsState = ({ db }: Opened) =>
    db.query<{ complete: number; needs_full: number }>(
      "SELECT complete, needs_full FROM stream_state WHERE stream = 'items'",
    );
  const storedCheckpoint = async ({ db }: Opened) => {
    const [row] = await db.query<{ checkpoint: string | null }>(
      "SELECT checkpoint FROM connections",
    );
    return row?.checkpoint == null
      ? null
      : (JSON.parse(row.checkpoint) as Record<string, unknown>);
  };
  const itemKeys = async ({ db }: Opened) =>
    (
      await db.query<{ record_key: string }>(
        "SELECT record_key FROM records WHERE stream = 'items' ORDER BY record_key",
      )
    ).map((r) => r.record_key);

  it("marks the stream as not read in full, where a plain connect marks every stream full", async () => {
    const here = await open();
    try {
      await seeded(here);
      await here.sync.intake.begin("run-2", {
        ...connect,
        streams: [{ name: "items", resumed: true }],
      });
      expect(
        await here.db.query(
          "SELECT stream, full_read FROM run_streams WHERE run_id = 'run-2' ORDER BY stream",
        ),
      ).toEqual([
        { stream: "items", full_read: 0 },
        { stream: "notes", full_read: 1 },
      ]);
      await here.sync.intake.abort("run-2", "failed");
      await here.sync.intake.begin("run-3", connect);
      expect(
        await here.db.query(
          "SELECT stream, full_read FROM run_streams WHERE run_id = 'run-3' ORDER BY stream",
        ),
      ).toEqual([
        { stream: "items", full_read: 1 },
        { stream: "notes", full_read: 1 },
      ]);
      await here.sync.intake.abort("run-3", "failed");
      await expect(
        here.sync.intake.begin("run-4", {
          ...connect,
          streams: [{ name: "items", resumed: "yes" as unknown as boolean }],
        }),
      ).rejects.toMatchObject({ code: "invalid_request" });
      await expect(
        here.sync.intake.begin("run-4", {
          ...connect,
          streams: [{ name: "items", resumed: "yes" as unknown as boolean }],
        }),
      ).rejects.toBeInstanceOf(RunIntakeError);
    } finally {
      await here.sync.close();
    }
  });

  it("publishes over the unchanged connection and saves the cursor, keeping every row", async () => {
    const here = await open();
    try {
      await seeded(here);
      const { ended } = await writeBack(here, "run-2", { resumed: true });
      expect(ended.outcome).toBe("succeeded");
      expect(await itemKeys(here)).toEqual(["one", "two"]);
      expect(await itemsState(here)).toEqual([{ complete: 1, needs_full: 0 }]);
      expect((await here.sync.intake.checkpoint?.("fixture"))?.streams).toEqual(
        {
          items: { state: { cursor: "c" }, cursorVersion: "1.2.0" },
          notes: { state: { cursor: "b" }, cursorVersion: "1.2.0" },
        },
      );
    } finally {
      await here.sync.close();
    }
  });

  /**
   * The cursor is read here; while the remote run takes its minutes, another
   * device deletes the connection and this device's own sync learns of it.
   * The write-back's connect then reconnects: a new lifetime, holding only the
   * rows after the old cursor. (A begin that had not learned of the deletion
   * is caught at publish instead: its lifetime moved, its rows and checkpoint
   * are purged.)
   */
  async function deletedMeanwhile() {
    const registry = createMemoryStreamSyncRegistry();
    const blobs = createMemoryStreamSyncBlobs();
    const here = await open({ registry, blobs, streams: ["items"] });
    const elsewhere = await open({ registry, blobs, streams: ["items"] });
    await seeded(here);
    await elsewhere.sync.cycle();
    await elsewhere.sync.deleter.requestConnectionDelete("fixture");
    await elsewhere.sync.cycle();
    await here.sync.cycle();
    expect(
      await here.db.query("SELECT control_state FROM connections"),
    ).toEqual([{ control_state: "deleted" }]);
    return { here, elsewhere };
  }

  it("a failed end of a run whose stream was deleted mid-run takes the fence's reset: no checkpoint, the stream incomplete and flagged for a full read", async () => {
    const registry = createMemoryStreamSyncRegistry();
    const blobs = createMemoryStreamSyncBlobs();
    const here = await open({ registry, blobs, streams: ["items"] });
    const elsewhere = await open({ registry, blobs, streams: ["items"] });
    try {
      await seeded(here);
      await elsewhere.sync.cycle();
      // A run of the same lifetime is collecting when the delete lands.
      await here.sync.intake.begin("run-2", { ...connect, connect: false });
      await elsewhere.sync.deleter.requestConnectionDelete("fixture");
      await elsewhere.sync.cycle();
      await here.sync.cycle();
      expect(
        await here.db.query("SELECT control_state FROM connections"),
      ).toEqual([{ control_state: "deleted" }]);
      const ended = await here.sync.intake.end("run-2", {
        finish: "completed",
        streams: { items: { ...observed(false), sourceAnswered: false } },
        checkpoints: {},
        lastBatch: -1,
      });
      expect(ended.outcome).toBe("failed");
      expect(await storedCheckpoint(here)).toBeNull();
      expect(await itemsState(here)).toEqual([{ complete: 0, needs_full: 1 }]);
    } finally {
      await here.sync.close();
      await elsewhere.sync.close();
    }
  });

  it("an end that finds a delete intent pending is fenced as control_deleted, though the connection is still active", async () => {
    const here = await open({ streams: ["items"] });
    try {
      await seeded(here);
      await here.sync.intake.begin("run-2", { ...connect, connect: false });
      await here.sync.intake.batch("run-2", {
        batch: 0,
        records: [{ stream: "items", data: { id: "two" } }],
      });
      await here.db.batch([
        {
          sql: "INSERT INTO delete_intents(connector, delete_id, intent) VALUES ('fixture', 'd1', '{}')",
          params: [],
        },
      ]);
      expect(
        await here.db.query("SELECT control_state FROM connections"),
      ).toEqual([{ control_state: "active" }]);
      await here.sync.intake.end("run-2", {
        finish: "completed",
        streams: { items: observed(true) },
        checkpoints: { items: { cursor: "c" } },
        lastBatch: 0,
      });
      expect(
        await here.db.query(
          "SELECT decision, reason FROM run_streams WHERE run_id = 'run-2'",
        ),
      ).toEqual([{ decision: "discarded", reason: "control_deleted" }]);
      expect(await storedCheckpoint(here)).toBeNull();
    } finally {
      await here.sync.close();
    }
  });

  it("saves no cursor when the connection was deleted after the cursor was read: the reconnect is a new lifetime without the rows before the cursor", async () => {
    const { here, elsewhere } = await deletedMeanwhile();
    try {
      const { ended } = await writeBack(here, "run-2", { resumed: true });
      expect(ended.outcome).toBe("succeeded");
      // The rows are kept, in the new lifetime.
      expect(await itemKeys(here)).toEqual(["two"]);
      expect(
        await here.db.query(
          "SELECT generation FROM runs WHERE run_id = 'run-2'",
        ),
      ).not.toEqual([{ generation: 1 }]);
      // The head is incomplete and no checkpoint claims the rows it lacks.
      expect(await itemsState(here)).toEqual([{ complete: 0, needs_full: 0 }]);
      expect(await storedCheckpoint(here)).toBeNull();
      expect(await here.sync.intake.checkpoint?.("fixture")).toBeNull();
      // So the next run reads the connection in full.
      const next = await here.sync.intake.begin("run-3", {
        ...connect,
        connect: false,
      });
      expect(next.start).toEqual({
        collection_mode: "full_refresh",
        state: null,
      });
    } finally {
      await here.sync.close();
      await elsewhere.sync.close();
    }
  });

  it("without `resumed`, the same reconnect takes the rows for a full read: the cursor is saved over them and the head is complete (what a plain connect still means)", async () => {
    const { here, elsewhere } = await deletedMeanwhile();
    try {
      await writeBack(here, "run-2", { resumed: false, publish: false });
      // Saved at end, over a lifetime that holds only the rows after it.
      expect(await storedCheckpoint(here)).toEqual({ items: { cursor: "c" } });
      await here.sync.publish();
      expect(await itemKeys(here)).toEqual(["two"]);
      expect(await itemsState(here)).toEqual([{ complete: 1, needs_full: 0 }]);
      // (This publication also purges the first run, retained from the old
      // lifetime, and clears the checkpoint with it; a plain connect relies on
      // that coincidence, a resumed run never saves the cursor.)
    } finally {
      await here.sync.close();
      await elsewhere.sync.close();
    }
  });

  /**
   * After the cursor was read, the stream was flagged for a full read (a
   * discarded or fenced run: `needs_full = 1`, and the connection's checkpoint
   * cleared with it, as both flaggers do).
   */
  async function flaggedMeanwhile() {
    const here = await open();
    await seeded(here);
    await here.db.batch([
      {
        sql: "UPDATE stream_state SET needs_full = 1, complete = 0 WHERE stream = 'items'",
        params: [],
      },
      { sql: "UPDATE connections SET checkpoint = NULL", params: [] },
    ]);
    expect(await here.sync.intake.checkpoint?.("fixture")).toBeNull();
    return here;
  }

  it("saves no cursor when the stream was flagged for a full read after the cursor was read: the next run still reads in full", async () => {
    const here = await flaggedMeanwhile();
    try {
      const { ended } = await writeBack(here, "run-2", { resumed: true });
      expect(ended.outcome).toBe("succeeded");
      expect(await itemKeys(here)).toEqual(["one", "two"]);
      // The run's cursor did not become the checkpoint. (The publication
      // itself lands on the registry's complete head, as any incremental
      // run's does, which clears the local flag; the cleared checkpoint is
      // what keeps the next read full.)
      expect(await storedCheckpoint(here)).toBeNull();
      expect(await here.sync.intake.checkpoint?.("fixture")).toBeNull();
      const next = await here.sync.intake.begin("run-3", {
        ...connect,
        connect: false,
      });
      expect(next.start).toEqual({
        collection_mode: "full_refresh",
        state: null,
      });
    } finally {
      await here.sync.close();
    }
  });

  it("without `resumed`, the flagged stream is taken as read in full and the cursor is saved", async () => {
    const here = await flaggedMeanwhile();
    try {
      await writeBack(here, "run-2", { resumed: false });
      expect(await itemsState(here)).toEqual([{ complete: 1, needs_full: 0 }]);
      expect(await storedCheckpoint(here)).toEqual({ items: { cursor: "c" } });
      expect(
        (await here.sync.intake.checkpoint?.("fixture"))?.streams.items?.state,
      ).toEqual({ cursor: "c" });
    } finally {
      await here.sync.close();
    }
  });

  it("hands out no cursor while a stream's head is incomplete: a resumed run over a reset base is followed by a full read, not by the same cursor forever", async () => {
    const here = await open({ streams: ["items"] });
    try {
      await seeded(here);
      // A newer connector changes the stream's primary key. The published head
      // is no base for it (`empty_base`), so a run that is not a full read
      // publishes an incomplete head and saves no cursor.
      here.resolveArtifact.mockImplementation(() => ({
        connector: "fixture",
        version: "1.3.0",
        streams: [
          {
            name: "items",
            semantics: "mutable_state" as const,
            primaryKey: ["id", "v"],
            coverageStrategy: "checkpoint_window" as const,
          },
        ],
      }));
      await writeBack(here, "run-2", { resumed: true }, { id: "two", v: 1 });
      expect(await itemsState(here)).toEqual([{ complete: 0, needs_full: 0 }]);
      expect((await storedCheckpoint(here))?.items).toEqual({ cursor: "a" });
      // The stored cursor is not handed out: a second resumed run would come
      // out incomplete again, and so on. The next remote run reads in full.
      expect(await here.sync.intake.checkpoint?.("fixture")).toBeNull();
      await writeBack(here, "run-3", { resumed: false }, { id: "three", v: 1 });
      expect(await itemsState(here)).toEqual([{ complete: 1, needs_full: 0 }]);
      expect(
        (await here.sync.intake.checkpoint?.("fixture"))?.streams.items?.state,
      ).toEqual({ cursor: "c" });
    } finally {
      await here.sync.close();
    }
  });

  it("with the stream selected, as the host writes it, the same reconnect still saves no cursor and keeps the rows", async () => {
    const { here, elsewhere } = await deletedMeanwhile();
    try {
      await here.sync.intake.begin("run-2", {
        ...connect,
        selectedStreams: ["items"],
        streams: [{ name: "items", resumed: true }],
      });
      await here.sync.intake.batch("run-2", {
        batch: 0,
        records: [{ stream: "items", data: { id: "two" } }],
      });
      const ended = await here.sync.intake.end("run-2", {
        wireDialect: "connector-end-evidence/1",
        lastBatch: 0,
        selectedStreams: ["items"],
        covered: ["items"],
        done: { status: "succeeded" },
        errors: [],
        checkpoints: { items: { cursor: "c" } },
        preflightExcludedStreams: [],
        detailCoverage: {},
        invalidDetailCoverageStreams: [],
        wholeStreamEvidence: [],
      });
      expect(ended.outcome).toBe("succeeded");
      await here.sync.publish();
      expect(await itemKeys(here)).toEqual(["two"]);
      expect(await itemsState(here)).toEqual([{ complete: 0, needs_full: 0 }]);
      expect(await storedCheckpoint(here)).toBeNull();
      expect(await here.sync.intake.checkpoint?.("fixture")).toBeNull();
    } finally {
      await here.sync.close();
      await elsewhere.sync.close();
    }
  });

  it("does not merge or save a checkpoint when a delete intent lands just before the END transaction", async () => {
    const here = await open({ streams: ["items"] });
    try {
      await seeded(here);
      await here.sync.intake.begin("raced-end", { ...connect, connect: false });
      await here.sync.intake.batch("raced-end", {
        batch: 0,
        records: [{ stream: "items", data: { id: "late" } }],
      });
      const originalBatch = here.db.batch.bind(here.db);
      let inserted = false;
      const intercepted = vi
        .spyOn(here.db, "batch")
        .mockImplementation(async (statements) => {
          if (
            !inserted &&
            statements.some(({ sql }) =>
              sql.includes("end_response=?,raw_end=?"),
            )
          ) {
            inserted = true;
            await originalBatch([
              {
                sql: "INSERT INTO delete_intents(connector,delete_id,intent) VALUES (?,?,?)",
                params: [
                  "fixture",
                  "synthetic-delete",
                  JSON.stringify({ pins: [] }),
                ],
              },
            ]);
          }
          return originalBatch(statements);
        });
      try {
        const ended = await here.sync.intake.end("raced-end", {
          finish: "completed",
          streams: { items: observed(true) },
          checkpoints: { items: { cursor: "do-not-save" } },
          lastBatch: 0,
        });
        expect(inserted).toBe(true);
        expect(ended.result).toBe("discarded");
        expect(await itemKeys(here)).toEqual(["one"]);
        expect((await storedCheckpoint(here))?.items).not.toEqual({
          cursor: "do-not-save",
        });
        expect(
          await here.db.query(
            "SELECT reason FROM run_streams WHERE run_id = ?",
            ["raced-end"],
          ),
        ).toEqual([{ reason: "control_deleted" }]);
      } finally {
        intercepted.mockRestore();
      }
    } finally {
      await here.sync.close();
    }
  });
});
