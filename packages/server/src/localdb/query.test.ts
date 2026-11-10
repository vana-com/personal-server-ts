import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type {
  SqlDriver,
  SqlStatement,
} from "../../../core/src/localdb/driver.js";
import {
  createRecordQuery,
  type StoredRecord,
} from "../../../core/src/localdb/query.js";
import { run } from "../../../core/src/test-support/memory-oracle.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const ROWS = 131_072;
const BUDGET = 48 * 1024 * 1024;
const key = (index: number) => String(index).padStart(6, "0");

type MemoryResult = {
  count: number;
  bodyBytes: number;
  ordered: boolean;
};

/** The existing oracle imports this file without starting the Vitest suite. */
export async function queryMemoryWorkload(input: {
  file: string;
  retainAll: boolean;
}): Promise<MemoryResult> {
  const db = openBetterSqlite3(input.file);
  try {
    const query = createRecordQuery(db);
    let records = query.streamRecords("c", "s");
    if (input.retainAll) {
      // Negative control: the same production reader, but every yielded
      // record is retained before the consumer may see its first record.
      const source = records;
      records = (async function* () {
        const retained: StoredRecord[] = [];
        for await (const record of source) retained.push(record);
        yield* retained;
      })();
    }
    let count = 0;
    let bodyBytes = 0;
    let ordered = true;
    for await (const record of records) {
      ordered &&= record.pkHash === key(count);
      bodyBytes += Buffer.byteLength(record.body, "utf8");
      count += 1;
    }
    return { count, bodyBytes, ordered };
  } finally {
    await db.close();
  }
}

if (!process.argv[1]?.endsWith("/memory-oracle-child.mjs")) {
  const { afterEach, describe, expect, it } = await import("vitest");
  const { openLocalDb } =
    await import("@opendatalabs/personal-server-ts-core/localdb");
  const opened = new Set<SqlDriver>();
  const dirs: string[] = [];
  const fresh = async () => {
    const dir = mkdtempSync(join(process.cwd(), ".query-test-"));
    dirs.push(dir);
    const file = join(dir, "records.sqlite");
    const db = openBetterSqlite3(file);
    opened.add(db);
    await openLocalDb(db, {
      owner: "0xabc",
      network: "moksha",
      deviceId: "query-test",
    });
    return { db, file };
  };
  const insert = (
    recordKey: string,
    pkHash = recordKey,
    stream = "s",
    connection = "c",
    stamp = 123,
    body = "{}",
  ): SqlStatement => ({
    sql: `INSERT INTO records
      (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256)
      VALUES (?, ?, ?, ?, ?, 'r', ?, 'fixture')`,
    params: [connection, stream, pkHash, recordKey, stamp, body],
  });
  afterEach(async () => {
    for (const db of opened) await db.close();
    opened.clear();
    for (const dir of dirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  describe("record query", () => {
    it("pages by record_key with default 25 and maximum 100; string lookup breaks key-type ties by pk_hash", async () => {
      const { db } = await fresh();
      const query = createRecordQuery(db);
      await db.batch([
        ...Array.from({ length: 105 }, (_, i) => insert(key(i), key(104 - i))),
        insert("foreign-stream", "foreign-stream", "other"),
        insert("foreign-connection", "foreign-connection", "s", "other"),
        { sql: "UPDATE write_ctx SET origin = 'remote' WHERE id = 1" },
        insert("1", "b", "collision", "c", 201, JSON.stringify({ id: "1" })),
        insert("1", "a", "collision", "c", 202, JSON.stringify({ id: 1 })),
        insert("", "empty", "collision"),
        insert("2", "z", "collision"),
      ]);
      const first = await query.listRecords({ connectionId: "c", stream: "s" });
      expect(first.records.map((r) => r.recordKey)).toEqual(
        Array.from({ length: 25 }, (_, i) => key(i)),
      );
      expect(first.nextCursor).toBe(key(24));
      expect(first.records.every((r) => r.emittedAt === 123)).toBe(true);
      const second = await query.listRecords({
        connectionId: "c",
        stream: "s",
        cursor: first.nextCursor!,
      });
      expect(second.records.map((r) => r.recordKey)).toEqual(
        Array.from({ length: 25 }, (_, i) => key(i + 25)),
      );
      const capped = await query.listRecords({
        connectionId: "c",
        stream: "s",
        limit: 1000,
      });
      expect(capped.records).toHaveLength(100);
      expect(capped.nextCursor).toBe(key(99));
      const last = await query.listRecords({
        connectionId: "c",
        stream: "s",
        cursor: capped.nextCursor!,
        limit: 100,
      });
      expect(last.records.map((r) => r.recordKey)).toEqual(
        Array.from({ length: 5 }, (_, i) => key(i + 100)),
      );
      expect(last.nextCursor).toBeNull();
      const afterEmpty = await query.listRecords({
        connectionId: "c",
        stream: "collision",
        cursor: "",
      });
      expect(afterEmpty.records.every((r) => r.recordKey > "")).toBe(true);
      const collision = await query.getRecord({
        connectionId: "c",
        stream: "collision",
        recordKey: "1",
      });
      expect(collision?.pkHash).toBe("a");
      expect(collision?.emittedAt).toBe(202);
      expect(typeof JSON.parse(collision!.body).id).toBe("number");
      expect(
        await query.getRecord({
          connectionId: "c",
          stream: "s",
          recordKey: "1",
        }),
      ).toBeNull();
    });

    it("pages changes by seq and returns gone only below the global compaction floor", async () => {
      const { db } = await fresh();
      const query = createRecordQuery(db);
      const input = { connectionId: "c", stream: "s" };
      expect(await query.changesSince({ ...input, cursor: 0 })).toEqual({
        changes: [],
        nextCursor: null,
      });
      await db.batch([
        insert("foreign-stream", "x", "other"),
        insert("a", "a", "s", "c", 101),
        insert("foreign-connection", "x", "s", "other"),
        insert("b", "b", "s", "c", 102),
        insert("c", "c", "s", "c", 103),
        {
          sql: "DELETE FROM records WHERE connection_id = 'c' AND stream = 's' AND pk_hash = 'b'",
        },
      ]);
      const first = await query.changesSince({ ...input, cursor: 0, limit: 2 });
      expect(first).not.toBe("gone");
      if (first === "gone") throw new Error("unexpected compaction refusal");
      expect(first.changes.map((c) => c.seq)).toEqual([2, 4]);
      expect(first.changes[0]?.record?.emittedAt).toBe(101);
      expect(first.changes[1]?.record).toBeNull();
      expect(first.nextCursor).toBe(4);
      const last = await query.changesSince({
        ...input,
        cursor: first.nextCursor!,
        limit: 2,
      });
      expect(last).not.toBe("gone");
      if (last === "gone") throw new Error("unexpected compaction refusal");
      expect(last.changes.map((c) => [c.seq, c.op, c.recordKey])).toEqual([
        [5, "upsert", "c"],
        [6, "remove", "b"],
      ]);
      expect(last.changes[1]?.record).toBeNull();
      expect(last.nextCursor).toBeNull();
      await db.batch([{ sql: "DELETE FROM record_changes WHERE seq <= 4" }]);
      expect(await query.changesSince({ ...input, cursor: 3 })).toBe("gone");
      const atFloor = await query.changesSince({ ...input, cursor: 4 });
      expect(atFloor).not.toBe("gone");
      if (atFloor === "gone") throw new Error("floor boundary refused");
      expect(atFloor.changes.map((c) => c.seq)).toEqual([5, 6]);
      await db.batch([{ sql: "DELETE FROM record_changes" }]);
      expect(await query.changesSince({ ...input, cursor: 5 })).toBe("gone");
      expect(await query.changesSince({ ...input, cursor: 6 })).toEqual({
        changes: [],
        nextCursor: null,
      });
    });

    it("#564 streams 131k records below 48 MiB in a fresh child and rejects retain-all", async () => {
      const { db, file } = await fresh();
      const body = JSON.stringify({ text: "é".repeat(512) });
      const bytesPerRecord = Buffer.byteLength(body, "utf8");
      expect(bytesPerRecord).toBeGreaterThan(body.length);
      for (let start = 0; start < ROWS; start += 512) {
        await db.batch(
          Array.from({ length: Math.min(512, ROWS - start) }, (_, offset) =>
            insert(
              key(start + offset),
              key(start + offset),
              "s",
              "c",
              123,
              body,
            ),
          ),
        );
      }
      await db.close();
      opened.delete(db);
      const module = fileURLToPath(import.meta.url);
      const measured = await run<MemoryResult>({
        module,
        exportName: "queryMemoryWorkload",
        args: { file, retainAll: false },
      });
      const retained = await run<MemoryResult>({
        module,
        exportName: "queryMemoryWorkload",
        args: { file, retainAll: true },
      });
      const result = {
        count: ROWS,
        bodyBytes: ROWS * bytesPerRecord,
        ordered: true,
      };
      expect(measured.result).toEqual(result);
      expect(retained.result).toEqual(result);
      console.info("query memory oracle", {
        records: ROWS,
        streamingPeakBytes: measured.peakBytes,
        retainedPeakBytes: retained.peakBytes,
        budgetBytes: BUDGET,
      });
      expect(measured.peakBytes).toBeLessThan(BUDGET);
      expect(retained.peakBytes).toBeGreaterThan(BUDGET);
    }, 120_000);
  });
}
