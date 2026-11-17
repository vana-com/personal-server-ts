// The mark of a stream says whether a row of it changed after a reader pinned
// it, with no cost per record: a trigger on `record_changes` (which every
// write of a row leaves an entry in) writes the mark only on the first change
// after it was cleared. Real SQLite and the real schema.
import { afterEach, describe, expect, it } from "vitest";
import {
  clearMark,
  pinStream,
  readMark,
} from "../../../core/src/localdb/complete-read.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

async function open() {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: "0xabc",
    network: "test",
    deviceId: "stream-change-marks",
  });
  drivers.push(db);
  await db.batch([
    { sql: "UPDATE write_ctx SET origin = 'remote'" },
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES ('c1','a','',1,'active',1)",
    },
  ]);
  return db;
}

const hex = (n: number) => `0x${n.toString(16).padStart(8, "0")}`;
const add = (db: SqlDriver, stream: string, n: number) =>
  db.batch([
    {
      sql: "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES ('c1',?,?,?,1,'r','{}','s')",
      params: [stream, hex(n), `k${n}`],
    },
  ]);
const mark = async (db: SqlDriver, stream = "items") =>
  (
    await db.query<{ epoch: number; dirty: number }>(
      "SELECT epoch, dirty FROM stream_change_marks WHERE connection_id = 'c1' AND stream = ?",
      [stream],
    )
  )[0];
/** The check each page makes, on the pin a reader holds. */
const unchangedSince = async (db: SqlDriver, pin: number) =>
  (
    await db.query<{ ok: number }>(
      "SELECT COALESCE((SELECT epoch FROM stream_change_marks WHERE connection_id = 'c1' AND stream = 'items'), 0) = ? AS ok",
      [pin],
    )
  )[0]!.ok === 1;

describe("the mark of a stream", () => {
  it("is written by the first change after it was cleared, not by each row", async () => {
    const db = await open();
    expect(await mark(db)).toBeUndefined();
    for (let i = 0; i < 5; i++) await add(db, "items", i);
    expect(await mark(db)).toEqual({ epoch: 1, dirty: 1 });
    await pinStream(db, "c1", "items");
    expect(await mark(db)).toEqual({ epoch: 1, dirty: 0 });
    await add(db, "items", 9);
    expect(await mark(db)).toEqual({ epoch: 2, dirty: 1 });
  });

  it.each([
    ["a row is added", (db: SqlDriver) => add(db, "items", 50)],
    [
      "a row is changed",
      (db: SqlDriver) =>
        db.batch([
          {
            sql: "UPDATE records SET stamp_o = 9 WHERE pk_hash = ?",
            params: [hex(1)],
          },
        ]),
    ],
    [
      "a row is removed",
      (db: SqlDriver) =>
        db.batch([
          { sql: "DELETE FROM records WHERE pk_hash = ?", params: [hex(1)] },
        ]),
    ],
    [
      "a change is logged without a row (a delete marker)",
      (db: SqlDriver) =>
        db.batch([
          {
            sql: "INSERT INTO record_changes(connection_id,stream,pk_hash,record_key,op,stamp_o,stamp_r,origin) VALUES ('c1','items',?,'k',  'remove',1,'r','remote')",
            params: [hex(77)],
          },
        ]),
    ],
  ])("ends a pin when %s", async (_name, change) => {
    const db = await open();
    await add(db, "items", 1);
    const pin = await pinStream(db, "c1", "items");
    expect(await unchangedSince(db, pin)).toBe(true);
    await change(db);
    expect(await unchangedSince(db, pin)).toBe(false);
  });

  it("does not end a pin when another stream or connection changes", async () => {
    const db = await open();
    await db.batch([
      {
        sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES ('c2','b','',1,'active',1)",
      },
    ]);
    await add(db, "items", 1);
    const pin = await pinStream(db, "c1", "items");
    await add(db, "other", 2);
    await db.batch([
      {
        sql: "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES ('c2','items',?,'k',1,'r','{}','s')",
        params: [hex(3)],
      },
    ]);
    expect(await unchangedSince(db, pin)).toBe(true);
  });

  it("does not end a pin when the change log is compacted", async () => {
    const db = await open();
    await add(db, "items", 1);
    const pin = await pinStream(db, "c1", "items");
    await db.batch([{ sql: "DELETE FROM record_changes" }]);
    expect(await unchangedSince(db, pin)).toBe(true);
  });

  it("keeps a pin ended when a second reader clears the mark afterwards", async () => {
    const db = await open();
    await add(db, "items", 1);
    const first = await pinStream(db, "c1", "items");
    await add(db, "items", 2);
    await pinStream(db, "c1", "items"); // a second reader's pin clears the flag
    expect(await unchangedSince(db, first)).toBe(false);
  });

  it("finds every change after a pin in any order of readers, writers and checks", async () => {
    // Random interleavings of two readers' pins and checks with writes of rows.
    // A reader that has finished pinning must see every later change.
    let seed = 1;
    const random = () => (seed = (seed * 1664525 + 1013904223) >>> 0) / 2 ** 32;
    let missed = 0;
    let detected = 0;
    for (let trial = 0; trial < 200; trial++) {
      const db = await open();
      const live = new Set<number>();
      let next = 0;
      let changes = 0;
      const readers = [0, 1].map(() => ({
        step: 0,
        pin: 0,
        since: 0,
        mark: { epoch: 0, dirty: 0 },
      }));
      for (let t = 0; t < 40; t++) {
        const x = random();
        if (x < 0.4) {
          const kind = live.size === 0 ? 0 : Math.floor(random() * 3);
          if (kind === 0) {
            await add(db, "items", next);
            live.add(next++);
          } else {
            const key = [...live][Math.floor(random() * live.size)]!;
            if (kind === 1)
              await db.batch([
                {
                  sql: "UPDATE records SET stamp_o = stamp_o + 1 WHERE pk_hash = ?",
                  params: [hex(key)],
                },
              ]);
            else {
              await db.batch([
                {
                  sql: "DELETE FROM records WHERE pk_hash = ?",
                  params: [hex(key)],
                },
              ]);
              live.delete(key);
            }
          }
          changes++;
          continue;
        }
        const reader = readers[x < 0.7 ? 0 : 1]!;
        if (reader.step === 0) {
          // The two steps of `pinStream`, taken apart so a write can fall between them.
          reader.mark = await readMark(db, "c1", "items");
          reader.step = 1;
        } else if (reader.step === 1) {
          reader.pin = await clearMark(db, "c1", "items", reader.mark);
          reader.since = changes;
          reader.step = 2;
        } else if (changes > reader.since) {
          if (await unchangedSince(db, reader.pin)) missed++;
          else detected++;
        }
      }
      await db.close();
      drivers.pop();
    }
    expect(detected).toBeGreaterThan(100);
    expect(missed).toBe(0);
  });
});
