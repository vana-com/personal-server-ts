import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type {
  SqlDriver,
  SqlStatement,
} from "../../../core/src/localdb/driver.js";
import {
  mergeIncoming,
  withOrigin,
  type WriteOrigin,
} from "../../../core/src/localdb/merge.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

describe("first_o merge", () => {
  const dirs: string[] = [];
  const drivers: SqlDriver[] = [];
  const fresh = async () => {
    const dir = mkdtempSync(join(process.cwd(), ".first-o-"));
    dirs.push(dir);
    const driver = openBetterSqlite3(join(dir, "db.sqlite"));
    drivers.push(driver);
    return openLocalDb(driver, {
      owner: "0xabc",
      network: "test-network",
      deviceId: "device-1",
    });
  };
  afterEach(async () => {
    for (const driver of drivers.splice(0)) {
      await driver.close().catch(() => undefined);
    }
    for (const dir of dirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  const merge = (
    db: SqlDriver,
    key: string,
    stamp: number,
    first: number | null,
    origin: WriteOrigin = "remote",
  ) => {
    const body = JSON.stringify({ revision: stamp });
    const stage: SqlStatement = {
      sql: `INSERT INTO incoming
        (op, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o)
        VALUES (?, 'stream', ?, ?, ?, 'run', ?, ?, ?)`,
      params: ["merge", key, key, stamp, body, `hash-${stamp}`, first],
    };
    return db.batch(
      withOrigin(origin, [stage, ...mergeIncoming("merge", "connection")]),
    );
  };
  const first = async (db: SqlDriver, key: string) => {
    const [row] = await db.query<{ first_o: number | null }>(
      "SELECT first_o FROM records WHERE connection_id = ? AND stream = ? AND pk_hash = ?",
      ["connection", "stream", key],
    );
    return row?.first_o;
  };
  const changes = async (db: SqlDriver) => {
    const [row] = await db.query<{ count: number }>(
      "SELECT count(*) AS count FROM record_changes",
    );
    return row!.count;
  };

  it("first-o-min-merge-newer-stamp-keeps-first", async () => {
    const db = await fresh();
    await merge(db, "row", 100, 100);
    await merge(db, "row", 500, 500);
    expect(await first(db, "row")).toBe(100);
    expect(
      await db.query(
        "SELECT stamp_o, stamp_r, body FROM records WHERE pk_hash = ?",
        ["row"],
      ),
    ).toEqual([
      { stamp_o: 500, stamp_r: "run", body: JSON.stringify({ revision: 500 }) },
    ]);

    await merge(db, "row", 50, 50);
    expect(await first(db, "row")).toBe(50);
    expect(
      await db.query(
        "SELECT stamp_o, stamp_r, body FROM records WHERE pk_hash = ?",
        ["row"],
      ),
    ).toEqual([
      { stamp_o: 500, stamp_r: "run", body: JSON.stringify({ revision: 500 }) },
    ]);
  });

  it("first-o-null-is-bottom", async () => {
    const db = await fresh();
    const pairs: readonly (readonly [number | null, number | null])[] = [
      [100, null],
      [null, 100],
      [null, null],
    ];
    for (const [index, [left, right]] of pairs.entries()) {
      const key = `pair-${index}`;
      await merge(db, key, 100, left);
      expect(await first(db, key)).toBe(left);
      await merge(db, key, 200, right);
      expect(await first(db, key)).toBeNull();
      await merge(db, key, 50, right);
      expect(await first(db, key)).toBeNull();
    }

    await merge(db, "import-new", 300, 300, "import");
    expect(await first(db, "import-new")).toBeNull();
    await merge(db, "import-existing", 400, 400);
    await merge(db, "import-existing", 200, 200, "import");
    expect(await first(db, "import-existing")).toBeNull();
    await merge(db, "import-new", 500, 500, "local");
    expect(await first(db, "import-new")).toBeNull();
    expect(
      await db.query(
        "SELECT origin FROM record_changes WHERE pk_hash = ? ORDER BY seq LIMIT 1",
        ["import-new"],
      ),
    ).toEqual([{ origin: "import" }]);
  });

  it("first-o-only-change-logs-nothing", async () => {
    const db = await fresh();
    await merge(db, "row", 500, 500);
    const before = await changes(db);
    expect(before).toBe(1);

    // An equal stamp changes only first_o, even though it lowers the checkpoint.
    await merge(db, "row", 500, 100);
    expect(await first(db, "row")).toBe(100);
    expect(await changes(db)).toBe(before);
    await merge(db, "row", 500, 100);
    expect(await changes(db)).toBe(before);

    // Losing stamped data can still lower first_o to unknown without publishing.
    await merge(db, "row", 100, null);
    expect(await first(db, "row")).toBeNull();
    expect(await changes(db)).toBe(before);

    // A stamp update and a checkpoint update together publish exactly once.
    await merge(db, "both", 100, 100);
    const beforeBoth = await changes(db);
    await merge(db, "both", 500, 50);
    expect(await first(db, "both")).toBe(50);
    expect(await changes(db)).toBe(beforeBoth + 1);
  });
});
