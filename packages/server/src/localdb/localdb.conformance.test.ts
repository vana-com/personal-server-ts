import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  connectionQueue,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { runDriverConformance } from "@opendatalabs/personal-server-ts-core/localdb/conformance";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { openSqlite3Cli } from "./sqlite3-cli-driver.test-utils.js";

// One suite, run per driver. The 3.22.0 row (Android 9's SQLite) runs only when
// LOCALDB_SQLITE3_CLI names a 3.22.0 `sqlite3` shell; CI builds one.
const CLI = process.env.LOCALDB_SQLITE3_CLI;
const rows: [string, (file: string) => SqlDriver][] = [
  ["node", (file) => openBetterSqlite3(file)],
  ...(CLI
    ? [
        ["node-sqlite-3.22.0", (file: string) => openSqlite3Cli(CLI, file)] as [
          string,
          (file: string) => SqlDriver,
        ],
      ]
    : []),
];

describe.each(rows)("local database on %s", (row, factory) => {
  const dirs: string[] = [];
  const open = new Set<SqlDriver>();
  let file: string;
  const makeDriver = async () => {
    const driver = factory(file);
    const close = driver.close.bind(driver);
    driver.close = async () => {
      open.delete(driver);
      await close();
    };
    open.add(driver);
    if (row.endsWith("3.22.0"))
      expect(driver.info.sqliteVersion).toBe("3.22.0");
    return driver;
  };
  const fresh = async () => {
    const dir = mkdtempSync(join(process.cwd(), ".localdb-conformance-"));
    dirs.push(dir);
    file = join(dir, "db.sqlite");
    return makeDriver();
  };
  afterEach(async () => {
    for (const d of open) await d.close().catch(() => undefined);
    open.clear();
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  runDriverConformance(makeDriver, { fresh });
});

describe("connection queue", () => {
  const gate = () => {
    let release!: () => void;
    const open = new Promise<void>((r) => (release = r));
    return { open, release };
  };

  it("runs operations on one connection one after another, even after a failure", async () => {
    const q = connectionQueue();
    const order: string[] = [];
    const g = gate();
    const first = q.run("c1", "end", async () => {
      order.push("end:start");
      await g.open;
      order.push("end:done");
      throw new Error("boom");
    });
    const second = q.run("c1", "publish", async () => {
      order.push("publish");
    });
    await Promise.resolve();
    expect(order).toEqual(["end:start"]);
    g.release();
    await expect(first).rejects.toThrow("boom");
    await second;
    expect(order).toEqual(["end:start", "end:done", "publish"]);
  });

  it("lets different connections run together", async () => {
    const q = connectionQueue();
    const g = gate();
    const started: string[] = [];
    const a = q.run("c1", "end", async () => (started.push("c1"), g.open));
    const b = q.run("c2", "end", async () => (started.push("c2"), g.open));
    await Promise.resolve();
    expect(started).toEqual(["c1", "c2"]);
    g.release();
    await Promise.all([a, b]);
  });

  it("joins an apply that is queued or running instead of starting a second", async () => {
    const q = connectionQueue();
    const g = gate();
    let runs = 0;
    const apply = () =>
      q.run("c1", "apply", async () => ((runs += 1), g.open, runs));
    const first = apply();
    const joined = apply();
    expect(joined).toBe(first);
    g.release();
    expect(await joined).toBe(1);
    expect(await apply()).toBe(2);
    expect(runs).toBe(2);
  });

  it("queues an apply behind a running end, and a joiner still shares its promise", async () => {
    const q = connectionQueue();
    const g = gate();
    const order: string[] = [];
    const end = q.run(
      "c1",
      "end",
      async () => (await g.open, order.push("end")),
    );
    const a1 = q.run("c1", "apply", async () => order.push("apply"));
    const a2 = q.run("c1", "apply", async () => order.push("apply-2"));
    expect(a2).toBe(a1);
    g.release();
    await Promise.all([end, a1]);
    expect(order).toEqual(["end", "apply"]);
  });
});
