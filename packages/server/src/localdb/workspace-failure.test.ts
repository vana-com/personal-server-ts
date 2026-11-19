import { afterEach, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { createWorkspaceValues } from "./workspace-values.js";
import { migrate } from "../../../core/src/localdb/migrate.js";
import { openWorkspace } from "../../../core/dist/localdb/workspace.js";
import {
  openLogWorkspace,
  workspaceAttempts,
  runtimeAdmission,
  type SqlDriver,
  type WorkspaceBinding,
} from "@opendatalabs/personal-server-ts-core/localdb";
const b: WorkspaceBinding = {
  owner: "o",
  databaseIncarnation: "db",
  connection: "c",
  generation: 1,
  keyCheck: "k",
  operation: "op",
  expectedHead: "h",
  codecVersion: 1,
};
const cleanup: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const f of cleanup.splice(0).reverse()) await f();
});
async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), "workspace-failure-"));
  cleanup.push(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "db"),
    db = openBetterSqlite3(path);
  cleanup.push(() => db.close().catch(() => {}));
  await db.query("PRAGMA journal_mode=WAL");
  await db.query("PRAGMA synchronous=NORMAL");
  await migrate(db);
  await db.batch([
    {
      sql: "INSERT INTO db_meta(id,owner,network,device_id,created_at) VALUES(1,'o','t','d',0)",
    },
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,control_state) VALUES('c','t','','active')",
    },
  ]);
  return { db, path };
}
it.each(["stage", "promote", "append"])(
  "SQLITE_FULL during %s keeps a durable intent and no progress",
  async (action) => {
    const { db, path } = await fixture();
    let arm = false;
    const driver: SqlDriver = {
      ...db,
      async batch(statements) {
        if (
          arm &&
          statements.some((s) =>
            s.sql.startsWith(
              action === "stage"
                ? "INSERT OR REPLACE INTO workspace_stage"
                : action === "promote"
                  ? "INSERT OR REPLACE INTO workspace_cells"
                  : "INSERT INTO body_value_chunks",
            ),
          )
        ) {
          arm = false;
          const [row] = await db.query<{ page_count: number }>(
            "PRAGMA page_count",
          );
          await db.batch([{ sql: `PRAGMA max_page_count=${row!.page_count}` }]);
        }
        return db.batch(statements);
      },
    };
    const ws = await openWorkspace(driver, b);
    if (action === "promote")
      for (let i = 0; i < 40; i++)
        await ws.stage("u", "fold", String(i), "x".repeat(60000));
    let run: () => Promise<unknown>;
    let lease: Awaited<ReturnType<typeof runtimeAdmission.acquire>> | undefined;
    if (action === "append") {
      const bytes = Buffer.alloc(50000, 1),
        values = createWorkspaceValues(driver, 1024 * 1024),
        token = await values.begin(
          b,
          bytes.length,
          createHash("sha256").update(bytes).digest("hex"),
          "binary",
        );
      lease = await runtimeAdmission.acquire("op", 1024 * 1024);
      run = () => values.append(token, 0, bytes, lease!);
    } else
      run = () =>
        action === "stage"
          ? ws.stage("u", "fold", "key", "x".repeat(60000))
          : ws.commitUnit("u", "d", 0);
    arm = true;
    try {
      await expect(run()).rejects.toMatchObject({
        reason: "disk-full",
        receipt: expect.stringMatching(/failed|pending/),
        retryable: true,
      });
    } finally {
      await lease?.release();
    }
    expect(await ws.position()).toBe(0);
    expect(await db.query("SELECT * FROM workspace_receipts")).toEqual([]);
    const rows = await db.query(
      "SELECT state,reason FROM workspace_attempts WHERE action=?",
      [action],
    );
    expect(rows).toContainEqual({ state: "failed", reason: "disk-full" });
    await db.close();
    const reopened = openBetterSqlite3(path);
    cleanup.push(() => reopened.close());
    expect(await reopened.query("SELECT position FROM workspaces")).toEqual([
      { position: 0 },
    ]);
    expect(
      await reopened.query(
        "SELECT state,reason FROM workspace_attempts WHERE action=?",
        [action],
      ),
    ).toEqual(rows);
  },
);
it("a failed failure-write leaves the precommitted pending intent for restart", async () => {
  const { db, path } = await fixture();
  let rejectFailure = false;
  const driver: SqlDriver = {
    ...db,
    async batch(statements) {
      if (
        rejectFailure &&
        statements.some((s) => s.sql.includes("SET state='failed'"))
      )
        throw Object.assign(new Error("disk full"), { code: "SQLITE_FULL" });
      return db.batch(statements);
    },
  };
  const ws = await openWorkspace(driver, b);
  rejectFailure = true;
  await expect(ws.commitUnit("u", "d", 1)).rejects.toMatchObject({
    receipt: "pending",
  });
  expect(await workspaceAttempts(db, b).next(0)).toMatchObject({
    unit: "u",
    action: "promote",
    state: "pending",
    reason: null,
  });
  expect(await ws.position()).toBe(0);
  await db.close();
  const reopened = openBetterSqlite3(path);
  cleanup.push(() => reopened.close());
  expect(await workspaceAttempts(reopened, b).next(0)).toMatchObject({
    state: "pending",
    reason: null,
  });
});
it("oversized admission is durable, retryable, and never advances a unit", async () => {
  const { db } = await fixture(),
    ws = await openLogWorkspace(db, b);
  await expect(ws.acquire(129 * 1024 * 1024)).rejects.toMatchObject({
    reason: "admission",
    receipt: "failed",
  });
  expect(await workspaceAttempts(db, b).next(0)).toMatchObject({
    action: "acquire",
    state: "failed",
    reason: "admission",
  });
  expect(await ws.position()).toBe(0);
});
it("a lost reply after promote commit resolves from the atomic success marker without marking applied work failed", async () => {
  const { db } = await fixture();
  let lose = false;
  const driver: SqlDriver = {
    ...db,
    async batch(statements) {
      const result = await db.batch(statements);
      if (
        lose &&
        statements.some((s) =>
          s.sql.startsWith("INSERT OR REPLACE INTO workspace_cells"),
        )
      ) {
        lose = false;
        throw new Error("lost commit reply");
      }
      return result;
    },
  };
  const ws = await openWorkspace(driver, b);
  await ws.stage("u", "fold", "key", "winner");
  lose = true;
  await expect(ws.commitUnit("u", "d", 0)).resolves.toBeUndefined();
  expect(await ws.position()).toBe(1);
  expect(
    await db.query(
      "SELECT state FROM workspace_attempts WHERE action='promote'",
    ),
  ).toEqual([{ state: "succeeded" }]);
});
