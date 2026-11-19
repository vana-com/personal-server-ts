import { expect, it } from "vitest";
import { fork } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { migrate } from "../../../core/src/localdb/migrate.js";
it.each(
  ["begin", "append", "seal", "stage", "receipt", "discard", "cleanup"].flatMap(
    (target) => ["before", "after"].map((edge) => ({ target, edge })),
  ),
)(
  "SIGKILL $edge $target commit reopens a complete prefix",
  async ({ edge, target }) => {
    const dir = await mkdtemp(join(tmpdir(), "workspace-crash-")),
      path = join(dir, "db");
    let db = openBetterSqlite3(path);
    try {
      await migrate(db);
      await db.batch([
        {
          sql: "INSERT INTO db_meta(id,owner,network,device_id,created_at) VALUES(1,'o','test','d',0)",
        },
        {
          sql: "INSERT INTO connections(connection_id,connector,ns,control_state) VALUES('c','test','','active')",
        },
      ]);
      await db.close();
      const child = fork(
        new URL("./workspace-crash.harness.ts", import.meta.url),
        [path, edge, target],
        {
          execArgv: ["--import", "tsx"],
          stdio: ["ignore", "ignore", "pipe", "ipc"],
        },
      );
      const timer = setTimeout(() => child.kill("SIGKILL"), 15000);
      try {
        await Promise.race([
          once(child, "message"),
          once(child, "exit").then(() => {
            throw new Error("child_exited_before_boundary");
          }),
        ]);
        const exit = once(child, "exit");
        child.kill("SIGKILL");
        expect((await exit)[1]).toBe("SIGKILL");
      } finally {
        clearTimeout(timer);
        child.kill("SIGKILL");
      }
      db = openBetterSqlite3(path);
      const order = [
        "begin",
        "append",
        "seal",
        "stage",
        "receipt",
        "discard",
        "cleanup",
      ];
      const reached = (step: string) =>
        order.indexOf(target) > order.indexOf(step) ||
        (target === step && edge === "after");
      const committed = reached("receipt");
      expect(await db.query("SELECT position FROM workspaces")).toEqual([
        { position: committed ? 1 : 0 },
      ]);
      expect(await db.query("SELECT payload FROM workspace_cells")).toEqual(
        committed && !reached("cleanup")
          ? [{ payload: '{"first_o":null,"delete":true}' }]
          : [],
      );
      expect(
        await db.query("SELECT unit,digest FROM workspace_receipts"),
      ).toEqual(committed ? [{ unit: "unit", digest: "digest" }] : []);
      const rows = await db.query("SELECT offset,sealed FROM body_values");
      expect(rows).toEqual(
        reached("begin")
          ? [
              {
                offset: reached("append") ? 12 : 0,
                sealed: reached("seal") ? 1 : 0,
              },
            ]
          : [],
      );
    } finally {
      await db.close().catch(() => {});
      await rm(dir, { recursive: true, force: true });
    }
  },
  30000,
);
