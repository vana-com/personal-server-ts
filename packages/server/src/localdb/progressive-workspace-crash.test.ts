import { expect, it } from "vitest";
import { fork } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { openLocalDb } from "../../../core/src/localdb/index.js";
import { replay } from "./progressive-workspace-crash.harness.js";

it.each(
  ["owner", "scan", "body", "partial-0", "partial-2"].flatMap((target) =>
    ["before", "after"].map((edge) => ({ target, edge })),
  ),
)(
  "SIGKILL $edge $target preserves truthful partial markers and replay",
  async ({ target, edge }) => {
    const dir = await mkdtemp(join(tmpdir(), "partial-crash-")),
      path = join(dir, "db");
    let db = await openLocalDb(openBetterSqlite3(path), {
      owner: "o",
      network: "test",
      deviceId: "d",
    });
    try {
      await db.batch([
        {
          sql: "INSERT INTO connections(connection_id,connector,ns,control_state) VALUES('c','test','','active')",
        },
      ]);
      await db.close();
      const child = fork(
        new URL("./progressive-workspace-crash.harness.ts", import.meta.url),
        [path, edge, target],
        {
          execArgv: ["--import", "tsx"],
          stdio: ["ignore", "ignore", "pipe", "ipc"],
        },
      );
      let stderr = "";
      child.stderr!.on("data", (data) => {
        stderr += data;
      });
      const timer = setTimeout(() => child.kill("SIGKILL"), 15000);
      try {
        await Promise.race([
          once(child, "message"),
          once(child, "exit").then(() => {
            throw new Error(`child_exited_before_boundary: ${stderr}`);
          }),
        ]);
        const exited = once(child, "exit");
        child.kill("SIGKILL");
        expect((await exited)[1]).toBe("SIGKILL");
      } finally {
        clearTimeout(timer);
        child.kill("SIGKILL");
      }
      db = await openLocalDb(openBetterSqlite3(path), {
        owner: "o",
        network: "test",
        deviceId: "d",
      });
      const applied =
        target === "partial-2"
          ? edge === "after"
            ? 3
            : 2
          : target === "partial-0" && edge === "after"
            ? 1
            : 0;
      expect(
        await db.query(
          "SELECT position FROM workspace_receipts ORDER BY position",
        ),
      ).toEqual(
        Array.from({ length: applied }, (_, i) => ({ position: i + 1 })),
      );
      expect(
        await db.query("SELECT parts_applied,parts_total FROM stream_partial"),
      ).toEqual(
        applied === 3 || target === "owner"
          ? []
          : [{ parts_applied: applied, parts_total: 3 }],
      );
      expect(await db.query("SELECT complete FROM stream_state")).toEqual(
        target === "owner" ? [] : [{ complete: applied === 3 ? 1 : 0 }],
      );
      expect(await db.query("SELECT position FROM log_state")).toEqual(
        applied === 3 ? [{ position: 3 }] : [],
      );
      if (applied === 1)
        expect(
          await db.query("SELECT pk_hash FROM partial_hidden"),
        ).toHaveLength(1);
      await replay(db, false, true);
      expect(await db.query("SELECT body FROM records")).toEqual([
        { body: '{"id":"k","v":3}' },
      ]);
      expect(await db.query("SELECT * FROM stream_partial")).toEqual([]);
      expect(await db.query("SELECT * FROM partial_hidden")).toEqual([]);
      expect(await db.query("SELECT position FROM log_state")).toEqual([
        { position: 3 },
      ]);
    } finally {
      await db.close().catch(() => {});
      await rm(dir, { recursive: true, force: true });
    }
  },
  30000,
);
