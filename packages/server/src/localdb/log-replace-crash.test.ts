import { expect, it } from "vitest";
import { fork } from "node:child_process";
import { once } from "node:events";
import { rm } from "node:fs/promises";
import { dirname } from "node:path";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

it.each(
  [
    "freeze",
    "selection",
    "canonical",
    "publication",
    "whole",
    "cleanup",
  ].flatMap((target) => ["before", "after"].map((edge) => ({ target, edge }))),
)(
  "replacement SIGKILL $edge $target preserves a truthful durable prefix",
  async ({ target, edge }) => {
    const child = fork(
      new URL("./log-replace-crash.harness.ts", import.meta.url),
      [edge, target],
      {
        execArgv: ["--import", "tsx"],
        stdio: ["ignore", "ignore", "pipe", "ipc"],
      },
    );
    let stderr = "";
    child.stderr!.on("data", (b) => {
      stderr += b;
    });
    const timer = setTimeout(() => child.kill("SIGKILL"), 60000);
    let path: string | undefined;
    try {
      const [receipt] = (await Promise.race([
        once(child, "message"),
        once(child, "exit").then(() => {
          throw new Error(`child_exited_before_boundary: ${stderr}`);
        }),
      ])) as [
        { path: string; before: number; operation: string; whole: boolean },
      ];
      path = receipt.path;
      const exit = once(child, "exit");
      child.kill("SIGKILL");
      expect((await exit)[1]).toBe("SIGKILL");
      const db = openBetterSqlite3(path);
      try {
        const committed =
          ["publication", "cleanup"].includes(target) ||
          (["canonical", "whole"].includes(target) && edge === "after");
        const [log] = await db.query<{ position: number }>(
          "SELECT position FROM log_state",
        );
        expect(log!.position).toBe(receipt.before + (committed ? 1 : 0));
        const [state] = await db.query<{ complete: number }>(
          "SELECT complete FROM stream_state",
        );
        if (committed) expect(state!.complete).toBe(receipt.whole ? 1 : 0);
        const cells = await db.query<{
          relation: string;
          key: string;
          payload: string;
        }>(
          "SELECT relation,key,payload FROM workspace_cells WHERE operation=?",
          [receipt.operation],
        );
        const cleaned = target === "cleanup" && edge === "after";
        const frozen = cells.some((c) => c.relation === "replacement");
        expect(frozen).toBe(
          !cleaned && (target !== "freeze" || edge === "after"),
        );
        if (frozen)
          expect(cells.filter((c) => c.relation === "changes").length).toBe(2);
        const selection = cells.find((c) => c.relation === "publication");
        const prepared =
          !cleaned &&
          target !== "freeze" &&
          (target !== "selection" || edge === "after");
        expect(Boolean(selection)).toBe(prepared);
        if (selection) {
          const value = JSON.parse(selection.payload);
          expect(value.published).toBe(
            (target === "publication" && edge === "after") ||
              target === "cleanup",
          );
          expect(value.complete).toBe(
            receipt.whole &&
              ((target === "publication" && edge === "after") ||
                target === "cleanup"),
          );
          expect(value.completesAfterPublish).toBe(receipt.whole);
        }
        const published = cells.filter(
          (c) => c.relation === "omissions" && JSON.parse(c.payload).published,
        );
        if (!committed) expect(published).toHaveLength(0);
        const rows = await db.query<{ body: string }>(
          "SELECT body FROM records ORDER BY pk_hash",
        );
        expect(
          rows.some(
            (r) => JSON.parse(r.body).id === 0 && JSON.parse(r.body).v === 2,
          ),
        ).toBe(true);
        // The changed rows and every unpublished omission remain durable. A
        // whole accepted completion drops all 28 old rows atomically.
        if (receipt.whole) expect(rows).toHaveLength(committed ? 2 : 30);
        else if (!committed) expect(rows).toHaveLength(30);
        else expect(rows.length).toBeGreaterThan(2);
      } finally {
        await db.close();
      }
    } finally {
      clearTimeout(timer);
      child.kill("SIGKILL");
      if (path) await rm(dirname(path), { recursive: true, force: true });
    }
  },
  90000,
);
