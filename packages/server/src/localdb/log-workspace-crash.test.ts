import { expect, it } from "vitest";
import { fork } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { migrate } from "../../../core/src/localdb/migrate.js";
it.each(
  [
    "enqueue",
    "finish",
    "begin",
    "append",
    "seal",
    "stage",
    "receipt",
    "discard",
    "cleanup",
    "phase-folded",
    "phase-sealed",
    "phase-ready",
    "phase-sent",
  ].flatMap((target) => ["before", "after"].map((edge) => ({ target, edge }))),
)(
  "SIGKILL $edge $target commit reopens a complete prefix",
  async ({ edge, target }) => {
    const dir = await mkdtemp(join(tmpdir(), "workspace-crash-")),
      path = join(dir, "db");
    let db = openBetterSqlite3(path);
    try {
      await db.query("PRAGMA journal_mode=WAL");
      await db.query("PRAGMA synchronous=NORMAL");
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
        "enqueue",
        "finish",
        "begin",
        "append",
        "seal",
        "stage",
        "receipt",
        "discard",
        "cleanup",
        "phase-folded",
        "phase-sealed",
        "phase-ready",
        "phase-sent",
      ];
      const reached = (step: string) =>
        order.indexOf(target) > order.indexOf(step) ||
        (target === step && edge === "after");
      const committed = reached("receipt");
      const cleaned = target.startsWith("phase-") ? false : reached("cleanup");
      if (target.startsWith("phase-")) {
        const phases = ["collect", "folded", "sealed", "ready", "sent"],
          at = phases.indexOf(target.slice(6));
        expect(await db.query("SELECT phase FROM workspaces")).toEqual([
          { phase: phases[at - (edge === "before" ? 1 : 0)] },
        ]);
      }
      expect(await db.query("SELECT job FROM workspace_jobs")).toEqual(
        reached("enqueue") && !reached("finish") ? [{ job: "job" }] : [],
      );
      expect(await db.query("SELECT position FROM workspaces")).toEqual(
        ["enqueue", "finish"].includes(target)
          ? []
          : [{ position: committed ? 1 : 0 }],
      );
      expect(await db.query("SELECT payload FROM workspace_cells")).toEqual(
        committed && !cleaned
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

it.todo(
  "D: SIGKILL after remote upload success before durable upload receipt; probe or retry identical sealed bytes",
);
it.todo(
  "D: SIGKILL before/after CAS send, remote land, and reply; an old-head read does not retract the in-flight CAS",
);
it.todo(
  "D: sent CAS can land after local generation/key/deletion fence; resolve actual remote head/version before resend or discard",
);
it.todo(
  "C1: SIGKILL before/after canonical seed promotion plus cursor reset, including unpublished local writes and revision validation",
);
it.todo(
  "C1/D: SIGKILL before/after canonical restore/publication finalization and accepted watermark transaction",
);
it.todo(
  "C2: SIGKILL before/after canonical partial visibility marker, rows, receipt, and final snapshot cursor commit",
);
it.todo(
  "C3/D: SIGKILL across replacement fragment completion and omission publication receipts",
);
