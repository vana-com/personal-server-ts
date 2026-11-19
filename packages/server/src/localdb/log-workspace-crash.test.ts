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
    "seed",
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
      let stderr = "",
        timedOut = false;
      child.stderr?.on("data", (chunk) => {
        stderr = (stderr + String(chunk)).slice(-8000);
      });
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill("SIGKILL");
      }, 15000);
      try {
        await Promise.race([
          once(child, "message"),
          once(child, "exit").then(([code, signal]) => {
            throw new Error(
              `child_exited_before_boundary code=${code} signal=${signal} timeout=${timedOut}: ${stderr}`,
            );
          }),
        ]);
        // The child must stay at the durable boundary until killed, even if delivery is delayed.
        const exit = once(child, "exit");
        await new Promise((resolve) => setTimeout(resolve, 100));
        child.kill("SIGKILL");
        const [code, signal] = await exit;
        expect({ code, signal }).toEqual({ code: null, signal: "SIGKILL" });
      } finally {
        clearTimeout(timer);
        child.kill("SIGKILL");
      }
      db = openBetterSqlite3(path);
      if (target === "seed") {
        const promoted = edge === "after";
        expect(await db.query("SELECT position FROM log_state")).toEqual([
          { position: promoted ? 0 : 2 },
        ]);
        expect(
          await db.query(
            "SELECT pk_hash,op,stamp_o FROM record_changes ORDER BY pk_hash",
          ),
        ).toEqual(
          promoted
            ? [
                { pk_hash: "gone", op: "remove", stamp_o: 2 },
                { pk_hash: "p", op: "upsert", stamp_o: 9 },
                { pk_hash: "pending", op: "upsert", stamp_o: 10 },
              ]
            : [{ pk_hash: "pending", op: "upsert", stamp_o: 10 }],
        );
        expect(
          await db.query("SELECT pk_hash,rank FROM log_tombstones"),
        ).toEqual(promoted ? [{ pk_hash: "gone", rank: 2 }] : []);
        expect(await db.query("SELECT phase FROM workspaces")).toEqual([
          { phase: promoted ? "finished" : "folded" },
        ]);
        return;
      }
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
  "C1/D: SIGKILL before/after canonical restore/publication finalization and accepted watermark transaction",
);
it.todo(
  "C2: SIGKILL before/after canonical partial visibility marker, rows, receipt, and final snapshot cursor commit",
);
it.todo(
  "C3/D: SIGKILL across replacement fragment completion and omission publication receipts",
);
