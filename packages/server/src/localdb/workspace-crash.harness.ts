import { openWorkspace } from "../../../core/dist/localdb/workspace.js";
import { createHash } from "node:crypto";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { createWorkspaceValues } from "./workspace-values.js";
import {
  runtimeAdmission,
  openLogWorkspace,
  type SqlDriver,
  type WorkspaceBinding,
} from "@opendatalabs/personal-server-ts-core/localdb";
const [path, edge, target] = process.argv.slice(2);
const base = openBetterSqlite3(path!);
await base.query("PRAGMA synchronous=NORMAL");
const patterns: Record<string, string> = {
  enqueue: "INSERT OR IGNORE INTO workspace_jobs",
  finish: "DELETE FROM workspace_jobs",
  begin: "INSERT INTO body_values(",
  append: "UPDATE body_values SET offset",
  seal: "UPDATE body_values SET sealed=1",
  stage: "INSERT OR REPLACE INTO workspace_stage",
  receipt: "INSERT OR IGNORE INTO workspace_receipts",
  seed: "UPDATE workspaces SET phase='finished'",
  discard: "UPDATE workspaces SET phase='aborted'",
  cleanup: "DELETE FROM workspace_cells WHERE",
};
const stop = async () => {
  process.on("message", () => {}); // Keep IPC referenced until the parent sends SIGKILL.
  process.send!({ edge, target });
  await new Promise(() => {});
};
const db: SqlDriver = {
  ...base,
  async batch(statements) {
    const match = statements.some((s) =>
      target!.startsWith("phase-")
        ? s.sql === "UPDATE workspaces SET phase=? WHERE operation=?" &&
          s.params?.[0] === target!.slice(6)
        : s.sql.includes(patterns[target!]!),
    );
    if (match && edge === "before") await stop();
    const result = await base.batch(statements);
    if (match && edge === "after") await stop();
    return result;
  },
};
const b: WorkspaceBinding = {
  owner: "o",
  databaseIncarnation: "db",
  connection: "c",
  generation: 1,
  keyCheck: "key",
  operation: "job",
  expectedHead: "h",
  codecVersion: 1,
};
await runtimeAdmission.enqueue(db, "job");
await runtimeAdmission.finish(db, "job");
const ws = await openWorkspace(db, b),
  values = createWorkspaceValues(db, 4096),
  bytes = Buffer.from("sealed value");
const token = await values.begin(
  b,
  bytes.length,
  createHash("sha256").update(bytes).digest("hex"),
  "utf8",
);
const lease = await runtimeAdmission.acquire(b.operation, 65536);
await values.append(token, 0, bytes, lease);
await lease.release();
await values.seal(token);
await ws.stage("unit", "fold", "key", '{"first_o":null,"delete":true}');
await ws.commitUnit("unit", "digest", 0);
if (target === "seed") {
  const typed = await openLogWorkspace(db, b);
  await typed.stageSeed(
    {
      kind: "upsert",
      stream: "s",
      pkHash: "p",
      stamp: { o: 1, r: "old" },
      firstSeen: null,
      value: { id: 1 },
    },
    ["id"],
  );
  await typed.stageSeed(
    {
      kind: "delete",
      stream: "s",
      pkHash: "gone",
      stamp: { o: 2, r: "delete" },
      key: [2],
    },
    ["id"],
  );
  await typed.transition("collect", "folded");
  await db.batch([
    { sql: "INSERT INTO log_state VALUES('c',2,0,'[]',NULL)" },
    {
      sql: "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES('c','s','p','1',9,'late','{}','hash')",
    },
    { sql: "DELETE FROM record_changes" },
    {
      sql: "INSERT INTO record_changes(connection_id,stream,pk_hash,record_key,op,stamp_o,stamp_r,origin) VALUES('c','s','pending','3','upsert',10,'local','local')",
    },
  ]);
  const old = { position: 2, base: 0, refs: [], snapshot: null };
  await typed.promoteSeed(old, { ...old, position: 0 }, 0);
} else if (target!.startsWith("phase-")) {
  await ws.transition("collect", "folded");
  await ws.transition("folded", "sealed");
  await ws.transition("sealed", "ready");
  await ws.transition("ready", "sent");
} else await ws.discard();
await ws.cleanupOne();
throw new Error("boundary_not_reached");
