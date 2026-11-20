// Child of log-output-crash.test.ts: the durable sequence of one compaction's
// outputs on a file database, stopped at a chosen commit and killed there by the
// parent. The remote store is a file the parent can read after the kill.
import { appendFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { join, dirname } from "node:path";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { createWorkspaceValues } from "./workspace-values.js";
import {
  outputProducer,
  sealOutputs,
  sendOutputs,
  settleOutputs,
  uploadOutputs,
} from "../../../core/dist/localdb/log-output.js";
import {
  runtimeAdmission,
  setWorkspaceAuthority,
} from "../../../core/dist/localdb/workspace.js";
import { openLogWorkspace } from "../../../core/dist/localdb/workspace-consumer.js";
import type { SqlDriver } from "../../../core/dist/localdb/driver.js";
import type { LocalSyncDeps } from "../../../core/dist/localdb/deps.js";

const OPERATION = "out-job";
const NAMES = ["a", "b", "c"] as const;
const [path, edge, target] = process.argv.slice(2);
const base = openBetterSqlite3(path!);
await base.query("PRAGMA synchronous=NORMAL");
const matches: Record<
  string,
  (s: { sql: string; params?: readonly unknown[] }) => boolean
> = {
  "output-seal": (s) => s.sql.includes("UPDATE body_values SET sealed=1"),
  "output-receipt": (s) =>
    s.sql.includes("INSERT OR IGNORE INTO workspace_receipts") &&
    String(s.params?.[1]).startsWith("output:"),
  "upload-receipt": (s) =>
    s.sql.includes("INSERT OR IGNORE INTO workspace_receipts") &&
    String(s.params?.[1]).startsWith("upload:"),
  ready: (s) =>
    s.sql === "UPDATE workspaces SET phase=? WHERE operation=?" &&
    s.params?.[0] === "ready",
  sent: (s) => s.sql.includes("UPDATE workspaces SET phase='sent'"),
  settle: (s) =>
    s.sql.includes(
      "UPDATE workspaces SET phase=? WHERE operation=? AND phase='sent'",
    ) && s.params?.[0] === "finished",
  cleanup: (s) => s.sql.includes("DELETE FROM workspace_sent"),
};
const stop = async () => {
  process.on("message", () => {});
  process.send!({ edge, target });
  await new Promise(() => {});
};
let seen = 0;
const db: SqlDriver = {
  ...base,
  async batch(statements) {
    // The first matching commit is the boundary.
    const hit = statements.some((s) => matches[target!]!(s)) && seen++ === 0;
    if (hit && edge === "before") await stop();
    const result = await base.batch(statements);
    if (hit && edge === "after") await stop();
    return result;
  },
};
db.boundedValues = createWorkspaceValues(db, 4096);
const deps = { db } as unknown as LocalSyncDeps;
const [meta] = await db.query<{
  owner: string;
  device_id: string;
  created_at: number;
}>("SELECT owner,device_id,created_at FROM db_meta WHERE id=1");
const binding = {
  owner: meta!.owner,
  databaseIncarnation: JSON.stringify([meta!.device_id, meta!.created_at]),
  connection: "c",
  generation: 1,
  keyCheck: "key",
  operation: OPERATION,
  expectedHead: "0xold",
  codecVersion: 1,
};
await setWorkspaceAuthority(db, binding);
const ws = await openLogWorkspace(db, binding);
const remote = join(dirname(path!), "remote.log");
const lease = await ws.acquire(128 * 1024 * 1024);
const producer = outputProducer(deps, ws, lease);
// A restarted producer would encrypt again: the bytes differ every time.
for (const name of NAMES) await producer.put(name, randomBytes(96));
await ws.transition("collect", "folded");
await lease.release();
await runtimeAdmission.finish(db, OPERATION);
await sealOutputs(ws);
const outputs = { ws, count: producer.count };
await uploadOutputs(deps, outputs, async (name, bytes) => {
  appendFileSync(
    remote,
    `${name} ${createHash("sha256").update(bytes).digest("hex")}\n`,
  );
});
await sendOutputs(outputs, 2, "0xold", "0xnew");
await settleOutputs(deps, outputs, { kind: "head", version: 2, head: "0xnew" });
throw new Error("boundary_not_reached");
