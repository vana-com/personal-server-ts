import { createHash } from "node:crypto";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { createWorkspaceValues } from "./workspace-values.js";
import {
  openWorkspace,
  runtimeAdmission,
  type SqlDriver,
  type WorkspaceBinding,
} from "@opendatalabs/personal-server-ts-core/localdb";
const [path, edge, target] = process.argv.slice(2);
const base = openBetterSqlite3(path!);
const patterns: Record<string, string> = {
  begin: "INSERT INTO body_values(",
  append: "UPDATE body_values SET offset",
  seal: "UPDATE body_values SET sealed=1",
  stage: "INSERT OR REPLACE INTO workspace_stage",
  receipt: "INSERT OR IGNORE INTO workspace_receipts",
  discard: "UPDATE workspaces SET phase='aborted'",
  cleanup: "DELETE FROM workspace_cells WHERE",
};
const stop = async () => {
  process.send!({ edge, target });
  await new Promise(() => {});
};
const db: SqlDriver = {
  ...base,
  async batch(statements) {
    const match = statements.some((s) => s.sql.includes(patterns[target!]!));
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
await ws.discard();
await ws.cleanupOne();
throw new Error("boundary_not_reached");
