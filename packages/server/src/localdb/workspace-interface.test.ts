import { afterEach, expect, it } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import ts from "typescript";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { migrate } from "../../../core/src/localdb/migrate.js";
import {
  openLogWorkspace,
  runtimeAdmission,
  setWorkspaceAuthority,
  type WorkspaceBinding,
} from "@opendatalabs/personal-server-ts-core/localdb";
const cleanup: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const f of cleanup.splice(0).reverse()) await f();
});
it("typed units validate sealed references and revoke staging aliases after receipt", async () => {
  const dir = await mkdtemp(join(tmpdir(), "workspace-interface-"));
  cleanup.push(() => rm(dir, { recursive: true, force: true }));
  const db = openBetterSqlite3(join(dir, "db"));
  cleanup.push(() => db.close());
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
  const ws = await openLogWorkspace(db, b),
    values = db.boundedValues!;
  const bytes = Buffer.from("body"),
    writer = await values.begin(
      b,
      4,
      createHash("sha256").update(bytes).digest("hex"),
      "utf8",
    ),
    lease = await runtimeAdmission.acquire("op", 65536);
  await values.append(writer, 0, bytes, lease);
  await lease.release();
  const body = await values.seal(writer);
  const unit = await ws.unit("u", "digest", 0);
  if (unit.state !== "staging") throw new Error("expected staging");
  await expect(
    unit.stage("outputs", {
      objectKey: "o",
      value: { ...body, id: "missing" },
    }),
  ).rejects.toThrow();
  const pendingStage = unit.stage("outputs", { objectKey: "o", value: body });
  await expect(
    unit.stage("outputs", { objectKey: "other", value: body }),
  ).rejects.toThrow("busy");
  await expect(unit.commit()).rejects.toThrow("busy");
  await pendingStage;
  const receipt = await unit.commit();
  expect(receipt.state).toBe("receipted");
  await expect(
    unit.stage("outputs", { objectKey: "o", value: body }),
  ).rejects.toThrow("receipted");
  expect((await ws.unit("u", "digest", 0)).state).toBe("receipted");
  await setWorkspaceAuthority(db, { ...b, keyCheck: "other" });
  await expect(ws.unit("u", "digest", 0)).rejects.toThrow();
  await setWorkspaceAuthority(db, b);
  await db.batch([
    { sql: "UPDATE connections SET generation=2 WHERE connection_id='c'" },
  ]);
  await expect(ws.unit("u", "digest", 0)).rejects.toThrow();
  await expect(openLogWorkspace(db, { ...b, generation: 2 })).rejects.toThrow();
});
it("consumer type contract rejects writer/reader confusion and staging a receipt", async () => {
  const path = join(
    process.cwd(),
    "packages/server/src/localdb/workspace-contract-check.harness.ts",
  );
  cleanup.push(() => rm(path, { force: true }));
  await writeFile(
    path,
    `import type {ByteLease,BoundedValueStore,ValueToken,ReceiptedWorkspaceUnit,StagingWorkspaceUnit,WorkspaceValueReader} from '@opendatalabs/personal-server-ts-core/localdb';
 declare const lease:ByteLease, store:BoundedValueStore, sealed:ValueToken, receipt:ReceiptedWorkspaceUnit, reader:WorkspaceValueReader, staging:StagingWorkspaceUnit;
 // @ts-expect-error a sealed reader cannot be appended
 store.append(sealed,0,new Uint8Array(),lease);
 // @ts-expect-error a reader has no append
 reader.append(new Uint8Array());
 // @ts-expect-error receipted units have no staging capability
 receipt.stage('fold',{});
 // @ts-expect-error fold rows require both independent maxima and a key
 staging.stage('fold',{value:sealed});
 `,
  );
  const program = ts.createProgram([path], {
    noEmit: true,
    strict: true,
    skipLibCheck: true,
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.Node16,
    moduleResolution: ts.ModuleResolutionKind.Node16,
  });
  expect(
    ts
      .getPreEmitDiagnostics(program)
      .map((d) => ts.flattenDiagnosticMessageText(d.messageText, "\n")),
  ).toEqual([]);
});
