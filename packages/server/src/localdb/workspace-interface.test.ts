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
  expect(values.supportsBorrowedSeal).toBe(true);
  const bytes = Buffer.from("body"),
    writer = await values.begin(
      b,
      4,
      createHash("sha256").update(bytes).digest("hex"),
      "utf8",
    ),
    lease = await runtimeAdmission.acquire("op", 65536);
  await values.append(writer, 0, bytes, lease);
  const body = await values.seal(writer, lease);
  await lease.release();
  const unit = await ws.unit("u", "digest", 0);
  if (unit.state !== "staging") throw new Error("expected staging");
  await expect(
    unit.stage("outputs", {
      objectKey: "o",
      value: { ...body, id: "missing" },
    }),
  ).rejects.toThrow();
  const lookupLease = await runtimeAdmission.acquire("op", 2 * 1024 * 1024);
  expect(
    await ws.lookup("u", "outputs", JSON.stringify(["o"]), lookupLease),
  ).toBeNull();
  await lookupLease.release();
  const pendingStage = unit.stage("outputs", { objectKey: "o", value: body });
  await expect(
    unit.stage("outputs", { objectKey: "other", value: body }),
  ).rejects.toThrow("busy");
  await expect(unit.commit()).rejects.toThrow("busy");
  await pendingStage;
  const stagedLease = await runtimeAdmission.acquire("op", 2 * 1024 * 1024);
  expect(
    await ws.lookup("u", "outputs", JSON.stringify(["o"]), stagedLease),
  ).toEqual({ objectKey: "o", value: body });
  await stagedLease.release();
  const receipt = await unit.commit();
  expect(receipt.state).toBe("receipted");
  await expect(
    unit.stage("outputs", { objectKey: "o", value: body }),
  ).rejects.toThrow("receipted");
  expect((await ws.unit("u", "digest", 0)).state).toBe("receipted");
  const streams = ["z", "a\n", "a", 'a"', "a\\", "é", "😀", "a\u0000", "aa"];
  const order = await ws.unit("order", "order-digest", 1);
  if (order.state !== "staging") throw new Error("expected staging");
  for (const stream of streams)
    await order.stage("streams", { stream, metadata: body });
  await order.commit();
  const cursor = ws.cursor("streams"),
    cursorLease = await runtimeAdmission.acquire("op", 2 * 1024 * 1024),
    seen = [];
  const pendingWriter = await values.begin(
    b,
    bytes.length,
    createHash("sha256").update(bytes).digest("hex"),
    "utf8",
  );
  await values.append(pendingWriter, 0, bytes, cursorLease);
  try {
    for (;;) {
      const next = await cursor.next(cursorLease);
      if (!next) break;
      if (seen.length === 0)
        await expect(values.seal(pendingWriter, cursorLease)).rejects.toThrow(
          "workspace_unit_owned",
        );
      seen.push(next.value.row.stream);
      await next.release();
      if (seen.length === 1) await values.seal(pendingWriter, cursorLease);
    }
  } finally {
    await cursor.close();
    await cursorLease.release();
  }
  expect(seen).toEqual([...streams].sort());
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
 // @ts-expect-error an unpublished completion must remain false
 staging.stage('publication',{stream:'s',watermark:1,complete:true,published:false,completesAfterPublish:true,from:null,to:null});
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

it("seed promotion reads current local rows and atomically validates the original cursor and control revision", async () => {
  const dir = await mkdtemp(join(tmpdir(), "workspace-seed-"));
  cleanup.push(() => rm(dir, { recursive: true, force: true }));
  const db = openBetterSqlite3(join(dir, "db"));
  cleanup.push(() => db.close());
  await migrate(db);
  await db.batch([
    { sql: "INSERT INTO db_meta VALUES(1,'o','test','d',0,0)" },
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,control_state) VALUES('c','test','','active')",
    },
    { sql: "INSERT INTO log_state VALUES('c',2,0,'[]',NULL)" },
  ]);
  const b: WorkspaceBinding = {
    owner: "o",
    databaseIncarnation: "db",
    connection: "c",
    generation: 1,
    keyCheck: "k",
    operation: "seed",
    expectedHead: "h",
    codecVersion: 1,
  };
  const ws = await openLogWorkspace(db, b);
  const expected = { position: 2, base: 0, refs: [], snapshot: null },
    target = { ...expected, position: 0 };
  await ws.stageSeed(
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
  await ws.stageSeed(
    {
      kind: "omitted",
      stream: "s",
      pkHash: "gone",
      stamp: { o: 1, r: "old" },
      key: [2],
    },
    ["id"],
  );
  await ws.transition("collect", "folded");
  // Arrives after seed preparation. Promotion must read this newer observation.
  await db.batch([
    {
      sql: "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES('c','s','p','1',9,'new','{}','hash')",
    },
    { sql: "DELETE FROM record_changes" },
  ]);
  await expect(ws.promoteSeed(expected, target, 1)).rejects.toThrow();
  expect(await db.query("SELECT position FROM log_state")).toEqual([
    { position: 2 },
  ]);
  expect(await db.query("SELECT * FROM record_changes")).toEqual([]);
  await ws.promoteSeed(expected, target, 0);
  expect(await db.query("SELECT position FROM log_state")).toEqual([
    { position: 0 },
  ]);
  expect(
    await db.query(
      "SELECT pk_hash,op,stamp_o,explicit_delete,pk_values FROM record_changes ORDER BY pk_hash",
    ),
  ).toEqual([
    {
      pk_hash: "gone",
      op: "remove",
      stamp_o: 1,
      explicit_delete: 0,
      pk_values: "[2]",
    },
    {
      pk_hash: "p",
      op: "upsert",
      stamp_o: 9,
      explicit_delete: 0,
      pk_values: null,
    },
  ]);
});

it("set-based history seed preserves pending changes, delete kinds and current-row selection exactly", async () => {
  const { seedFromHistory } = await import("./history-seed.test-utils.js");
  const { writeLogState } =
    await import("../../../core/src/localdb/log-state.js");
  const dir = await mkdtemp(join(tmpdir(), "workspace-seed-oracle-"));
  cleanup.push(() => rm(dir, { recursive: true, force: true }));
  const db = openBetterSqlite3(join(dir, "db"));
  cleanup.push(() => db.close());
  await migrate(db);
  await db.batch([
    {
      sql: "INSERT INTO db_meta(id,owner,network,device_id,created_at) VALUES(1,'o','test','d',0)",
    },
  ]);
  const old = { position: 2, base: 0, refs: [], snapshot: null },
    target = { ...old, position: 0 };
  for (const connection of ["c", "reference"]) {
    await db.batch([
      {
        sql: "INSERT INTO connections(connection_id,connector,ns,control_state) VALUES(?,'test','','active')",
        params: [connection],
      },
      writeLogState(connection, old),
      ...["live", "resurrected", "only-delete", "pending"].map((pk) => ({
        sql: "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES(?,'s',?,?,9,'local','{}','hash')",
        params: [connection, pk, pk],
      })),
      {
        sql: "DELETE FROM record_changes WHERE connection_id=?",
        params: [connection],
      },
      {
        sql: "INSERT INTO record_changes(connection_id,stream,pk_hash,record_key,op,stamp_o,stamp_r,origin) VALUES(?,'s','pending','pending','upsert',10,'pending','local')",
        params: [connection],
      },
    ]);
  }
  const stamp = { o: 1, r: "history" };
  const up = (pkHash: string) => ({
    kind: "upsert" as const,
    stream: "s",
    pkHash,
    stamp,
    firstSeen: null,
    value: { id: pkHash },
  });
  const del = (pkHash: string, kind: "delete" | "omitted") => ({
    kind,
    stream: "s",
    pkHash,
    key: [pkHash],
    stamp,
  });
  const entries = [
    up("live"),
    up("missing"),
    del("explicit", "delete"),
    del("omission", "omitted"),
    del("resurrected", "delete"),
    up("resurrected"),
    del("only-delete", "delete"),
    up("pending"),
  ];
  const ws = await openLogWorkspace(db, {
    owner: "o",
    databaseIncarnation: "db",
    connection: "c",
    generation: 1,
    keyCheck: "k",
    operation: "seed-oracle",
    expectedHead: "h",
    codecVersion: 1,
  });
  for (const entry of entries) await ws.stageSeed(entry, ["id"]);
  await ws.transition("collect", "folded");
  await ws.promoteSeed(old, target, 0);
  await db.batch([
    ...seedFromHistory("reference", entries, new Map([["s", ["id"]]])),
    writeLogState("reference", target),
  ]);
  for (const table of ["record_changes", "log_tombstones"]) {
    const columns =
      table === "record_changes"
        ? "stream,pk_hash,record_key,op,stamp_o,stamp_r,origin,explicit_delete,pk_values"
        : "stream,pk_hash,record_key,stamp_o,stamp_r,rank";
    expect(
      await db.query(
        `SELECT ${columns} FROM ${table} WHERE connection_id='c' ORDER BY pk_hash`,
      ),
    ).toEqual(
      await db.query(
        `SELECT ${columns} FROM ${table} WHERE connection_id='reference' ORDER BY pk_hash`,
      ),
    );
  }
});
