import Database from "better-sqlite3";
import { afterEach, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { MergeContext } from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";
import { BINARY_NAMESPACE_ROLE } from "./pdpp-binary-chunks.js";

/**
 * Write-side invariants the read side relies on (asked by the #438 lane):
 * (1) removing a quarantine fact raises the connection's integrity epoch in
 *     the same transaction;
 * (2) the one quarantine predicate, given a row's generation, hides a key
 *     fact's rows of exactly that generation, including the generation a
 *     pending reset introduces;
 * (3) every blob namespace whose bytes a reader can be served has a
 *     manifest trigger in the visibility view.
 */

const sourceId = "https://source.invalid/declaration";
const at = "2026-10-21T00:00:00.000Z";
const binding = {
  digest: `sha256:${"a".repeat(64)}`,
  version: "1",
  stream: "messages",
  semantics: "mutable_state" as const,
  primaryKey: ["id"],
  schemaDigest: `sha256:${"b".repeat(64)}`,
};
const declarations: MergeContext["declarations"] = [
  { sourceId, binding, validateData: (data) => typeof data.id === "string" },
];
const credential = "replica-secret";
const directories: string[] = [];
const closers: (() => void)[] = [];
afterEach(() => {
  for (const close of closers.splice(0)) close();
  for (const path of directories.splice(0))
    rmSync(path, { recursive: true, force: true });
});

function device() {
  const directory = mkdtempSync(join(tmpdir(), "pdpp-invariants-"));
  directories.push(directory);
  const db = new Database(join(directory, "db.sqlite"));
  const store = createSqliteRecordStore(db);
  store.registerConnection({
    instance: "conn_a",
    sourceId,
    method: "collector",
    label: "A",
  });
  store.replication.beginBaseline({
    owner: "owner",
    declarations: [{ sourceId, binding }],
  });
  const receiver = createReplicaReceiver({
    db,
    store,
    owner: "owner",
    enabled: true,
    authenticate: (c: unknown) => (c === credential ? "owner" : undefined),
    declarations: () => declarations,
  });
  closers.push(() => db.open && store.close());
  return { db, store, receiver };
}

it("(1) removing a key or connection quarantine fact raises the integrity epoch in the same transaction", () => {
  const { db, store } = device();
  db.transaction(() => {
    db.prepare(
      "INSERT INTO pdpp_replica_quarantined_keys VALUES ('conn_a',1,'messages','a')",
    ).run();
    db.prepare(
      "INSERT INTO pdpp_replica_quarantined_connections VALUES ('conn_a')",
    ).run();
    store.fenceReplicaConnection("conn_a");
  })();
  const before = store.replicaIntegrityEpoch("conn_a");
  db.prepare("DELETE FROM pdpp_replica_quarantined_keys").run();
  expect(store.replicaIntegrityEpoch("conn_a")).toBe(before + 1);
  db.prepare("DELETE FROM pdpp_replica_quarantined_connections").run();
  expect(store.replicaIntegrityEpoch("conn_a")).toBe(before + 2);
});

it("(2) with the row's generation, a key fact hides rows of exactly its generation, as the canonical current-generation rule does", () => {
  const { db, store } = device();
  store.ingestBatch(
    [
      {
        instance: "conn_a",
        stream: "messages",
        key: "a",
        data: { id: "a", text: "canonical-1" },
        emitted_at: at,
      },
    ],
    () => binding.semantics,
    () => ["id"],
    { method: "collector", generation: 1 },
  );
  // A preview row in the generation a pending reset introduces.
  db.exec(
    "CREATE TEMP TABLE preview_rows (instance TEXT, stream TEXT, record_key TEXT, generation INTEGER); INSERT INTO preview_rows VALUES ('conn_a','messages','a',2)",
  );
  // An owner overlay or local row of the current generation.
  db.exec(
    "CREATE TEMP TABLE current_rows (instance TEXT, stream TEXT, record_key TEXT, generation INTEGER); INSERT INTO current_rows VALUES ('conn_a','messages','a',1)",
  );
  const preview = () =>
    (
      db
        .prepare(
          `SELECT count(*) AS n FROM preview_rows r WHERE ${store.unquarantinedRecordSql("r", "r.generation")}`,
        )
        .get() as { n: number }
    ).n;
  const current = () =>
    (
      db
        .prepare(
          `SELECT count(*) AS n FROM current_rows r WHERE ${store.unquarantinedRecordSql("r", "r.generation")}`,
        )
        .get() as { n: number }
    ).n;
  const canonical = () =>
    (
      db
        .prepare(
          `SELECT count(*) AS n FROM pdpp_records r WHERE r.deleted=0 AND ${store.unquarantinedRecordSql("r")}`,
        )
        .get() as { n: number }
    ).n;
  expect([preview(), current(), canonical()]).toEqual([1, 1, 1]);
  const quarantine = (generation: number) =>
    db.transaction(() => {
      db.prepare(
        "INSERT INTO pdpp_replica_quarantined_keys VALUES ('conn_a',?,'messages','a')",
      ).run(generation);
      store.fenceReplicaConnection("conn_a");
    })();
  // The binding is at generation 1; the fact is for generation 2.
  // A generation-2 fact hides the generation-2 row only: the current
  // generation's overlay row and canonical row agree and stay visible.
  quarantine(2);
  expect([preview(), current(), canonical()]).toEqual([0, 1, 1]);
  // A generation-1 fact hides both generation-1 rows, as before.
  quarantine(1);
  expect([preview(), current(), canonical()]).toEqual([0, 0, 0]);
});

it("(2) a row-generation lookup of key facts is a primary-key search", () => {
  const { db, store } = device();
  db.exec(
    "CREATE TEMP TABLE plan_rows (instance TEXT, stream TEXT, record_key TEXT, generation INTEGER)",
  );
  const plan = (
    db
      .prepare(
        `EXPLAIN QUERY PLAN SELECT 1 FROM plan_rows r WHERE ${store.unquarantinedRecordSql("r", "r.generation")}`,
      )
      .all() as { detail: string }[]
  )
    .map((row) => row.detail)
    .join("\n");
  // (instance, generation, stream, record_key): no extra index is needed.
  expect(plan).toContain(
    "sqlite_autoindex_pdpp_replica_quarantined_keys_1 (instance=? AND generation=? AND stream=? AND record_key=?)",
  );
});

it("(3) every reader-visible blob namespace has manifest insert and delete triggers in the visibility view", () => {
  const { db } = device();
  const triggers = db
    .prepare(
      "SELECT sql FROM sqlite_master WHERE type='trigger' AND tbl_name='pdpp_binary_manifests'",
    )
    .all() as { sql: string }[];
  const visible = Object.entries(BINARY_NAMESPACE_ROLE)
    .filter(([, role]) => role === "reader")
    .map(([namespace]) => namespace);
  expect(visible.sort()).toEqual(["canonical", "pending", "received"]);
  // The namespaces a trigger fires for: its WHEN clause's IN list.
  const covered = (event: string, row: "NEW" | "OLD") =>
    new Set(
      triggers
        .filter((t) => t.sql.includes(event))
        .flatMap((t) => {
          const list = new RegExp(
            `WHEN ${row}\\.namespace IN \\(([^)]*)\\)`,
          ).exec(t.sql)?.[1];
          return list ? list.split(",").map((n) => n.trim().slice(1, -1)) : [];
        }),
    );
  for (const namespace of visible) {
    expect(covered("AFTER INSERT", "NEW"), namespace).toContain(namespace);
    expect(covered("AFTER DELETE", "OLD"), namespace).toContain(namespace);
  }
});
