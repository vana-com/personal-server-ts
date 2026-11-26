import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import {
  importFingerprint,
  createLocalSeed,
  createSeedIntake,
} from "../../../core/src/localdb/index.js";
import { rebaselineKeyedLoad } from "../../../core/src/localdb/log-keyed.js";
import { createSeedStaging } from "../../../core/src/stream-sync/seed-staging.js";
import { createFsStreamSyncFiles } from "../stream-sync/fs-files.js";
import { endRequest } from "../../../core/src/test-utils/run-end.js";
import type { openDevice } from "./late-seed-harness.test-utils.js";
import {
  connectionId,
  drivers,
  owner,
  state,
  world,
} from "./late-seed-harness.test-utils.js";

// A seed after a stream's first real write is fill-only: it adds a record the
// stream never saw, and leaves a record the stream holds, or ever deleted or
// omitted, alone. These tests drive real runs, publication and compaction,
// then seed from another install. Each invariant of the late-seed model
// (docs/formal/late-seed) has a test here.

const dirs: string[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});
it("a seed after a real write fills the keys the stream never saw, and another device gets them", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("refresh", ["B"]);
  await a.publish();
  expect((await a.seed("install-1", ["A", "B", "C"])).kind).toBe("imported");
  expect(await a.keys()).toEqual(["A", "B", "C"]);
  expect(await a.snapshot()).toMatchObject([
    { record_key: "A", stamp_o: 0, stamp_r: "seed" },
    { record_key: "B", stamp_r: "refresh" },
    { record_key: "C", stamp_o: 0, stamp_r: "seed" },
  ]);
  await a.publish();
  const b = await w.device("b");
  await b.sync.cycle();
  expect(await b.keys()).toEqual(["A", "B", "C"]);
});

it("a seed never touches a record a real write holds: body, stamp and first_o stay and nothing is logged", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("real", ["A"]);
  await a.publish();
  const before = await state(a);
  // The row has a first_o to lose, so the check below has teeth.
  expect(before.rows).toMatchObject([{ record_key: "A", stamp_r: "real" }]);
  expect(before.rows[0]).toHaveProperty("first_o");
  expect((before.rows[0] as { first_o: number | null }).first_o).not.toBeNull();
  const result = await a.seed("install-1", ["A"], "items", { legacy: true });
  expect(result.kind).toBe("imported");
  expect(await state(a)).toEqual(before);
});

it("an explicit delete that was published and compacted keeps a later seed out across a restart", async () => {
  const w = await world();
  const dir = mkdtempSync(join(process.cwd(), ".late-seed-test-"));
  dirs.push(dir);
  const path = join(dir, "db.sqlite");
  const first = await w.device("a", path);
  await first.run("real", ["A", "B"]);
  await first.publish();
  await first.run("delete", ["A"], { remove: true });
  await first.publish();
  await first.publish();
  expect(await first.keys()).toEqual(["B"]);
  // Publication pruned the pending change: no explicit-delete event remains.
  expect(
    await first.db.query(
      "SELECT count(*) AS n FROM record_changes WHERE explicit_delete = 1 AND record_key = 'A' AND stream = 'items'",
    ),
  ).toEqual([{ n: 0 }]);
  await first.db.close();
  drivers.splice(drivers.indexOf(first.db), 1);
  const reopened = await w.device("a", path);
  const result = await reopened.seed("install-2", ["A", "Z"]);
  expect(result.kind).toBe("imported");
  // Z was never in the stream and fills; A was deleted and stays out. The
  // receipt holds both staged rows; the audit says one of them was blocked.
  expect(await reopened.keys()).toEqual(["B", "Z"]);
  expect(result).toMatchObject({ blocked: 1, receipt: { rows: 2 } });
});

it("a tombstone written before it kept a record key still keeps a seed out", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("real", ["A", "B"]);
  await a.publish();
  await a.run("delete", ["A"], { remove: true });
  await a.publish();
  // The tombstone of a device that upgraded from before the column.
  await a.db.batch([{ sql: "UPDATE log_tombstones SET record_key = NULL" }]);
  expect(
    await a.db.query(
      "SELECT count(*) AS n FROM log_tombstones WHERE record_key IS NULL",
    ),
  ).toEqual([{ n: 1 }]);
  const result = await a.seed("install-2", ["A", "Z"]);
  expect(await a.keys()).toEqual(["B", "Z"]);
  expect(result).toMatchObject({ kind: "imported", blocked: 1 });
});

/**
 * What a device holds after an upgrade from the build before this one: that
 * build wrote a tombstone only for what it applied from the log, never for a
 * delete or omission it published itself.
 */
async function asBuiltBefore(device: Awaited<ReturnType<typeof openDevice>>) {
  await device.db.batch([{ sql: "DELETE FROM log_tombstones" }]);
}

it("a delete the earlier build published and compacted keeps a late seed out after the upgrade", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("real", ["A", "B"]);
  await a.publish();
  await a.run("delete", ["A"], { remove: true });
  await a.publish();
  await a.publish();
  await asBuiltBefore(a);
  expect(
    await a.db.query(
      "SELECT count(*) AS n FROM record_changes WHERE record_key = 'A' AND stream = 'items'",
    ),
  ).toEqual([{ n: 0 }]);
  expect((await a.seed("install-2", ["A", "Z"])).kind).toBe("imported");
  expect(await a.keys()).toEqual(["B", "Z"]);
  // The record stays gone for another device too.
  await a.publish();
  const b = await w.device("b");
  await b.sync.cycle();
  expect(await b.keys()).toEqual(["B", "Z"]);
});

it("an omission the earlier build published keeps a late seed out after the upgrade", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("real", ["A", "B"]);
  await a.publish();
  await a.run("refresh", ["B"]);
  await a.publish();
  await a.publish();
  expect(await a.keys()).toEqual(["B"]);
  await asBuiltBefore(a);
  await a.seed("install-2", ["A", "Z"]);
  expect(await a.keys()).toEqual(["B", "Z"]);
});

it("a delete that a log compaction folded into a snapshot keeps a late seed out after the upgrade", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("real", ["A", "B"]);
  await a.publish();
  await a.run("delete", ["A"], { remove: true });
  await a.publish();
  // The compaction rule (`shouldCompact`) reads the segments' real sizes, so
  // grow the log until a head carries a snapshot.
  let snapshot: string | null = null;
  for (let i = 0; snapshot === null && i < 400; i++) {
    await a.run(`more-${i}`, [`K${i}`]);
    await a.publish();
    [{ snapshot }] = await a.db.query<{ snapshot: string | null }>(
      "SELECT snapshot FROM log_state",
    );
  }
  expect(snapshot).not.toBeNull();
  await asBuiltBefore(a);
  await a.seed("install-2", ["A", "Z"]);
  expect(await a.keys()).not.toContain("A");
  expect(await a.keys()).toContain("Z");
});

it("a seed whose recovery cannot read the log writes no rows and no receipt; once the log reads, a retry fills only the keys no deletion covers", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("real", ["A", "B"]);
  await a.publish();
  await a.run("delete", ["A"], { remove: true });
  await a.publish();
  await a.publish();
  await asBuiltBefore(a);
  // The log's segments are in storage, but this read cannot find them.
  const stored = a.deps.blobs;
  let hidden = true;
  (a.deps as { blobs: typeof stored }).blobs = {
    ...stored,
    get: async (key) =>
      hidden && key.includes("/s-") ? null : stored.get(key),
  };
  const before = await state(a);

  // The recovery of the log's deletions fails the import before it writes.
  await expect(a.seed("install-2", ["A", "Z"])).rejects.toThrow(
    "missing log segment",
  );
  // Neither a fill nor a receipt: A could come back from a log that was not read.
  expect(await state(a)).toEqual(before);
  expect(await a.keys()).toEqual(["B"]);
  expect(await a.db.query("SELECT * FROM import_ledger")).toEqual([]);

  hidden = false;
  expect((await a.seed("install-2", ["A", "Z"])).kind).toBe("imported");
  // Z was never in the stream and fills; A was deleted and stays out.
  expect(await a.keys()).toEqual(["B", "Z"]);
  expect(
    await a.db.query(
      "SELECT state, rows FROM import_ledger WHERE stream = 'items'",
    ),
  ).toEqual([{ state: "imported", rows: 2 }]);
});

it("the first retry of a reopened seed_window_closed receipt is `imported`, though every key is already held; a repeat is `already-imported`", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("real", ["A", "B"]);
  await a.publish();
  // The earlier build's receipt for this very upload: it named no rows.
  const empty = await importFingerprint((async function* () {})());
  await a.db.batch([
    {
      sql: `INSERT INTO import_ledger (source, connection_id, stream, state, rows, fingerprint, reason, at, revision, generation, highest_seq)
            VALUES (?, ?, 'items', 'excluded', ?, ?, 'seed_window_closed', 1, 'install-3-upload', 1, 0)`,
      params: [
        JSON.stringify(["install-3", "fixture"]),
        connectionId,
        empty.rows,
        empty.fingerprint,
      ],
    },
  ]);
  const before = await state(a);

  // Every key is held: nothing fills, but this call writes the first receipt
  // that completed the revision.
  const first = await a.seed("install-3", ["A", "B"]);
  expect(first.kind).toBe("imported");
  expect(await state(a)).toEqual(before);
  expect(
    await a.db.query("SELECT state, reason, rows FROM import_ledger"),
  ).toEqual([{ state: "imported", reason: null, rows: 2 }]);

  expect((await a.seed("install-3", ["A", "B"])).kind).toBe("already-imported");
});

it("an explicit delete that has not published yet keeps a seed out", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("real", ["A", "B"]);
  await a.publish();
  await a.run("delete", ["A"], { remove: true });
  expect(await a.keys()).toEqual(["B"]);
  await a.seed("install-2", ["A"]);
  expect(await a.keys()).toEqual(["B"]);
});

it("a full refresh that omitted a seeded record keeps a later install's seed from bringing it back", async () => {
  const w = await world();
  const a = await w.device("a");
  expect((await a.seed("install-1", ["A", "B"])).kind).toBe("imported");
  await a.run("refresh", ["B"]);
  // The drop is made when the replace publishes: until then A is held, and a
  // second install's seed of it changes nothing.
  const held = await state(a);
  await a.seed("install-2", ["A"]);
  expect(await state(a)).toEqual(held);
  await a.publish();
  expect(await a.keys()).toEqual(["B"]);
  // The publish wrote the device's own tombstone for A. Retiring the receipts
  // lets compaction prune the change that recorded the drop.
  await a.db.batch([{ sql: "UPDATE import_ledger SET state = 'retired'" }]);
  await a.publish();
  expect(
    await a.db.query(
      "SELECT count(*) AS n FROM record_changes WHERE stream = 'items' AND record_key = 'A'",
    ),
  ).toEqual([{ n: 0 }]);
  await a.seed("install-3", ["A"]);
  expect(await a.keys()).toEqual(["B"]);
  // A real write still wins afterwards, and brings A back as real data.
  await a.run("later", ["A", "B"]);
  await a.publish();
  expect(await a.keys()).toEqual(["A", "B"]);
  expect(
    await a.db.query(
      "SELECT stamp_r FROM records WHERE record_key = 'A' AND stream = 'items'",
    ),
  ).toEqual([{ stamp_r: "later" }]);
});

it("an empty full refresh removes every seeded record, and a later seed does not bring them back", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.seed("install-1", ["A", "B"]);
  await a.run("empty", []);
  await a.publish();
  expect(await a.keys()).toEqual([]);
  await a.seed("install-2", ["A", "B"]);
  expect(await a.keys()).toEqual([]);
});

it("a delete another device published keeps a seed out of the device that applied it and of a fresh one", async () => {
  const w = await world();
  const a = await w.device("a");
  const b = await w.device("b");
  await a.seed("install-1", ["A", "B"]);
  await a.publish();
  await b.sync.cycle();
  await b.run("delete", ["A"], { remove: true });
  await b.publish();
  await a.sync.cycle();
  expect(await a.keys()).toEqual(["B"]);
  await a.seed("install-2", ["A"]);
  expect(await a.keys()).toEqual(["B"]);
  const c = await w.device("c");
  await c.sync.cycle();
  await c.seed("install-3", ["A"]);
  expect(await c.keys()).toEqual(["B"]);
});

it("a delete that commits between the read and the merge keeps its key out", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("real", ["R"]);
  await a.publish();
  const batch = a.db.batch.bind(a.db);
  let raced = false;
  a.db.batch = async (statements) => {
    if (
      !raced &&
      statements.some((s) => s.sql.startsWith("INSERT INTO records"))
    ) {
      raced = true;
      await batch([
        {
          sql: "INSERT INTO log_tombstones (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, rank) SELECT connection_id, stream, pk_hash, record_key, 9000, 'late-delete', 2 FROM (SELECT 'pdpp.fixture~' AS connection_id, 'items' AS stream, ? AS pk_hash, 'A' AS record_key)",
          params: [createHash("sha256").update('["A"]').digest("hex")],
        },
      ]);
    }
    return batch(statements);
  };
  await a.seed("install-1", ["A", "B"]);
  expect(await a.keys()).toEqual(["B", "R"]);
});

it("two devices that see the switch at the same time converge on one copy of each record", async () => {
  const w = await world();
  const c = await w.device("c");
  await c.run("refresh", ["R"]);
  await c.publish();
  const a = await w.device("a");
  const b = await w.device("b");
  await a.sync.cycle();
  await b.sync.cycle();
  // Neither has applied the other's seed when it seeds.
  expect((await a.seed("install-a", ["A", "B"])).kind).toBe("imported");
  expect((await b.seed("install-b", ["A", "B"])).kind).toBe("imported");
  await a.publish();
  await b.publish();
  await a.sync.cycle();
  await b.sync.cycle();
  await c.sync.cycle();
  const rows = async (d: typeof a) =>
    d.db.query(
      "SELECT record_key, stamp_o, stamp_r, body FROM records ORDER BY record_key",
    );
  expect(await a.keys()).toEqual(["A", "B", "R"]);
  expect(await rows(b)).toEqual(await rows(a));
  expect(await rows(c)).toEqual(await rows(a));
  // A retry on either device adds nothing.
  const settled = await state(a);
  await a.seed("install-a", ["A", "B"]);
  await a.publish();
  expect(await state(a)).toEqual(settled);
});

it("a seed that arrives after a delete another device made, but before this device applied it, converges on the delete", async () => {
  const w = await world();
  const a = await w.device("a");
  const b = await w.device("b");
  await a.run("real", ["A", "R"]);
  await a.publish();
  await b.sync.cycle();
  await b.run("delete", ["A"], { remove: true });
  await b.publish();
  // a has not applied b's delete; it seeds A and then publishes.
  await a.seed("install-1", ["A"]);
  await a.publish();
  await b.sync.cycle();
  await a.sync.cycle();
  expect(await a.keys()).toEqual(["R"]);
  expect(await b.keys()).toEqual(["R"]);
});

it("a seed after a real write is published at the seed stamp and a later real write beats it", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("real", ["R"]);
  await a.publish();
  await a.seed("install-1", ["A"], "items", { v: "seed" });
  await a.publish();
  const b = await w.device("b");
  await b.sync.cycle();
  await b.run("later", ["A"]);
  await b.publish();
  await a.sync.cycle();
  expect(
    await a.db.query(
      "SELECT stamp_r, body FROM records WHERE record_key = 'A' AND stream = 'items'",
    ),
  ).toEqual([{ stamp_r: "later", body: '{"id":"A"}' }]);
});

it("a seed in another stream does not touch the rows of a stream a real write owns", async () => {
  const w = await world();
  const a = await w.device("a", ":memory:", ["items", "other"]);
  await a.run("real", ["A"]);
  expect((await a.seed("install-1", ["Z"], "items")).kind).toBe("imported");
  expect((await a.seed("install-1", ["X"], "other")).kind).toBe("imported");
  expect(await a.keys()).toEqual(["A", "Z"]);
  expect(await a.snapshot("other")).toMatchObject([
    { record_key: "X", stamp_o: 0, stamp_r: "seed" },
  ]);
});

it("a seed after a published seed-only head fills the keys the first one lacked", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.seed("install-1", ["A"]);
  await a.publish();
  expect(
    await a.db.query(
      "SELECT head_version FROM stream_state WHERE stream = 'items'",
    ),
  ).toEqual([{ head_version: 1 }]);
  expect((await a.seed("install-2", ["A", "B"])).kind).toBe("imported");
  expect(await a.keys()).toEqual(["A", "B"]);
});

it("a seed into a connection that was deleted is refused", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("real", ["R"]);
  await a.publish();
  await a.db.batch([
    {
      sql: "UPDATE connections SET deleted_at = 1, control_state = 'deleted' WHERE connection_id = 'pdpp.fixture~'",
    },
  ]);
  expect(await a.seed("install-1", ["A"])).toEqual({
    kind: "refused",
    reason: "connection_deleted",
  });
  expect(await a.keys()).toEqual(["R"]);
});

it("replaying a completed import after a real write adds nothing and keeps its receipt", async () => {
  const w = await world();
  const dir = mkdtempSync(join(process.cwd(), ".late-seed-test-"));
  dirs.push(dir);
  const path = join(dir, "db.sqlite");
  const first = await w.device("a", path);
  expect((await first.seed("install-1", ["A", "B"])).kind).toBe("imported");
  await first.run("refresh", ["B"]);
  await first.publish();
  const changes = await first.db.query("SELECT * FROM record_changes");
  const ledger = await first.db.query("SELECT * FROM import_ledger");
  await first.db.close();
  drivers.splice(drivers.indexOf(first.db), 1);
  const reopened = await w.device("a", path);
  const replay = await reopened.seed("install-1", ["A", "B"]);
  expect(replay.kind).toBe("already-imported");
  expect(await reopened.keys()).toEqual(["B"]);
  expect(await reopened.db.query("SELECT * FROM record_changes")).toEqual(
    changes,
  );
  // The replay refreshes the receipt's time and sequence mark; nothing else.
  const stable = (rows: Record<string, unknown>[]) =>
    rows.map(({ at: _at, highest_seq: _seq, ...rest }) => rest);
  expect(
    stable(await reopened.db.query("SELECT * FROM import_ledger")),
  ).toEqual(stable(ledger));
});

const manifest = JSON.stringify({
  connector_key: "fixture",
  version: "1",
  streams: ["items", "other"].map((name) => ({
    name,
    primary_key: ["id"],
    semantics: "mutable_state",
  })),
});
async function* upload(ids: string[]) {
  const lines = [
    JSON.stringify({
      primaryKey: ["id"],
      profile: { key: null, version: "1" },
      records: ids.length,
    }),
    ...ids.map((id) => JSON.stringify({ id })),
  ];
  yield new TextEncoder().encode(lines.join("\n") + "\n");
}
function seedHost(
  device: Awaited<ReturnType<typeof openDevice>>,
  root: string,
) {
  const staging = createSeedStaging(createFsStreamSyncFiles(root));
  return createSeedIntake(
    createLocalSeed({
      getDeps: async () => device.deps,
      manifests: () => [manifest],
      staging,
    }),
  );
}

it("a staged seed that arrives after a real write fills what the stream lacks, even across a restart", async () => {
  const w = await world();
  const dir = mkdtempSync(join(process.cwd(), ".late-seed-test-"));
  dirs.push(dir);
  const path = join(dir, "db.sqlite");
  const first = await w.device("a", path);
  await first.run("refresh", ["B"]);
  await first.publish();
  const intake = seedHost(first, join(dir, "staging"));
  await intake.put("fixture", "items", upload(["A", "B"]));
  await intake.put("fixture", "other", upload(["X"]));
  expect(await intake.status("fixture")).toEqual({
    targetKnown: true,
    streams: { items: { state: "merged" }, other: { state: "merged" } },
  });
  const ledger = () =>
    first.db.query(
      "SELECT stream, state, reason, rows FROM import_ledger ORDER BY stream",
    );
  expect(await ledger()).toEqual([
    { stream: "items", state: "imported", reason: null, rows: 2 },
    { stream: "other", state: "imported", reason: null, rows: 1 },
  ]);
  expect(await first.keys()).toEqual(["A", "B"]);
  expect(await first.snapshot()).toMatchObject([
    { record_key: "A", stamp_o: 0, stamp_r: "seed" },
    { record_key: "B", stamp_r: "refresh" },
  ]);
  expect(await first.snapshot("other")).toMatchObject([{ record_key: "X" }]);
  const changes = await first.db.query("SELECT * FROM record_changes");
  const before = await ledger();

  await first.db.close();
  drivers.splice(drivers.indexOf(first.db), 1);
  const reopened = await w.device("a", path);
  const again = seedHost(reopened, join(dir, "staging"));
  // The same upload again: the receipts answer and no body is consumed.
  expect(await again.put("fixture", "items", upload(["A", "B"]))).toEqual({
    state: "merged",
  });
  expect(await again.status("fixture")).toEqual({
    targetKnown: true,
    streams: { items: { state: "merged" }, other: { state: "merged" } },
  });
  expect(await reopened.keys()).toEqual(["A", "B"]);
  expect(await reopened.db.query("SELECT * FROM record_changes")).toEqual(
    changes,
  );
  expect(
    await reopened.db.query(
      "SELECT stream, state, reason, rows FROM import_ledger ORDER BY stream",
    ),
  ).toEqual(before);
});

it("an excluded receipt an older build wrote does not stop the stream's seed", async () => {
  const w = await world();
  const dir = mkdtempSync(join(process.cwd(), ".late-seed-test-"));
  dirs.push(dir);
  const first = await w.device("a", join(dir, "db.sqlite"));
  await first.run("refresh", ["B"]);
  await first.publish();
  const intake = seedHost(first, join(dir, "staging"));
  await intake.put("fixture", "other", upload(["X"]));
  const [receipt] = await first.db.query<{ source: string; revision: string }>(
    "SELECT source, revision FROM import_ledger WHERE stream = 'other'",
  );
  // What the build before this one left for a stream a real write owned.
  await first.db.batch([
    {
      sql: "UPDATE import_ledger SET stream = 'items', state = 'excluded', reason = 'seed_window_closed', rows = 0, highest_seq = 0, fingerprint = 'e' WHERE stream = 'other'",
    },
  ]);
  await first.db.batch([
    {
      sql: "DELETE FROM records WHERE stream = 'other'",
    },
  ]);
  expect(receipt).toBeDefined();
  await intake.put("fixture", "items", upload(["A", "B"]));
  expect(await first.keys()).toEqual(["A", "B"]);
  expect(
    await first.db.query(
      "SELECT state, reason FROM import_ledger WHERE stream = 'items'",
    ),
  ).toEqual([{ state: "imported", reason: null }]);
});

it("an upload still staged after an upgrade is retried under its revision, though the earlier build's receipt names no rows", async () => {
  const w = await world();
  const dir = mkdtempSync(join(process.cwd(), ".late-seed-test-"));
  dirs.push(dir);
  const a = await w.device("a", join(dir, "db.sqlite"));
  await a.run("refresh", ["B"]);
  await a.publish();
  const intake = seedHost(a, join(dir, "staging"));
  await intake.put("fixture", "items", upload(["A", "B"]));
  // What the earlier build left for this very upload: it read a stream a real
  // write owned, kept the upload staged, and wrote the fingerprint of no rows
  // under the upload's own revision.
  const empty = await importFingerprint((async function* () {})());
  await a.db.batch([
    // The earlier build never merged A: no row, and no change to prune.
    { sql: "DELETE FROM records WHERE record_key = 'A'" },
    { sql: "DELETE FROM record_changes WHERE record_key = 'A'" },
    {
      sql: "UPDATE import_ledger SET state = 'excluded', reason = 'seed_window_closed', rows = ?, fingerprint = ?, highest_seq = 0 WHERE stream = 'items'",
      params: [empty.rows, empty.fingerprint],
    },
  ]);
  expect(await a.keys()).toEqual(["B"]);
  expect(await intake.status("fixture")).toEqual({
    targetKnown: true,
    streams: { items: { state: "merged" } },
  });
  expect(await a.keys()).toEqual(["A", "B"]);
  expect(
    await a.db.query(
      "SELECT state, reason, rows FROM import_ledger WHERE stream = 'items'",
    ),
  ).toEqual([{ state: "imported", reason: null, rows: 2 }]);
});

it("the audit lists a final exclusion and leaves out the earlier build's retryable one", async () => {
  const w = await world();
  const a = await w.device("a");
  const receipt = (stream: string, reason: string) => ({
    sql: `INSERT INTO import_ledger (source, connection_id, stream, state, rows, fingerprint, reason, at, revision, generation, highest_seq) VALUES ('s', ?, ?, 'excluded', 0, 'e', ?, 1, 'r', 1, 0)`,
    params: [connectionId, stream, reason],
  });
  await a.db.batch([
    receipt("retry", "seed_window_closed"),
    receipt("final", "seed_skipped"),
  ]);
  expect(
    (await a.sync.listing.status({ audit: true })).importExclusions,
  ).toEqual([{ reason: "seed_skipped", streams: 1 }]);
});

it("a fresh device that only applied a remote head fills a seed for that stream", async () => {
  const w = await world();
  const b = await w.device("b");
  await b.run("refresh", ["B"], { observedAt: 5000 });
  await b.publish();
  // No local run on "a": its only head comes from applying b's publication.
  const a = await w.device("a");
  await a.sync.cycle();
  expect(
    await a.db.query(
      "SELECT head_version, floor_o FROM stream_state WHERE stream = 'items'",
    ),
  ).toEqual([{ head_version: 1, floor_o: null }]);
  expect((await a.seed("install-1", ["A"])).kind).toBe("imported");
  expect(await a.keys()).toEqual(["A", "B"]);
});

it("an accepted run that declared a stream but wrote nothing leaves it open to a seed, and a later full refresh still wins", async () => {
  const w = await world();
  const a = await w.device("a");
  // Accepted with no rows and no coverage for "items": the connector asked
  // to be retried before it wrote anything.
  await a.sync.intake.begin("empty", {
    connector: "fixture",
    artifactDigest: "fixture",
    join: true,
    streams: [{ name: "items" }],
    wantFull: true,
    owner: { address: owner, leaseId: null },
  });
  await a.sync.intake.batch("empty", { batch: 0, records: [] });
  expect(
    await a.sync.intake.end(
      "empty",
      endRequest({ lastBatch: 0, streams: ["items"], retry: true }),
    ),
  ).toMatchObject({ outcome: "retry_pending", coveredStreams: [] });
  await a.publish();
  expect(await a.keys()).toEqual([]);
  expect((await a.seed("install-1", ["A"])).kind).toBe("imported");
  expect(await a.keys()).toEqual(["A"]);
  // A later full refresh that does not list A drops it, as it drops any
  // record it does not list: the seed is below every real stamp.
  await a.run("real", ["R"]);
  await a.publish();
  expect(await a.keys()).toEqual(["R"]);
  expect(
    await a.db.query(
      "SELECT stamp_r FROM records WHERE record_key = 'R' AND stream = 'items'",
    ),
  ).toEqual([{ stamp_r: "real" }]);
});

it("a seed tombstone survives a keyed-load rebaseline, so a late fill stays deleted", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("real", ["B"]);
  await a.publish();
  // The first import deleted "A" in the old store: a seed tombstone, which
  // only this device holds (it is never published to the log).
  const first = await a.importSource("install-1", (base) => ({
    ...base,
    async *records() {},
    async *deletions() {
      yield { id: "A" };
    },
  }));
  expect(first).toMatchObject({ kind: "imported", tombstoned: 1 });
  const tombstones = () =>
    a.db.query(
      "SELECT record_key, stamp_o, stamp_r FROM log_tombstones WHERE stream = 'items'",
    );
  expect(await tombstones()).toEqual([
    { record_key: "A", stamp_o: 0, stamp_r: "seed" },
  ]);
  // Recovery ends an unfinished key-ordered load and drops the log's tombstones.
  await rebaselineKeyedLoad(
    { db: a.db, logger: { info() {} } as never },
    connectionId,
    "test",
  );
  expect(await tombstones()).toEqual([
    { record_key: "A", stamp_o: 0, stamp_r: "seed" },
  ]);
  // A later seed from another install cannot bring "A" back.
  expect((await a.seed("install-2", ["A", "Z"])).kind).toBe("imported");
  expect(await a.keys()).toEqual(["B", "Z"]);
});

it("a rebaseline still drops the tombstones the log delivered", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("real", ["A", "B"]);
  await a.publish();
  await a.run("delete", ["A"], { remove: true });
  await a.publish();
  const tombstones = () =>
    a.db.query("SELECT record_key FROM log_tombstones WHERE stream = 'items'");
  expect(await tombstones()).toEqual([{ record_key: "A" }]);
  await rebaselineKeyedLoad(
    { db: a.db, logger: { info() {} } as never },
    connectionId,
    "test",
  );
  expect(await tombstones()).toEqual([]);
});

it("a receipt cleanup never drops an upload that replaced the one its status listed", async () => {
  const w = await world();
  const dir = mkdtempSync(join(process.cwd(), ".late-seed-test-"));
  dirs.push(dir);
  const device = await w.device("a", join(dir, "db.sqlite"));
  await device.run("refresh", ["B"]);
  await device.publish();
  const real = createSeedStaging(createFsStreamSyncFiles(join(dir, "staging")));
  let listings = 0;
  const staging = {
    ...real,
    // The status lists once under the lock, then the intake lists again. A
    // newer upload stages straight after the intake's listing, before the
    // receipt cleanup takes the lock.
    async staged(connector: string) {
      const listed = await real.staged(connector);
      if (++listings === 2)
        await real.stage(connector, "items", upload(["N1", "N2"]));
      return listed;
    },
  };
  const intake = createSeedIntake(
    createLocalSeed({
      getDeps: async () => device.deps,
      manifests: () => [manifest],
      staging,
    }),
  );
  await intake.put("fixture", "items", upload(["A", "B"]));
  const merged = (await real.staged("fixture")).items!.upload;
  listings = 0;
  await intake.status("fixture");
  const kept = (await real.staged("fixture")).items;
  expect(kept?.upload).toBeDefined();
  expect(kept?.upload).not.toBe(merged);
  expect(kept?.records).toBe(2);
});

it("a stage and a drop of one stream are serialized: a stage during a drop is not removed by it", async () => {
  const w = await world();
  const dir = mkdtempSync(join(process.cwd(), ".late-seed-test-"));
  dirs.push(dir);
  const device = await w.device("a", join(dir, "db.sqlite"));
  const files = createFsStreamSyncFiles(join(dir, "staging"));
  let release!: () => void;
  const gate = new Promise<void>((resolve) => (release = resolve));
  let held!: () => void;
  const holding = new Promise<void>((resolve) => (held = resolve));
  let gated = false;
  let published!: () => void;
  const publishing = new Promise<void>((resolve) => (published = resolve));
  const staging = createSeedStaging({
    ...files,
    async write(path, bytes) {
      await files.write(path, bytes);
      if (gated && path.startsWith("staged/")) published();
    },
    async remove(prefix) {
      if (!gated && prefix.startsWith("staged/")) {
        gated = true;
        held();
        await gate;
      }
      return files.remove(prefix);
    },
  });
  const seed = createLocalSeed({
    getDeps: async () => device.deps,
    manifests: () => [manifest],
    staging,
  });
  const a = await seed.staging.stage("fixture", "items", upload(["A"]));
  const dropping = seed.staging.drop("fixture", "items", a.upload);
  await holding;
  // The drop has read the pointer and is mid-removal; a new upload arrives.
  const staging2 = seed.staging.stage("fixture", "items", upload(["B"]));
  // Unserialized, the new pointer lands while the drop is held; serialized,
  // it cannot, so the wait times out.
  await Promise.race([
    publishing,
    new Promise((resolve) => setTimeout(resolve, 300)),
  ]);
  release();
  await dropping;
  const b = await staging2;
  expect((await staging.staged("fixture")).items?.upload).toBe(b.upload);
  const source = staging.source("install", async () => ({
    receipts: {},
    skipped: [],
  }));
  const rows = [];
  for await (const row of source.records("fixture", "items", b.upload))
    rows.push(row);
  expect(rows).toEqual([{ id: "B" }]);
});
