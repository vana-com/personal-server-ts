import { afterEach, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import { createImportLedger } from "../../../core/src/localdb/import-ledger.js";
import { importLegacySource } from "../../../core/src/localdb/legacy-import.js";
import {
  readBackLegacyImport,
  createImportProjectionReader,
} from "../../../core/src/localdb/import-readback.js";
import { LEGACY_SCOPE_BINDINGS } from "../../../core/src/legacy-projection/index.js";
import { legacyConnectorKey } from "../../../core/src/storage/canonical-legacy-projection.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type {
  ImportSource,
  CopyRecords,
  LegacyCopy,
} from "../../../core/src/localdb/legacy-import-types.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
const dbs = new Set<SqlDriver>();
const dirs: string[] = [];
afterEach(async () => {
  for (const db of dbs) await db.close();
  dbs.clear();
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});
const time = "2026-01-01T00:00:00.000Z";
const payload = {
  id: "account",
  display_name: "Example",
  uri: "uri",
  followers: 1,
  following: 2,
  images: [],
};
async function fixture(path = ":memory:") {
  const db = await openLocalDb(openBetterSqlite3(path), {
    owner: "0xabc",
    network: "test",
    deviceId: "fixture",
  });
  dbs.add(db);
  await db.batch([
    {
      sql: "INSERT OR IGNORE INTO connections (connection_id,connector,ns,generation,control_state) VALUES ('connection','spotify','known',1,'active')",
    },
  ]);
  const unexpected = async (): Promise<never> => {
    throw new Error("unexpected external call");
  };
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    queue: connectionQueue(),
    ownerAddress: "0xabc",
    registry: {
      read: unexpected,
      post: unexpected,
      listControlRows: unexpected,
      listStreamRows: unexpected,
    },
    blobs: { get: unexpected, put: unexpected },
    keys: {
      namespaceHmac: unexpected,
      encrypt: unexpected,
      encryptPart: unexpected,
      decrypt: unexpected,
    },
    signer: { signAddData: unexpected },
    logger: { info() {}, warn() {} },
    now: () => 1,
    newOp: () => `proof-${++op}`,
  };
  const source: ImportSource = {
    source: "fixture",
    owner: "0xabc",
    network: "test",
    revision: "revision",
    target: {
      connectionId: "connection",
      connector: "spotify",
      stream: "profile",
      primaryKey: ["id"],
      semantics: "mutable_state",
      incremental: true,
    },
    exclusions: [],
    async *records() {
      yield { ...payload };
    },
  };
  const copy: LegacyCopy = {
    id: "copy",
    path: "fixture/copy.json",
    contentHash: "f".repeat(64),
    revision: "revision",
    dataSet: "spotify.profile",
    sources: [
      { source: source.source, connectionId: "connection", stream: "profile" },
    ],
  };
  const copyRecords: CopyRecords = async function* () {
    yield { ...payload };
  };
  const peers = async function* () {
    yield source;
  };
  const projections = createImportProjectionReader(
    deps,
    time,
    peers,
    copyRecords,
  );
  const run = () => readBackLegacyImport(deps, source, projections, copy);
  return {
    db,
    deps,
    source,
    copy,
    projections,
    copyRecords,
    peers,
    run,
    import: () => importLegacySource(deps, createImportLedger(db), source),
  };
}
it("readback-sorted-count-and-fingerprint", async () => {
  const f = await fixture();
  await f.import();
  expect((await f.run()).pass).toBe(true);
  await f.db.batch([
    { sql: "UPDATE records SET body_sha256 = ?", params: ["f".repeat(64)] },
  ]);
  expect((await f.run()).pass).toBe(false);
});
it("readback-exact-copy", async () => {
  const f = await fixture();
  await f.import();
  const first = await f.run();
  expect(first.pass).toBe(true);
  expect((await f.run()).projections).toEqual(first.projections);
  const changed = createImportProjectionReader(
    f.deps,
    time,
    f.peers,
    async function* () {
      yield { ...payload, additional: "uncovered content" };
    },
  );
  expect(
    (await readBackLegacyImport(f.deps, f.source, changed, f.copy)).pass,
  ).toBe(false);
});
it("readback-no-missing-seam-pass", async () => {
  const f = await fixture();
  await f.import();
  const absent = createImportProjectionReader(f.deps, time, f.peers);
  expect(
    await readBackLegacyImport(f.deps, f.source, absent, f.copy),
  ).toMatchObject({ pass: false, reason: "copy_unreadable" });
  expect(
    (
      await readBackLegacyImport(
        f.deps,
        f.source,
        { compare: async () => [] },
        null,
      )
    ).pass,
  ).toBe(false);
});
it("readback-missing-or-lossy-holds", async () => {
  const f = await fixture();
  expect(await f.run()).toMatchObject({
    pass: false,
    receipt: null,
    reason: "missing_receipt",
  });
  await f.import();
  const missing = createImportProjectionReader(
    f.deps,
    time,
    async function* () {},
    f.copyRecords,
  );
  expect(
    (await readBackLegacyImport(f.deps, f.source, missing, f.copy)).pass,
  ).toBe(false);
  expect(
    (
      await readBackLegacyImport(
        f.deps,
        { ...f.source, exclusions: [{ reason: "uncovered", rows: 1 }] },
        f.projections,
        f.copy,
      )
    ).pass,
  ).toBe(false);
  await f.db.batch([{ sql: "UPDATE import_ledger SET revision = NULL" }]);
  expect(await f.run()).toMatchObject({
    pass: false,
    receipt: null,
    reason: "missing_receipt",
  });
});
it("readback-newer-different-row-holds", async () => {
  const f = await fixture();
  await f.import();
  await f.db.batch([
    {
      sql: "UPDATE records SET body = ?, stamp_o = 99",
      params: [JSON.stringify({ ...payload, display_name: "Changed" })],
    },
  ]);
  expect((await f.run()).pass).toBe(false);
});
it("readback-every-legacy-data-set", async () => {
  const f = await fixture();
  for (const [name, binding] of LEGACY_SCOPE_BINDINGS) {
    const source: ImportSource = {
      ...f.source,
      target: {
        ...f.source.target,
        connector: legacyConnectorKey(binding.pdppSource),
        stream: binding.pdppStreams[0]!,
        primaryKey: binding.primaryKey[binding.pdppStreams[0]!]!,
      },
      async *records() {},
    };
    const reader = createImportProjectionReader(
      f.deps,
      time,
      async function* () {
        yield source;
      },
    );
    const results = await reader.compare(source, null);
    expect(
      results.some((p) => p.dataSet === name),
      name,
    ).toBe(true);
    const names = [...LEGACY_SCOPE_BINDINGS]
      .filter(
        ([, b]) =>
          legacyConnectorKey(b.pdppSource) === source.target.connector &&
          b.pdppStreams.includes(source.target.stream),
      )
      .map(([n]) => n)
      .sort();
    expect(results.map((p) => p.dataSet).sort()).toEqual(names);
  }
});
it("readback-fixed-projection-time", async () => {
  const f = await fixture();
  const source: ImportSource = {
    ...f.source,
    target: { ...f.source.target, connector: "chatgpt", stream: "memories" },
    async *records() {
      yield { id: "m", content: "memory", created_at: null };
    },
  };
  await f.db.batch([{ sql: "UPDATE connections SET connector = 'chatgpt'" }]);
  await importLegacySource(f.deps, createImportLedger(f.db), source);
  const expected = {
    memories: [
      { id: "m", content: "memory", created_at: time, type: "memory" },
    ],
    total: 1,
  };
  const copy = {
    ...f.copy,
    dataSet: "chatgpt.memories",
    sources: [
      {
        source: source.source,
        connectionId: source.target.connectionId,
        stream: source.target.stream,
      },
    ],
  };
  const projection = createImportProjectionReader(
    f.deps,
    time,
    async function* () {
      yield source;
    },
    async function* () {
      yield expected;
    },
  );
  expect(
    (await readBackLegacyImport(f.deps, source, projection, copy)).pass,
  ).toBe(true);
});
it("readback-mutation-during-proof-and-unbound-copy-hold", async () => {
  const f = await fixture();
  await f.import();
  expect(
    (
      await readBackLegacyImport(f.deps, f.source, f.projections, {
        ...f.copy,
        dataSet: "unbound",
      })
    ).pass,
  ).toBe(false);
  const projection = {
    compare: async () => {
      const proofs = await f.projections.compare(f.source, f.copy);
      f.source.records = async function* () {
        throw new Error("source_changed");
      };
      return proofs;
    },
  };
  expect(
    await readBackLegacyImport(f.deps, f.source, projection, f.copy),
  ).toMatchObject({ pass: false, reason: "source_changed" });
});
it("readback-reopen-and-no-proof-status-writes", async () => {
  const dir = mkdtempSync(join(process.cwd(), ".import-readback-test-"));
  dirs.push(dir);
  const path = join(dir, "db.sqlite");
  const first = await fixture(path);
  await first.import();
  await first.db.close();
  dbs.delete(first.db);
  const f = await fixture(path);
  const before = await f.db.query("SELECT * FROM import_ledger");
  expect((await f.run()).pass).toBe(true);
  expect(await f.db.query("SELECT * FROM import_ledger")).toEqual(before);
  expect(await f.db.query("SELECT * FROM import_snapshot")).toEqual([]);
});
it("readback-projection-bound-retains-large-copy", async () => {
  const f = await fixture();
  f.source.records = async function* () {
    yield { ...payload, extra: "x".repeat(3 * 1024 * 1024) };
  };
  await f.import();
  expect(await f.run()).toMatchObject({
    pass: false,
    reason: "projection_bound_exceeded",
  });
});

it("readback-order-independent-and-equal-count-different-body-fails", async () => {
  const f = await fixture();
  await f.db.batch([{ sql: "UPDATE connections SET connector = 'chatgpt'" }]);
  let pass = 0;
  const values = [
    { id: "a", content: "first", created_at: time },
    { id: "b", content: "second", created_at: time },
  ];
  const source: ImportSource = {
    ...f.source,
    target: { ...f.source.target, connector: "chatgpt", stream: "memories" },
    async *records() {
      yield* ++pass % 2 ? values : [...values].reverse();
    },
  };
  await importLegacySource(f.deps, createImportLedger(f.db), source);
  const reader = createImportProjectionReader(f.deps, time, async function* () {
    yield source;
  });
  expect((await readBackLegacyImport(f.deps, source, reader, null)).pass).toBe(
    true,
  );
  // A self-consistent different stored body still fails source equality.
  const { createHash } = await import("node:crypto");
  const body = JSON.stringify({
    content: "different",
    created_at: time,
    id: "a",
  });
  await f.db.batch([
    {
      sql: "UPDATE records SET body = ?, body_sha256 = ?, stamp_o = 99 WHERE record_key = 'a'",
      params: [body, createHash("sha256").update(body).digest("hex")],
    },
  ]);
  expect(
    await readBackLegacyImport(f.deps, source, reader, null),
  ).toMatchObject({ pass: false, reason: "record_mismatch" });
});
it("readback-missing-joined-peer-and-arrival-evidence-hold", async () => {
  const f = await fixture();
  for (const name of [
    "icloud_notes.notes",
    "wholefoods.nutrition",
    "strava.activities",
  ]) {
    const binding = LEGACY_SCOPE_BINDINGS.get(name)!;
    const stream = binding.pdppStreams[0]!;
    const source: ImportSource = {
      ...f.source,
      target: {
        ...f.source.target,
        connector: legacyConnectorKey(binding.pdppSource),
        stream,
        primaryKey: binding.primaryKey[stream]!,
      },
      async *records() {
        yield { id: "one" };
      },
    };
    const reader = createImportProjectionReader(
      f.deps,
      time,
      async function* () {
        yield source;
      },
    );
    expect(
      (await reader.compare(source, null)).find((p) => p.dataSet === name)
        ?.pass,
      name,
    ).toBe(false);
  }
});
it("readback-missing-row-and-incomplete-projection-coverage-hold", async () => {
  const f = await fixture();
  await f.import();
  const good = await f.projections.compare(f.source, f.copy);
  expect(
    (
      await readBackLegacyImport(
        f.deps,
        f.source,
        { compare: async () => [...good, ...good] },
        f.copy,
      )
    ).pass,
  ).toBe(false);
  await f.db.batch([{ sql: "DELETE FROM records" }]);
  expect((await f.run()).pass).toBe(false);
});

it("readback-copy-revision-and-malformed-identity-hold", async () => {
  const f = await fixture();
  await f.import();
  for (const copy of [
    { ...f.copy, revision: "different" },
    { ...f.copy, contentHash: "" },
    { ...f.copy, id: "" },
  ]) {
    expect(
      (await readBackLegacyImport(f.deps, f.source, f.projections, copy)).pass,
    ).toBe(false);
  }
});
