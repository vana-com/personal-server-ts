import { fixtureProjections } from "./import-projection.test-utils.js";
import { readBackLegacyImport } from "../../../core/src/localdb/import-readback.js";
import { afterEach, expect, it, vi } from "vitest";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  rmSync,
  existsSync,
  readFileSync,
  symlinkSync,
} from "node:fs";
import { join } from "node:path";
import type Database from "better-sqlite3";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import { openRecordStore } from "../pdpp/records-bootstrap.js";
import {
  admitReplication,
  beginReplicationStep,
} from "../storage/pdpp-replication-door.js";
import { openLegacyAccess } from "./legacy-access.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import {
  createLegacyEraseLedger,
  createImportLedger,
} from "../../../core/src/localdb/import-ledger.js";
import { importLegacySource } from "../../../core/src/localdb/legacy-import.js";
import { retireLegacyCopies } from "../../../core/src/localdb/legacy-retire.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import type {
  LegacyWriteSeal,
  LegacyWriteHold,
} from "../../../core/src/storage/legacy-write-seal.js";
import type { DeclarationSnapshot } from "../../../core/src/pdpp/types.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type {
  ImportSource,
  LegacyRetireFileReport,
} from "../../../core/src/localdb/legacy-import-types.js";
const dirs: string[] = [];
const natives: Database.Database[] = [];
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
  for (const db of natives.splice(0)) if (db.open) db.close();
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});
const body = {
  id: "account",
  display_name: "Name",
  uri: "uri",
  followers: 1,
  following: 2,
  images: [],
};
async function fixture() {
  const root = mkdtempSync(join(process.cwd(), ".legacy-access-test-"));
  dirs.push(root);
  mkdirSync(join(root, "data"));
  const db = initializeDatabase(join(root, "index.db"));
  natives.push(db);
  const store = openRecordStore(db, false);
  store.registerConnection({
    instance: "instance",
    sourceId: "urn:fixture",
    method: "profile-source",
    label: "Test",
  });
  expect(
    store.ingestBatch(
      [
        {
          instance: "instance",
          stream: "profile",
          key: "account",
          data: body,
          emitted_at: "2026-01-01T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "profile-source", generation: 1 },
    ).accepted,
  ).toBe(1);
  const file = join(root, "data", "copy.json");
  writeFileSync(
    file,
    JSON.stringify({
      scope: "fixture.profile",
      collectedAt: "2026-01-01T00:00:00.000Z",
      data: body,
    }),
  );
  const index = createIndexManager(db);
  index.insert({} as LegacyWriteHold, {
    fileId: null,
    path: "copy.json",
    scope: "fixture.profile",
    collectedAt: "2026-01-01T00:00:00.000Z",
    sizeBytes: 100,
  });
  const local = await openLocalDb(
    openBetterSqlite3(join(root, "local.sqlite")),
    { owner: "0xabc", network: "test", deviceId: "device" },
  );
  drivers.push(local);
  const eraseLedger = createLegacyEraseLedger(local, () => 1);
  const seal: LegacyWriteSeal = {
    commit: async () => {
      throw new Error("unexpected legacy write");
    },
    remove: vi.fn(async (work) => work()),
    admit: () => null,
    verdict: () => "switched",
  };
  const declarations: DeclarationSnapshot[] = [
    {
      source_id: "urn:fixture",
      source_kind: "connector",
      version: "1",
      digest: "digest",
      streams: [
        {
          name: "profile",
          primary_key: ["id"],
          fields: ["id"],
          required_fields: ["id"],
        },
      ],
    },
  ];
  const target = {
    connectionId: "control",
    connector: "profile-source",
    stream: "profile",
    primaryKey: ["id"],
    semantics: "mutable_state" as const,
    incremental: true,
  };
  const options = {
    importProjection: fixtureProjections,
    db,
    owner: "0xabc",
    network: "test",
    root,
    declarations,
    eraseLedger,
    legacyWriteSeal: seal,
    isSwitched: async () => true,
    isQuiescent: async () => true,
    verifyBinding: vi.fn(async () => true),
    resolveTarget: async () => target,
  };
  return { root, db, store, file, local, eraseLedger, options, seal, target };
}
async function collect<T>(source: AsyncIterable<T>) {
  const items: T[] = [];
  for await (const item of source) items.push(item);
  return items;
}
it("legacy-access-unswitched-and-unknown-refuse", async () => {
  const f = await fixture();
  const before = f.db.prepare("SELECT total_changes() AS n").get();
  for (const change of [
    { isSwitched: async () => false },
    { isQuiescent: async () => false },
  ])
    await expect(openLegacyAccess({ ...f.options, ...change })).rejects.toThrow(
      "legacy_access_unavailable",
    );
  expect(f.options.verifyBinding).not.toHaveBeenCalled();
  expect(f.db.prepare("SELECT total_changes() AS n").get()).toEqual(before);
  expect(existsSync(f.file)).toBe(true);
});
it("legacy-access-owner-network-root-match", async () => {
  const f = await fixture();
  await expect(
    openLegacyAccess({ ...f.options, owner: "0xdef" }),
  ).rejects.toThrow("legacy_identity_mismatch");
  await expect(
    openLegacyAccess({ ...f.options, network: "other" }),
  ).rejects.toThrow("legacy_identity_mismatch");
  await expect(
    openLegacyAccess({ ...f.options, verifyBinding: async () => false }),
  ).rejects.toThrow("legacy_identity_mismatch");
  const other = join(f.root, "other");
  mkdirSync(other);
  await expect(openLegacyAccess({ ...f.options, root: other })).rejects.toThrow(
    "legacy_identity_mismatch",
  );
});
it("legacy-access-closes-replication-first", async () => {
  const f = await fixture();
  admitReplication(f.db);
  const step = beginReplicationStep(f.db);
  try {
    const access = await openLegacyAccess(f.options);
    expect(step.signal.aborted).toBe(true);
    expect(f.db.prepare("SELECT off FROM pdpp_replica_door").get()).toEqual({
      off: 1,
    });
    expect((await collect(access.sources())).length).toBe(1);
    await access.close();
    expect(f.db.open).toBe(true);
  } finally {
    step.close();
  }
});
it("legacy-access-hash-fenced-erase", async () => {
  const f = await fixture();
  const access = await openLegacyAccess(f.options);
  const [copy] = await collect(access.copies());
  expect(copy).toBeDefined();
  const replacement = JSON.stringify({
    scope: "fixture.profile",
    data: { ...body, extra: "retained" },
  });
  writeFileSync(f.file, replacement);
  expect(await access.erase(copy!)).toBe(false);
  expect(readFileSync(f.file, "utf8")).toBe(replacement);
  expect(await f.eraseLedger.has(copy!)).toBe(false);
});
it("legacy-access-no-gateway-delete-and-intent-before-unlink", async () => {
  const f = await fixture();
  const access = await openLegacyAccess(f.options);
  const [copy] = await collect(access.copies());
  const record = f.eraseLedger.record;
  f.eraseLedger.record = vi.fn(async (value) => {
    expect(existsSync(f.file)).toBe(true);
    await record(value);
    expect(await f.eraseLedger.has(value)).toBe(true);
  });
  expect(await access.erase(copy!)).toBe(true);
  expect(existsSync(f.file)).toBe(false);
  expect(f.seal.remove).toHaveBeenCalled();
  expect(f.db.prepare("SELECT count(*) AS n FROM data_files").get()).toEqual({
    n: 0,
  });
  expect(await access.erasedWithIntent(copy!)).toBe(true);
  expect(await collect(access.copies())).toEqual([copy]);
});
it("legacy-access-absence-needs-exact-durable-intent", async () => {
  const f = await fixture();
  const access = await openLegacyAccess(f.options);
  const [copy] = await collect(access.copies());
  await access.erase(copy!);
  expect(
    await access.erasedWithIntent({ ...copy!, contentHash: "f".repeat(64) }),
  ).toBe(false);
  writeFileSync(f.file, "replacement");
  expect(await access.erasedWithIntent(copy!)).toBe(false);
  rmSync(f.file);
  await f.eraseLedger.finish(copy!);
  expect(await access.erasedWithIntent(copy!)).toBe(false);
});
it("legacy-access-source-revision-and-complete-unknown-inventory", async () => {
  const f = await fixture();
  const access = await openLegacyAccess(f.options);
  const sources = await collect(access.sources());
  const source = sources[0] as ImportSource;
  expect(await collect(source.records())).toEqual([body]);
  f.db.prepare("UPDATE pdpp_write_clock SET value = value + 1").run();
  await expect(collect(source.records())).rejects.toThrow("source_changed");
  const next = await openLegacyAccess(f.options);
  f.db
    .prepare(
      "INSERT INTO pdpp_records (instance,stream,record_key,data,version,emitted_at) VALUES ('unbound','unknown','a','{}',1,'2026-01-01T00:00:00Z')",
    )
    .run();
  expect(await collect(next.sources())).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        kind: "excluded",
        reason: "undeclared_source",
      }),
    ]),
  );
});
it("legacy-access-orphan-is-inventory-and-symlink-refuses", async () => {
  const f = await fixture();
  const access = await openLegacyAccess(f.options);
  writeFileSync(
    join(f.root, "data", "orphan.json"),
    JSON.stringify({ scope: "fixture.profile", data: body }),
  );
  expect(
    (await collect(access.copies())).find((c) => c.path.endsWith("orphan.json"))
      ?.sources,
  ).toEqual([]);
  symlinkSync(f.file, join(f.root, "data", "link.json"));
  await expect(collect(access.copies())).rejects.toThrow("legacy_path_refused");
});
it.each(["after-unlink", "before-receipt"])(
  "legacy-access-crash-reopen-reconciliation: %s",
  async (crashPoint) => {
    const f = await fixture();
    let access = await openLegacyAccess(f.options);
    const [source] = await collect(access.sources());
    const [copy] = await collect(access.copies());
    await f.local.batch([
      {
        sql: "INSERT INTO connections (connection_id,connector,ns,generation,control_state) VALUES ('control','profile-source','known',1,'active')",
      },
    ]);
    const unexpected = async (): Promise<never> => {
      throw new Error("unexpected external call");
    };
    let op = 0;
    const deps: LocalSyncDeps = {
      db: f.local,
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
      now: () => 2,
      newOp: () => `op-${++op}`,
    };
    await importLegacySource(
      deps,
      createImportLedger(f.local),
      source as ImportSource,
    );
    await f.local.batch([
      { sql: "UPDATE stream_state SET publish_watermark = 100" },
    ]);
    const proofAccess = {
      ...access,
      readBack: async () => [
        await readBackLegacyImport(deps, source as ImportSource),
      ],
    };
    expect(
      (await retireLegacyCopies(deps, proofAccess, { reportFile: () => {} }))
        .ready,
    ).toBe(1);
    expect(existsSync(f.file)).toBe(true);
    const originalBatch = f.local.batch.bind(f.local);
    if (crashPoint === "after-unlink")
      f.db.exec(
        "CREATE TRIGGER fixture_crash BEFORE DELETE ON data_files BEGIN SELECT RAISE(ABORT,'crash after unlink'); END",
      );
    f.local.batch = async (statements) => {
      if (
        crashPoint === "before-receipt" &&
        statements.some(
          (s) =>
            s.sql.includes("UPDATE import_ledger") &&
            s.params?.[0] === "retired",
        )
      )
        throw new Error("crash after unlink");
      return originalBatch(statements);
    };
    await expect(
      retireLegacyCopies(deps, proofAccess, {
        streamSync: { retireLegacy: true },
        reportFile: () => {},
      }),
    ).rejects.toThrow("crash after unlink");
    expect(existsSync(f.file)).toBe(false);
    expect(await f.eraseLedger.has(copy!)).toBe(true);
    f.local.batch = originalBatch;
    await access.close();
    // Close both databases, then create fresh handles and adapters.
    await f.local.close();
    drivers.splice(drivers.indexOf(f.local), 1);
    f.db.close();
    const local = await openLocalDb(
      openBetterSqlite3(join(f.root, "local.sqlite")),
      { owner: "0xabc", network: "test", deviceId: "device" },
    );
    drivers.push(local);
    const raw = initializeDatabase(join(f.root, "index.db"));
    natives.push(raw);
    if (crashPoint === "after-unlink") raw.exec("DROP TRIGGER fixture_crash");
    const journal = createLegacyEraseLedger(local, () => 3);
    Object.assign(deps, { db: local });
    access = await openLegacyAccess({
      ...f.options,
      db: raw,
      eraseLedger: journal,
    });
    const erase = vi.spyOn(access, "erase");
    const reports: LegacyRetireFileReport[] = [];
    const result = await retireLegacyCopies(
      deps,
      {
        ...access,
        readBack: async () => {
          throw new Error("absent copy cannot be read");
        },
      },
      {
        streamSync: { retireLegacy: true },
        reportFile: (r) => reports.push(r),
      },
    );
    expect(result).toMatchObject({ ready: 1, deleted: 0 });
    expect(erase).not.toHaveBeenCalled();
    expect(reports).toEqual([
      { file: copy!.id, decision: "retired", reason: "erase-reconciled" },
    ]);
    expect(await collect(journal.pending())).toEqual([]);
    expect(raw.prepare("SELECT count(*) AS n FROM data_files").get()).toEqual({
      n: 0,
    });
    expect(await collect(access.copies())).toEqual([]);
    expect(await local.query("SELECT state FROM import_ledger")).toEqual([
      { state: "retired" },
    ]);
  },
);
it("legacy-access-missing-file-without-intent-is-reported", async () => {
  const f = await fixture();
  const access = await openLegacyAccess(f.options);
  rmSync(f.file);
  expect(await collect(access.copies())).toEqual([
    expect.objectContaining({ contentHash: "", sources: [] }),
  ]);
});
it("legacy-access-concurrent-erase-is-once-only", async () => {
  const f = await fixture();
  const access = await openLegacyAccess(f.options);
  const [copy] = await collect(access.copies());
  expect(
    (await Promise.all([access.erase(copy!), access.erase(copy!)])).filter(
      Boolean,
    ),
  ).toHaveLength(1);
  expect(await access.erasedWithIntent(copy!)).toBe(true);
});
it("legacy-access-journal-failure-leaves-file-and-index", async () => {
  const f = await fixture();
  const access = await openLegacyAccess(f.options);
  const [copy] = await collect(access.copies());
  f.eraseLedger.record = async () => {
    throw new Error("journal unavailable");
  };
  await expect(access.erase(copy!)).rejects.toThrow("journal unavailable");
  expect(existsSync(f.file)).toBe(true);
  expect(f.db.prepare("SELECT count(*) AS n FROM data_files").get()).toEqual({
    n: 1,
  });
});
it("legacy-access-revision-binds-content-not-device-counter", async () => {
  const a = await fixture();
  const b = await fixture();
  b.db
    .prepare("UPDATE pdpp_records SET data = ?")
    .run(JSON.stringify({ ...body, display_name: "Different" }));
  const one = await openLegacyAccess(a.options);
  const two = await openLegacyAccess(b.options);
  const first = (await collect(one.sources()))[0] as ImportSource;
  const second = (await collect(two.sources()))[0] as ImportSource;
  expect(first.revision).not.toBe(second.revision);
});
it.each(["no-binding", "no-declaration", "orphan"])(
  "legacy-access-removes-unimported-copy: %s",
  async (kind) => {
    const f = await fixture();
    const path =
      kind === "orphan" ? join(f.root, "data", "orphan.json") : f.file;
    if (kind === "orphan") writeFileSync(path, "unmapped old bytes");
    const access = await openLegacyAccess({
      ...f.options,
      ...(kind === "no-binding"
        ? { importProjection: { bindings: new Map() } }
        : {}),
      ...(kind === "no-declaration" ? { declarations: [] } : {}),
    });
    const copy = (await collect(access.copies())).find((c) => c.path === path)!;
    expect(copy.sources).toEqual([]);
    expect(await access.erase(copy)).toBe(true);
    expect(existsSync(path)).toBe(false);
    expect(await f.eraseLedger.has(copy)).toBe(true);
    await access.finishErase(copy);
    expect(await f.eraseLedger.has(copy)).toBe(false);
  },
);
it("native access selects the latest active account and counts the older rows", async () => {
  const f = await fixture();
  f.store.registerConnection({
    instance: "newer",
    sourceId: "urn:fixture",
    method: "profile-source",
    label: "Newer",
  });
  expect(
    f.store.ingestBatch(
      [
        {
          instance: "newer",
          stream: "profile",
          key: "account",
          data: body,
          emitted_at: "2026-02-01T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "profile-source", generation: 1 },
    ).accepted,
  ).toBe(1);
  const access = await openLegacyAccess(f.options);
  const inventory = await collect(access.sources());
  expect(inventory).toHaveLength(2);
  expect(inventory.find((s) => "kind" in s)).toMatchObject({
    kind: "excluded",
    reason: "older_instance",
    rows: 1,
  });
  const selected = inventory.find((s) => !("kind" in s))!;
  expect(JSON.parse(selected.source)[0]).toBe("newer");
});
it("reuses native source statements across replay passes", async () => {
  const f = await fixture();
  const second = { ...body, id: "second" };
  expect(
    f.store.ingestBatch(
      [
        {
          instance: "instance",
          stream: "profile",
          key: "second",
          data: second,
          emitted_at: "2026-01-01T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "profile-source", generation: 1 },
    ).accepted,
  ).toBe(1);
  const prepare = vi.spyOn(f.db, "prepare");
  const pragma = vi.spyOn(f.db, "pragma");
  try {
    const access = await openLegacyAccess(f.options);
    const [source] = await collect(access.sources());
    expect(source).not.toHaveProperty("kind");
    for (let pass = 0; pass < 2; pass++)
      expect(await collect((source as ImportSource).records())).toEqual([
        body,
        second,
      ]);
    expect(
      prepare.mock.calls.filter(([sql]) =>
        sql.startsWith("SELECT data FROM pdpp_records"),
      ),
    ).toHaveLength(1);
    expect(
      prepare.mock.calls.filter(
        ([sql]) => sql === "SELECT value FROM pdpp_write_clock WHERE id = 1",
      ),
    ).toHaveLength(1);
    expect(
      pragma.mock.calls.filter(([sql]) => sql === "shrink_memory"),
    ).toHaveLength(0);
    expect(
      prepare.mock.calls.filter(([sql]) => sql === "PRAGMA shrink_memory"),
    ).toHaveLength(1);
    await access.close();
    expect(f.db.open).toBe(true);
  } finally {
    prepare.mockRestore();
    pragma.mockRestore();
  }
});
it("seeks past the previous key while hashing a native revision", async () => {
  const f = await fixture();
  const prepare = vi.spyOn(f.db, "prepare");
  try {
    const access = await openLegacyAccess(f.options);
    const sql = prepare.mock.calls
      .map(([sql]) => sql)
      .filter((sql) =>
        sql.includes("length(CAST(data AS BLOB)) AS bytes FROM pdpp_records"),
      )
      .at(-1)!;
    const plan = f.db
      .prepare("EXPLAIN QUERY PLAN " + sql)
      .all(...Array(sql.match(/\?/g)?.length ?? 0).fill(null)) as {
      detail: string;
    }[];
    expect(
      plan.some((row) =>
        /SEARCH pdpp_records.+instance.+stream.+record_key/.test(row.detail),
      ),
    ).toBe(true);
    await access.close();
  } finally {
    prepare.mockRestore();
  }
});
it("rechecks quiescence between native snapshot hash pages", async () => {
  const f = await fixture();
  const rows = Array.from({ length: 128 }, (_, i) => ({
    instance: "instance",
    stream: "profile",
    key: `row-${i}`,
    data: { ...body, id: `row-${i}` },
    emitted_at: "2026-01-01T00:00:00.000Z",
  }));
  expect(
    f.store.ingestBatch(
      rows,
      () => "mutable_state",
      () => ["id"],
      { method: "profile-source", generation: 1 },
    ).accepted,
  ).toBe(128);
  await expect(
    openLegacyAccess({
      ...f.options,
      isQuiescent: vi.fn().mockResolvedValueOnce(true).mockResolvedValue(false),
    }),
  ).rejects.toThrow("legacy_access_unavailable");
});
