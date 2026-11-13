/**
 * Retirement after the one-time seed, with the real legacy-access over a
 * temporary legacy store and a real local database. The "host" here is the
 * test: its importer seeds through legacy-access, its port opens legacy-access
 * again for retirement.
 */
import { afterEach, expect, it, vi } from "vitest";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type Database from "better-sqlite3";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import { openRecordStore } from "../pdpp/records-bootstrap.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { openLegacyAccess } from "./legacy-access.js";
import { fixtureProjections } from "./import-projection.test-utils.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import {
  createImportLedger,
  createLegacyEraseLedger,
} from "../../../core/src/localdb/import-ledger.js";
import { importLegacySource } from "../../../core/src/localdb/legacy-import.js";
import { readBackLegacyImport } from "../../../core/src/localdb/import-readback.js";
import { canonicalImportRow } from "../../../core/src/localdb/import-snapshot.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import { createImportWaker } from "../../../core/src/sync/account-mode/import-waker.js";
import type {
  LegacyWriteHold,
  LegacyWriteSeal,
} from "../../../core/src/storage/legacy-write-seal.js";
import type { DeclarationSnapshot } from "../../../core/src/pdpp/types.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { ImportSource } from "../../../core/src/localdb/legacy-import-types.js";
import type { ImportRunner } from "../../../core/src/sync/account-mode/import-waker.js";
import {
  retireAfterImport,
  type LegacyRetirePort,
} from "./retire-after-import.js";

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

/** One switched owner: a legacy store with one old file and its record, plus
 * the owner's local database. */
async function host(options: { switched?: () => boolean } = {}) {
  const root = mkdtempSync(join(tmpdir(), "retire-after-import-"));
  dirs.push(root);
  mkdirSync(join(root, "data"));
  const native = initializeDatabase(join(root, "index.db"));
  natives.push(native);
  const store = openRecordStore(native, false);
  store.registerConnection({
    instance: "instance",
    sourceId: "urn:fixture",
    method: "profile-source",
    label: "Test",
  });
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
  );
  const file = join(root, "data", "copy.json");
  writeFileSync(
    file,
    JSON.stringify({
      scope: "fixture.profile",
      collectedAt: "2026-01-01T00:00:00.000Z",
      data: body,
    }),
  );
  createIndexManager(native).insert({} as LegacyWriteHold, {
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
  await local.batch([
    {
      sql: "INSERT INTO connections (connection_id,connector,ns,generation,control_state) VALUES ('control','profile-source','known',1,'active')",
    },
  ]);
  const unexpected = async (): Promise<never> => {
    throw new Error("unexpected external call");
  };
  let op = 0;
  const logs: { level: "info" | "warn"; obj: Record<string, unknown> }[] = [];
  const deps: LocalSyncDeps = {
    db: local,
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
    logger: {
      info: (obj) => logs.push({ level: "info", obj }),
      warn: (obj) => logs.push({ level: "warn", obj }),
    },
    now: () => 1,
    newOp: () => `op-${++op}`,
  };
  const seal: LegacyWriteSeal = {
    commit: async () => {
      throw new Error("unexpected legacy write");
    },
    remove: async (work) => work(),
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
  const switched = options.switched ?? (() => true);
  const accessOptions = {
    importProjection: fixtureProjections,
    db: native,
    owner: "0xabc",
    network: "test",
    root,
    declarations,
    eraseLedger: createLegacyEraseLedger(local, () => 1),
    legacyWriteSeal: seal,
    isSwitched: async () => switched(),
    isQuiescent: async () => true,
    verifyBinding: async () => true,
    resolveTarget: async () => ({
      connectionId: "control",
      connector: "profile-source",
      stream: "profile",
      primaryKey: ["id"],
      semantics: "mutable_state" as const,
      incremental: true,
    }),
  };
  /** The host's one-time seed: import every legacy source, then close. */
  const seeded = { runs: 0 };
  const importer: ImportRunner = {
    async run() {
      seeded.runs++;
      const access = await openLegacyAccess(accessOptions);
      try {
        for await (const source of access.sources())
          if (!("kind" in source))
            await importLegacySource(
              deps,
              createImportLedger(local),
              source as ImportSource,
            );
      } finally {
        await access.close();
      }
    },
  };
  const opened = { count: 0 };
  const port: LegacyRetirePort = {
    async open() {
      opened.count++;
      const access = await openLegacyAccess(accessOptions);
      return {
        access: {
          copies: () => access.copies(),
          erase: (copy) => access.erase(copy),
          erasedWithIntent: (copy) => access.erasedWithIntent(copy),
          finishErase: (copy) => access.finishErase(copy),
          readBack: async (copy) => {
            const proofs = [];
            for await (const source of access.sources())
              if (
                !("kind" in source) &&
                copy.sources.some(
                  (s) => s.connectionId === source.target.connectionId,
                )
              )
                proofs.push(
                  await readBackLegacyImport(deps, source as ImportSource),
                );
            return proofs;
          },
        },
        close: () => access.close(),
      };
    },
  };
  const wrapped = (streamSync: { retireLegacy?: boolean }, p = port) =>
    retireAfterImport({
      importer,
      port: p,
      getDeps: async () => deps,
      isSwitched: switched,
      streamSync: () => streamSync,
      logger: deps.logger,
    });
  const receipts = () =>
    local.query<{ state: string }>(
      "SELECT state FROM import_ledger ORDER BY stream",
    );
  const stored = () =>
    local.query<{ body: string }>("SELECT body FROM records ORDER BY 1");
  return {
    file,
    local,
    deps,
    logs,
    importer,
    seeded,
    opened,
    port,
    wrapped,
    receipts,
    stored,
    accessOptions,
  };
}

const run = (runner: ImportRunner) => runner.run(new AbortController().signal);
const reportsOf = (logs: { obj: Record<string, unknown> }[]) =>
  logs.filter((l) => l.obj.mode !== undefined).map((l) => l.obj);

it("setting off: the seed runs, the files stay, the report is read-back only", async () => {
  const f = await host();
  await run(f.wrapped({ retireLegacy: false }));
  expect(f.seeded.runs).toBe(1);
  expect(existsSync(f.file)).toBe(true);
  expect(await f.receipts()).toEqual([{ state: "imported" }]);
  expect(reportsOf(f.logs)).toEqual([
    expect.objectContaining({
      mode: "readback-only",
      files: 1,
      ready: 1,
      deleted: 0,
      readbackFailures: 0,
    }),
  ]);
});

it("setting on: after a successful import the old file is gone, a real write still wins, a restart is idempotent", async () => {
  const f = await host();
  await run(f.wrapped({ retireLegacy: true }));
  expect(f.seeded.runs).toBe(1);
  expect(existsSync(f.file)).toBe(false);
  expect(await f.receipts()).toEqual([{ state: "retired" }]);
  expect(reportsOf(f.logs)).toEqual([
    expect.objectContaining({ mode: "delete", files: 1, deleted: 1 }),
  ]);

  // A real write made after the seed is the database's value; retirement
  // never touches records.
  const real = await canonicalImportRow({ ...body, display_name: "Real" }, [
    "id",
  ]);
  await f.local.batch([
    {
      sql: "UPDATE records SET body = ?, body_sha256 = ?, stamp_o = 99",
      params: [real.body, real.body_sha256],
    },
  ]);
  const before = await f.stored();
  expect(before[0]!.body).toContain("Real");

  // A restart runs the same wrapped importer again: nothing is left to
  // remove, no file reappears, and the real write is untouched.
  f.logs.length = 0;
  await run(f.wrapped({ retireLegacy: true }));
  expect(existsSync(f.file)).toBe(false);
  expect(await f.stored()).toEqual(before);
  expect(reportsOf(f.logs)).toEqual([
    expect.objectContaining({ mode: "delete", files: 0, deleted: 0 }),
  ]);
  expect(f.logs.filter((l) => l.level === "warn")).toEqual([]);
});

it("an owner who is not switched runs nothing, not even the port", async () => {
  const f = await host({ switched: () => false });
  const open = vi.spyOn(f.port, "open");
  // Direct: an importer that returns for an owner no longer switched.
  let imports = 0;
  const wrapped = retireAfterImport({
    importer: { run: async () => void imports++ },
    port: f.port,
    getDeps: async () => f.deps,
    isSwitched: () => false,
    streamSync: () => ({ retireLegacy: true }),
    logger: f.deps.logger,
  });
  await run(wrapped);
  expect(imports).toBe(1);
  expect(open).not.toHaveBeenCalled();
  expect(existsSync(f.file)).toBe(true);

  // Through the real waker, an unswitched owner never reaches the importer.
  const waker = createImportWaker({
    authority: {
      ready: Promise.resolve(),
      read: () => ({ kind: "legacy" }) as never,
    },
    owner: "0xabc",
    importer: wrapped,
  });
  await waker.wake();
  expect(imports).toBe(1);
  expect(open).not.toHaveBeenCalled();
  expect(existsSync(f.file)).toBe(true);
});

it("a failed import retires nothing and the failure still reaches the waker", async () => {
  const f = await host();
  const failing: ImportRunner = {
    run: async () => {
      throw new Error("import failed");
    },
  };
  const wrapped = retireAfterImport({
    importer: failing,
    port: f.port,
    getDeps: async () => f.deps,
    isSwitched: () => true,
    streamSync: () => ({ retireLegacy: true }),
    logger: f.deps.logger,
  });
  await expect(run(wrapped)).rejects.toThrow("import failed");
  expect(f.opened.count).toBe(0);
  expect(existsSync(f.file)).toBe(true);
});

it("a retirement error leaves the import done, is logged, and the next run retires", async () => {
  const f = await host();
  let broken = true;
  const flaky: LegacyRetirePort = {
    open: async (deps) => {
      if (broken) throw new Error("legacy store unavailable");
      return f.port.open(deps);
    },
  };
  const warnings: Record<string, unknown>[] = [];
  const wrapped = retireAfterImport({
    importer: f.importer,
    port: flaky,
    getDeps: async () => f.deps,
    isSwitched: () => true,
    streamSync: () => ({ retireLegacy: true }),
    logger: {
      info: () => {},
      warn: (obj) => warnings.push(obj),
    },
  });
  await expect(run(wrapped)).resolves.toBeUndefined();
  expect(f.seeded.runs).toBe(1);
  expect(await f.receipts()).toEqual([{ state: "imported" }]);
  expect(existsSync(f.file)).toBe(true);
  expect(warnings).toEqual([{ error: "Error: legacy store unavailable" }]);

  broken = false;
  await run(wrapped);
  expect(existsSync(f.file)).toBe(false);
  expect(await f.receipts()).toEqual([{ state: "retired" }]);
});

it("an erase error mid-retirement does not fail the run either", async () => {
  const f = await host();
  const port: LegacyRetirePort = {
    open: async (deps) => {
      const opened = await f.port.open(deps);
      return {
        ...opened,
        access: {
          ...opened.access,
          erase: async () => {
            throw new Error("disk error");
          },
        },
      };
    },
  };
  await expect(
    run(f.wrapped({ retireLegacy: true }, port)),
  ).resolves.toBeUndefined();
  expect(existsSync(f.file)).toBe(true);
  expect(f.logs.some((l) => l.level === "warn")).toBe(true);
});

it("shutdown during retirement stops before the next copy", async () => {
  const f = await host();
  const controller = new AbortController();
  const port: LegacyRetirePort = {
    open: async (deps) => {
      const opened = await f.port.open(deps);
      return {
        ...opened,
        access: {
          ...opened.access,
          copies: async function* () {
            controller.abort();
            yield* opened.access.copies();
          },
        },
      };
    },
  };
  await f.wrapped({ retireLegacy: true }, port).run(controller.signal);
  expect(f.seeded.runs).toBe(1);
  expect(existsSync(f.file)).toBe(true);
  expect(reportsOf(f.logs)).toEqual([
    expect.objectContaining({ files: 0, deleted: 0, stopped: true }),
  ]);
});
