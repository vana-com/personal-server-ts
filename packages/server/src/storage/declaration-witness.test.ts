import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import {
  runDeclarationWitness,
  OfflineDeclarationWitnessError,
} from "./declaration-witness.js";

const faults = vi.hoisted(() => ({ open: "", read: "" }));
const opened = vi.hoisted(() => [] as Array<InstanceType<typeof Database>>);
vi.mock("better-sqlite3", async (importOriginal) => {
  const { default: Actual } = await importOriginal<typeof import("better-sqlite3")>();
  return {
    default: function TrackedDatabase(...args: ConstructorParameters<typeof Actual>) {
      if (faults.open) throw Object.assign(new Error("PRIVATE_NATIVE"), { code: faults.open });
      const db = new Actual(...args);
      if (faults.read && db.readonly) {
        vi.spyOn(db, "prepare").mockImplementation(() => {
          throw Object.assign(new Error("PRIVATE_NATIVE"), { code: faults.read });
        });
      }
      opened.push(db);
      return db;
    },
  };
});

const sourceKey = "conn_witness";
const stream = "messages";
const nextSchema = {
  type: "object",
  properties: { id: { type: "string" }, count: { type: "integer" } },
  required: ["id", "count"],
  additionalProperties: false,
};

describe("offline declaration witness over the real SQLite store", () => {

  function seedDeclaration(path = join(root, "pdpp-declarations.db"), names = [stream], current = 1): void {
    const db = new Database(path);
    try {
      db.exec(`CREATE TABLE pdpp_current_declarations (
        source_id TEXT NOT NULL, version TEXT NOT NULL, digest TEXT NOT NULL,
        snapshot_json TEXT NOT NULL, document TEXT NOT NULL, accepted_at TEXT NOT NULL,
        is_current INTEGER NOT NULL, origin TEXT NOT NULL,
        PRIMARY KEY (source_id, version))`);
      db.prepare("INSERT INTO pdpp_current_declarations VALUES (?, 'v1', 'digest', ?, '{}', 'now', ?, 'configured')")
        .run("https://example.test/source", JSON.stringify({
          source_id: "https://example.test/source",
          streams: names.map((name) => ({ name, schema: nextSchema })),
        }), current);
    } finally { db.close(); }
    opened.length = 0;
  }

  it.each([0, 7, 103])("walks a declared stream with %s rows using the exact bound source ID", async (count) => {
    seed(count);
    seedDeclaration();
    await expect(run()).resolves.toEqual({ verdict: "pass", checked: count });
    expect(opened).toHaveLength(2);
    expectClosed();
  });

  it("validates declared rows against nextSchema without disclosing values", async () => {
    seed(7, 4);
    seedDeclaration();
    const result = await run();
    expect(result.verdict).toBe("fail");
    expect(JSON.stringify(result)).not.toContain("PRIVATE_VALUE");
    expectClosed();
  });

  it("rejects undeclared streams even when they have stored rows", async () => {
    seed(2);
    seedDeclaration(undefined, ["other"]);
    await expect(run()).rejects.toMatchObject({ code: "missing_stream" });
    expectClosed();
  });

  it("ignores retained declarations that are not current", async () => {
    seed();
    seedDeclaration(undefined, [stream], 0);
    await expect(run()).rejects.toMatchObject({ code: "unverifiable_source" });
    expectClosed();
  });

  it("uses an explicit declarationsDbPath", async () => {
    seed();
    const declarationsDbPath = join(root, "custom.db");
    seedDeclaration(declarationsDbPath);
    await expect(run({ declarationsDbPath })).resolves.toEqual({ verdict: "pass", checked: 0 });
    expect(existsSync(join(root, "pdpp-declarations.db"))).toBe(false);
    expectClosed();
  });

  it.each(["missing table", "invalid JSON", "wrong source", "invalid streams", "ambiguous current"])(
    "fails closed and closes both handles for %s", async (kind) => {
      seed();
      const path = join(root, "pdpp-declarations.db");
      seedDeclaration();
      const db = new Database(path);
      if (kind === "missing table") db.exec("DROP TABLE pdpp_current_declarations");
      if (kind === "invalid JSON") db.exec("UPDATE pdpp_current_declarations SET snapshot_json = 'PRIVATE_BAD_JSON'");
      if (kind === "wrong source") db.prepare("UPDATE pdpp_current_declarations SET snapshot_json = ?")
        .run(JSON.stringify({ source_id: "other", streams: [{ name: stream }] }));
      if (kind === "invalid streams") db.prepare("UPDATE pdpp_current_declarations SET snapshot_json = ?")
        .run(JSON.stringify({ source_id: "https://example.test/source", streams: [null] }));
      if (kind === "ambiguous current") db.exec(`INSERT INTO pdpp_current_declarations
        SELECT source_id, 'v2', digest, snapshot_json, document, accepted_at, is_current, origin
        FROM pdpp_current_declarations`);
      db.close();
      opened.length = 0;
      const error = await run().catch((error: unknown) => error);
      expect(error).toMatchObject({ code: "unverifiable_source" });
      expect(String(error)).not.toContain("PRIVATE_BAD_JSON");
      expect(opened).toHaveLength(2);
      expectClosed();
    },
  );

  it("closes both handles when schema validation throws", async () => {
    seed(1);
    seedDeclaration();
    await expect(run({ nextSchema: { type: "INVALID_PRIVATE_TYPE" } })).rejects.toMatchObject({ code: "invalid_schema" });
    expect(opened).toHaveLength(2);
    expectClosed();
  });

  it("preserves both database files and existing WAL/SHM bytes", async () => {
    seed(2);
    const declarationsPath = join(root, "pdpp-declarations.db");
    seedDeclaration();
    const keepers: Array<InstanceType<typeof Database>> = [];
    const readers: Array<InstanceType<typeof Database>> = [];
    try {
      for (const path of [dbPath, declarationsPath]) {
        const keeper = new Database(path);
        keepers.push(keeper);
        keeper.pragma("journal_mode = WAL");
        keeper.pragma("wal_checkpoint(TRUNCATE)");
        const table = path === dbPath ? "pdpp_instance_binding" : "pdpp_current_declarations";
        keeper.exec(`UPDATE ${table} SET source_id = source_id`);
        const reader = new Database(path, { readonly: true });
        readers.push(reader);
        reader.exec("BEGIN");
        reader.prepare(`SELECT * FROM ${table}`).all();
      }
      const paths = [dbPath, declarationsPath].flatMap((path) => [path, path + "-wal", path + "-shm"]);
      const before = paths.map((path) => readFileSync(path));
      opened.length = 0;
      await expect(run()).resolves.toEqual({ verdict: "pass", checked: 2 });
      expect(opened).toHaveLength(2);
      expectClosed();
      expect(paths.map((path) => readFileSync(path))).toEqual(before);
    } finally {
      for (const db of [...readers, ...keepers]) if (db.open) db.close();
    }
  });
  let root: string;
  let dbPath: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "pdpp-offline-witness-"));
    dbPath = join(root, "records.sqlite");
    opened.length = 0;
    faults.open = "";
    faults.read = "";
  });

  afterEach(() => {
    vi.restoreAllMocks();
    for (const db of opened) if (db.open) db.close();
    rmSync(root, { recursive: true, force: true });
  });

  function seed(count = 0, badIndex = -1): void {
    const db = new Database(dbPath);
    try {
      const store = createSqliteRecordStore(db);
      for (const instance of [sourceKey, "conn_other"]) {
        store.registerConnection({
          instance, sourceId: "https://example.test/source", method: "test", label: "test",
        });
        const data = Array.from({ length: instance === sourceKey ? count : 1 }, (_, i) => {
          const id = `private-key-${String(i).padStart(4, "0")}`;
          return {
            instance, stream, key: id,
            data: { id, count: instance === sourceKey && i !== badIndex ? i : "PRIVATE_VALUE" },
            emitted_at: "2026-10-15T00:00:00.000Z",
          };
        });
        expect(store.ingestBatch(data, () => "mutable_state", () => ["id"], {
          method: "test", generation: 1,
        }).accepted).toBe(data.length);
      }
      // A read-only open must not sweep this unclaimed metadata.
      store.putBlobMeta({
        blobId: "orphan", mimeType: "text/plain", sizeBytes: 0, sha256: "test",
      });
    } finally {
      db.close();
    }
    opened.length = 0;
  }

  const run = (overrides: Partial<Parameters<typeof runDeclarationWitness>[0]> = {}) =>
    runDeclarationWitness({ dbPath, sourceKey, stream, nextSchema, limit: 3, budgetMs: 30_000, ...overrides });

  it.each(["conn_missing", "https://example.test/source"])(
    "rejects an unregistered source identity: %s", async (unknownSource) => {
      seed();
      await expect(run({ sourceKey: unknownSource })).rejects.toMatchObject({
        code: "missing_source",
      });
      expectClosed();
    },
  );

  it("fails closed for an unknown stream without a retained declaration registry", async () => {
    seed();
    await expect(run({ stream: "typo_messages" })).rejects.toMatchObject({
      code: "unverifiable_source",
    });
    expectClosed();
  });

  it("cannot verify even an empty registered source without retained declarations", async () => {
    seed();
    await expect(run()).rejects.toMatchObject({ code: "unverifiable_source" });
    expectClosed();
  });

  function expectClosed(): void {
    expect(opened.length).toBeGreaterThan(0);
    for (const db of opened) {
      expect(db.readonly).toBe(true);
      expect(db.open).toBe(false);
    }
  }

  it("fails closed for populated streams with one read-only connection and no writes", async () => {
    seed(103);
    const before = readFileSync(dbPath);
    await expect(run()).rejects.toMatchObject({ code: "unverifiable_source" });
    expect(opened).toHaveLength(1);
    expectClosed();
    expect(readFileSync(dbPath)).toEqual(before);
  });

  it("never turns a missing database into an empty-stream pass, even with zero budget", async () => {
    for (const budgetMs of [30_000, 0]) {
      await expect(run({ budgetMs })).rejects.toMatchObject({
        name: "OfflineDeclarationWitnessError", code: "missing_database",
      });
    }
    expect(existsSync(dbPath)).toBe(false);
    expect(opened).toHaveLength(0);
  });

  it("closes an unsupported store without migrating it", async () => {
    seed();
    const db = new Database(dbPath);
    db.prepare("UPDATE pdpp_schema_version SET version = 0").run();
    db.close();
    opened.length = 0;
    const before = readFileSync(dbPath);
    await expect(run()).rejects.toMatchObject({ code: "unsupported_store" });
    expectClosed();
    expect(readFileSync(dbPath)).toEqual(before);
  });

  it("closes after opening an invalid database and never exposes its bytes or path", async () => {
    writeFileSync(dbPath, "PRIVATE_DATABASE_BYTES");
    const error = await run().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(OfflineDeclarationWitnessError);
    expect(String(error)).not.toMatch(/PRIVATE_DATABASE_BYTES|records.sqlite|pdpp-offline/);
    expectClosed();
  });

  it.each([
    { pageSize: 0 }, { pageSize: -1 }, { pageSize: 1.5 }, { pageSize: Infinity },
    { limit: 0 }, { limit: -1 }, { limit: 1.5 }, { limit: Infinity },
    { budgetMs: -1 }, { budgetMs: NaN }, { budgetMs: Infinity },
    { dbPath: "" }, { sourceKey: "" }, { stream: "" },
  ])("rejects invalid options without opening storage: %j", async (options) => {
    await expect(run(options)).rejects.toMatchObject({ code: "invalid_argument" });
    expect(opened).toHaveLength(0);
  });

  it("never logs record values on a failed witness", async () => {
    seed(1, 0);
    const logs = (["log", "info", "warn", "error"] as const)
      .map((method) => vi.spyOn(console, method).mockImplementation(() => {}));
    await expect(run()).rejects.toMatchObject({ code: "unverifiable_source" });
    for (const log of logs) expect(log).not.toHaveBeenCalled();
    expectClosed();
  });

  it("treats a directory path as store_unreadable", async () => {
    await expect(run({ dbPath: root })).rejects.toMatchObject({ code: "store_unreadable" });
    expect(opened).toHaveLength(0);
  });

  it.each(["EACCES", "EPERM", "SQLITE_CANTOPEN", "SQLITE_READONLY_DIRECTORY"])(
    "redacts opening/permission errors as store_unreadable: %s", async (code) => {
      seed();
      faults.open = code;
      const error = await run().catch((error: unknown) => error);
      expect(error).toMatchObject({ code: "store_unreadable" });
      expect(String(error)).not.toContain("PRIVATE_NATIVE");
      expect(opened).toHaveLength(0);
    },
  );

  it("maps readonly directory failures during registry reads and closes", async () => {
    seed();
    faults.read = "SQLITE_READONLY_DIRECTORY";
    const error = await run().catch((error: unknown) => error);
    expect(error).toMatchObject({ code: "store_unreadable" });
    expect(String(error)).not.toContain("PRIVATE_NATIVE");
    expectClosed();
  });

  it.each([0, 30_000])("verifies identities before the budget check (%s)", async (budgetMs) => {
    seed();
    await expect(run({ budgetMs })).rejects.toMatchObject({ code: "unverifiable_source" });
    await expect(run({ budgetMs, sourceKey: "missing" })).rejects.toMatchObject({ code: "missing_source" });
    expectClosed();
  });

  it.each([{ pageSize: 2, limit: undefined }, { pageSize: 2, limit: 0 }, { limit: 2 }])(
    "accepts pageSize and the legacy limit alias: %j", async (options) => {
      seed();
      await expect(run(options)).rejects.toMatchObject({ code: "unverifiable_source" });
      expectClosed();
    },
  );

  it.each(["deleted", "unregistered", "missing_registry"])(
    "fails closed for %s connection metadata", async (kind) => {
      seed();
      const db = new Database(dbPath);
      if (kind === "deleted") createSqliteRecordStore(db).deleteConnection(sourceKey);
      if (kind === "unregistered") db.prepare("UPDATE pdpp_instance_binding SET source_id = NULL WHERE instance = ?").run(sourceKey);
      if (kind === "missing_registry") db.exec("DROP TABLE pdpp_instance_binding");
      db.close();
      opened.length = 0;
      const before = readFileSync(dbPath);
      await expect(run()).rejects.toMatchObject({
        code: kind === "missing_registry" ? "unverifiable_source" : "missing_source",
      });
      expectClosed();
      expect(readFileSync(dbPath)).toEqual(before);
    },
  );

  it("does not change the database or existing WAL/SHM sidecars", async () => {
    seed(2);
    const keeper = new Database(dbPath);
    keeper.pragma("wal_checkpoint(TRUNCATE)");
    keeper.prepare("UPDATE pdpp_instance_binding SET label = 'sidecar-test' WHERE instance = ?").run(sourceKey);
    const paths = [dbPath, dbPath + "-wal", dbPath + "-shm"];
    for (const path of paths) expect(existsSync(path)).toBe(true);
    // Keep an existing read lock so opening the witness need not initialize
    // reader marks in the shared-memory sidecar.
    const reader = new Database(dbPath, { readonly: true });
    reader.exec("BEGIN");
    reader.prepare("SELECT * FROM pdpp_instance_binding").all();
    const before = paths.map((path) => readFileSync(path));
    opened.length = 0;
    try {
      await expect(run()).rejects.toMatchObject({ code: "unverifiable_source" });
      expectClosed();
      expect(paths.map((path) => readFileSync(path))).toEqual(before);
    } finally {
      reader.close();
      keeper.close();
    }
  });

  it("publishes the witness subpath alongside the other tsc-built entries", () => {
    const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8"));
    expect(pkg.exports["./witness"]).toEqual({
      types: "./dist/storage/declaration-witness.d.ts",
      import: "./dist/storage/declaration-witness.js",
    });
  });
});
