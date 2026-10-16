import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import {
  runDeclarationWitness,
  OfflineDeclarationWitnessError,
} from "./declaration-witness.js";

const opened = vi.hoisted(() => [] as Array<InstanceType<typeof Database>>);
vi.mock("better-sqlite3", async (importOriginal) => {
  const { default: Actual } = await importOriginal<typeof import("better-sqlite3")>();
  return {
    default: function TrackedDatabase(...args: ConstructorParameters<typeof Actual>) {
      const db = new Actual(...args);
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
  let root: string;
  let dbPath: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "pdpp-offline-witness-"));
    dbPath = join(root, "records.sqlite");
    opened.length = 0;
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

  function expectClosed(): void {
    expect(opened.length).toBeGreaterThan(0);
    for (const db of opened) {
      expect(db.readonly).toBe(true);
      expect(db.open).toBe(false);
    }
  }

  it("passes across many pages with one port, one connection and no writes", async () => {
    seed(103);
    const before = readFileSync(dbPath);
    await expect(run()).resolves.toEqual({ verdict: "pass", checked: 103 });
    expect(opened).toHaveLength(1);
    expectClosed();
    expect(readFileSync(dbPath)).toEqual(before);
  });

  it("stops on a later-page failure without returning keys, values or cursors", async () => {
    seed(30, 11);
    const result = await run();
    expect(result).toEqual({
      verdict: "fail",
      checked: 12,
      failure: {
        recordKeyDigest: createHash("sha256").update("private-key-0011").digest("hex"),
        instancePath: "/count",
        keyword: "type",
      },
    });
    expect(JSON.stringify(result)).not.toMatch(/PRIVATE_VALUE|private-key|nextCursor/);
    expectClosed();
  });

  it("passes an empty stream in an existing valid database", async () => {
    seed();
    await expect(run()).resolves.toEqual({ verdict: "pass", checked: 0 });
    expectClosed();
  });

  it("returns partial without reading records when the budget is already exhausted", async () => {
    seed(10);
    await expect(run({ budgetMs: 0 })).resolves.toEqual({ verdict: "partial", checked: 0 });
    expectClosed();
  });

  it("returns partial with the accumulated count when the budget expires between pages", async () => {
    seed(10);
    let calls = 0;
    vi.spyOn(performance, "now").mockImplementation(() => ++calls <= 2 ? 0 : 10);
    await expect(run({ budgetMs: 5 })).resolves.toEqual({ verdict: "partial", checked: 3 });
    expectClosed();
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

  it("closes the database after schema compilation fails and redacts the error", async () => {
    seed(1);
    const error = await run({ nextSchema: { type: "PRIVATE_SCHEMA" } }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(OfflineDeclarationWitnessError);
    expect(error).toMatchObject({ code: "invalid_schema" });
    expect(String(error)).not.toContain("PRIVATE_SCHEMA");
    expectClosed();
  });

  it("closes after a record decoding error without exposing its contents", async () => {
    seed(1);
    const db = new Database(dbPath);
    db.prepare("UPDATE pdpp_records SET data = ? WHERE instance = ?")
      .run('{"PRIVATE_VALUE":', sourceKey);
    db.close();
    opened.length = 0;
    const error = await run().catch((e: unknown) => e);
    expect(error).toMatchObject({ code: "read_failed" });
    expect(String(error)).not.toContain("PRIVATE_VALUE");
    expectClosed();
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
    { limit: 0 }, { limit: -1 }, { limit: 1.5 }, { limit: Infinity },
    { budgetMs: -1 }, { budgetMs: NaN }, { budgetMs: Infinity },
    { dbPath: "" }, { sourceKey: "" }, { stream: "" },
  ])("rejects invalid options without opening storage: %j", async (options) => {
    await expect(run(options)).rejects.toMatchObject({ code: "invalid_argument" });
    expect(opened).toHaveLength(0);
  });


  it("does not report pass after a terminal page exceeds the budget", async () => {
    seed(1);
    let calls = 0;
    vi.spyOn(performance, "now").mockImplementation(() => ++calls <= 2 ? 0 : 10);
    await expect(run({ budgetMs: 5 })).resolves.toEqual({ verdict: "partial", checked: 1 });
    expectClosed();
  });

  it("caps very large requested pages so limit plus lookahead cannot overflow", async () => {
    seed(1_003);
    let calls = 0;
    vi.spyOn(performance, "now").mockImplementation(() => ++calls <= 2 ? 0 : 10);
    await expect(run({ limit: Number.MAX_SAFE_INTEGER, budgetMs: 5 }))
      .resolves.toEqual({ verdict: "partial", checked: 1_000 });
    expectClosed();
  });

  it("retains the initial schema when the caller mutates it between pages", async () => {
    seed(8);
    const schema = structuredClone(nextSchema);
    const pending = run({ nextSchema: schema });
    schema.properties.count.type = "string";
    await expect(pending).resolves.toEqual({ verdict: "pass", checked: 8 });
    expectClosed();
  });

  it("never logs record values on a failed witness", async () => {
    seed(1, 0);
    const logs = (["log", "info", "warn", "error"] as const)
      .map((method) => vi.spyOn(console, method).mockImplementation(() => {}));
    await expect(run()).resolves.toMatchObject({ verdict: "fail" });
    for (const log of logs) expect(log).not.toHaveBeenCalled();
    expectClosed();
  });

  it("treats a directory path as a typed open failure", async () => {
    await expect(run({ dbPath: root })).rejects.toMatchObject({ code: "open_failed" });
    expect(opened).toHaveLength(0);
  });

  it("publishes the witness subpath alongside the other tsc-built entries", () => {
    const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8"));
    expect(pkg.exports["./witness"]).toEqual({
      types: "./dist/storage/declaration-witness.d.ts",
      import: "./dist/storage/declaration-witness.js",
    });
  });
});
