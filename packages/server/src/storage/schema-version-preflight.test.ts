import { createHash } from "node:crypto";
import { readdir, mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createServer, type ServerContext } from "../bootstrap.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

const counters = [
  {
    label: "legacy 18",
    legacy: 18,
    pdpp: 14,
    error: "Unsupported index.db schema version 18; runtime supports 17",
  },
  {
    label: "PDPP 17",
    legacy: 17,
    pdpp: 17,
    error: "Unsupported index.db PDPP schema version 17; runtime supports 16",
  },
];

async function seedDatabase(root: string, legacy: number, pdpp: number) {
  const dbPath = join(root, "index.db");
  const db = new Database(dbPath);
  // Real Desktop v15/v14 schema and rows: an unguarded legacy18 open
  // could otherwise migrate successfully and run startup collection.
  db.exec(
    await readFile(
      new URL("./__fixtures__/desktop-d-index.sql", import.meta.url),
      "utf8",
    ),
  );
  db.exec(
    "CREATE TABLE IF NOT EXISTS preflight_sentinel (value TEXT NOT NULL); DELETE FROM preflight_sentinel; INSERT INTO preflight_sentinel VALUES ('preserve-me')",
  );
  db.exec(
    "CREATE TABLE IF NOT EXISTS pdpp_schema_version (id INTEGER PRIMARY KEY, version INTEGER NOT NULL)",
  );
  db.prepare(
    "INSERT INTO pdpp_schema_version (id, version) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET version = excluded.version",
  ).run(pdpp);
  db.pragma(`user_version = ${legacy}`);
  db.pragma("journal_mode = DELETE");
  db.close();
  return dbPath;
}

async function snapshot(root: string, dbPath: string) {
  const names = (await readdir(root))
    .filter((name) => name === "index.db" || name.startsWith("index.db-"))
    .sort();
  const files = Object.fromEntries(
    await Promise.all(
      names.map(async (name) => [
        name,
        createHash("sha256")
          .update(await readFile(join(root, name)))
          .digest("hex"),
      ]),
    ),
  );
  const inspection = new Database(dbPath, { readonly: true });
  let journalMode: unknown;
  try {
    journalMode = inspection.pragma("journal_mode", { simple: true });
  } finally {
    inspection.close();
  }
  return { names, files, journalMode };
}

const startupConfig = ServerConfigSchema.parse({
  tunnel: { enabled: false },
  payment: { enabled: false },
  pdpp: { enabled: false },
});

describe("schema version preflight", () => {
  it.each(counters)(
    "direct store rejects $label without changing index.db or sidecars",
    async ({ legacy, pdpp, error }) => {
      const root = await mkdtemp(join(tmpdir(), "schema-preflight-direct-"));
      let db: Database.Database | undefined;
      try {
        const dbPath = await seedDatabase(root, legacy, pdpp);
        const before = await snapshot(root, dbPath);
        db = new Database(dbPath);
        // copy-assertion-ok: refusal must identify unsupported and supported versions.
        expect(() => createSqliteRecordStore(db!)).toThrow(error);
        db.close();
        db = undefined;
        expect(await snapshot(root, dbPath)).toEqual(before);
      } finally {
        if (db?.open) db.close();
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  it.each(counters)(
    "server startup rejects $label before touching index.db or sidecars",
    async ({ legacy, pdpp, error }) => {
      const root = await mkdtemp(join(tmpdir(), "schema-preflight-startup-"));
      let context: ServerContext | undefined;
      try {
        const dbPath = await seedDatabase(root, legacy, pdpp);
        const before = await snapshot(root, dbPath);
        // copy-assertion-ok: startup must expose the same actionable schema refusal.
        await expect(async () => {
          context = await createServer(startupConfig, { rootPath: root });
          await context.cleanup();
          context = undefined;
        }).rejects.toThrow(error);
        await context?.cleanup();
        context = undefined;
        expect(await snapshot(root, dbPath)).toEqual(before);
      } finally {
        await context?.cleanup();
        await rm(root, { recursive: true, force: true });
      }
    },
  );
});
