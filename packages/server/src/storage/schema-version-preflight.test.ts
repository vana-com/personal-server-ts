import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createServer } from "../bootstrap.js";
import { initializeDatabase } from "./index-schema.js";
import {
  createSqliteRecordStore,
  PDPP_RECORD_SCHEMA_VERSION,
} from "./pdpp-records-sqlite-store.js";
import {
  CONVERGED_INDEX_SCHEMA_VERSION,
  INDEX_SCHEMA_VERSION,
  LEGACY_GATE_INDEX_SCHEMA_VERSION,
} from "./schema-versions.js";

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});

/** A real current root (both counters current), then raw stamp edits. */
async function seedRoot(edit?: (db: Database.Database) => void) {
  const root = await mkdtemp(join(tmpdir(), "schema-preflight-"));
  roots.push(root);
  const dbPath = join(root, "index.db");
  const db = initializeDatabase(dbPath);
  createSqliteRecordStore(db);
  db.close();
  const raw = new Database(dbPath);
  edit?.(raw);
  raw.pragma("journal_mode = DELETE");
  raw.close();
  return { root, dbPath };
}

async function snapshot(root: string, dbPath: string) {
  const names = (await readdir(root))
    .filter((name) => name.startsWith("index.db"))
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
  try {
    return {
      names,
      files,
      journalMode: inspection.pragma("journal_mode", { simple: true }),
    };
  } finally {
    inspection.close();
  }
}

const gateRows = (db: Database.Database) =>
  Object.fromEntries(
    [
      "legacy_publication_policy",
      "legacy_publication_transitions",
      "legacy_publication_retained_versions",
      "legacy_publication_holds",
    ].map((table) => [
      table,
      db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all(),
    ]),
  );

describe("index.db compatibility stamps", () => {
  it("shares monotonic constants: converged 17 below gate 18", () => {
    expect(CONVERGED_INDEX_SCHEMA_VERSION).toBe(17);
    expect(LEGACY_GATE_INDEX_SCHEMA_VERSION).toBe(18);
    expect(INDEX_SCHEMA_VERSION).toBe(LEGACY_GATE_INDEX_SCHEMA_VERSION);
  });

  it.each([16, 17])(
    "keeps a never-enrolled v%i root at the converged stamp, gate tables present or not",
    async (version) => {
      const { dbPath } = await seedRoot((db) => {
        if (version === 17)
          db.exec(
            "DROP TRIGGER legacy_publication_insert_fence; DROP TABLE legacy_publication_policy; DROP TABLE legacy_publication_transitions",
          );
        db.pragma(`user_version = ${version}`);
      });
      for (let open = 0; open < 2; open++) {
        const db = initializeDatabase(dbPath);
        expect(db.pragma("user_version", { simple: true })).toBe(
          CONVERGED_INDEX_SCHEMA_VERSION,
        );
        expect(db.pragma("recursive_triggers", { simple: true })).toBe(0);
        db.close();
      }
    },
  );

  it.each(["stopped", "restoring", "mirroring", "quiescing"])(
    "moves an experimental gate v17 root with %s enrollment history to v18 and keeps every row",
    async (state) => {
      let before: ReturnType<typeof gateRows> | undefined;
      const { dbPath } = await seedRoot((db) => {
        db.prepare(
          "INSERT INTO legacy_publication_policy VALUES ('0xowner', 'gen', 'spotify.profile', ?, 4, 1, NULL)",
        ).run(state);
        db.prepare(
          "INSERT INTO legacy_publication_transitions VALUES ('0xowner', 'gen', 'spotify.profile', ?, 4, NULL)",
        ).run(state);
        db.prepare(
          "INSERT INTO legacy_publication_holds VALUES ('hold', 'spotify.profile', 'remote-head', '{}', x'00', 'now')",
        ).run();
        db.pragma(`user_version = ${CONVERGED_INDEX_SCHEMA_VERSION}`);
        before = gateRows(db);
      });
      const db = initializeDatabase(dbPath);
      expect(db.pragma("user_version", { simple: true })).toBe(
        LEGACY_GATE_INDEX_SCHEMA_VERSION,
      );
      expect(db.pragma("recursive_triggers", { simple: true })).toBe(1);
      expect(gateRows(db)).toEqual(before);
      db.close();
      const reopened = initializeDatabase(dbPath);
      expect(reopened.pragma("user_version", { simple: true })).toBe(
        LEGACY_GATE_INDEX_SCHEMA_VERSION,
      );
      expect(gateRows(reopened)).toEqual(before);
      reopened.close();
    },
  );

  it("detects enrollment from a transition row alone (policy row lost)", async () => {
    const { dbPath } = await seedRoot((db) => {
      db.prepare(
        "INSERT INTO legacy_publication_transitions VALUES ('0xowner', 'gen', 'spotify.profile', 'mirroring', 4, NULL)",
      ).run();
      db.pragma(`user_version = ${CONVERGED_INDEX_SCHEMA_VERSION}`);
    });
    const db = initializeDatabase(dbPath);
    expect(db.pragma("user_version", { simple: true })).toBe(
      LEGACY_GATE_INDEX_SCHEMA_VERSION,
    );
    db.close();
  });
});

const futures = [
  {
    label: `index.db ${INDEX_SCHEMA_VERSION + 1}`,
    edit: (db: Database.Database) =>
      db.pragma(`user_version = ${INDEX_SCHEMA_VERSION + 1}`),
    error: `Unsupported index.db schema version ${INDEX_SCHEMA_VERSION + 1}; runtime supports ${INDEX_SCHEMA_VERSION}`,
  },
  {
    label: `PDPP ${PDPP_RECORD_SCHEMA_VERSION + 1}`,
    edit: (db: Database.Database) =>
      db
        .prepare("UPDATE pdpp_schema_version SET version = ? WHERE id = 1")
        .run(PDPP_RECORD_SCHEMA_VERSION + 1),
    error: `Unsupported index.db PDPP schema version ${PDPP_RECORD_SCHEMA_VERSION + 1}; runtime supports ${PDPP_RECORD_SCHEMA_VERSION}`,
  },
];

describe("unknown future schema preflight", () => {
  it.each(futures)(
    "index opener refuses $label without changing index.db or sidecars",
    async ({ edit, error }) => {
      const { root, dbPath } = await seedRoot(edit);
      const before = await snapshot(root, dbPath);
      // copy-assertion-ok: refusal must identify unsupported and supported versions.
      expect(() => initializeDatabase(dbPath)).toThrow(error);
      expect(await snapshot(root, dbPath)).toEqual(before);
    },
  );

  it.each(futures)(
    "record store refuses $label without changing index.db or sidecars",
    async ({ edit, error }) => {
      const { root, dbPath } = await seedRoot(edit);
      const before = await snapshot(root, dbPath);
      const db = new Database(dbPath);
      try {
        // copy-assertion-ok: refusal must identify unsupported and supported versions.
        expect(() => createSqliteRecordStore(db)).toThrow(error);
      } finally {
        db.close();
      }
      expect(await snapshot(root, dbPath)).toEqual(before);
    },
  );

  it.each(futures)(
    "server startup refuses $label before touching index.db or sidecars",
    async ({ edit, error }) => {
      const { root, dbPath } = await seedRoot(edit);
      const before = await snapshot(root, dbPath);
      // copy-assertion-ok: startup must expose the same actionable refusal.
      await expect(
        createServer(
          ServerConfigSchema.parse({
            tunnel: { enabled: false },
            payment: { enabled: false },
            pdpp: { enabled: false },
          }),
          { rootPath: root },
        ),
      ).rejects.toThrow(error);
      expect(await snapshot(root, dbPath)).toEqual(before);
    },
  );
});
