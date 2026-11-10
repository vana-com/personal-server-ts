import { createHash } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { initializeDatabase } from "./index-schema.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

const sql = readFileSync(
  new URL(
    "./__fixtures__/desktop-dde-upgrade/desktop-dde-index.sql",
    import.meta.url,
  ),
  "utf8",
);
const fixture = JSON.parse(
  readFileSync(
    new URL(
      "./__fixtures__/desktop-dde-upgrade/desktop-dde-index.json",
      import.meta.url,
    ),
    "utf8",
  ),
) as {
  provenance: { sqlSha256: string };
  instance: string;
  sourceId: string;
  method: string;
  generation: number;
  archiveInstance: string;
  collectedAt: string;
  blobId: string;
  blobSha256: string;
  archiveBytesSha256: string;
  snapshots: {
    "strava.activities": DataFileEnvelope;
    "strava.coverage_diagnostics": DataFileEnvelope;
  };
};

function normalizeSqlValue(value: unknown): unknown {
  if (value instanceof Uint8Array) return Array.from(value);
  if (Array.isArray(value)) return value.map(normalizeSqlValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => [
        key,
        normalizeSqlValue(nested),
      ]),
    );
  }
  return value;
}

function storedRows(db: Database.Database) {
  const tables = db
    .prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )
    .all() as { name: string }[];
  const names = [
    ...tables.map(({ name }) => name),
    ...(db
      .prepare(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'sqlite_sequence'",
      )
      .get()
      ? ["sqlite_sequence"]
      : []),
  ];
  return Object.fromEntries(
    names.map((name) => [
      name,
      normalizeSqlValue(
        db.prepare(`SELECT * FROM "${name}" ORDER BY rowid`).all(),
      ),
    ]),
  );
}

function expectedUpgradedRows(original: ReturnType<typeof storedRows>) {
  const expected = structuredClone(original) as ReturnType<typeof storedRows>;
  (
    expected.pdpp_schema_version as { id: number; version: number }[]
  )[0]!.version = 16;
  return expected;
}

describe("Desktop DDE index.db upgrade", () => {
  let dir: string;
  let db: Database.Database | undefined;

  afterEach(() => {
    if (db?.open) db.close();
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it("preserves historical archives and blob custody through schema convergence and reopen", async () => {
    expect(createHash("sha256").update(sql).digest("hex")).toBe(
      fixture.provenance.sqlSha256,
    );
    dir = mkdtempSync(join(tmpdir(), "ps-desktop-dde-upgrade-"));
    const path = join(dir, "index.db");
    db = new Database(path);
    db.exec(sql);

    expect(db.pragma("user_version", { simple: true })).toBe(15);
    expect(db.prepare("SELECT version FROM pdpp_schema_version").get()).toEqual(
      {
        version: 15,
      },
    );
    expect(
      db
        .prepare(
          "SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?",
        )
        .get("idx_pdpp_record_changes_blob_ref"),
    ).toBeUndefined();
    const original = storedRows(db);
    expect(original.pdpp_strava_transition).toHaveLength(1);
    expect(original.pdpp_record_changes).toHaveLength(4);
    expect(original.pdpp_records).toHaveLength(3);
    expect(original.pdpp_blob_claims).toHaveLength(1);
    expect(original.sqlite_sequence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "data_files" }),
        expect.objectContaining({ name: "pdpp_record_changes" }),
      ]),
    );
    db.close();

    db = initializeDatabase(path);
    let store = createSqliteRecordStore(db);
    expect(db.pragma("user_version", { simple: true })).toBe(17);
    expect(db.prepare("SELECT version FROM pdpp_schema_version").get()).toEqual(
      {
        version: 16,
      },
    );
    expect(
      db
        .prepare(
          "SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?",
        )
        .get("idx_pdpp_record_changes_blob_ref"),
    ).toBeDefined();
    expect(storedRows(db)).toEqual(expectedUpgradedRows(original));

    const archive = fixture.archiveInstance;
    const assertArchivedPayload = () => {
      const historical = db!
        .prepare("SELECT * FROM pdpp_strava_transition WHERE instance=?")
        .get(fixture.instance) as {
        instance: string;
        archive_instance: string;
        generation: number;
        activities_covered: number;
        snapshots_json: string;
      };
      expect({
        instance: historical.instance,
        archiveInstance: historical.archive_instance,
        generation: historical.generation,
        activitiesCovered: historical.activities_covered === 1,
        snapshots: JSON.parse(historical.snapshots_json),
      }).toEqual({
        instance: fixture.instance,
        archiveInstance: archive,
        generation: fixture.generation,
        activitiesCovered: false,
        snapshots: fixture.snapshots,
      });
      expect(store.getInstanceBinding(fixture.instance)).toMatchObject({
        sourceId: fixture.sourceId,
        method: "strava-browser",
        generation: fixture.generation,
      });
      expect(
        db!
          .prepare(
            "SELECT instance, stream FROM pdpp_records WHERE instance = ? ORDER BY stream, record_key",
          )
          .all(archive),
      ).toEqual(
        expect.arrayContaining([
          { instance: archive, stream: "activities" },
          { instance: archive, stream: "coverage_diagnostics" },
        ]),
      );
      expect(
        db!
          .prepare(
            "SELECT COUNT(*) AS count FROM pdpp_record_changes WHERE instance = ?",
          )
          .get(archive),
      ).toEqual({ count: 4 });
      expect(
        db!
          .prepare(
            "SELECT instance, generation FROM pdpp_blob_claims WHERE blob_id = ?",
          )
          .get(fixture.blobId),
      ).toEqual({ instance: archive, generation: 1 });
      expect(store.getBlobMeta(fixture.blobId)?.sha256).toBe(
        fixture.blobSha256,
      );
      const bytes = Buffer.from(store.getBlobBytes(fixture.blobId)!);
      expect(createHash("sha256").update(bytes).digest("hex")).toBe(
        fixture.archiveBytesSha256,
      );
    };
    assertArchivedPayload();

    expect(() =>
      store.replaceStream({
        instance: fixture.instance,
        stream: "activities",
        method: "strava",
        generation: 1,
        primaryKey: ["id"],
        emittedAt: fixture.collectedAt,
        envelopes: [],
      }),
    ).toThrow("binding_generation_mismatch");

    const beforeReopen = storedRows(db);
    store.close();
    db = initializeDatabase(path);
    store = createSqliteRecordStore(db);
    expect(storedRows(db)).toEqual(beforeReopen);
    assertArchivedPayload();
    expect(db.pragma("integrity_check", { simple: true })).toBe("ok");

    store.deleteConnection(fixture.instance);
    store.close();
    db = initializeDatabase(path);
    store = createSqliteRecordStore(db);
    expect(store.getBlobMeta(fixture.blobId)).toBeUndefined();
    expect(store.getBlobBytes(fixture.blobId)).toBeUndefined();
    expect(db.prepare("SELECT * FROM pdpp_blob_claims").all()).toEqual([]);
    expect(db.prepare("SELECT * FROM pdpp_strava_transition").all()).toEqual(
      [],
    );
    expect(
      db
        .prepare("SELECT * FROM pdpp_records WHERE instance=?")
        .all(fixture.archiveInstance),
    ).toEqual([]);
    store.close();
  });

  it("keeps archive claims while unreadable retained history may reference them", () => {
    dir = mkdtempSync(join(tmpdir(), "ps-desktop-dde-history-"));
    const path = join(dir, "index.db");
    db = new Database(path);
    db.exec(sql);
    db.prepare(
      "UPDATE pdpp_record_changes SET data = ? WHERE stream = 'coverage_diagnostics'",
    ).run("{unreadable");
    db.close();

    db = initializeDatabase(path);
    const store = createSqliteRecordStore(db);
    const ambiguous = store.storeBlobBytes(
      Buffer.from("bytes possibly referenced by unreadable history"),
      "application/octet-stream",
    );
    store.close();
    db = initializeDatabase(path);
    const reopened = createSqliteRecordStore(db);
    expect(reopened.getBlobBytes(fixture.blobId)).toBeDefined();
    expect(reopened.getBlobBytes(ambiguous.blobId)).toBeDefined();
    expect(db.prepare("SELECT * FROM pdpp_blob_claims").all()).toHaveLength(1);

    reopened.deleteConnection(fixture.instance);
    expect(reopened.getBlobMeta(fixture.blobId)).toBeUndefined();
    expect(reopened.getBlobBytes(fixture.blobId)).toBeUndefined();
    expect(reopened.getBlobBytes(ambiguous.blobId)).toBeUndefined();
    expect(db.prepare("SELECT * FROM pdpp_strava_transition").all()).toEqual(
      [],
    );
    reopened.close();
  });
});
