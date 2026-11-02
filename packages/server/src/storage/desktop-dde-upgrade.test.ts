import { createHash } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createLegacyScopeView } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { initializeDatabase } from "./index-schema.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createStravaMethodTransition } from "./strava-method-transition.js";

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

type Store = ReturnType<typeof createSqliteRecordStore>;

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

function activity(id: string, freshness: string) {
  return { id, activity_type: id === "b" ? "Run" : "Ride", freshness };
}

function browserRun(store: Store, ids: string[]) {
  const emittedAt = "2026-10-22T00:00:00.000Z";
  return store.replaceStream({
    instance: fixture.instance,
    stream: "activities",
    method: "strava-browser",
    generation: fixture.generation,
    primaryKey: ["id"],
    emittedAt,
    sourceCollectedAt: emittedAt,
    envelopes: ids.map((id) => ({
      instance: fixture.instance,
      stream: "activities",
      key: id,
      data: activity(id, "live"),
      emitted_at: emittedAt,
    })),
  });
}

describe("Desktop DDE index.db upgrade", () => {
  let dir: string;
  let db: Database.Database | undefined;

  afterEach(() => {
    if (db?.open) db.close();
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it("preserves the DDE Strava transition through schema convergence, browser takeover, and reopen", async () => {
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
    const assertArchivedPayload = (activitiesCovered = false) => {
      expect(store.stravaTransition(fixture.instance)).toMatchObject({
        instance: fixture.instance,
        archiveInstance: archive,
        generation: fixture.generation,
        activitiesCovered,
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

    const files = {
      findEntry: () => undefined,
      readEnvelope: async () => {
        throw new Error("DDE fixture snapshots are canonical");
      },
    } as never;
    const createTransition = () =>
      createStravaMethodTransition(
        store,
        createLegacyScopeView({
          authority: createLegacyScopeAuthority(db!),
          records: store,
          configuredMethods: () => ["strava-browser"],
        }),
        files,
      );
    const pending = createTransition();
    expect(await pending.status(fixture.instance)).toBe("pending");
    expect(await pending.view.readLatest("strava.activities")).toMatchObject({
      kind: "canonical",
      envelope: fixture.snapshots["strava.activities"],
    });
    expect(
      await pending.view.readLatest("strava.coverage_diagnostics"),
    ).toMatchObject({
      kind: "canonical",
      envelope: fixture.snapshots["strava.coverage_diagnostics"],
    });

    const run = browserRun(store, ["a", "b", "new"]);
    expect(run.applied).toBe(true);
    expect(await pending.status(fixture.instance)).toBe("covered");
    expect(await pending.view.readLatest("strava.activities")).toMatchObject({
      kind: "canonical",
      envelope: {
        data: {
          activities: [
            activity("a", "live"),
            activity("b", "live"),
            activity("new", "live"),
          ],
        },
      },
    });
    expect(
      await pending.view.readLatest("strava.coverage_diagnostics"),
    ).toMatchObject({
      kind: "canonical",
      envelope: fixture.snapshots["strava.coverage_diagnostics"],
    });
    expect(store.stravaTransition(fixture.instance)?.activitiesCovered).toBe(
      true,
    );
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
    assertArchivedPayload(true);
    const reopened = createTransition();
    expect(await reopened.status(fixture.instance)).toBe("covered");
    expect(
      await reopened.view.readLatest("strava.coverage_diagnostics"),
    ).toMatchObject({
      kind: "canonical",
      envelope: fixture.snapshots["strava.coverage_diagnostics"],
    });
    expect(db.pragma("integrity_check", { simple: true })).toBe("ok");

    store.clearStravaTransitionScope("strava.activities");
    store.close();
    db = initializeDatabase(path);
    store = createSqliteRecordStore(db);
    expect(store.getBlobMeta(fixture.blobId)).toBeUndefined();
    expect(store.getBlobBytes(fixture.blobId)).toBeUndefined();
    expect(db.prepare("SELECT * FROM pdpp_blob_claims").all()).toEqual([]);
    const reset = store.stravaTransition(fixture.instance);
    expect(reset).not.toBeNull();
    expect(reset!.snapshots["strava.activities"]).toBeUndefined();
    expect(reset!.snapshots["strava.coverage_diagnostics"]).toEqual(
      fixture.snapshots["strava.coverage_diagnostics"],
    );
    store.close();
  });

  it("keeps archive claims while unreadable retained history may reference them", () => {
    dir = mkdtempSync(join(tmpdir(), "ps-desktop-dde-reset-"));
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
    expect(() =>
      store.clearStravaTransitionScope("strava.activities"),
    ).not.toThrow();
    expect(store.getBlobBytes(fixture.blobId)).toBeDefined();
    expect(store.getBlobBytes(ambiguous.blobId)).toBeDefined();
    expect(db.prepare("SELECT * FROM pdpp_blob_claims").all()).toHaveLength(1);

    store.clearStravaTransitionScope("strava.coverage_diagnostics");
    expect(store.getBlobMeta(fixture.blobId)).toBeUndefined();
    expect(store.getBlobBytes(fixture.blobId)).toBeUndefined();
    expect(store.getBlobBytes(ambiguous.blobId)).toBeUndefined();
    expect(store.stravaTransition(fixture.instance)).not.toBeNull();
    store.close();
  });
});
