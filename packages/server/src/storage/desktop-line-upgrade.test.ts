import { afterEach, describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LegacyScopeHead } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import type {
  ListRecordsPage,
  PdppBlobMeta,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { initializeDatabase } from "./index-schema.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

// Captured with D's actual index initializer, record store and takeover
// authority, not by removing columns from the current schema. The SQL is
// self-contained so the regression does not require Git history at test time.
const sql = readFileSync(
  new URL("./__fixtures__/desktop-d-index.sql", import.meta.url),
  "utf8",
);
const fixture = JSON.parse(
  readFileSync(
    new URL("./__fixtures__/desktop-d-index.json", import.meta.url),
    "utf8",
  ),
) as {
  instance: string;
  method: string;
  generation: number;
  head: LegacyScopeHead;
  cursor: string;
  listingCursor: string;
  listingNext: ListRecordsPage;
  changesSince: string;
  historicalBlob: PdppBlobMeta;
  liveBlob: PdppBlobMeta;
};

function storedRows(db: Database.Database) {
  const tables = db
    .prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != 'pdpp_schema_version' ORDER BY name",
    )
    .all() as { name: string }[];
  return Object.fromEntries(
    tables.map(({ name }) => [
      name,
      db.prepare(`SELECT * FROM "${name}" ORDER BY rowid`).all(),
    ]),
  );
}

describe("Desktop D index.db upgrade", () => {
  let dir: string;
  let db: Database.Database | undefined;
  afterEach(() => {
    if (db?.open) db.close();
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it("preserves Desktop data, Oura replacement proofs, receipts and cursors through upgrade, writes and reopen", () => {
    dir = mkdtempSync(join(tmpdir(), "ps-desktop-upgrade-"));
    const path = join(dir, "index.db");
    db = new Database(path);
    db.exec(sql);
    expect(db.pragma("user_version", { simple: true })).toBe(15);
    expect(db.prepare("SELECT version FROM pdpp_schema_version").get()).toEqual(
      {
        version: 14,
      },
    );
    expect(
      db
        .prepare("SELECT name FROM sqlite_master WHERE name = ?")
        .get("idx_pdpp_record_changes_blob_ref"),
    ).toBeUndefined();
    const original = storedRows(db);
    const receipts = db.prepare("SELECT * FROM pdpp_stream_completion").all();
    expect(receipts).toHaveLength(3);
    db.close();

    db = initializeDatabase(path);
    let store = createSqliteRecordStore(db);
    expect(db.pragma("user_version", { simple: true })).toBe(17);
    expect(db.prepare("SELECT version FROM pdpp_schema_version").get()).toEqual(
      {
        version: 15,
      },
    );
    expect(
      db
        .prepare("SELECT name FROM sqlite_master WHERE name = ?")
        .get("idx_pdpp_record_changes_blob_ref"),
    ).toBeDefined();
    // Compare application rows, including the populated history, blobs,
    // bindings, generation/reset clocks, epoch and takeover ledgers.
    expect(storedRows(db)).toEqual(original);

    const assertDesktopState = () => {
      const authority = createLegacyScopeAuthority(db!);
      expect(authority.eligibleLegacyHead("oura.sleep")).toEqual(fixture.head);
      expect(
        authority.hasCompletedReplacement!(
          "oura.sleep",
          fixture.head,
          fixture.instance,
          fixture.generation,
          fixture.method,
          fixture.cursor,
        ),
      ).toBe(true);
      expect(store.getInstanceBinding(fixture.instance)).toMatchObject({
        generation: 2,
        method: "oura-browser",
        sourceId: "https://registry.pdpp.dev/sources/oura",
      });
      expect(
        store.listRecords("sleep", {
          instanceIds: [fixture.instance],
          limit: 1,
          order: "asc",
          cursor: fixture.listingCursor,
        }),
      ).toEqual(fixture.listingNext);
      expect(store.getBlobMeta(fixture.historicalBlob.blobId)).toEqual(
        fixture.historicalBlob,
      );
      expect(
        Buffer.from(store.getBlobBytes(fixture.historicalBlob.blobId)!),
      ).toEqual(Buffer.from("retained Desktop history bytes"));
      expect(Buffer.from(store.getBlobBytes(fixture.liveBlob.blobId)!)).toEqual(
        Buffer.from("live Desktop blob bytes"),
      );
    };
    assertDesktopState();
    expect(
      store.changesSince("sleep", {
        instanceIds: [fixture.instance],
        limit: 100,
        changesSince: fixture.changesSince,
      }).data,
    ).toEqual([]);
    // Opening a sync session reserves a write-clock horizon. Capture the
    // resulting state so reopening must preserve that reservation too.
    const beforeReopen = storedRows(db);
    store.close();

    // A second startup must preserve the same data and completion fences.
    db = initializeDatabase(path);
    store = createSqliteRecordStore(db);
    expect(storedRows(db)).toEqual(beforeReopen);
    assertDesktopState();
    const write = store.ingestBatch(
      [
        {
          instance: fixture.instance,
          stream: "sleep",
          key: "after-upgrade",
          data: { id: "after-upgrade", day: "2026-10-22", score: 90 },
          emitted_at: "2026-10-22T12:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: fixture.method, generation: fixture.generation },
    );
    expect(write.accepted).toBe(1);
    store.close();

    db = initializeDatabase(path);
    store = createSqliteRecordStore(db);
    assertDesktopState();
    expect(
      store.getRecord(fixture.instance, "sleep", "after-upgrade")?.data,
    ).toEqual({
      id: "after-upgrade",
      day: "2026-10-22",
      score: 90,
    });
    expect(
      store
        .changesSince("sleep", {
          instanceIds: [fixture.instance],
          limit: 100,
          changesSince: fixture.changesSince,
        })
        .data.map((row) => row.recordKey),
    ).toEqual(["after-upgrade"]);
    expect(db.pragma("integrity_check", { simple: true })).toBe("ok");
    store.close();
  });
});
