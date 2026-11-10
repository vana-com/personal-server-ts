import type Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { initializeDatabase } from "./index-schema.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import {
  createScopeDeletionHistory,
  migrateScopeDeletionHistory,
} from "./scope-deletion-history.js";

const OWNER = "0x1111111111111111111111111111111111111111";
const SOURCE = "https://registry.pdpp.dev/sources/oura";
describe("startup scope deletion migration", () => {
  let db: Database.Database;
  let store: ReturnType<typeof createSqliteRecordStore>;
  const logger = { info: vi.fn(), error: vi.fn() };
  function write(stream: string, key: string, emittedAt: string) {
    store.replaceStream({
      instance: "connection",
      stream,
      method: "oura",
      generation: 1,
      primaryKey: ["id"],
      emittedAt,
      sourceCollectedAt: emittedAt,
      envelopes: [
        {
          instance: "connection",
          stream,
          key,
          data: { id: key },
          emitted_at: emittedAt,
        },
      ],
    });
  }
  function unmarked(scope: string) {
    db.prepare(
      "INSERT INTO vana_scope_deletion_history (owner_address, scope, deleted_at, tombstone_version) VALUES (?, ?, ?, ?)",
    ).run(OWNER, scope, "2026-09-11T00:00:00Z", "1");
  }
  beforeEach(() => {
    db = initializeDatabase(":memory:");
    store = createSqliteRecordStore(db);
    createScopeDeletionHistory(db, OWNER, store);
    store.registerConnection({
      instance: "connection",
      sourceId: SOURCE,
      method: "oura",
      label: "",
    });
    write("activity", "newer-client-time", "2099-01-01T00:00:00Z");
    const historical = ["2026-09-10T23:59:00Z", "2026-09-11T00:00:01Z"];
    const added = store.ingestBatch(
      historical.map((emitted_at, index) => ({
        instance: "connection",
        stream: "activity",
        key: `historical-${index}`,
        data: { id: `historical-${index}` },
        emitted_at,
      })),
      () => "mutable_state",
      () => ["id"],
      { method: "oura", generation: 1 },
    );
    expect(added.rejected).toEqual([]);
    write("readiness", "sibling", "2026-09-01T00:00:00Z");
    unmarked("oura.activity");
    vi.clearAllMocks();
  });
  afterEach(() => store.close());
  it("skips and counts unmarked entries when replication is enabled", () => {
    migrateScopeDeletionHistory(db, OWNER, store, logger, {
      dryRun: true,
      replicationEnabled: true,
    });
    migrateScopeDeletionHistory(db, OWNER, store, logger, {
      replicationEnabled: true,
    });
    expect(
      store.getRecord("connection", "activity", "newer-client-time"),
    ).toBeDefined();
    expect(
      createScopeDeletionHistory(db, OWNER).get("oura.activity")?.eraseApplied,
    ).not.toBe(true);
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({
        skipped: "replication",
        count: 1,
        dryRun: true,
      }),
      expect.any(String),
    );
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({
        scope: "oura.activity",
        skipped: "replication",
      }),
      expect.any(String),
    );
  });
  it("erases all exclusive rows regardless of supplied time and preserves sibling rows", () => {
    migrateScopeDeletionHistory(db, OWNER, store, logger);
    expect(
      store.getRecord("connection", "activity", "newer-client-time"),
    ).toBeUndefined();
    expect(
      store.getRecord("connection", "activity", "historical-0"),
    ).toBeUndefined();
    expect(
      store.getRecord("connection", "activity", "historical-1"),
    ).toBeUndefined();
    expect(store.getRecord("connection", "readiness", "sibling")).toBeDefined();
    expect(store.getInstanceBinding("connection").generation).toBe(2);
    expect(
      createScopeDeletionHistory(db, OWNER).get("oura.activity")?.eraseApplied,
    ).toBe(true);
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({ scope: "oura.activity", rule: "erase_all" }),
      "Scope deletion migration",
    );
  });
  it("keeps history unmarked if exclusive rows lack a method binding", () => {
    db.prepare(
      "INSERT INTO pdpp_records (instance, stream, record_key, data, version, emitted_at, deleted) VALUES (?, ?, ?, ?, ?, ?, 0)",
    ).run(
      "orphan",
      "activity",
      "orphan",
      '{"id":"orphan"}',
      1,
      "2026-09-10T00:00:00Z",
    );
    migrateScopeDeletionHistory(db, OWNER, store, logger);
    expect(
      createScopeDeletionHistory(db, OWNER).get("oura.activity")?.eraseApplied,
    ).not.toBe(true);
    expect(
      store.getRecord("connection", "activity", "newer-client-time"),
    ).toBeDefined();
    expect(logger.error).toHaveBeenCalledWith(
      expect.objectContaining({
        scope: "oura.activity",
        instance: "orphan",
        stream: "activity",
        error: "Cannot establish the owner of a stream",
      }),
      "Scope deletion migration failed; deletion remains hidden",
    );
  });

  it("keeps a shared archived stream while removing a migrated scope", () => {
    store.registerConnection({
      instance: "claude",
      sourceId: "https://registry.pdpp.dev/sources/claude",
      method: "anthropic",
      label: "",
    });
    for (const stream of ["account_profile", "conversations"]) {
      store.replaceStream({
        instance: "claude",
        stream,
        method: "anthropic",
        generation: 1,
        primaryKey: ["id"],
        emittedAt: "2026-09-10T00:00:00Z",
        sourceCollectedAt: "2026-09-10T00:00:00Z",
        envelopes: [
          {
            instance: "claude",
            stream,
            key: stream,
            data: { id: stream },
            emitted_at: "2026-09-10T00:00:00Z",
          },
        ],
      });
    }
    store.transitionClaudeToLive({
      instance: "claude",
      expectedGeneration: 1,
      expectedWriteClock: store.transitionWriteClock(),
      snapshots: {
        "claude.conversations": {
          version: "1.0",
          scope: "claude.conversations",
          collectedAt: "2026-09-10T00:00:00Z",
          data: {},
        },
      },
    });
    const archive = store.claudeTransition("claude")!.archiveInstance;
    unmarked("claude.conversations");
    migrateScopeDeletionHistory(db, OWNER, store, logger);
    expect(
      store.getRecord(archive, "account_profile", "account_profile"),
    ).toBeDefined();
    expect(
      store.getRecord(archive, "conversations", "conversations"),
    ).toBeUndefined();
    expect(store.getInstanceBinding("claude").generation).toBe(3);
  });

  it("counts and erases an archived scope while preserving its sibling and fencing its connection", () => {
    store.registerConnection({
      instance: "strava",
      sourceId: "https://registry.pdpp.dev/sources/strava",
      method: "strava",
      label: "",
    });
    for (const stream of ["activities", "coverage_diagnostics"]) {
      store.replaceStream({
        instance: "strava",
        stream,
        method: "strava",
        generation: 1,
        primaryKey: ["id"],
        emittedAt: "2026-09-10T00:00:00Z",
        sourceCollectedAt: "2026-09-10T00:00:00Z",
        envelopes: [
          {
            instance: "strava",
            stream,
            key: stream,
            data: { id: stream },
            emitted_at: "2026-09-10T00:00:00Z",
          },
        ],
      });
    }
    store.transitionStravaToBrowser({
      instance: "strava",
      expectedGeneration: 1,
      expectedWriteClock: store.transitionWriteClock(),
      snapshots: {
        "strava.coverage_diagnostics": {
          version: "1.0",
          scope: "strava.coverage_diagnostics",
          collectedAt: "2026-09-10T00:00:00Z",
          data: {},
        },
      },
    });
    const archive = store.stravaTransition("strava")!.archiveInstance;
    unmarked("strava.coverage_diagnostics");
    migrateScopeDeletionHistory(db, OWNER, store, logger);
    expect(
      store.getRecord(archive, "coverage_diagnostics", "coverage_diagnostics"),
    ).toBeUndefined();
    expect(store.getRecord(archive, "activities", "activities")).toBeDefined();
    expect(store.getInstanceBinding("strava").generation).toBe(3);
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({
        scope: "strava.coverage_diagnostics",
        streams: expect.arrayContaining([
          expect.objectContaining({ stream: "coverage_diagnostics", erase: 1 }),
          expect.objectContaining({ stream: "activities", keep: 1 }),
        ]),
      }),
      expect.any(String),
    );
  });

  it("dry run reports erase and keep counts without changing rows or marker", () => {
    migrateScopeDeletionHistory(db, OWNER, store, logger, { dryRun: true });
    expect(
      store.getRecord("connection", "activity", "newer-client-time"),
    ).toBeDefined();
    expect(
      createScopeDeletionHistory(db, OWNER).get("oura.activity")?.eraseApplied,
    ).not.toBe(true);
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({
        scope: "oura.activity",
        rule: "erase_all",
        streams: expect.arrayContaining([
          expect.objectContaining({
            stream: "activity",
            erase: 3,
            tables: expect.objectContaining({
              pdpp_record_changes: { erase: 3, keep: 0 },
            }),
          }),
          expect.objectContaining({
            stream: "readiness",
            keep: 1,
            tables: expect.objectContaining({
              pdpp_stream_completion: { erase: 0, keep: 1 },
            }),
          }),
        ]),
      }),
      "Scope deletion migration preview",
    );
  });
  it("rolls back a failed entry, continues, and retries only unmarked entries", () => {
    unmarked("oura.readiness");
    db.exec(
      "CREATE TRIGGER stop_activity BEFORE DELETE ON pdpp_records WHEN OLD.stream = 'activity' BEGIN SELECT RAISE(ABORT, 'interrupted'); END",
    );
    migrateScopeDeletionHistory(db, OWNER, store, logger);
    const history = createScopeDeletionHistory(db, OWNER);
    expect(history.get("oura.activity")?.eraseApplied).not.toBe(true);
    expect(
      store.getRecord("connection", "activity", "newer-client-time"),
    ).toBeDefined();
    expect(history.get("oura.readiness")?.eraseApplied).toBe(true);
    expect(logger.error).toHaveBeenCalled();
    db.exec("DROP TRIGGER stop_activity");
    migrateScopeDeletionHistory(db, OWNER, store, logger);
    expect(history.get("oura.activity")?.eraseApplied).toBe(true);
    expect(
      store.getRecord("connection", "activity", "newer-client-time"),
    ).toBeUndefined();
  });
});
