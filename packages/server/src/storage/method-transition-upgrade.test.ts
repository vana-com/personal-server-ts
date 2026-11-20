import Database from "better-sqlite3";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { createLegacyScopeView } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import { initializeDatabase } from "./index-schema.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

const sql = readFileSync(
  new URL(
    "./__fixtures__/desktop-dde-upgrade/desktop-dde-index.sql",
    import.meta.url,
  ),
  "utf8",
);
const stravaFixture = JSON.parse(
  readFileSync(
    new URL(
      "./__fixtures__/desktop-dde-upgrade/desktop-dde-index.json",
      import.meta.url,
    ),
    "utf8",
  ),
) as {
  provenance: {
    seed: { rawSqlLegacyFileSeeds: { path: string; scope: string }[] };
  };
  snapshots: Record<string, Omit<DataFileEnvelope, "version">>;
};
/** What each indexed Strava legacy file holds, by its path in `data_files`. */
const stravaFiles = new Map(
  stravaFixture.provenance.seed.rawSqlLegacyFileSeeds.map(
    ({ path, scope }) => [path, stravaFixture.snapshots[scope]!] as const,
  ),
);
const CLAUDE = "https://registry.pdpp.dev/sources/claude";
const STRAVA_LIVE = "strava:fixture-owner";
const STRAVA_ARCHIVE = "retired-strava:0634f6db-e43f-4225-88ba-4716585dc293";
const T = "2026-11-01T00:00:00.000Z";

type Store = ReturnType<typeof createSqliteRecordStore>;

describe("upgrade of an install with a pending method transition (pre-prod gap)", () => {
  let dir: string;
  let db: Database.Database | undefined;
  afterEach(() => {
    db?.close();
    db = undefined;
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  /**
   * `legacyFile: false` is an install whose export file is gone. The view
   * reads a legacy head as production does: through `readLegacyHead`.
   */
  function stravaInstall({ legacyFile }: { legacyFile: boolean }) {
    dir = mkdtempSync(join(tmpdir(), "ps-transition-upgrade-"));
    const path = join(dir, "index.db");
    // A Desktop v15 index.db captured with a pending export-to-live Strava
    // transition: export rows a and b live under the archive instance.
    db = new Database(path);
    db.exec(sql);
    db.close();
    db = initializeDatabase(path);
    if (!legacyFile) db.prepare("DELETE FROM data_files").run();
    const store = createSqliteRecordStore(db);
    const view = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: () => ["strava", "strava-browser"],
      readLegacyHead: async (head) => {
        const file = stravaFiles.get(head.path);
        if (!file) throw new Error(`no legacy file at ${head.path}`);
        return { version: "1.0", ...file };
      },
    });
    return { db, store, view };
  }

  function stravaLiveWrite(store: Store) {
    store.replaceStream({
      instance: STRAVA_LIVE,
      stream: "activities",
      method: "strava-browser",
      generation: 2,
      primaryKey: ["id"],
      emittedAt: T,
      sourceCollectedAt: T,
      envelopes: [
        {
          instance: STRAVA_LIVE,
          stream: "activities",
          key: "c",
          data: { id: "c", activity_type: "Swim", freshness: "live" },
          emitted_at: T,
        },
      ],
    });
  }

  it("Strava: with no legacy file, returns live data only; export-only history is absent until seeded", async () => {
    const { db, store, view } = stravaInstall({ legacyFile: false });
    stravaLiveWrite(store);

    const read = await view.readLatest("strava.activities");
    expect(read).toMatchObject({ kind: "canonical" });
    const ids = (
      read as { envelope: { data: { activities: { id: string }[] } } }
    ).envelope.data.activities.map((a) => a.id);
    // Known gap: export-only activities a and b are not returned.
    expect(ids).toEqual(["c"]);

    // The history still exists on disk, under the retired archive instance,
    // and the transition record that names it survives the upgrade.
    expect(
      db
        .prepare(
          "SELECT record_key FROM pdpp_records WHERE instance = ? AND stream = 'activities' ORDER BY record_key",
        )
        .all(STRAVA_ARCHIVE),
    ).toEqual([{ record_key: "a" }, { record_key: "b" }]);
    expect(
      db.prepare("SELECT archive_instance FROM pdpp_strava_transition").all(),
    ).toEqual([{ archive_instance: STRAVA_ARCHIVE }]);
    store.close();
  });

  it("Strava: a live write beside a readable legacy file: the live data wins and the file's activities are not returned", async () => {
    const { store, view } = stravaInstall({ legacyFile: true });
    stravaLiveWrite(store);
    const read = await view.readLatest("strava.activities");
    expect(read).toMatchObject({ kind: "canonical" });
    // Known gap: activities a and b exist only in the legacy file and the
    // archive; the read does not merge them with the live activity.
    expect(
      (
        read as { envelope: { data: { activities: { id: string }[] } } }
      ).envelope.data.activities.map((a) => a.id),
    ).toEqual(["c"]);
    store.close();
  });

  it("Strava: before live writes, the read serves the legacy file and never the archive", async () => {
    const { store, view } = stravaInstall({ legacyFile: true });
    expect(await view.readLatest("strava.activities")).toEqual({
      kind: "file",
      deletion: "canonical",
    });
    store.close();
  });

  it("Strava: once the legacy file is gone and live never wrote, the read refuses; the archive is not served", async () => {
    const { store, view } = stravaInstall({ legacyFile: false });
    expect(await view.readLatest("strava.activities")).toEqual({
      kind: "refused",
      refusal: {
        status: "unavailable",
        reason: "no_connection",
        candidates: 0,
      },
    });
    store.close();
  });

  const CLAUDE_CONNECTION = "conn_claude";
  const CLAUDE_ARCHIVE = "retired-claude:11111111-1111-4111-8111-111111111111";
  /** The export `transitionClaudeToLive` archived as the historical snapshot. */
  const claudeExport: DataFileEnvelope = {
    version: "1.0",
    scope: "claude.conversations",
    collectedAt: "2026-10-20T00:00:00.000Z",
    data: {
      organizationId: "org",
      profile: { name: "Reader", plan: "Team" },
      source: "official-export",
      total: 1,
      messageTotal: 1,
      conversations: [
        {
          id: "export-only",
          title: "Export only",
          messages: [{ id: "export-message", content: "Export message" }],
        },
      ],
    },
  };

  // No captured Claude index.db exists, so this rebuilds the state the removed
  // `transitionClaudeToLive` left on disk, as a database from before the
  // upgrade (index schema 15, records schema 14): the export rows moved to a
  // `retired-claude:` instance, a `pdpp_claude_transition` row holding the
  // export as its historical snapshot, and the connection rebound to
  // `anthropic-live` at the next generation, with the reset clock at the write
  // clock the transition read. The database is closed and reopened through
  // `initializeDatabase`, which is the upgrade under test.
  function claudeInstall({ legacyHead }: { legacyHead: boolean }) {
    dir = mkdtempSync(join(tmpdir(), "ps-transition-upgrade-"));
    const path = join(dir, "index.db");
    const old = initializeDatabase(path);
    const seed = createSqliteRecordStore(old);
    seed.registerConnection({
      instance: CLAUDE_CONNECTION,
      sourceId: CLAUDE,
      method: "anthropic",
      label: "",
    });
    const exported = (stream: string, data: { id: string }) =>
      seed.replaceStream({
        instance: CLAUDE_CONNECTION,
        stream,
        method: "anthropic",
        generation: 1,
        primaryKey: ["id"],
        emittedAt: "2026-10-20T00:00:00.000Z",
        sourceCollectedAt: "2026-10-20T00:00:00.000Z",
        envelopes: [
          {
            instance: CLAUDE_CONNECTION,
            stream,
            key: data.id,
            data,
            emitted_at: "2026-10-20T00:00:00.000Z",
          },
        ],
      });
    exported("conversations", { id: "export-only", title: "Export only" });
    exported("messages", { id: "export-message" });
    old.transaction(() => {
      const clock = (
        old
          .prepare("SELECT value FROM pdpp_write_clock WHERE id = 1")
          .get() as {
          value: number;
        }
      ).value;
      old
        .prepare(
          "INSERT INTO pdpp_claude_transition (instance, archive_instance, generation, snapshots_json) VALUES (?, ?, 2, ?)",
        )
        .run(
          CLAUDE_CONNECTION,
          CLAUDE_ARCHIVE,
          JSON.stringify({ "claude.conversations": claudeExport }),
        );
      for (const table of [
        "pdpp_records",
        "pdpp_record_changes",
        "pdpp_blob_claims",
        "pdpp_stream_completion",
        "pdpp_record_arrival",
      ])
        old
          .prepare(`UPDATE ${table} SET instance = ? WHERE instance = ?`)
          .run(CLAUDE_ARCHIVE, CLAUDE_CONNECTION);
      old
        .prepare(
          "UPDATE pdpp_instance_binding SET method = 'anthropic-live', generation = 2, reset_clock = ? WHERE instance = ?",
        )
        .run(clock, CLAUDE_CONNECTION);
    })();
    if (legacyHead)
      old
        .prepare(
          "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
        )
        .run(
          "claude/conversations/old.json",
          "claude.conversations",
          "2026-10-20T00:00:00.000Z",
          1,
        );
    const live = (stream: string, data: Record<string, unknown>) =>
      seed.ingestBatch(
        [
          {
            instance: CLAUDE_CONNECTION,
            stream,
            key: String(data.id),
            data,
            emitted_at: T,
          },
        ],
        () => "mutable_state",
        () => ["id"],
        { method: "anthropic-live", generation: 2 },
      );
    live("account_plan", {
      id: "account_plan",
      account_id: "org",
      plan_display_name: null,
    });
    live("conversations", { id: "live-chat", title: "Live", message_count: 1 });
    live("messages", {
      id: "live-message",
      conversation_id: "live-chat",
      role: "human",
      content: "Live message",
      attachments: [],
    });
    // Age the database to the shape the installed version left: the records
    // schema before v15 (history index) and v16 (Strava transition).
    old.exec(
      "DROP INDEX IF EXISTS idx_pdpp_record_changes_blob_ref; DROP TABLE pdpp_strava_transition; UPDATE pdpp_schema_version SET version = 14 WHERE id = 1; PRAGMA user_version = 15;",
    );
    expect(
      old.prepare("SELECT version FROM pdpp_schema_version").get(),
    ).toEqual({ version: 14 });
    const resetClock = (
      old
        .prepare(
          "SELECT reset_clock FROM pdpp_instance_binding WHERE instance = ?",
        )
        .get(CLAUDE_CONNECTION) as { reset_clock: number }
    ).reset_clock;
    old.close();

    db = initializeDatabase(path);
    const store = createSqliteRecordStore(db);
    const view = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) =>
        sourceId === CLAUDE ? ["anthropic-live"] : [],
      readLegacyHead: async () => claudeExport,
    });
    return { db, store, view, archive: CLAUDE_ARCHIVE, resetClock };
  }

  const conversationIds = (read: unknown) =>
    (
      read as {
        envelope: { data: { conversations: { id: string }[] } };
      }
    ).envelope.data.conversations.map((c) => c.id);

  it("Claude: returns live data only; export-only history is absent until seeded", async () => {
    const { db, store, view, archive, resetClock } = claudeInstall({
      legacyHead: false,
    });
    // The upgrade ran, and kept the transition's snapshot and reset clock.
    expect(db.prepare("SELECT version FROM pdpp_schema_version").get()).toEqual(
      { version: 16 },
    );
    expect(resetClock).toBeGreaterThan(0);
    expect(store.getInstanceBinding(CLAUDE_CONNECTION)).toMatchObject({
      method: "anthropic-live",
      generation: 2,
      resetClock,
    });
    expect(
      JSON.parse(
        (
          db
            .prepare("SELECT snapshots_json FROM pdpp_claude_transition")
            .get() as { snapshots_json: string }
        ).snapshots_json,
      ),
    ).toEqual({ "claude.conversations": claudeExport });
    const read = await view.readLatest("claude.conversations");
    expect(read).toMatchObject({ kind: "canonical" });
    // Known gap: the export-only conversation is not returned.
    expect(conversationIds(read)).toEqual(["live-chat"]);
    expect(
      db
        .prepare(
          "SELECT record_key FROM pdpp_records WHERE instance = ? AND stream = 'conversations'",
        )
        .all(archive),
    ).toEqual([{ record_key: "export-only" }]);
    expect(
      db.prepare("SELECT archive_instance FROM pdpp_claude_transition").all(),
    ).toEqual([{ archive_instance: archive }]);
    store.close();
  });

  it("Claude: while the legacy export file remains, the read serves it and never the archive", async () => {
    const { store, view } = claudeInstall({ legacyHead: true });
    expect(await view.readLatest("claude.conversations")).toEqual({
      kind: "file",
      deletion: "canonical",
    });
    store.close();
  });
});
