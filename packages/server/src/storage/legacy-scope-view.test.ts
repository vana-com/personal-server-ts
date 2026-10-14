import Database from "better-sqlite3";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  createLegacyScopeView,
  type LegacyScopeAuthority,
} from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { initializeDatabase } from "./index-schema.js";

const OURA = "https://registry.pdpp.dev/sources/oura";
const GITHUB = "https://registry.pdpp.dev/sources/github";

/** The (source, method) pairs a boot configures, as Desktop names them. */
const CONFIGURED: Record<string, string[]> = {
  [OURA]: ["oura", "oura-browser"],
  [GITHUB]: ["github-browser"],
};

type Store = ReturnType<typeof createSqliteRecordStore>;

function connect(
  store: Store,
  instance: string,
  method = "oura",
  source = OURA,
) {
  store.registerConnection({ instance, sourceId: source, method, label: "" });
}

function replace(
  store: Store,
  instance: string,
  stream: string,
  ids: string[],
  {
    method = "oura",
    score = 80,
    collectedAt = "2026-09-09T07:00:00.000Z",
  } = {},
) {
  store.replaceStream({
    instance,
    stream,
    method,
    generation: 1,
    primaryKey: ["id"],
    emittedAt: "2026-09-10T07:00:00.000Z",
    sourceCollectedAt: collectedAt,
    envelopes: ids.map((id) => ({
      instance,
      stream,
      key: id,
      data: { id, day: "2026-09-01", score },
      emitted_at: "2026-09-10T07:00:00.000Z",
    })),
  });
}

function ingest(
  store: Store,
  instance: string,
  id: string,
  emittedAt: string,
  score = 80,
) {
  const result = store.ingestBatch(
    [
      {
        instance,
        stream: "activity",
        key: id,
        data: { id, day: "2026-09-01", score },
        emitted_at: emittedAt,
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "oura", generation: 1 },
  );
  expect(result.rejected).toEqual([]);
}

describe("legacy scope view over the real SQLite record store", () => {
  let db: InstanceType<typeof Database>;
  let store: Store;
  let view: ReturnType<typeof createLegacyScopeView>;

  beforeEach(() => {
    db = initializeDatabase(":memory:");
    store = createSqliteRecordStore(db);
    view = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
    });
  });
  afterEach(() => store.close());

  it("refuses a scope when two accounts of its methods hold data", async () => {
    connect(store, "conn_a", "oura");
    connect(store, "conn_b", "oura-browser");
    replace(store, "conn_a", "activity", ["a1"]);
    replace(store, "conn_b", "sleep", ["b1"], { method: "oura-browser" });

    for (const scope of ["oura.activity", "oura.sleep"]) {
      expect(await view.readLatest(scope)).toEqual({
        kind: "refused",
        refusal: {
          status: "unavailable",
          reason: "ambiguous_connection",
          candidates: 2,
        },
      });
      expect(view.listingFor(scope)).toEqual({ kind: "refused" });
    }
  });

  it("reads the one connection that holds data, beside one that never did", async () => {
    connect(store, "conn_a", "oura");
    connect(store, "conn_b", "oura-browser");
    replace(store, "conn_a", "activity", ["a1"]);

    const read = await view.readLatest("oura.activity");
    expect(read.kind).toBe("canonical");
    expect(read.kind === "canonical" && read.envelope.data).toEqual({
      days: [{ id: "a1", day: "2026-09-01", score: 80 }],
    });
  });

  it("leaves a scope to its file until a connection of its methods holds its streams", async () => {
    connect(store, "conn_a", "oura");
    expect(await view.readLatest("oura.activity")).toEqual({ kind: "file" });
    expect(await view.readLatest("notes.manual")).toEqual({ kind: "file" });
    expect(view.listingFor("oura.activity")).toEqual({ kind: "file" });

    // Another stream's data does not convert this scope ...
    replace(store, "conn_a", "readiness", ["r1"]);
    expect(await view.readLatest("oura.activity")).toEqual({ kind: "file" });
    expect(view.ownsScope("oura.activity")).toBe(false);
    // ... and an unbound scope of the namespace is never converted.
    expect(view.ownsScope("oura.manual")).toBe(false);
    expect(view.ownsScope("oura.readiness")).toBe(true);
  });

  it("does not record a takeover when the canonical scope has no data", async () => {
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "oura/activity/old.json",
      "oura.activity",
      "2026-01-01T00:00:00.000Z",
      12,
    );
    connect(store, "conn_a", "oura");

    expect(await view.readLatest("oura.activity")).toEqual({ kind: "file" });
    expect(db.prepare("SELECT * FROM legacy_scope_takeovers").all()).toEqual(
      [],
    );
  });

  it("keeps listings on legacy until an unreceipted canonical view is taken over", async () => {
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "oura/activity/old.json",
      "oura.activity",
      "2026-01-01T00:00:00.000Z",
      12,
    );
    connect(store, "conn_a", "oura");
    ingest(store, "conn_a", "a1", "2026-09-10T07:00:00.000Z");

    expect(view.listingFor("oura.activity")).toEqual({ kind: "file" });
  });

  it("keeps a reset or deleted connection's scopes canonical, never back to the file", async () => {
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);
    store.resetInstanceBinding({
      instance: "conn_a",
      expectedMethod: "oura",
      expectedGeneration: 1,
      nextMethod: "oura",
    });
    // Reset erased the rows that showed ownership; ownership stays.
    expect(view.ownsScope("oura.activity")).toBe(true);
    expect((await view.readLatest("oura.activity")).kind).toBe("refused");

    store.deleteConnection("conn_a");
    expect(await view.readLatest("oura.activity")).toEqual({
      kind: "refused",
      refusal: {
        status: "unavailable",
        reason: "no_connection",
        candidates: 0,
      },
    });
  });

  it("routes a shared public source by the configured method, not by a source name", async () => {
    connect(store, "github:owner", "github-browser", GITHUB);
    store.replaceStream({
      instance: "github:owner",
      stream: "profile",
      method: "github-browser",
      generation: 1,
      primaryKey: ["id"],
      emittedAt: "2026-09-10T07:00:00.000Z",
      sourceCollectedAt: "2026-09-09T07:00:00.000Z",
      envelopes: [
        {
          instance: "github:owner",
          stream: "profile",
          key: "profile",
          data: {
            id: "profile",
            username: "current-user",
            profileUrl: "https://github.com/current-user",
          },
          emitted_at: "2026-09-10T07:00:00.000Z",
        },
      ],
    });

    const read = await view.readLatest("github.profile");
    expect(read.kind).toBe("canonical");
    expect(read.kind === "canonical" && read.envelope.data).toEqual({
      username: "current-user",
      profileUrl: "https://github.com/current-user",
    });
  });

  it("refuses a pair this boot does not configure, and every owned scope without a mounted store", async () => {
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);

    const unconfigured = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: () => ["oura-browser"],
    });
    const unmounted = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
    });
    for (const other of [unconfigured, unmounted]) {
      expect(await other.readLatest("oura.activity")).toEqual({
        kind: "refused",
        refusal: {
          status: "unavailable",
          reason: "connection_unavailable",
          detail: "method_not_configured",
        },
      });
      expect(await other.readLatest("oura.readiness")).toEqual({
        kind: "file",
      });
    }
  });

  it("lists the same collectedAt a read returns", async () => {
    connect(store, "conn_a", "oura");
    const agree = async () => {
      const read = await view.readLatest("oura.activity");
      const listed = view.listingFor("oura.activity");
      expect(read.kind).toBe("canonical");
      expect(listed).toEqual({
        kind: "canonical",
        collectedAt: read.kind === "canonical" && read.envelope.collectedAt,
      });
    };

    // Rows only: the newest row time.
    ingest(store, "conn_a", "a1", "2026-09-01T00:00:00.000Z");
    ingest(store, "conn_a", "a2", "2026-09-03T00:00:00.000Z");
    await agree();
    // A receipt: the producer's collection time, older than the rows.
    replace(store, "conn_a", "activity", ["a1", "a2"], {
      collectedAt: "2026-09-09T00:00:00.000Z",
    });
    await agree();
    // A later ingest leaves the receipt's live count stale: rows again.
    ingest(store, "conn_a", "a3", "2026-09-12T00:00:00.000Z");
    await agree();
    expect(view.listCanonicalScopes("oura.")).toEqual([
      { scope: "oura.activity", collectedAt: "2026-09-12T00:00:00.000Z" },
    ]);
    expect(view.listCanonicalScopes("github.")).toEqual([]);
  });

  it("records automatic takeover without changing the superseded legacy index entry", async () => {
    db.prepare(
      `INSERT INTO data_files (scope, version, cas_revision, collected_at, path, producer)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(
      "oura.activity",
      7,
      9,
      "2026-01-01T00:00:00.000Z",
      "oura/activity/old.json",
      null,
    );
    const before = db.prepare("SELECT * FROM data_files").all();
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);
    expect((await view.readLatest("oura.activity")).kind).toBe("canonical");
    expect(db.prepare("SELECT * FROM data_files").all()).toEqual(before);
    expect(db.prepare("SELECT * FROM legacy_scope_takeovers").all()).toEqual([
      expect.objectContaining({
        scope: "oura.activity",
        superseded_version: 7,
        superseded_collected_at: "2026-01-01T00:00:00.000Z",
        superseded_path: "oura/activity/old.json",
        taken_over_at: expect.any(String),
      }),
    ]);
  });

  it("records every eligible version once, including a later legacy head", async () => {
    db.prepare(
      `INSERT INTO data_files (scope, version, cas_revision, collected_at, path, producer)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(
      "oura.activity",
      7,
      9,
      "2026-01-01T00:00:00.000Z",
      "oura/activity/old.json",
      null,
    );
    db.prepare(
      `INSERT INTO data_files (scope, version, cas_revision, collected_at, path, producer)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(
      "oura.activity",
      6,
      8,
      "2025-12-01T00:00:00.000Z",
      "oura/activity/older.json",
      null,
    );
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);
    expect((await view.readLatest("oura.activity")).kind).toBe("canonical");
    expect((await view.readLatest("oura.activity")).kind).toBe("canonical");

    db.prepare(
      `INSERT INTO data_files (scope, version, cas_revision, collected_at, path, producer)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(
      "oura.activity",
      8,
      10,
      "2026-02-01T00:00:00.000Z",
      "oura/activity/new.json",
      null,
    );
    replace(store, "conn_a", "activity", ["a2"], {
      collectedAt: "2026-02-02T00:00:00.000Z",
    });
    expect((await view.readLatest("oura.activity")).kind).toBe("canonical");
    expect(
      db
        .prepare(
          "SELECT superseded_version, superseded_cas_revision, superseded_path FROM legacy_scope_takeovers ORDER BY superseded_version",
        )
        .all(),
    ).toEqual([
      {
        superseded_version: 6,
        superseded_cas_revision: 8,
        superseded_path: "oura/activity/older.json",
      },
      {
        superseded_version: 7,
        superseded_cas_revision: 9,
        superseded_path: "oura/activity/old.json",
      },
      {
        superseded_version: 8,
        superseded_cas_revision: 10,
        superseded_path: "oura/activity/new.json",
      },
    ]);
  });

  it("keeps legacy reads when canonical rows were emptied without completion proof", async () => {
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "oura/activity/old.json",
      "oura.activity",
      "2026-01-01T00:00:00.000Z",
      12,
    );
    connect(store, "conn_a", "oura");
    ingest(store, "conn_a", "a1", "2026-09-10T07:00:00.000Z");
    store.replaceStream({
      instance: "conn_a",
      stream: "activity",
      method: "oura",
      generation: 1,
      primaryKey: ["id"],
      emittedAt: "2026-09-11T07:00:00.000Z",
      envelopes: [],
    });
    expect(await view.readLatest("oura.activity")).toEqual({ kind: "file" });
    expect(db.prepare("SELECT * FROM legacy_scope_takeovers").all()).toEqual(
      [],
    );
  });

  it("keeps the legacy head when valid rows have no matching completion receipt", async () => {
    db.prepare(
      `INSERT INTO data_files (scope, version, cas_revision, collected_at, path, producer)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(
      "oura.activity",
      7,
      9,
      "2026-01-01T00:00:00.000Z",
      "oura/activity/old.json",
      null,
    );
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);
    ingest(store, "conn_a", "a1", "2026-09-10T08:00:00.000Z", 91);
    expect(
      store.listStreams(["conn_a"]).find((entry) => entry.stream === "activity")
        ?.recordCount,
    ).toBe(1);
    expect(store.listStreamCompletions("conn_a")).toEqual([]);

    expect(await view.readLatest("oura.activity")).toEqual({ kind: "file" });
    expect(db.prepare("SELECT * FROM legacy_scope_takeovers").all()).toEqual(
      [],
    );
  });

  it("does not use a later completion receipt to take over an earlier partial snapshot", async () => {
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "oura/activity/old.json",
      "oura.activity",
      "2026-01-01T00:00:00.000Z",
      12,
    );
    connect(store, "conn_a", "oura");
    ingest(store, "conn_a", "uncompleted", "2026-09-10T07:00:00.000Z");
    const racing = {
      ...store,
      readSnapshot<T>(read: () => T): T {
        const snapshot = store.readSnapshot(read);
        replace(store, "conn_a", "activity", ["completed"]);
        return snapshot;
      },
    };
    const racingView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: racing,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
    });
    expect(await racingView.readLatest("oura.activity")).toEqual({
      kind: "file",
    });
    expect(db.prepare("SELECT * FROM legacy_scope_takeovers").all()).toEqual(
      [],
    );
  });

  it("does not take over a first legacy head inserted after an unreceipted row snapshot", async () => {
    connect(store, "conn_a", "oura");
    ingest(store, "conn_a", "uncompleted", "2026-09-10T07:00:00.000Z");
    let inserted = false;
    const racing = {
      ...store,
      readSnapshot<T>(read: () => T): T {
        const snapshot = store.readSnapshot(read);
        if (!inserted) {
          inserted = true;
          db.prepare(
            "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
          ).run(
            "oura/activity/concurrent.json",
            "oura.activity",
            "2026-01-01T00:00:00.000Z",
            12,
          );
        }
        return snapshot;
      },
    };
    const racingView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: racing,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
    });
    expect((await racingView.readLatest("oura.activity")).kind).not.toBe(
      "canonical",
    );
    expect(db.prepare("SELECT * FROM legacy_scope_takeovers").all()).toEqual(
      [],
    );
    expect(await view.readLatest("oura.activity")).toEqual({ kind: "file" });
    expect(db.prepare("SELECT path FROM data_files").all()).toEqual([
      { path: "oura/activity/concurrent.json" },
    ]);
  });

  it("does not take over a legacy head that changes after a receipted row snapshot", async () => {
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "oura/activity/old.json",
      "oura.activity",
      "2026-01-01T00:00:00.000Z",
      12,
    );
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);
    let inserted = false;
    const racing = {
      ...store,
      readSnapshot<T>(read: () => T): T {
        const snapshot = store.readSnapshot(read);
        if (!inserted) {
          inserted = true;
          db.prepare(
            "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
          ).run(
            "oura/activity/new.json",
            "oura.activity",
            "2026-02-01T00:00:00.000Z",
            12,
          );
        }
        return snapshot;
      },
    };
    const racingView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: racing,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
    });

    expect((await racingView.readLatest("oura.activity")).kind).toBe("file");
    expect(db.prepare("SELECT * FROM legacy_scope_takeovers").all()).toEqual(
      [],
    );
    expect(
      db.prepare("SELECT path FROM data_files ORDER BY path").all(),
    ).toEqual([
      { path: "oura/activity/new.json" },
      { path: "oura/activity/old.json" },
    ]);
  });

  it("refuses when another account appears after a receipted projection snapshot", async () => {
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "oura/activity/old.json",
      "oura.activity",
      "2026-01-01T00:00:00.000Z",
      12,
    );
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);
    let inserted = false;
    const racing = {
      ...store,
      readSnapshot<T>(read: () => T): T {
        const snapshot = store.readSnapshot(read);
        if (!inserted) {
          inserted = true;
          connect(store, "conn_b", "oura");
          ingest(store, "conn_b", "other-account", "2026-09-10T07:00:00.000Z");
        }
        return snapshot;
      },
    };
    const racingView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: racing,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
    });
    expect((await racingView.readLatest("oura.activity")).kind).toBe("refused");
    expect(db.prepare("SELECT * FROM legacy_scope_takeovers").all()).toEqual(
      [],
    );
  });

  it("does not expose a deleted connection's legacy data when an empty live connection exists", async () => {
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "oura/activity/old.json",
      "oura.activity",
      "2026-01-01T00:00:00.000Z",
      12,
    );
    connect(store, "conn_a", "oura");
    store.deleteConnection("conn_a");
    connect(store, "conn_b", "oura");
    expect((await view.readLatest("oura.activity")).kind).toBe("refused");
    expect(view.listingFor("oura.activity")).toEqual({ kind: "refused" });
  });

  it("keeps legacy reads and listing after a reset before first takeover", async () => {
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "oura/activity/old.json",
      "oura.activity",
      "2026-01-01T00:00:00.000Z",
      12,
    );
    connect(store, "conn_a", "oura");
    store.resetInstanceBinding({
      instance: "conn_a",
      expectedMethod: "oura",
      expectedGeneration: 1,
      nextMethod: "oura",
    });
    expect(await view.readLatest("oura.activity")).toEqual({ kind: "file" });
    expect(view.listingFor("oura.activity")).toEqual({ kind: "file" });
    expect(view.ownsScope("oura.activity")).toBe(true);
    expect(db.prepare("SELECT * FROM legacy_scope_takeovers").all()).toEqual(
      [],
    );
  });

  it("refuses legacy fallback after reset has erased a successful takeover", async () => {
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "oura/activity/old.json",
      "oura.activity",
      "2026-01-01T00:00:00.000Z",
      12,
    );
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);
    expect((await view.readLatest("oura.activity")).kind).toBe("canonical");
    expect(
      db.prepare("SELECT * FROM legacy_scope_takeovers").all(),
    ).not.toEqual([]);

    store.resetInstanceBinding({
      instance: "conn_a",
      expectedMethod: "oura",
      expectedGeneration: 1,
      nextMethod: "oura",
    });

    expect((await view.readLatest("oura.activity")).kind).toBe("refused");
    expect(view.listingFor("oura.activity")).toEqual({ kind: "refused" });
    expect(view.ownsScope("oura.activity")).toBe(true);
  });

  it("does not classify an explicitly produced legacy row as an old connector file", async () => {
    db.prepare(
      `INSERT INTO data_files (scope, version, cas_revision, collected_at, path, producer)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(
      "oura.activity",
      7,
      9,
      "2026-01-01T00:00:00.000Z",
      "oura/activity/projected.json",
      "pdpp-projector",
    );
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);

    expect((await view.readLatest("oura.activity")).kind).toBe("canonical");
    expect(db.prepare("SELECT * FROM legacy_scope_takeovers").all()).toEqual(
      [],
    );
  });

  it("records a non-projector producer as a superseded legacy version", async () => {
    db.prepare(
      `INSERT INTO data_files (scope, version, cas_revision, collected_at, path, producer)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(
      "oura.activity",
      7,
      9,
      "2026-01-01T00:00:00.000Z",
      "oura/activity/foreign.json",
      "foreign-writer",
    );
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);

    expect((await view.readLatest("oura.activity")).kind).toBe("canonical");
    expect(
      db.prepare("SELECT superseded_path FROM legacy_scope_takeovers").all(),
    ).toEqual([{ superseded_path: "oura/activity/foreign.json" }]);
  });

  it("writes nothing while deciding, reading or listing", async () => {
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);
    const before = db.prepare("SELECT total_changes() AS n").get();
    expect((await view.readLatest("oura.activity")).kind).toBe("canonical");
    view.listingFor("oura.activity");
    view.listCanonicalScopes(undefined);
    view.ownsScope("oura.readiness");
    expect(db.prepare("SELECT total_changes() AS n").get()).toEqual(before);
  });
});

describe("the legacy scope authority without the record store", () => {
  it("finds no connection and creates nothing in a database the store never opened", async () => {
    const db = new Database(":memory:");
    try {
      const view = createLegacyScopeView({
        authority: createLegacyScopeAuthority(db),
        configuredMethods: () => [],
      });
      expect(await view.readLatest("oura.activity")).toEqual({ kind: "file" });
      expect(view.listCanonicalScopes(undefined)).toEqual([]);
      expect(db.prepare("SELECT name FROM sqlite_master").all()).toEqual([]);
    } finally {
      db.close();
    }
  });
});

describe("one snapshot for the selection and the rows", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "pdpp-legacy-scope-race-"));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  /**
   * Another connection commits, between the decision and the row read, a
   * second account plus a repair of account one's row. The repaired row only
   * ever existed while the scope was ambiguous, so it must not be served.
   */
  it("refuses rows read after the selection stopped holding", async () => {
    const path = join(dir, "state.db");
    const db = new Database(path);
    const other = new Database(path);
    const store = createSqliteRecordStore(db);
    const writer = createSqliteRecordStore(other);
    try {
      connect(store, "conn_a");
      replace(store, "conn_a", "activity", ["a1"]);
      const authority = createLegacyScopeAuthority(db);
      let decisions = 0;
      const racing: LegacyScopeAuthority = {
        ...authority,
        readSnapshot(read) {
          const value = authority.readSnapshot(read);
          if (++decisions === 1) {
            other.transaction(() => {
              connect(writer, "conn_b");
              replace(writer, "conn_b", "activity", ["b1"]);
              replace(writer, "conn_a", "activity", ["a1"], { score: 91 });
            })();
          }
          return value;
        },
      };
      const view = createLegacyScopeView({
        authority: racing,
        records: store,
        configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      });

      const read = await view.readLatest("oura.activity");
      expect(decisions).toBe(1);
      expect(read).toEqual({
        kind: "refused",
        refusal: {
          status: "unavailable",
          reason: "store_inconsistent_read",
          detail: "the connection selection changed",
        },
      });
      // The next read sees the settled state and names it.
      expect(await view.readLatest("oura.activity")).toMatchObject({
        kind: "refused",
        refusal: { reason: "ambiguous_connection" },
      });
    } finally {
      other.close();
      db.close();
    }
  });
});
