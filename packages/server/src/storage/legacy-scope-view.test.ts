import Database from "better-sqlite3";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createLegacyScopeView,
  type LegacyScopeAuthority,
  type LegacyCoverageVerdict,
} from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { initializeDatabase } from "./index-schema.js";

const OURA = "https://registry.pdpp.dev/sources/oura";
const GITHUB = "https://registry.pdpp.dev/sources/github";
const CLAUDE = "https://registry.pdpp.dev/sources/claude";
const STRAVA = "https://registry.pdpp.dev/sources/strava";

/** The (source, method) pairs a boot configures, as Desktop names them. */
const CONFIGURED: Record<string, string[]> = {
  [OURA]: ["oura", "oura-browser"],
  [GITHUB]: ["github-browser"],
  [CLAUDE]: ["anthropic"],
  [STRAVA]: ["strava"],
};

const CLAUDE_PROFILE = {
  id: "org",
  organization_id: "org",
  full_name: "Synthetic reader",
  plan: null,
  name_source: "users_json",
  metadata_status: "valid",
};
const CLAUDE_COLLECTED = "2026-09-10T07:00:00.000Z";

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
    generation = 1,
    collectedAt = "2026-09-09T07:00:00.000Z",
  } = {},
) {
  store.replaceStream({
    instance,
    stream,
    method,
    generation,
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
  { stream = "activity", method = "oura" } = {},
) {
  const result = store.ingestBatch(
    [
      {
        instance,
        stream,
        key: id,
        data: { id, day: "2026-09-01", score },
        emitted_at: emittedAt,
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method, generation: 1 },
  );
  expect(result.rejected).toEqual([]);
}

function addClaudeProjects(store: Store, count = 1) {
  const projects = Array.from({ length: count }, (_, index) => {
    const payload = {
      uuid: `project-${index + 1}`,
      name: "Research",
      docs: [],
    };
    const bytes = new TextEncoder().encode(
      JSON.stringify({
        format: "anthropic-source-record-v1",
        stream: "projects",
        record_key: payload.uuid,
        payload,
      }),
    );
    const meta = store.storeBlobBytesForInstance({
      instance: "conn_claude",
      method: "anthropic",
      generation: 1,
      bytes,
      mimeType: "application/json",
    });
    return {
      key: payload.uuid,
      blobId: meta.blobId,
      bytes,
      project: {
        id: payload.uuid,
        blob_ref: {
          blob_id: meta.blobId,
          sha256: meta.sha256,
          size_bytes: meta.sizeBytes,
          mime_type: meta.mimeType,
        },
      },
    };
  });

  store.replaceStream({
    instance: "conn_claude",
    stream: "account_profile",
    method: "anthropic",
    generation: 1,
    primaryKey: ["id"],
    emittedAt: CLAUDE_COLLECTED,
    sourceCollectedAt: CLAUDE_COLLECTED,
    envelopes: [
      {
        instance: "conn_claude",
        stream: "account_profile",
        key: "org",
        data: CLAUDE_PROFILE,
        emitted_at: CLAUDE_COLLECTED,
      },
    ],
  });
  store.replaceStream({
    instance: "conn_claude",
    stream: "projects",
    method: "anthropic",
    generation: 1,
    primaryKey: ["id"],
    emittedAt: CLAUDE_COLLECTED,
    sourceCollectedAt: CLAUDE_COLLECTED,
    envelopes: projects.map(({ key, project }) => ({
      instance: "conn_claude",
      stream: "projects",
      key,
      data: project,
      emitted_at: CLAUDE_COLLECTED,
    })),
  });
  store.replaceStream({
    instance: "conn_claude",
    stream: "project_documents",
    method: "anthropic",
    generation: 1,
    primaryKey: ["id"],
    emittedAt: CLAUDE_COLLECTED,
    sourceCollectedAt: CLAUDE_COLLECTED,
    envelopes: [],
  });
  return projects;
}

function addLegacyClaudeHead(db: InstanceType<typeof Database>) {
  db.prepare(
    "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
  ).run(
    "claude/projects/old.json",
    "claude.projects",
    "2026-01-01T00:00:00.000Z",
    12,
  );
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

  it("persists reviewed exception evidence in the verdict ledger", () => {
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "chatgpt/memories/old.json",
      "chatgpt.memories",
      "2026-06-08T18:05:53.547Z",
      1,
    );
    const authority = createLegacyScopeAuthority(db);
    const head = authority.eligibleLegacyHead("chatgpt.memories")!;
    const exception = {
      path: "$.memories[].created_at",
      reason:
        "legacy collector wrote collection time; canonical carries source creation time",
      authority: "canonical" as const,
    };
    const coverage: LegacyCoverageVerdict = {
      covered: true,
      comparisonCase: "canonical_newer",
      reason: null,
      reasonCounts: {
        no_stable_key: 0,
        missing_entity: 0,
        missing_field: 0,
        field_mismatch: 0,
        type_mismatch: 0,
        timestamp_format: 0,
        identity_mismatch: 0,
        creation_mismatch: 0,
        array_order: 0,
        payload_growth: 0,
        missing_raw_blob: 0,
        projection_unavailable: 0,
      },
      appliedExceptions: [exception],
      missingEntityCount: 0,
      mismatchedFieldPaths: [],
      legacyBytes: 100,
      canonicalBytes: 100,
      byteDelta: 0,
    };
    expect(
      authority.confirmRead("chatgpt.memories", head, () => true, {
        instance: "conn_a",
        generation: 1,
        writeClock: authority.writeClock(),
        arrivalRevision: authority.arrivalRevision(),
        canonicalCursor: "0:0:receipt:revision:3",
        coverage,
        cached: false,
      }),
    ).toBe(true);
    expect(authority.verdictFor("chatgpt.memories")[0]).toMatchObject({
      verdict: "covered",
      comparisonCase: "canonical_newer",
      appliedExceptions: [exception],
    });
    expect(
      authority.cachedVerdict(
        "chatgpt.memories",
        "conn_a",
        1,
        head.id,
        "0:0:receipt:revision:3",
      )?.appliedExceptions,
    ).toEqual([exception]);
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

  it("compares the projected Claude conversation joined from three streams", async () => {
    connect(store, "conn_claude", "anthropic", CLAUDE);
    const rows = [
      ["account_profile", CLAUDE_PROFILE],
      [
        "conversations",
        {
          id: "cv1",
          title: "A",
          create_time: null,
          update_time: null,
          project_id: null,
          message_count: 1,
          is_starred: false,
        },
      ],
      [
        "messages",
        {
          id: "m1",
          conversation_id: "cv1",
          role: "user",
          parent_id: null,
          content: "hello",
          create_time: "2026-09-01T00:00:00.000Z",
          update_time: null,
          attachments: [],
        },
      ],
    ] as const;
    for (const [stream, data] of rows) {
      store.replaceStream({
        instance: "conn_claude",
        stream,
        method: "anthropic",
        generation: 1,
        primaryKey: ["id"],
        emittedAt: CLAUDE_COLLECTED,
        sourceCollectedAt: CLAUDE_COLLECTED,
        envelopes: [
          {
            instance: "conn_claude",
            stream,
            key: data.id,
            data,
            emitted_at: CLAUDE_COLLECTED,
          },
        ],
      });
    }
    const projected = await view.readLatest("claude.conversations");
    expect(projected.kind).toBe("canonical");
    expect(
      projected.kind === "canonical" &&
        (projected.envelope.data.conversations as unknown[]).length,
    ).toBe(1);
  });

  it("keeps Claude legacy authoritative when a conversation lacks its raw blob reference", async () => {
    connect(store, "conn_claude", "anthropic", CLAUDE);
    const rows = [
      ["account_profile", CLAUDE_PROFILE],
      [
        "conversations",
        {
          id: "cv1",
          title: "A",
          create_time: null,
          update_time: null,
          project_id: null,
          message_count: 1,
          is_starred: false,
        },
      ],
      [
        "messages",
        {
          id: "m1",
          conversation_id: "cv1",
          role: "user",
          parent_id: null,
          content: "hello",
          create_time: "2026-09-01T00:00:00.000Z",
          update_time: null,
          attachments: [],
        },
      ],
    ] as const;
    for (const [stream, data] of rows) {
      store.replaceStream({
        instance: "conn_claude",
        stream,
        method: "anthropic",
        generation: 1,
        primaryKey: ["id"],
        emittedAt: CLAUDE_COLLECTED,
        sourceCollectedAt: CLAUDE_COLLECTED,
        envelopes: [
          {
            instance: "conn_claude",
            stream,
            key: data.id,
            data,
            emitted_at: CLAUDE_COLLECTED,
          },
        ],
      });
    }
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "claude/conversations/old.json",
      "claude.conversations",
      "2026-09-01T00:00:00.000Z",
      1,
    );
    const parityView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead: async () => ({
        version: "1.0",
        scope: "claude.conversations",
        collectedAt: "2026-09-01T00:00:00.000Z",
        data: { conversations: [{ id: "cv1", messages: [] }] },
      }),
    });

    expect(await parityView.readLatest("claude.conversations")).toEqual({
      kind: "file",
    });
    expect(parityView.verdictFor("claude.conversations")[0]).toMatchObject({
      verdict: "not_covered",
      reason: { reason: "missing_raw_blob" },
      reasonCounts: { missing_raw_blob: 1 },
    });
  });

  it("keeps covering Claude project rows with their raw blob references", async () => {
    connect(store, "conn_claude", "anthropic", CLAUDE);
    addClaudeProjects(store);
    const projected = await view.readLatest("claude.projects");
    expect(projected.kind).toBe("canonical");
    if (projected.kind !== "canonical") return;
    addLegacyClaudeHead(db);
    const parityView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead: async () => projected.envelope,
    });

    expect(await parityView.readLatest("claude.projects")).toMatchObject({
      kind: "canonical",
    });
    expect(
      parityView.verdictFor("claude.projects")[0]?.reasonCounts
        .missing_raw_blob,
    ).toBe(0);
  });

  it("keeps parity verdicts isolated by connection instance", async () => {
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);
    const projected = await view.readLatest("oura.activity");
    expect(projected.kind).toBe("canonical");
    if (projected.kind !== "canonical") return;
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "oura/activity/old.json",
      "oura.activity",
      "2026-10-01T00:00:00.000Z",
      1,
    );
    const parityView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead: async () => projected.envelope,
    });
    expect((await parityView.readLatest("oura.activity")).kind).toBe(
      "canonical",
    );
    db.prepare(
      "UPDATE pdpp_stream_completion SET source_collected_at = ? WHERE instance = ? AND stream = ?",
    ).run("2026-09-12T00:00:00.000Z", "conn_a", "activity");
    expect(parityView.listingFor("oura.activity")).toEqual({ kind: "refused" });
    expect((await parityView.readLatest("oura.activity")).kind).toBe(
      "canonical",
    );
    store.deleteConnection("conn_a");
    connect(store, "conn_b", "oura");
    replace(store, "conn_b", "activity", ["a1"]);
    expect((await parityView.readLatest("oura.activity")).kind).toBe(
      "canonical",
    );
    expect(
      db
        .prepare(
          "SELECT instance FROM legacy_scope_takeovers ORDER BY instance",
        )
        .all(),
    ).toEqual([{ instance: "conn_a" }, { instance: "conn_b" }]);
    ingest(store, "conn_b", "a1", "2026-09-10T08:00:00.000Z", 91);
    expect(parityView.listingFor("oura.activity")).toEqual({ kind: "refused" });
    expect((await parityView.readLatest("oura.activity")).kind).toBe("refused");
    expect(parityView.listingFor("oura.activity")).toEqual({ kind: "refused" });
    expect(parityView.verdictFor("oura.activity")).toMatchObject([
      { instance: "conn_a", verdict: "covered" },
      {
        instance: "conn_b",
        verdict: "not_covered",
        reason: { reason: "field_mismatch" },
      },
    ]);
  });

  it("does not fall back to an unchanged head after connection generation replacement", async () => {
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);
    const projected = await view.readLatest("oura.activity");
    expect(projected.kind).toBe("canonical");
    if (projected.kind !== "canonical") return;
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "oura/activity/old.json",
      "oura.activity",
      "2026-10-01T00:00:00.000Z",
      1,
    );
    const parityView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead: async () => projected.envelope,
    });

    expect((await parityView.readLatest("oura.activity")).kind).toBe(
      "canonical",
    );
    store.resetInstanceBinding({
      instance: "conn_a",
      expectedMethod: "oura",
      expectedGeneration: 1,
      nextMethod: "oura",
    });
    replace(store, "conn_a", "activity", ["a1"], {
      score: 91,
      generation: 2,
    });

    expect((await parityView.readLatest("oura.activity")).kind).toBe("refused");
    expect(parityView.verdictFor("oura.activity")).toMatchObject([
      { generation: 1, verdict: "covered" },
      { generation: 2, verdict: "not_covered" },
    ]);
    expect(
      db
        .prepare(
          "SELECT generation FROM legacy_scope_takeovers WHERE scope = ? AND instance = ?",
        )
        .all("oura.activity", "conn_a"),
    ).toEqual([{ generation: 1 }]);
  });

  it("keeps an unchanged superseded head from falling back for a replacement account", async () => {
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);
    const projected = await view.readLatest("oura.activity");
    expect(projected.kind).toBe("canonical");
    if (projected.kind !== "canonical") return;
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "oura/activity/old.json",
      "oura.activity",
      "2026-10-01T00:00:00.000Z",
      1,
    );
    const parityView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead: async () => projected.envelope,
    });

    expect((await parityView.readLatest("oura.activity")).kind).toBe(
      "canonical",
    );
    store.deleteConnection("conn_a");
    connect(store, "conn_b", "oura");
    replace(store, "conn_b", "activity", ["a1"], { score: 91 });

    expect((await parityView.readLatest("oura.activity")).kind).toBe("refused");
    expect(parityView.verdictFor("oura.activity")).toMatchObject([
      { instance: "conn_a", generation: 1, verdict: "covered" },
      { instance: "conn_b", generation: 1, verdict: "not_covered" },
    ]);
  });

  it("honors a reset that commits while a cache-miss evaluation is in flight", async () => {
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);
    const projected = await view.readLatest("oura.activity");
    expect(projected.kind).toBe("canonical");
    if (projected.kind !== "canonical") return;
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "oura/activity/old.json",
      "oura.activity",
      "2026-10-01T00:00:00.000Z",
      1,
    );
    let resume!: () => void;
    let started!: () => void;
    const readStarted = new Promise<void>((resolve) => (started = resolve));
    const waitForResume = new Promise<void>((resolve) => (resume = resolve));
    const parityView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead: async () => {
        started();
        await waitForResume;
        return projected.envelope;
      },
    });

    const inFlight = parityView.readLatest("oura.activity");
    await readStarted;
    parityView.resetTakeover("oura.activity");
    resume();

    expect(await inFlight).toEqual({ kind: "file" });
    expect(parityView.verdictFor("oura.activity")).toEqual([]);
    expect(db.prepare("SELECT * FROM legacy_scope_takeovers").all()).toEqual(
      [],
    );
  });

  it("reuses the covered projection without reading source rows again", async () => {
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);
    const projected = await view.readLatest("oura.activity");
    expect(projected.kind).toBe("canonical");
    if (projected.kind !== "canonical") return;
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "oura/activity/old.json",
      "oura.activity",
      "2026-10-01T00:00:00.000Z",
      1,
    );
    const parityView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead: async () => projected.envelope,
    });
    const listRecords = vi.spyOn(store, "listRecords");

    expect((await parityView.readLatest("oura.activity")).kind).toBe(
      "canonical",
    );
    const storedCursor = db
      .prepare(
        "SELECT canonical_cursor FROM legacy_scope_takeover_verdicts WHERE scope = ?",
      )
      .get("oura.activity") as { canonical_cursor: string };
    expect(storedCursor.canonical_cursor).toContain("canonical-legacy-view/5");
    const callsAfterFirstRead = listRecords.mock.calls.length;
    expect(callsAfterFirstRead).toBeGreaterThan(0);
    expect((await parityView.readLatest("oura.activity")).kind).toBe(
      "canonical",
    );

    expect(listRecords).toHaveBeenCalledTimes(callsAfterFirstRead);
  });

  it("refreshes a covered projection after an unchanged re-delivery changes arrival order", async () => {
    connect(store, "conn_a", "strava", STRAVA);
    replace(store, "conn_a", "activities", ["a", "b"], { method: "strava" });
    const initialProjection = await view.readLatest("strava.activities");
    expect(initialProjection.kind).toBe("canonical");
    if (initialProjection.kind !== "canonical") return;
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "strava/activities/old.json",
      "strava.activities",
      "2026-09-01T00:00:00.000Z",
      1,
    );
    const parityView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead: async () => initialProjection.envelope,
    });
    const listRecords = vi.spyOn(store, "listRecords");

    const warm = await parityView.readLatest("strava.activities");
    expect(warm.kind).toBe("canonical");
    if (warm.kind !== "canonical") return;
    const callsAfterWarm = listRecords.mock.calls.length;
    const repeated = await parityView.readLatest("strava.activities");
    expect(repeated.kind).toBe("canonical");
    expect(listRecords).toHaveBeenCalledTimes(callsAfterWarm);

    ingest(store, "conn_a", "a", "2026-09-10T07:00:00.000Z", 80, {
      stream: "activities",
      method: "strava",
    });
    expect(store.listArrivalOrder("conn_a", "activities")).toEqual(["b", "a"]);
    const refreshed = await parityView.readLatest("strava.activities");
    expect(listRecords.mock.calls.length).toBeGreaterThan(callsAfterWarm);

    expect(refreshed.kind).toBe("canonical");
    if (refreshed.kind !== "canonical") return;
    expect(refreshed.envelope.data).toMatchObject({
      activities: [{ id: "b" }, { id: "a" }],
    });
    expect(refreshed.revision).not.toBe(warm.revision);
    const callsAfterRefresh = listRecords.mock.calls.length;
    expect(callsAfterRefresh).toBeGreaterThan(callsAfterWarm);

    expect((await parityView.readLatest("strava.activities")).kind).toBe(
      "canonical",
    );
    expect(listRecords).toHaveBeenCalledTimes(callsAfterRefresh);
  });

  it("refreshes a covered projection after an unchanged replacement reorders records", async () => {
    connect(store, "conn_a", "strava", STRAVA);
    replace(store, "conn_a", "activities", ["a", "b"], { method: "strava" });
    const initialProjection = await view.readLatest("strava.activities");
    expect(initialProjection.kind).toBe("canonical");
    if (initialProjection.kind !== "canonical") return;
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "strava/activities/old.json",
      "strava.activities",
      "2026-09-01T00:00:00.000Z",
      1,
    );
    const parityView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead: async () => initialProjection.envelope,
    });
    const warm = await parityView.readLatest("strava.activities");
    expect(warm.kind).toBe("canonical");
    if (warm.kind !== "canonical") return;

    replace(store, "conn_a", "activities", ["b", "a"], { method: "strava" });
    expect(store.listArrivalOrder("conn_a", "activities")).toEqual(["b", "a"]);
    const refreshed = await parityView.readLatest("strava.activities");

    expect(refreshed.kind).toBe("canonical");
    if (refreshed.kind !== "canonical") return;
    expect(refreshed.envelope.data).toMatchObject({
      activities: [{ id: "b" }, { id: "a" }],
    });
    expect(refreshed.revision).not.toBe(warm.revision);
  });

  it("re-evaluates a same-time parity verdict after only arrival order changes", async () => {
    connect(store, "conn_a", "strava", STRAVA);
    replace(store, "conn_a", "activities", ["a", "b"], { method: "strava" });
    const initialProjection = await view.readLatest("strava.activities");
    expect(initialProjection.kind).toBe("canonical");
    if (initialProjection.kind !== "canonical") return;
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "strava/activities/old.json",
      "strava.activities",
      "2026-09-09T07:00:00.000Z",
      1,
    );
    const parityView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead: async () => initialProjection.envelope,
    });

    expect((await parityView.readLatest("strava.activities")).kind).toBe(
      "canonical",
    );
    expect(parityView.verdictFor("strava.activities")[0]).toMatchObject({
      verdict: "covered",
      comparisonCase: "same_time",
    });

    ingest(store, "conn_a", "a", "2026-09-10T07:00:00.000Z", 80, {
      stream: "activities",
      method: "strava",
    });
    expect(store.listArrivalOrder("conn_a", "activities")).toEqual(["b", "a"]);
    await parityView.readLatest("strava.activities");

    expect(parityView.verdictFor("strava.activities")[0]).toMatchObject({
      verdict: "not_covered",
      comparisonCase: "same_time",
      reason: { reason: "array_order" },
    });
  });

  it("reuses a not-covered verdict without rebuilding the projection", async () => {
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);
    const projected = await view.readLatest("oura.activity");
    expect(projected.kind).toBe("canonical");
    if (projected.kind !== "canonical") return;
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "oura/activity/old.json",
      "oura.activity",
      "2026-10-01T00:00:00.000Z",
      1,
    );
    const legacy = {
      ...projected.envelope,
      data: { values: ["legacy-only"] } as typeof projected.envelope.data,
    };
    const parityView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead: async () => legacy,
    });
    const listRecords = vi.spyOn(store, "listRecords");

    expect((await parityView.readLatest("oura.activity")).kind).toBe("file");
    const callsAfterEvaluation = listRecords.mock.calls.length;
    expect(callsAfterEvaluation).toBeGreaterThan(0);
    expect((await parityView.readLatest("oura.activity")).kind).toBe("file");
    expect(listRecords).toHaveBeenCalledTimes(callsAfterEvaluation);
  });

  it("does not treat one newer unproven upsert as a newer full stream", async () => {
    connect(store, "conn_a", "oura");
    store.replaceStream({
      instance: "conn_a",
      stream: "activity",
      method: "oura",
      generation: 1,
      primaryKey: ["id"],
      emittedAt: "2026-03-01T00:00:00.000Z",
      sourceCollectedAt: "2026-03-01T00:00:00.000Z",
      envelopes: [
        {
          instance: "conn_a",
          stream: "activity",
          key: "a1",
          data: { id: "a1", day: "2026-03-01", score: 90 },
          emitted_at: "2026-03-01T00:00:00.000Z",
        },
      ],
    });
    ingest(store, "conn_a", "a2", "2026-10-01T00:00:00.000Z");
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "oura/activity/june.json",
      "oura.activity",
      "2026-06-01T00:00:00.000Z",
      1,
    );
    const legacyData = { days: [{ id: "a1", day: "2026-03-01", score: 80 }] };
    const parityView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead: async () => ({
        version: "1.0",
        scope: "oura.activity",
        collectedAt: "2026-06-01T00:00:00.000Z",
        data: legacyData,
      }),
    });
    expect((await parityView.readLatest("oura.activity")).kind).toBe("file");
    expect(parityView.verdictFor("oura.activity")[0]).toMatchObject({
      comparisonCase: "same_time",
      reason: { reason: "field_mismatch" },
    });
  });

  it("records a newer file fallback when the canonical projection becomes unavailable", async () => {
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);
    const projected = await view.readLatest("oura.activity");
    expect(projected.kind).toBe("canonical");
    if (projected.kind !== "canonical") return;
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "oura/activity/old.json",
      "oura.activity",
      "2026-10-01T00:00:00.000Z",
      1,
    );
    const parityView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead: async () => projected.envelope,
    });
    expect((await parityView.readLatest("oura.activity")).kind).toBe(
      "canonical",
    );
    store.replaceStream({
      instance: "conn_a",
      stream: "activity",
      method: "oura",
      generation: 1,
      primaryKey: ["id"],
      emittedAt: "2026-10-02T00:00:00.000Z",
      envelopes: [],
    });
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "oura/activity/new.json",
      "oura.activity",
      "2026-10-02T00:00:00.000Z",
      1,
    );
    expect((await parityView.readLatest("oura.activity")).kind).toBe("file");
    expect(parityView.verdictFor("oura.activity")[0]).toMatchObject({
      verdict: "not_covered",
      reason: { reason: "projection_unavailable" },
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

  it.each(["budget", "invalid bytes"] as const)(
    "serves the current legacy head around Claude blob %s failures only before takeover",
    async (failure) => {
      addLegacyClaudeHead(db);
      const legacyRows = db.prepare("SELECT * FROM data_files").all();
      connect(store, "conn_claude", "anthropic", CLAUDE);
      const blobs = addClaudeProjects(store, failure === "budget" ? 3 : 1);
      const oversized = 22 * 1024 * 1024;

      const setSize = (blob: (typeof blobs)[number], size: number) => {
        const row = db
          .prepare(
            "SELECT data FROM pdpp_records WHERE instance = ? AND stream = ? AND record_key = ?",
          )
          .get("conn_claude", "projects", blob.key) as { data: string };
        const data = JSON.parse(row.data) as {
          blob_ref: { size_bytes: number };
        };
        data.blob_ref.size_bytes = size;
        db.prepare(
          "UPDATE pdpp_records SET data = ? WHERE instance = ? AND stream = ? AND record_key = ?",
        ).run(JSON.stringify(data), "conn_claude", "projects", blob.key);
        db.prepare(
          "UPDATE pdpp_blobs SET size_bytes = ? WHERE blob_id = ?",
        ).run(size, blob.blobId);
      };

      const makeFailure = () => {
        if (failure === "invalid bytes") {
          db.prepare(
            "UPDATE pdpp_blob_bytes SET bytes = ? WHERE blob_id = ?",
          ).run(Buffer.from("corrupt"), blobs[0]!.blobId);
          return;
        }
        for (const blob of blobs) setSize(blob, oversized);
      };
      const clearFailure = () => {
        if (failure === "invalid bytes") {
          db.prepare(
            "UPDATE pdpp_blob_bytes SET bytes = ? WHERE blob_id = ?",
          ).run(Buffer.from(blobs[0]!.bytes), blobs[0]!.blobId);
          return;
        }
        for (const blob of blobs)
          setSize(blob, blob.project.blob_ref.size_bytes);
      };

      makeFailure();
      expect(await view.readLatest("claude.projects")).toEqual({
        kind: "file",
      });
      expect(view.listingFor("claude.projects")).toEqual({ kind: "file" });
      expect(db.prepare("SELECT * FROM data_files").all()).toEqual(legacyRows);
      expect(db.prepare("SELECT * FROM legacy_scope_takeovers").all()).toEqual(
        [],
      );

      clearFailure();
      expect((await view.readLatest("claude.projects")).kind).toBe("canonical");
      expect(
        db.prepare("SELECT * FROM legacy_scope_takeovers").all(),
      ).not.toEqual([]);

      makeFailure();
      expect((await view.readLatest("claude.projects")).kind).toBe("refused");
    },
  );

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
