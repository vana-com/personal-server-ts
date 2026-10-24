import Database from "better-sqlite3";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { homedir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/node";
import {
  createLegacyScopeView,
  type LegacyScopeAuthority,
  type LegacyCoverageVerdict,
} from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { initializeDatabase } from "./index-schema.js";
import { createIndexManager } from "./index-manager.js";
import { createNodeDataStorage } from "./node-data-storage.js";

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

const OPT_IN: ReadonlySet<string> = new Set(["oura-browser"]);

describe("legacy scope view over the real SQLite record store", () => {
  let db: InstanceType<typeof Database>;
  let store: Store;
  let view: ReturnType<typeof createLegacyScopeView>;
  let persistentDir: string | undefined;

  beforeEach(() => {
    db = initializeDatabase(":memory:");
    store = createSqliteRecordStore(db);
    view = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
    });
  });
  afterEach(() => {
    store.close();
    if (persistentDir) {
      rmSync(persistentDir, { recursive: true, force: true });
      persistentDir = undefined;
    }
  });

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

  describe("a cached confirmation while another connection commits", () => {
    const covered: LegacyCoverageVerdict = {
      covered: true,
      comparisonCase: "same_time",
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
      appliedExceptions: [],
      missingEntityCount: 0,
      mismatchedFieldPaths: [],
      legacyBytes: 100,
      canonicalBytes: 100,
      byteDelta: 0,
    };

    function twoConnections() {
      const dir = mkdtempSync(join(tmpdir(), "legacy-authority-"));
      const path = join(dir, "index.db");
      const reader = initializeDatabase(path);
      const readerStore = createSqliteRecordStore(reader);
      const writer = initializeDatabase(path);
      reader
        .prepare(
          "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
        )
        .run(
          "oura/sleep/old.json",
          "oura.sleep",
          "2026-06-08T18:05:53.547Z",
          1,
        );
      const authority = createLegacyScopeAuthority(reader);
      const head = authority.eligibleLegacyHead("oura.sleep")!;
      const verdict = (
        cached: boolean,
        coverage: LegacyCoverageVerdict = covered,
      ) => ({
        instance: "conn_a",
        generation: 1,
        writeClock: authority.writeClock(),
        arrivalRevision: authority.arrivalRevision(),
        canonicalCursor: "0:0:receipt:revision:1",
        coverage,
        cached,
      });
      // Commits an unrelated scope from the other connection, after the
      // confirmation has taken its read snapshot.
      const commitElsewhere = () => {
        writer
          .prepare(
            "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
          )
          .run(
            `other/${Math.random()}.json`,
            "other.scope",
            "2026-06-09T00:00:00.000Z",
            1,
          );
        return true;
      };
      const close = () => {
        readerStore.close();
        writer.close();
        rmSync(dir, { recursive: true, force: true });
      };
      return { reader, authority, head, verdict, commitElsewhere, close };
    }

    it("confirms a takeover that already names its method", () => {
      const t = twoConnections();
      try {
        expect(
          t.authority.confirmRead(
            "oura.sleep",
            t.head,
            () => true,
            "oura",
            t.verdict(false),
          ),
        ).toBe(true);
        expect(
          t.authority.confirmRead(
            "oura.sleep",
            t.head,
            t.commitElsewhere,
            "oura",
            t.verdict(true),
          ),
        ).toBe(true);
      } finally {
        t.close();
      }
    });

    it("names the method of an older unknown record without a snapshot conflict", () => {
      const t = twoConnections();
      try {
        t.reader
          .prepare(
            `INSERT INTO legacy_scope_takeovers
              (scope, instance, generation, superseded_version, superseded_cas_revision, superseded_collected_at, superseded_path)
              VALUES ('oura.sleep', 'conn_a', 1, 1, 1, '2026-06-08T18:05:53.547Z', 'oura/sleep/old.json')`,
          )
          .run();
        expect(
          t.authority.confirmRead(
            "oura.sleep",
            t.head,
            () => true,
            "oura",
            t.verdict(true),
          ),
        ).toBe(true);
        expect(t.authority.hasMethodTakeover("oura.sleep", "oura")).toBe(true);
      } finally {
        t.close();
      }
    });

    it("does not lock a scope from a cached not-covered verdict", () => {
      const t = twoConnections();
      const notCovered: LegacyCoverageVerdict = {
        ...covered,
        covered: false,
        reason: "missing_entity",
        reasonCounts: { ...covered.reasonCounts, missing_entity: 1 },
        missingEntityCount: 1,
      };
      try {
        expect(
          t.authority.confirmRead(
            "oura.sleep",
            t.head,
            () => true,
            "oura",
            t.verdict(false, notCovered),
          ),
        ).toBe(true);
        expect(
          t.authority.confirmRead(
            "oura.sleep",
            t.head,
            () => true,
            "oura",
            t.verdict(true, notCovered),
          ),
        ).toBe(true);
        expect(t.authority.hasCanonicalAuthority("oura.sleep")).toBe(false);
      } finally {
        t.close();
      }
    });
  });

  it("persists provenance-backed omission evidence in the verdict ledger", () => {
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run("oura/sleep/old.json", "oura.sleep", "2026-06-08T18:05:53.547Z", 1);
    const authority = createLegacyScopeAuthority(db);
    const head = authority.eligibleLegacyHead("oura.sleep")!;
    const omission = {
      path: "$.sleepPeriods[].type",
      reason: "off_enum_type",
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
      appliedExceptions: [omission],
      missingEntityCount: 0,
      mismatchedFieldPaths: [],
      legacyBytes: 100,
      canonicalBytes: 100,
      byteDelta: 0,
    };
    expect(
      authority.confirmRead("oura.sleep", head, () => true, "oura", {
        instance: "conn_a",
        generation: 1,
        writeClock: authority.writeClock(),
        arrivalRevision: authority.arrivalRevision(),
        canonicalCursor: "0:0:receipt:revision:5",
        coverage,
        cached: false,
      }),
    ).toBe(true);
    // The takeover names the method whose read proved it.
    expect(
      db
        .prepare(
          "SELECT instance, generation, method FROM legacy_scope_takeovers WHERE scope = ?",
        )
        .all("oura.sleep"),
    ).toEqual([{ instance: "conn_a", generation: 1, method: "oura" }]);
    expect(authority.hasMethodTakeover("oura.sleep", "oura")).toBe(true);
    expect(authority.hasMethodTakeover("oura.sleep", "oura-browser")).toBe(
      false,
    );
    expect(authority.verdictFor("oura.sleep")[0]).toMatchObject({
      verdict: "covered",
      comparisonCase: "canonical_newer",
      appliedExceptions: [omission],
    });
    expect(
      authority.cachedVerdict(
        "oura.sleep",
        "conn_a",
        1,
        head.id,
        "0:0:receipt:revision:5",
      )?.appliedExceptions,
    ).toEqual([omission]);
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

  it("keeps known same-organization profile metadata while delivering newer live Claude messages", async () => {
    connect(store, "live", "anthropic-live", CLAUDE);
    for (const [stream, data] of [
      [
        "account_plan",
        { id: "account_plan", account_id: "org", plan_display_name: null },
      ],
      [
        "conversations",
        { id: "existing", title: "Existing chat", message_count: 1 },
      ],
      [
        "messages",
        {
          id: "message",
          conversation_id: "existing",
          role: "human",
          content: "Actual message",
          attachments: [],
        },
      ],
    ] as const) {
      store.ingestBatch(
        [
          {
            instance: "live",
            stream,
            key: data.id,
            data,
            emitted_at: CLAUDE_COLLECTED,
          },
        ],
        () => "mutable_state",
        () => ["id"],
        { method: "anthropic-live", generation: 1 },
      );
    }
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "claude/conversations/old.json",
      "claude.conversations",
      "2026-09-01T00:00:00.000Z",
      1,
    );
    const makeView = () =>
      createLegacyScopeView({
        authority: createLegacyScopeAuthority(db),
        records: store,
        configuredMethods: (sourceId) =>
          sourceId === CLAUDE ? ["anthropic-live"] : [],
        readLegacyHead: async (head) => ({
          version: "1.0",
          scope: "claude.conversations",
          collectedAt: "2026-09-01T00:00:00.000Z",
          data: {
            organizationId: head.path.includes("other") ? "other-org" : "org",
            profile: { name: "Known reader", plan: "Known team" },
            source: "official-export",
            total: 0,
            messageTotal: 0,
            conversations: [],
          },
        }),
      });
    const liveView = makeView();
    for (const current of [liveView, liveView, makeView()]) {
      expect(await current.readLatest("claude.conversations")).toMatchObject({
        kind: "canonical",
        envelope: {
          data: {
            organizationId: "org",
            profile: { name: "Known reader", plan: "Known team" },
            source: "live-session",
            total: 1,
            conversations: [
              { id: "existing", messages: [{ content: "Actual message" }] },
            ],
          },
        },
      });
    }
    // A new file from another organization is history; it cannot lend metadata.
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "claude/conversations/other.json",
      "claude.conversations",
      "2026-09-02T00:00:00.000Z",
      1,
    );
    expect(await makeView().readLatest("claude.conversations")).toMatchObject({
      kind: "canonical",
      envelope: {
        data: {
          organizationId: "org",
          profile: { name: "Known reader", plan: "Known team" },
        },
      },
    });
  });

  describe("live Claude history with an unknown message count", () => {
    // anthropic-live 0.3.6 writes message_count: null when the run did not
    // read the conversation detail; the projection reports that row partial.
    function ingest(stream: string, data: Record<string, unknown>) {
      store.ingestBatch(
        [
          {
            instance: "live",
            stream,
            key: String(data.id),
            data,
            emitted_at: CLAUDE_COLLECTED,
          },
        ],
        () => "mutable_state",
        () => ["id"],
        { method: "anthropic-live", generation: 1 },
      );
    }
    function seed(messageCount: number | null) {
      connect(store, "live", "anthropic-live", CLAUDE);
      ingest("account_plan", {
        id: "account_plan",
        account_id: "org",
        plan_display_name: null,
      });
      ingest("conversations", {
        id: "existing",
        title: "Existing chat",
        message_count: messageCount,
      });
      ingest("messages", {
        id: "message",
        conversation_id: "existing",
        role: "human",
        content: "Actual message",
        attachments: [],
      });
      db.prepare(
        "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
      ).run(
        "claude/conversations/old.json",
        "claude.conversations",
        "2026-09-01T00:00:00.000Z",
        1,
      );
    }
    let legacyData: Record<string, unknown> = {
      organizationId: "org",
      profile: { name: null, plan: null },
      source: "official-export",
      total: 0,
      messageTotal: 0,
      conversations: [],
    };
    const makeView = () =>
      createLegacyScopeView({
        authority: createLegacyScopeAuthority(db),
        records: store,
        configuredMethods: (sourceId) =>
          sourceId === CLAUDE ? ["anthropic-live"] : [],
        readLegacyHead: async () => ({
          version: "1.0",
          scope: "claude.conversations",
          collectedAt: "2026-09-01T00:00:00.000Z",
          data: legacyData,
        }),
      });

    it("cannot take over from the legacy file, on first, repeated or recreated reads", async () => {
      seed(null);
      const view = makeView();
      for (const current of [view, view, makeView()]) {
        expect(await current.readLatest("claude.conversations")).toEqual({
          kind: "file",
          deletion: "canonical",
        });
      }
      expect(
        createLegacyScopeAuthority(db)
          .verdictFor("claude.conversations")
          .filter((row) => row.verdict === "covered"),
      ).toEqual([]);
    });

    it("keeps serving the canonical view when a partial row appears after takeover", async () => {
      seed(1);
      expect(await makeView().readLatest("claude.conversations")).toMatchObject(
        { kind: "canonical" },
      );
      ingest("conversations", {
        id: "later",
        title: "Later chat",
        message_count: null,
      });
      const view = makeView();
      for (const current of [view, view, makeView()]) {
        expect(await current.readLatest("claude.conversations")).toMatchObject({
          kind: "canonical",
          envelope: {
            data: {
              conversations: [
                { id: "existing", messageCount: 1 },
                { id: "later", messageCount: 0, messages: [] },
              ],
            },
          },
        });
      }
    });

    it("keeps serving the canonical view when a taken-over conversation loses its message count", async () => {
      seed(1);
      const first = await makeView().readLatest("claude.conversations");
      expect(first.kind).toBe("canonical");
      // A legacy file holding that same conversation is covered and taken over.
      legacyData = first.kind === "canonical" ? first.envelope.data : {};
      db.prepare(
        "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
      ).run(
        "claude/conversations/same.json",
        "claude.conversations",
        "2026-09-02T00:00:00.000Z",
        1,
      );
      expect(await makeView().readLatest("claude.conversations")).toMatchObject(
        { kind: "canonical" },
      );
      // The next run did not read its detail.
      ingest("conversations", {
        id: "existing",
        title: "Existing chat",
        message_count: null,
      });
      const view = makeView();
      for (const current of [view, view, makeView()]) {
        expect(await current.readLatest("claude.conversations")).toMatchObject({
          kind: "canonical",
          envelope: {
            data: {
              conversations: [
                {
                  id: "existing",
                  messageCount: 1,
                  messages: [{ content: "Actual message" }],
                },
              ],
            },
          },
        });
      }
    });

    it("keeps a proven message deletion after takeover when the count becomes unknown", async () => {
      seed(1);
      const first = await makeView().readLatest("claude.conversations");
      expect(first.kind).toBe("canonical");
      legacyData = first.kind === "canonical" ? first.envelope.data : {};
      db.prepare(
        "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
      ).run(
        "claude/conversations/same.json",
        "claude.conversations",
        "2026-09-02T00:00:00.000Z",
        1,
      );
      expect(await makeView().readLatest("claude.conversations")).toMatchObject(
        { kind: "canonical" },
      );
      // A later, receipt-backed full replacement drops the message and does
      // not know the conversation's count. A partial row is still present,
      // so it does not undo the receipts' proof of the deletion.
      const later = "2026-09-20T00:00:00.000Z";
      for (const [stream, rows] of [
        [
          "account_plan",
          [{ id: "account_plan", account_id: "org", plan_display_name: null }],
        ],
        [
          "conversations",
          [{ id: "existing", title: "Existing chat", message_count: null }],
        ],
        ["messages", []],
      ] as const) {
        store.replaceStream({
          instance: "live",
          stream,
          method: "anthropic-live",
          generation: 1,
          primaryKey: ["id"],
          emittedAt: later,
          sourceCollectedAt: later,
          envelopes: rows.map((data) => ({
            instance: "live",
            stream,
            key: data.id,
            data,
            emitted_at: later,
          })),
        });
      }
      const view = makeView();
      for (const current of [view, view, makeView()]) {
        expect(await current.readLatest("claude.conversations")).toMatchObject({
          kind: "canonical",
          envelope: {
            data: {
              conversations: [
                { id: "existing", messageCount: 0, messages: [] },
              ],
            },
          },
        });
      }
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
      deletion: "canonical",
    });
    expect(parityView.verdictFor("claude.conversations")[0]).toMatchObject({
      verdict: "not_covered",
      reason: { reason: "missing_raw_blob" },
      reasonCounts: { missing_raw_blob: 1 },
    });
  });

  it("counts missing Claude raw blobs across mixed populations without relabeling mismatches", async () => {
    connect(store, "conn_claude", "anthropic", CLAUDE);
    const validProjects = addClaudeProjects(store);
    const validProject = validProjects[0]!;
    const put = (
      stream: string,
      rows: { key: string; data: Record<string, unknown> }[],
    ) =>
      store.replaceStream({
        instance: "conn_claude",
        stream,
        method: "anthropic",
        generation: 1,
        primaryKey: ["id"],
        emittedAt: CLAUDE_COLLECTED,
        sourceCollectedAt: CLAUDE_COLLECTED,
        envelopes: rows.map(({ key, data }) => ({
          instance: "conn_claude",
          stream,
          key,
          data,
          emitted_at: CLAUDE_COLLECTED,
        })),
      });
    put("conversations", [
      { key: "cv1", data: { id: "cv1", title: "One", message_count: 0 } },
      { key: "cv2", data: { id: "cv2", title: "Two", message_count: 0 } },
    ]);
    put("projects", [
      { key: "project-missing-1", data: { id: "project-missing-1" } },
      { key: "project-missing-2", data: { id: "project-missing-2" } },
      { key: validProject.key, data: validProject.project },
    ]);
    for (const [scope, path] of [
      ["claude.conversations", "claude/conversations/old.json"],
      ["claude.projects", "claude/projects/old.json"],
    ] as const) {
      db.prepare(
        "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
      ).run(path, scope, "2026-09-01T00:00:00.000Z", 1);
    }
    expect(
      createLegacyScopeAuthority(db).eligibleLegacyHead("claude.conversations"),
    ).toMatchObject({
      path: "claude/conversations/old.json",
    });
    expect(db.prepare("SELECT * FROM legacy_scope_takeovers").all()).toEqual(
      [],
    );
    const legacyHead = (scope: string) => ({
      version: "1.0",
      scope,
      collectedAt: "2026-09-01T00:00:00.000Z",
      data: scope.endsWith("projects")
        ? { projects: [] }
        : { conversations: [] },
    });
    const readLegacy = vi.fn(async (head: { path: string }) =>
      legacyHead(
        head.path.includes("/projects/")
          ? "claude.projects"
          : "claude.conversations",
      ),
    );
    const parityView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead: readLegacy,
    });

    expect(parityView.listingFor("claude.conversations")).toEqual({
      kind: "file",
      deletion: "canonical",
    });
    const conversationRead = await parityView.readLatest(
      "claude.conversations",
    );
    expect(readLegacy).toHaveBeenCalled();
    expect(conversationRead).toEqual({ kind: "file", deletion: "canonical" });
    expect(parityView.verdictFor("claude.conversations")[0]).toMatchObject({
      verdict: "not_covered",
      reason: { reason: "missing_raw_blob" },
      reasonCounts: { missing_raw_blob: 2 },
    });
    expect(await parityView.readLatest("claude.projects")).toEqual({
      kind: "file",
      deletion: "canonical",
    });
    expect(parityView.verdictFor("claude.projects")[0]).toMatchObject({
      verdict: "not_covered",
      reason: { reason: "missing_raw_blob" },
      reasonCounts: { missing_raw_blob: 2 },
    });
    expect(store.findBlobReferences(validProject.blobId)).toEqual([
      {
        instance: "conn_claude",
        stream: "projects",
        recordKey: validProject.key,
      },
    ]);

    connect(store, "conn_strava", "strava", STRAVA);
    replace(store, "conn_strava", "activities", ["same-id"], {
      method: "strava",
    });
    const projected = await view.readLatest("strava.activities");
    expect(projected.kind).toBe("canonical");
    if (projected.kind !== "canonical") return;
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "strava/activities/old.json",
      "strava.activities",
      "2026-09-09T07:00:00.000Z",
      1,
    );
    const mismatchView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead: async () => ({
        ...projected.envelope,
        data: {
          ...projected.envelope.data,
          activities: [{ id: "same-id", day: "2026-09-01", score: 81 }],
        },
      }),
    });
    await mismatchView.readLatest("strava.activities");
    expect(mismatchView.verdictFor("strava.activities")).toEqual([]);
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
    expect(parityView.verdictFor("claude.projects")).toEqual([]);
  });

  it("keeps scope authority across a connection replacement", async () => {
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
    expect(parityView.listingFor("oura.activity").kind).toBe("canonical");
    expect((await parityView.readLatest("oura.activity")).kind).toBe(
      "canonical",
    );
    store.deleteConnection("conn_a");
    connect(store, "conn_b", "oura");
    replace(store, "conn_b", "activity", ["a1"]);
    expect((await parityView.readLatest("oura.activity")).kind).toBe(
      "canonical",
    );
    expect(db.prepare("SELECT * FROM legacy_scope_takeovers").all()).toEqual(
      [],
    );
    ingest(store, "conn_b", "a1", "2026-09-10T08:00:00.000Z", 91);
    expect(parityView.listingFor("oura.activity").kind).toBe("canonical");
    expect((await parityView.readLatest("oura.activity")).kind).toBe(
      "canonical",
    );
    expect(parityView.listingFor("oura.activity").kind).toBe("canonical");
    expect(parityView.verdictFor("oura.activity")).toEqual([]);
  });

  it("keeps scope authority through a covering connection generation replacement", async () => {
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
    replace(store, "conn_a", "activity", ["a1"], { generation: 2 });

    expect((await parityView.readLatest("oura.activity")).kind).toBe(
      "canonical",
    );
    expect(parityView.listingFor("oura.activity").kind).toBe("canonical");
    expect(
      db
        .prepare(
          "SELECT generation FROM legacy_scope_takeovers WHERE scope = ? AND instance = ?",
        )
        .all("oura.activity", "conn_a"),
    ).toEqual([]);
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

    expect((await parityView.readLatest("oura.activity")).kind).toBe(
      "canonical",
    );
    expect(parityView.listingFor("oura.activity").kind).toBe("canonical");
  });

  it("honors a reset that commits while a cache-miss evaluation is in flight", async () => {
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "oura/activity/old.json",
      "oura.activity",
      "2026-10-01T00:00:00.000Z",
      1,
    );
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);
    const projected = await view.readLatest("oura.activity");
    expect(projected.kind).toBe("canonical");
    if (projected.kind !== "canonical") return;
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

    expect(await inFlight).toEqual({ kind: "file", deletion: "canonical" });
    expect(parityView.verdictFor("oura.activity")).toEqual([]);
    expect(db.prepare("SELECT * FROM legacy_scope_takeovers").all()).toEqual(
      [],
    );
  });

  it("keeps canonical authority after a later legacy file appears", async () => {
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
    const readLegacyHead = vi.fn(async () => projected.envelope);
    const parityView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead,
    });
    const listRecords = vi.spyOn(store, "listRecords");

    expect((await parityView.readLatest("oura.activity")).kind).toBe(
      "canonical",
    );
    expect((await parityView.readLatest("oura.activity")).kind).toBe(
      "canonical",
    );
    expect(readLegacyHead).not.toHaveBeenCalled();
    expect(listRecords).toHaveBeenCalled();
  });

  it("keeps listing after canonical data changes under locked authority", async () => {
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
    replace(store, "conn_a", "activity", ["a1"], {
      score: 90,
      collectedAt: "2026-09-12T07:00:00.000Z",
    });
    expect(parityView.listingFor("oura.activity").kind).toBe("canonical");
    expect((await parityView.readLatest("oura.activity")).kind).toBe(
      "canonical",
    );
    expect(parityView.listingFor("oura.activity").kind).toBe("canonical");
  });

  it("ignores a legacy write that arrives during a read after takeover", async () => {
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);
    const projected = await view.readLatest("oura.activity");
    expect(projected.kind).toBe("canonical");
    if (projected.kind !== "canonical") return;
    db.prepare(
      "DELETE FROM legacy_scope_canonical_authority WHERE scope = ?",
    ).run("oura.activity");
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "oura/activity/old.json",
      "oura.activity",
      "2026-09-01T00:00:00.000Z",
      1,
    );
    const initialView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead: async () => projected.envelope,
    });
    expect((await initialView.readLatest("oura.activity")).kind).toBe(
      "canonical",
    );
    replace(store, "conn_a", "activity", ["a1"], {
      score: 90,
      collectedAt: "2026-09-12T07:00:00.000Z",
    });

    let markStarted!: () => void;
    let releaseRead!: () => void;
    const started = new Promise<void>((resolve) => (markStarted = resolve));
    const gate = new Promise<void>((resolve) => (releaseRead = resolve));
    const racingView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead: async (head) => {
        expect(head.path).toBe("oura/activity/old.json");
        markStarted();
        await gate;
        return projected.envelope;
      },
    });
    const inFlight = racingView.readLatest("oura.activity");
    await started;
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "oura/activity/new.json",
      "oura.activity",
      "2026-10-02T00:00:00.000Z",
      1,
    );
    releaseRead();

    expect((await inFlight).kind).toBe("canonical");
    expect(racingView.listingFor("oura.activity").kind).toBe("canonical");
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
    expect(listRecords.mock.calls.length).toBeGreaterThan(callsAfterWarm);

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
    expect(listRecords.mock.calls.length).toBeGreaterThan(callsAfterRefresh);
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

  it("keeps late legacy data out of a scope with canonical authority", async () => {
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
    const readLegacyHead = vi.fn(async () => initialProjection.envelope);
    const parityView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead,
    });

    expect((await parityView.readLatest("strava.activities")).kind).toBe(
      "canonical",
    );
    expect(parityView.verdictFor("strava.activities")).toEqual([]);
    expect(readLegacyHead).not.toHaveBeenCalled();

    ingest(store, "conn_a", "a", "2026-09-10T07:00:00.000Z", 80, {
      stream: "activities",
      method: "strava",
    });
    expect(store.listArrivalOrder("conn_a", "activities")).toEqual(["b", "a"]);
    await parityView.readLatest("strava.activities");

    expect((await parityView.readLatest("strava.activities")).kind).toBe(
      "canonical",
    );
    expect(parityView.verdictFor("strava.activities")).toEqual([]);
  });

  it("ignores a legacy write after canonical authority", async () => {
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
    const readLegacyHead = vi.fn(async () => ({
      ...projected.envelope,
      data: { values: ["legacy-only"] } as typeof projected.envelope.data,
    }));
    const parityView = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead,
    });
    const listRecords = vi.spyOn(store, "listRecords");

    expect((await parityView.readLatest("oura.activity")).kind).toBe(
      "canonical",
    );
    expect(readLegacyHead).not.toHaveBeenCalled();
    expect(listRecords).toHaveBeenCalled();
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
    expect((await parityView.readLatest("oura.activity")).kind).toBe("refused");
    expect(parityView.verdictFor("oura.activity")).toEqual([]);
  });

  it("leaves a scope to its file until a connection of its methods holds its streams", async () => {
    connect(store, "conn_a", "oura");
    expect(await view.readLatest("oura.activity")).toEqual({
      kind: "file",
      deletion: "file",
    });
    expect(await view.readLatest("notes.manual")).toEqual({
      kind: "file",
      deletion: "file",
    });
    expect(view.listingFor("oura.activity")).toEqual({
      kind: "file",
      deletion: "file",
    });

    // Another stream's data does not convert this scope ...
    replace(store, "conn_a", "readiness", ["r1"]);
    expect(await view.readLatest("oura.activity")).toEqual({
      kind: "file",
      deletion: "file",
    });
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

    expect(await view.readLatest("oura.activity")).toEqual({
      kind: "file",
      deletion: "file",
    });
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

    expect(view.listingFor("oura.activity")).toEqual({
      kind: "file",
      deletion: "canonical",
    });
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
      fullName: "",
      bio: "",
      company: "",
      location: "",
      website: "",
      avatarUrl: "",
      followers: 0,
      following: 0,
      repositoryCount: 0,
      profileUrl: "https://github.com/current-user",
      pinnedRepositories: [],
      organizations: [],
      achievements: [],
      contributionsLastYear: null,
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
        deletion: "file",
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
    expect(
      db.prepare("SELECT scope FROM legacy_scope_canonical_authority").all(),
    ).toEqual([{ scope: "oura.activity" }]);
  });

  it("keeps later legacy writes as history after takeover, including after restart", async () => {
    const tempRoot = join(homedir(), ".tmp");
    mkdirSync(tempRoot, { recursive: true });
    persistentDir = mkdtempSync(join(tempRoot, "ps-legacy-authority-"));
    const path = join(persistentDir, "index.db");
    store.close();
    db = initializeDatabase(path);
    store = createSqliteRecordStore(db);
    view = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
    });
    db.prepare(
      `INSERT INTO data_files (scope, version, cas_revision, collected_at, path)
         VALUES (?, ?, ?, ?, ?)`,
    ).run(
      "oura.activity",
      1,
      1,
      "2026-01-01T00:00:00.000Z",
      "oura/activity/old.json",
    );
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);
    expect((await view.readLatest("oura.activity")).kind).toBe("canonical");

    const storage = createNodeDataStorage({
      indexManager: createIndexManager(db),
      hierarchyOptions: { dataDir: join(persistentDir, "data") },
    });
    const remoteLegacy = createDataFileEnvelope(
      "oura.activity",
      "2026-10-01T00:00:00.000Z",
      { days: [{ id: "remote-only" }] },
    );
    const replica = await storage.commitVersion!({
      kind: "replica",
      envelope: remoteLegacy,
      metadata: {
        schemaId: null,
        dataPointId: `0x${"11".repeat(32)}`,
        version: 2,
      },
    });
    expect(replica.kind).toBe("stored");
    expect(
      db
        .prepare("SELECT path FROM data_files WHERE scope = ? ORDER BY id")
        .all("oura.activity"),
    ).toEqual([
      { path: "oura/activity/old.json" },
      { path: replica.kind === "stored" ? replica.entry.path : "" },
    ]);
    expect((await view.readLatest("oura.activity")).kind).toBe("canonical");
    expect(view.listingFor("oura.activity").kind).toBe("canonical");

    store.close();
    db = initializeDatabase(path);
    store = createSqliteRecordStore(db);
    view = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
    });
    expect((await view.readLatest("oura.activity")).kind).toBe("canonical");
    expect(view.listingFor("oura.activity").kind).toBe("canonical");
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
    expect(await view.readLatest("oura.activity")).toEqual({
      kind: "file",
      deletion: "canonical",
    });
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
        deletion: "canonical",
      });
      expect(view.listingFor("claude.projects")).toEqual({
        kind: "file",
        deletion: "canonical",
      });
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

    expect(await view.readLatest("oura.activity")).toEqual({
      kind: "file",
      deletion: "canonical",
    });
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
      deletion: "canonical",
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
    expect(await view.readLatest("oura.activity")).toEqual({
      kind: "file",
      deletion: "canonical",
    });
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
    expect(await view.readLatest("oura.activity")).toEqual({
      kind: "file",
      deletion: "canonical",
    });
    expect(view.listingFor("oura.activity")).toEqual({
      kind: "file",
      deletion: "canonical",
    });
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

  function legacyHead(
    scope: string,
    path: string,
    producer: string | null = null,
  ) {
    db.prepare(
      `INSERT INTO data_files (scope, version, cas_revision, collected_at, path, producer)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(scope, 7, 9, "2026-01-01T00:00:00.000Z", path, producer);
  }

  describe("an opt-in oura-browser does not take a scope over from a legacy file", () => {
    beforeEach(() => {
      view = createLegacyScopeView({
        authority: createLegacyScopeAuthority(db),
        records: store,
        configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
        optInMethods: OPT_IN,
      });
    });

    it("keeps the file for a covered projection, and still owns the scope for deletion safety", async () => {
      legacyHead("oura.activity", "oura/activity/old.json");
      connect(store, "conn_b", "oura-browser");
      replace(store, "conn_b", "activity", ["a1"], { method: "oura-browser" });

      expect(await view.readLatest("oura.activity")).toEqual({
        kind: "file",
        deletion: "file",
      });
      expect(view.listingFor("oura.activity")).toEqual({
        kind: "file",
        deletion: "file",
      });
      expect(view.listCanonicalScopes(undefined)).toEqual([]);
      // The rows exist; a legacy-only deletion would resurface them.
      expect(view.ownsScope("oura.activity")).toBe(true);
      expect(db.prepare("SELECT * FROM legacy_scope_takeovers").all()).toEqual(
        [],
      );
    });

    it("keeps the file when two oura-browser accounts hold data (no ambiguity)", async () => {
      connect(store, "conn_b", "oura-browser");
      connect(store, "conn_c", "oura-browser");
      replace(store, "conn_b", "activity", ["a1"], { method: "oura-browser" });
      replace(store, "conn_c", "sleep", ["s1"], { method: "oura-browser" });

      for (const scope of ["oura.activity", "oura.sleep"]) {
        legacyHead(scope, `${scope}/old.json`);
        expect(await view.readLatest(scope)).toEqual({
          kind: "file",
          deletion: "file",
        });
        expect(view.listingFor(scope)).toEqual({
          kind: "file",
          deletion: "file",
        });
      }
    });

    it("serves the projection when there is no legacy head, and refuses two accounts", async () => {
      connect(store, "conn_b", "oura-browser");
      replace(store, "conn_b", "activity", ["a1"], { method: "oura-browser" });
      expect((await view.readLatest("oura.activity")).kind).toBe("canonical");
      expect(view.listingFor("oura.activity").kind).toBe("canonical");

      connect(store, "conn_c", "oura-browser");
      replace(store, "conn_c", "activity", ["a2"], { method: "oura-browser" });
      expect(await view.readLatest("oura.activity")).toEqual({
        kind: "refused",
        refusal: {
          status: "unavailable",
          reason: "ambiguous_connection",
          candidates: 2,
        },
      });
    });

    it("keeps an opted-in projection canonical after a legacy head appears", async () => {
      connect(store, "conn_b", "oura-browser");
      replace(store, "conn_b", "activity", ["a1"], { method: "oura-browser" });
      expect((await view.readLatest("oura.activity")).kind).toBe("canonical");
      expect(
        db.prepare("SELECT scope FROM legacy_scope_canonical_authority").all(),
      ).toEqual([{ scope: "oura.activity" }]);
      legacyHead("oura.activity", "oura/activity/later.json");
      expect((await view.readLatest("oura.activity")).kind).toBe("canonical");
      expect(view.listingFor("oura.activity").kind).toBe("canonical");
    });

    it("says so once when it keeps the file over a connection that holds synced rows", async () => {
      const info = vi.fn();
      const logged = createLegacyScopeView({
        authority: createLegacyScopeAuthority(db),
        records: store,
        configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
        optInMethods: OPT_IN,
        logger: { info },
      });
      legacyHead("oura.activity", "oura/activity/old.json");
      connect(store, "conn_b", "oura-browser");
      // Registered but never held data: nothing to report.
      expect(await logged.readLatest("oura.activity")).toEqual({
        kind: "file",
        deletion: "file",
      });
      expect(info).not.toHaveBeenCalled();

      replace(store, "conn_b", "activity", ["a1"], { method: "oura-browser" });
      await logged.readLatest("oura.activity");
      logged.listingFor("oura.activity");
      await logged.readLatest("oura.activity");
      expect(info).toHaveBeenCalledTimes(1);
      expect(info).toHaveBeenCalledWith(
        {
          scope: "oura.activity",
          legacyHeadCollectedAt: "2026-01-01T00:00:00.000Z",
          heldConnections: 1,
        },
        "Legacy file kept as the latest body; a method that opts out of takeover holds synced rows",
      );

      // A second connection that holds rows is a new fact worth one more line.
      connect(store, "conn_c", "oura-browser");
      replace(store, "conn_c", "sleep", ["s1"], { method: "oura-browser" });
      await logged.readLatest("oura.activity");
      expect(info).toHaveBeenCalledTimes(2);
      expect(info.mock.calls[1]![0]).toMatchObject({ heldConnections: 2 });
    });

    function recordTakeover(instance: string, method: string) {
      db.prepare(
        `INSERT INTO legacy_scope_takeovers
         (scope, instance, generation, method, superseded_version, superseded_cas_revision, superseded_collected_at, superseded_path)
         VALUES (?, ?, 1, ?, ?, ?, ?, ?)`,
      ).run(
        "oura.activity",
        instance,
        method,
        7,
        9,
        "2026-01-01T00:00:00.000Z",
        "oura/activity/old.json",
      );
    }

    it("serves the projection after a takeover oura-browser itself earned", async () => {
      legacyHead("oura.activity", "oura/activity/old.json");
      connect(store, "conn_b", "oura-browser");
      replace(store, "conn_b", "activity", ["a1"], { method: "oura-browser" });
      recordTakeover("conn_b", "oura-browser");
      expect((await view.readLatest("oura.activity")).kind).toBe("canonical");
    });

    it.each([
      ["another method earned on the same connection", "conn_b", "oura"],
      ["does not name its method (an older runtime)", "", ""],
    ])(
      "stays gated for a takeover that %s",
      async (_name, instance, method) => {
        legacyHead("oura.activity", "oura/activity/old.json");
        connect(store, "conn_b", "oura-browser");
        replace(store, "conn_b", "activity", ["a1"], {
          method: "oura-browser",
        });
        recordTakeover(instance, method);
        // The browser rows do not serve. The recorded takeover still marks
        // the file superseded, so the read refuses rather than serving it.
        expect(await view.readLatest("oura.activity")).toEqual({
          kind: "refused",
          refusal: {
            status: "unavailable",
            reason: "no_connection",
            candidates: 0,
          },
        });
      },
    );

    it("serves the file after the oura-browser connection is deleted or replaced", async () => {
      legacyHead("oura.activity", "oura/activity/old.json");
      connect(store, "conn_b", "oura-browser");
      replace(store, "conn_b", "activity", ["a1"], { method: "oura-browser" });
      expect(view.ownsScope("oura.activity")).toBe(true);
      store.deleteConnection("conn_b");
      expect(await view.readLatest("oura.activity")).toEqual({
        kind: "file",
        deletion: "file",
      });
      expect(view.listingFor("oura.activity")).toEqual({
        kind: "file",
        deletion: "file",
      });
      // The deleted connection's rows are gone: nothing blocks a legacy delete.
      expect(view.ownsScope("oura.activity")).toBe(false);

      connect(store, "conn_c", "oura-browser");
      replace(store, "conn_c", "activity", ["a2"], { method: "oura-browser" });
      // Rows a delete would expose, but the file is served and judged as one.
      expect(await view.readLatest("oura.activity")).toEqual({
        kind: "file",
        deletion: "file",
      });
      expect(view.listingFor("oura.activity")).toEqual({
        kind: "file",
        deletion: "file",
      });
      expect(view.ownsScope("oura.activity")).toBe(true);
    });

    it("still refuses a deleted oura-browser connection when there is no legacy file", async () => {
      connect(store, "conn_b", "oura-browser");
      replace(store, "conn_b", "activity", ["a1"], { method: "oura-browser" });
      store.deleteConnection("conn_b");
      expect(await view.readLatest("oura.activity")).toEqual({
        kind: "refused",
        refusal: {
          status: "unavailable",
          reason: "no_connection",
          candidates: 0,
        },
      });
    });
  });

  describe("every other binding keeps its automatic takeover of a legacy file", () => {
    it.each([
      {
        name: "oura-browser where it is not opt-in (a dev build)",
        scope: "oura.activity",
        seed: () => {
          connect(store, "conn_b", "oura-browser");
          replace(store, "conn_b", "activity", ["a1"], {
            method: "oura-browser",
          });
        },
      },
      {
        name: "oura (PAT method)",
        scope: "oura.activity",
        seed: () => {
          connect(store, "conn_a", "oura");
          replace(store, "conn_a", "activity", ["a1"]);
        },
      },
      {
        name: "github-browser",
        scope: "github.profile",
        seed: () => {
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
        },
      },
    ])(
      "$name: a legacy head with a complete projection goes canonical",
      async ({ scope, seed }) => {
        legacyHead(scope, `${scope}/old.json`);
        seed();
        expect((await view.readLatest(scope)).kind).toBe("canonical");
        expect(
          db.prepare("SELECT scope FROM legacy_scope_takeovers").all(),
        ).toEqual([{ scope }]);
      },
    );
  });

  it("records canonical authority once while deciding, reading and listing", async () => {
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"]);
    const before = db.prepare("SELECT total_changes() AS n").get();
    expect((await view.readLatest("oura.activity")).kind).toBe("canonical");
    view.listingFor("oura.activity");
    view.listCanonicalScopes(undefined);
    view.ownsScope("oura.readiness");
    expect(db.prepare("SELECT total_changes() AS n").get()).toEqual({
      n: before.n + 1,
    });
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
      expect(await view.readLatest("oura.activity")).toEqual({
        kind: "file",
        deletion: "file",
      });
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
