import Database from "better-sqlite3";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
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
import { createStreamDeclarationRegistry } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";

const OURA = "https://registry.pdpp.dev/sources/oura";
const GITHUB = "https://registry.pdpp.dev/sources/github";
const CLAUDE = "https://registry.pdpp.dev/sources/claude";
const STRAVA = "https://registry.pdpp.dev/sources/strava";

/** The (source, method) pairs a boot configures, as Desktop names them. */
const CONFIGURED: Record<string, string[]> = {
  [OURA]: ["oura", "oura-browser"],
  [GITHUB]: ["github-browser"],
  [CLAUDE]: ["anthropic"],
  [STRAVA]: ["strava", "strava-browser"],
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
      const verdict = (cached: boolean) => ({
        instance: "conn_a",
        generation: 1,
        writeClock: authority.writeClock(),
        arrivalRevision: authority.arrivalRevision(),
        canonicalCursor: "0:0:receipt:revision:1",
        coverage: covered,
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
    let organizationId = "org";
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
          data: {
            organizationId,
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
    // A new file from another organization cannot lend its metadata or take over.
    organizationId = "other-org";
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run(
      "claude/conversations/other.json",
      "claude.conversations",
      "2026-09-02T00:00:00.000Z",
      1,
    );
    expect(await makeView().readLatest("claude.conversations")).toEqual({
      kind: "file",
      deletion: "canonical",
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
      version: "1.0" as const,
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
    // Without a receipt, canonical collection time comes from record emission.
    db.prepare("UPDATE data_files SET collected_at = ? WHERE scope = ?").run(
      "2026-09-10T07:00:00.000Z",
      "strava.activities",
    );
    db.prepare("DELETE FROM pdpp_stream_completion WHERE instance = ?").run(
      "conn_strava",
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
    expect(mismatchView.verdictFor("strava.activities")[0]).toMatchObject({
      verdict: "not_covered",
      reason: { reason: "field_mismatch" },
      reasonCounts: { missing_raw_blob: 0, field_mismatch: 1 },
    });
  });

  it("keeps covering Claude project rows with their raw blob references", async () => {
    connect(store, "conn_claude", "anthropic", CLAUDE);
    addClaudeProjects(store);
    const projected = await view.readLatest("claude.projects");
    expect(projected.kind).toBe("canonical");
    if (projected.kind !== "canonical") return;
    addLegacyClaudeHead(db);
    // Keep this comparison-fallback test unreceipted. Complete syncs use replacement.
    db.prepare("DELETE FROM pdpp_stream_completion WHERE instance = ?").run(
      "conn_claude",
    );
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

  it("keeps replacement proof and parity verdicts isolated by connection instance", async () => {
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"], {
      collectedAt: "2026-10-02T00:00:00.000Z",
    });
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
    ).run("2026-10-03T00:00:00.000Z", "conn_a", "activity");
    expect(parityView.listingFor("oura.activity")).toEqual({ kind: "refused" });
    expect((await parityView.readLatest("oura.activity")).kind).toBe(
      "canonical",
    );
    store.deleteConnection("conn_a");
    connect(store, "conn_b", "oura");
    replace(store, "conn_b", "activity", ["a1"], {
      collectedAt: "2026-10-04T00:00:00.000Z",
    });
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
      {
        instance: "conn_b",
        verdict: "not_covered",
        reason: { reason: "field_mismatch" },
      },
    ]);
  });

  it("requires fresh completion after generation replacement before replacing the unchanged head", async () => {
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"], {
      collectedAt: "2026-10-02T00:00:00.000Z",
    });
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
    expect((await parityView.readLatest("oura.activity")).kind).toBe("refused");
    expect(parityView.listingFor("oura.activity")).toEqual({ kind: "refused" });
    replace(store, "conn_a", "activity", ["a1"], {
      score: 91,
      generation: 2,
    });
    expect((await parityView.readLatest("oura.activity")).kind).toBe("refused");
    const staleVerdicts = parityView.verdictFor("oura.activity");
    expect(staleVerdicts).toMatchObject([
      { instance: "conn_a", generation: 2, verdict: "not_covered" },
    ]);
    replace(store, "conn_a", "activity", ["a1"], {
      score: 91,
      generation: 2,
      collectedAt: "2026-10-03T00:00:00.000Z",
    });

    const fresh = await parityView.readLatest("oura.activity");
    expect(fresh.kind).toBe("canonical");
    if (fresh.kind !== "canonical")
      throw new Error("Expected freshly completed generation");
    expect(fresh.envelope.data).toMatchObject({
      days: [{ id: "a1", score: 91 }],
    });
    expect(parityView.verdictFor("oura.activity")).toEqual(staleVerdicts);
    expect(
      db
        .prepare(
          "SELECT generation FROM legacy_scope_takeovers WHERE scope = ? AND instance = ? ORDER BY generation",
        )
        .all("oura.activity", "conn_a"),
    ).toEqual([{ generation: 1 }, { generation: 2 }]);
  });

  it("requires the replacement account to complete its own sync before replacing the old head", async () => {
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["a1"], {
      collectedAt: "2026-10-02T00:00:00.000Z",
    });
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
    expect((await parityView.readLatest("oura.activity")).kind).toBe("refused");
    expect(parityView.listingFor("oura.activity")).toEqual({ kind: "refused" });
    replace(store, "conn_b", "activity", ["a1"], { score: 91 });
    expect((await parityView.readLatest("oura.activity")).kind).toBe("refused");
    const staleVerdicts = parityView.verdictFor("oura.activity");
    expect(staleVerdicts).toMatchObject([
      { instance: "conn_b", generation: 1, verdict: "not_covered" },
    ]);
    replace(store, "conn_b", "activity", ["a1"], {
      score: 91,
      collectedAt: "2026-10-03T00:00:00.000Z",
    });

    const fresh = await parityView.readLatest("oura.activity");
    expect(fresh.kind).toBe("canonical");
    if (fresh.kind !== "canonical")
      throw new Error("Expected freshly completed account");
    expect(fresh.envelope.data).toMatchObject({
      days: [{ id: "a1", score: 91 }],
    });
    expect(parityView.verdictFor("oura.activity")).toEqual(staleVerdicts);
    expect(
      db
        .prepare(
          "SELECT instance FROM legacy_scope_takeovers ORDER BY instance",
        )
        .all(),
    ).toEqual([{ instance: "conn_a" }, { instance: "conn_b" }]);
  });

  it.each([false, true])(
    "refuses stale completion without a legacy reader (prior takeover: %s)",
    async (priorTakeover) => {
      connect(store, "conn_a", "oura");
      db.prepare(
        "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
      ).run(
        "oura/activity/newer.json",
        "oura.activity",
        "2026-10-14T22:00:00.000Z",
        1,
      );
      if (priorTakeover) {
        replace(store, "conn_a", "activity", ["a1"], {
          collectedAt: "2026-10-15T00:00:00.000Z",
        });
        expect((await view.readLatest("oura.activity")).kind).toBe("canonical");
      }
      replace(store, "conn_a", "activity", ["a1"], {
        collectedAt: "2026-09-10T06:00:00.000Z",
      });
      expect((await view.readLatest("oura.activity")).kind).toBe(
        priorTakeover ? "refused" : "file",
      );
      const takeovers = db
        .prepare(
          "SELECT instance, generation, replacement_cursor FROM legacy_scope_takeovers",
        )
        .all();
      expect(takeovers).toEqual(
        priorTakeover
          ? [
              {
                instance: "conn_a",
                generation: 1,
                replacement_cursor: expect.any(String),
              },
            ]
          : [],
      );
      replace(store, "conn_a", "activity", ["a1"], {
        collectedAt: "2026-10-16T00:00:00.000Z",
      });
      expect((await view.readLatest("oura.activity")).kind).toBe("canonical");
      expect(
        db
          .prepare(
            "SELECT instance, generation, replacement_cursor FROM legacy_scope_takeovers",
          )
          .all(),
      ).toEqual([
        {
          instance: "conn_a",
          generation: 1,
          replacement_cursor: expect.any(String),
        },
      ]);
    },
  );

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
    // Keep this comparison-fallback test unreceipted. Complete syncs use replacement.
    db.prepare("DELETE FROM pdpp_stream_completion WHERE instance = ?").run(
      "conn_a",
    );
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
    // Keep this comparison-fallback test unreceipted. Complete syncs use replacement.
    db.prepare("DELETE FROM pdpp_stream_completion WHERE instance = ?").run(
      "conn_a",
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
    expect(storedCursor.canonical_cursor).toContain("canonical-legacy-view/12");
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
    // Keep this comparison-fallback test unreceipted. Complete syncs use replacement.
    db.prepare("DELETE FROM pdpp_stream_completion WHERE instance = ?").run(
      "conn_a",
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
    // Keep this comparison-fallback test unreceipted. Complete syncs use replacement.
    // Without a receipt, canonical collection time comes from record emission.
    db.prepare("UPDATE data_files SET collected_at = ? WHERE scope = ?").run(
      "2026-09-10T07:00:00.000Z",
      "strava.activities",
    );
    db.prepare("DELETE FROM pdpp_stream_completion WHERE instance = ?").run(
      "conn_a",
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
    // Keep this comparison-fallback test unreceipted. Complete syncs use replacement.
    db.prepare("DELETE FROM pdpp_stream_completion WHERE instance = ?").run(
      "conn_a",
    );
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

  it("does not rebind a non-head replacement cursor when legacy metadata changes", async () => {
    const scope = "oura.activity";
    const authority = createLegacyScopeAuthority(db);
    const insert = db.prepare(
      "INSERT INTO data_files (scope, path, collected_at, version, cas_revision) VALUES (?, ?, ?, ?, ?)",
    );
    insert.run(scope, "oura/activity/a.json", "2026-01-01T00:00:00.000Z", 7, 9);
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["fresh-only"]);
    const current = createLegacyScopeView({
      authority,
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead: async () => {
        throw new Error("Complete replacement must not read historical bodies");
      },
    });
    const canonicalSnapshot = () => ({
      rows: db.prepare("SELECT * FROM pdpp_records").all(),
      receipts: db.prepare("SELECT * FROM pdpp_stream_completion").all(),
      writeClock: authority.writeClock(),
      arrivalRevision: authority.arrivalRevision(),
    });
    const originalCanonical = canonicalSnapshot();
    expect((await current.readLatest(scope)).kind).toBe("canonical");
    const headA = authority.eligibleLegacyHead(scope);
    if (!headA) throw new Error("Missing original head");
    const originalProof = db
      .prepare(
        "SELECT replacement_cursor FROM legacy_scope_takeovers WHERE superseded_path = ?",
      )
      .get(headA.path) as { replacement_cursor: string | null } | undefined;
    if (!originalProof?.replacement_cursor)
      throw new Error("Actual completed read did not persist proof");
    expect(originalProof.replacement_cursor.startsWith(`${headA.id}:`)).toBe(
      true,
    );
    const cursor = originalProof.replacement_cursor.slice(
      String(headA.id).length + 1,
    );
    const proved = (
      head: NonNullable<ReturnType<typeof authority.eligibleLegacyHead>>,
    ) =>
      authority.hasCompletedReplacement?.(
        scope,
        head,
        "conn_a",
        1,
        "oura",
        cursor,
      );
    expect(proved(headA)).toBe(true);

    insert.run(
      scope,
      "oura/activity/b.json",
      "2026-02-01T00:00:00.000Z",
      8,
      10,
    );
    db.prepare(
      "UPDATE data_files SET version = version + 1, cas_revision = cas_revision + 1 WHERE path = ?",
    ).run(headA.path);
    const indexedBeforeBRead = db
      .prepare("SELECT * FROM data_files ORDER BY id")
      .all();
    expect((await current.readLatest(scope)).kind).toBe("canonical");
    const headB = authority.eligibleLegacyHead(scope);
    if (!headB) throw new Error("Missing newer head");
    expect(headB.path).toBe("oura/activity/b.json");
    expect(proved(headB)).toBe(true);
    expect(current.listingFor(scope).kind).toBe("canonical");
    expect(db.prepare("SELECT * FROM data_files ORDER BY id").all()).toEqual(
      indexedBeforeBRead,
    );
    expect(canonicalSnapshot()).toEqual(originalCanonical);

    // Simulate removing only B from the legacy index; A's changed revision remains.
    db.prepare("DELETE FROM data_files WHERE path = ?").run(headB.path);
    const changedA = authority.eligibleLegacyHead(scope);
    if (!changedA) throw new Error("Historical A did not remain indexed");
    expect(changedA.id).toBe(headA.id);
    expect(changedA.version).toBe(headA.version + 1);
    expect(changedA.casRevision).toBe(headA.casRevision + 1);
    const beforeReearning = db
      .prepare("SELECT * FROM data_files ORDER BY id")
      .all();
    expect({
      validProof: proved(changedA),
      canonicalListing: current.listingFor(scope).kind === "canonical",
    }).toEqual({ validProof: false, canonicalListing: false });
    expect(current.verdictFor(scope)).toEqual([]);
    expect((await current.readLatest(scope)).kind).toBe("canonical");
    expect(proved(changedA)).toBe(true);
    expect(current.listingFor(scope).kind).toBe("canonical");
    expect(db.prepare("SELECT * FROM data_files ORDER BY id").all()).toEqual(
      beforeReearning,
    );
    expect(canonicalSnapshot()).toEqual(originalCanonical);
    expect(current.verdictFor(scope)).toEqual([]);
  });

  it("automatically replaces a keyless duplicate legacy body after an accepted fresh sync", async () => {
    legacyHead("oura.activity", "oura/activity/old.json");
    const indexed = db.prepare("SELECT * FROM data_files").all();
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", ["fresh-only"], { score: 91 });
    const makeView = () =>
      createLegacyScopeView({
        authority: createLegacyScopeAuthority(db),
        records: store,
        configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
        readLegacyHead: async () => ({
          version: "1.0",
          scope: "oura.activity",
          collectedAt: "2026-01-01T00:00:00.000Z",
          data: {
            activities: [
              { score: 2 },
              { id: "old-duplicate", score: 3 },
              { id: "old-duplicate", score: 4 },
            ],
          },
        }),
      });
    const replacement = makeView();
    for (const current of [replacement, replacement, makeView()]) {
      const read = await current.readLatest("oura.activity");
      expect(read.kind).toBe("canonical");
      if (read.kind !== "canonical")
        throw new Error("accepted sync did not replace legacy body");
      expect(JSON.stringify(read.envelope.data)).toContain("fresh-only");
      expect(JSON.stringify(read.envelope.data)).not.toContain("old-duplicate");
      expect(current.listingFor("oura.activity")).toEqual({
        kind: "canonical",
        collectedAt: read.envelope.collectedAt,
      });
    }
    expect(db.prepare("SELECT * FROM data_files").all()).toEqual(indexed);
    expect(
      db
        .prepare(
          "SELECT instance, generation, method FROM legacy_scope_takeovers",
        )
        .all(),
    ).toEqual([{ instance: "conn_a", generation: 1, method: "oura" }]);
  });

  it("accepts an empty completed replacement without deleting indexed legacy files", async () => {
    legacyHead("oura.activity", "oura/activity/old.json");
    const indexed = db.prepare("SELECT * FROM data_files").all();
    connect(store, "conn_a", "oura");
    replace(store, "conn_a", "activity", []);
    const makeView = () =>
      createLegacyScopeView({
        authority: createLegacyScopeAuthority(db),
        records: store,
        configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
        readLegacyHead: async () => ({
          version: "1.0",
          scope: "oura.activity",
          collectedAt: "2026-01-01T00:00:00.000Z",
          data: { activities: [{ old: true }] },
        }),
      });
    for (const view of [makeView(), makeView()]) {
      const read = await view.readLatest("oura.activity");
      expect(read.kind).toBe("canonical");
      if (read.kind !== "canonical")
        throw new Error("empty completion did not replace");
      expect(read.envelope.data).toEqual({ days: [] });
      expect(view.listingFor("oura.activity").kind).toBe("canonical");
    }
    expect(db.prepare("SELECT * FROM data_files").all()).toEqual(indexed);
    expect(
      db.prepare("SELECT replacement_cursor FROM legacy_scope_takeovers").all(),
    ).toEqual([{ replacement_cursor: expect.any(String) }]);
  });

  it("does not earn completed replacement from a row without a receipt", async () => {
    legacyHead("oura.activity", "oura/activity/old.json");
    connect(store, "conn_a", "oura");
    ingest(store, "conn_a", "fresh-only", "2026-09-10T07:00:00.000Z", 91);
    const view = createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
      readLegacyHead: async () => ({
        version: "1.0",
        scope: "oura.activity",
        collectedAt: "2026-01-01T00:00:00.000Z",
        data: { activities: [{ old: true }] },
      }),
    });
    expect((await view.readLatest("oura.activity")).kind).toBe("file");
    expect(
      db
        .prepare(
          "SELECT * FROM legacy_scope_takeovers WHERE replacement_cursor IS NOT NULL",
        )
        .all(),
    ).toEqual([]);
  });

  for (const race of ["head", "selection", "write", "reset"] as const) {
    it(`refuses completed replacement when ${race} changes before confirmation`, async () => {
      legacyHead("oura.activity", "oura/activity/old.json");
      connect(store, "conn_a", "oura");
      replace(store, "conn_a", "activity", ["fresh-only"]);
      const authority = createLegacyScopeAuthority(db);
      const confirm = authority.confirmRead.bind(authority);
      let injected = false;
      authority.confirmRead = (...args) => {
        if (!injected && args[4]?.completion) {
          injected = true;
          if (race === "head")
            db.prepare(
              "UPDATE data_files SET cas_revision = cas_revision + 1 WHERE scope = ?",
            ).run("oura.activity");
          if (race === "selection") {
            connect(store, "conn_b", "oura");
            replace(store, "conn_b", "activity", ["other"]);
          }
          if (race === "write")
            ingest(store, "conn_a", "later", "2026-09-11T07:00:00.000Z");
          if (race === "reset") authority.resetTakeover("oura.activity");
        }
        return confirm(...args);
      };
      const view = createLegacyScopeView({
        authority,
        records: store,
        configuredMethods: (sourceId) => CONFIGURED[sourceId] ?? [],
        readLegacyHead: async () => ({
          version: "1.0",
          scope: "oura.activity",
          collectedAt: "2026-01-01T00:00:00.000Z",
          data: { activities: [{ old: true }] },
        }),
      });
      const read = await view.readLatest("oura.activity");
      expect(injected).toBe(true);
      expect(read.kind).not.toBe("canonical");
      expect(db.prepare("SELECT * FROM legacy_scope_takeovers").all()).toEqual(
        [],
      );
    });
  }

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

    it("yields to a legacy head that appears after the projection", async () => {
      connect(store, "conn_b", "oura-browser");
      replace(store, "conn_b", "activity", ["a1"], { method: "oura-browser" });
      expect((await view.readLatest("oura.activity")).kind).toBe("canonical");
      legacyHead("oura.activity", "oura/activity/later.json");
      expect(await view.readLatest("oura.activity")).toEqual({
        kind: "file",
        deletion: "file",
      });
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
        name: "oura-browser with a completed three-stream run where it is not opt-in",
        scope: "oura.activity",
        seed: () => {
          connect(store, "conn_b", "oura-browser");
          replace(store, "conn_b", "activity", ["a1"], {
            method: "oura-browser",
          });
          for (const stream of ["sleep", "readiness"]) {
            replace(store, "conn_b", stream, [], { method: "oura-browser" });
          }
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

  describe("strava-browser beside the Strava export method", () => {
    it("serves strava.activities from a strava-browser connection", async () => {
      connect(store, "conn_live", "strava-browser", STRAVA);
      replace(store, "conn_live", "activities", ["a1"], {
        method: "strava-browser",
      });

      const read = await view.readLatest("strava.activities");

      expect(read.kind).toBe("canonical");
      expect(read.kind === "canonical" && read.envelope.data).toEqual({
        activities: [{ id: "a1", day: "2026-09-01", score: 80 }],
      });
    });

    // The browser method declares no diagnostics stream.
    it("leaves strava.coverage_diagnostics to the export method", async () => {
      connect(store, "conn_live", "strava-browser", STRAVA);
      replace(store, "conn_live", "activities", ["a1"], {
        method: "strava-browser",
      });

      expect(await view.readLatest("strava.coverage_diagnostics")).toEqual({
        kind: "file",
        deletion: "file",
      });
    });

    // Never a mix of two producers: the owner must hold one Strava method.
    it("refuses activities, not diagnostics, while both methods hold data", async () => {
      connect(store, "conn_export", "strava", STRAVA);
      connect(store, "conn_live", "strava-browser", STRAVA);
      replace(store, "conn_export", "activities", ["a1"], { method: "strava" });
      replace(store, "conn_export", "coverage_diagnostics", ["d1"], {
        method: "strava",
      });
      replace(store, "conn_live", "activities", ["a2"], {
        method: "strava-browser",
      });

      expect(await view.readLatest("strava.activities")).toEqual({
        kind: "refused",
        refusal: {
          status: "unavailable",
          reason: "ambiguous_connection",
          candidates: 2,
        },
      });
      expect((await view.readLatest("strava.coverage_diagnostics")).kind).toBe(
        "canonical",
      );
    });
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

describe("Oura completed wholesale snapshots with retained tombstones", () => {
  for (const [takenOver, removedHead] of [
    [false, false],
    [true, false],
    [false, true],
  ] as const) {
    it(`keeps incomplete replacement legacy fallback only while legacy-owned: takeover=${takenOver}, removedHead=${removedHead}`, async () => {
      const dir = mkdtempSync(join(tmpdir(), "oura-lossy-replacement-"));
      const db = initializeDatabase(join(dir, "index.db"));
      const store = createSqliteRecordStore(db);
      const authority = createLegacyScopeAuthority(db);
      let snapshots = 0;
      const view = createLegacyScopeView({
        authority: {
          ...authority,
          readSnapshot(read) {
            const value = authority.readSnapshot(read);
            if (removedHead && ++snapshots === 1) {
              db.prepare("DELETE FROM data_files WHERE scope=?").run(
                "oura.activity",
              );
            }
            return value;
          },
        },
        records: store,
        configuredMethods: () => ["oura-browser"],
      });
      const streams = ["sleep", "readiness", "activity"];
      try {
        connect(store, "lossy", "oura-browser");
        db.prepare(
          "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
        ).run(
          "oura/activity/old.json",
          "oura.activity",
          "2026-01-01T00:00:00.000Z",
          1,
        );
        for (const stream of streams)
          replace(
            store,
            "lossy",
            stream,
            stream === "activity" ? ["old-a", "old-b"] : [],
            {
              method: "oura-browser",
            },
          );
        if (takenOver) {
          expect((await view.readLatest("oura.activity")).kind).toBe(
            "canonical",
          );
        }
        expect(authority.hasTakeover("oura.activity", "lossy", 1)).toBe(
          takenOver,
        );
        const collectedAt = "2026-09-11T07:00:00.000Z";
        for (const stream of streams) {
          store.replaceStream({
            instance: "lossy",
            stream,
            method: "oura-browser",
            generation: 1,
            primaryKey: ["id"],
            emittedAt: collectedAt,
            sourceCollectedAt: collectedAt,
            envelopes:
              stream === "activity"
                ? [
                    {
                      instance: "lossy",
                      stream,
                      key: "new-good",
                      data: { id: "new-good", day: "2026-09-01", score: 81 },
                      emitted_at: collectedAt,
                    },
                    {
                      instance: "lossy",
                      stream,
                      key: "new-bad",
                      data: { id: "new-bad", score: 82 },
                      emitted_at: collectedAt,
                    },
                  ]
                : [],
          });
        }
        expect(store.listStreamCompletions("lossy")).toHaveLength(3);
        expect(
          db
            .prepare("SELECT COUNT(*) AS n FROM pdpp_records WHERE deleted=1")
            .get(),
        ).toEqual({ n: 2 });
        const read = await view.readLatest("oura.activity");
        if (takenOver || removedHead) {
          expect(read).toMatchObject({
            kind: "refused",
            refusal: { reason: "canonical_view_incomplete" },
          });
        } else {
          expect(read).toMatchObject({ kind: "file" });
          expect(authority.hasTakeover("oura.activity", "lossy", 1)).toBe(
            false,
          );
        }
      } finally {
        store.close();
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }

  for (const ids of [["old-a"], ["new-only"], []] as string[][]) {
    it(
      "serves exact current complete rows and listing after restart: " +
        JSON.stringify(ids),
      async () => {
        const dir = mkdtempSync(join(tmpdir(), "oura-wholesale-"));
        const databasePath = join(dir, "index.db");
        const legacyPath = join(dir, "old.json");
        const historical = '{"retained":"old file bytes"}\n';
        writeFileSync(legacyPath, historical);
        let db = initializeDatabase(databasePath);
        let store = createSqliteRecordStore(db);
        const streams = ["sleep", "readiness", "activity"];
        const makeView = () =>
          createLegacyScopeView({
            authority: createLegacyScopeAuthority(db),
            records: store,
            configuredMethods: () => ["oura-browser"],
            readLegacyHead: async () => {
              throw new Error(
                "Complete replacement must not require historical parity",
              );
            },
          });
        try {
          connect(store, "wholesale", "oura-browser");
          for (const stream of streams) {
            writeFileSync(legacyPath + "." + stream, historical);
            db.prepare(
              "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
            ).run(
              legacyPath + "." + stream,
              "oura." + stream,
              "2026-01-01T00:00:00.000Z",
              historical.length,
            );
            replace(
              store,
              "wholesale",
              stream,
              stream === "activity" ? ["old-a", "old-b"] : [],
              {
                method: "oura-browser",
                collectedAt: "2026-09-09T07:00:00.000Z",
              },
            );
          }
          const initial = makeView();
          for (const stream of streams) {
            const read = await initial.readLatest("oura." + stream);
            expect(read.kind, JSON.stringify(read)).toBe("canonical");
          }
          const oldIndex = db
            .prepare("SELECT * FROM data_files ORDER BY id")
            .all();
          for (const stream of streams)
            replace(
              store,
              "wholesale",
              stream,
              stream === "activity" ? ids : [],
              {
                method: "oura-browser",
                collectedAt: "2026-09-11T07:00:00.000Z",
              },
            );
          expect(
            db
              .prepare("SELECT COUNT(*) AS n FROM pdpp_records WHERE deleted=1")
              .get(),
          ).toEqual({ n: ids.includes("old-a") ? 1 : 2 });
          const receipts = store.listStreamCompletions("wholesale");
          expect(receipts).toHaveLength(3);
          for (const receipt of receipts)
            expect(receipt).toMatchObject({
              generation: 1,
              method: "oura-browser",
              liveCount: receipt.stream === "activity" ? ids.length : 0,
              sourceCollectedAt: "2026-09-11T07:00:00.000Z",
            });
          const verify = async () => {
            const current = makeView();
            for (const stream of streams) {
              const read = await current.readLatest("oura." + stream);
              expect(read.kind).toBe("canonical");
              if (read.kind !== "canonical")
                throw new Error("Expected completed wholesale projection");
              const rows =
                stream === "sleep"
                  ? read.envelope.data.dailyScores
                  : read.envelope.data.days;
              expect(rows).toEqual(
                (stream === "activity" ? ids : []).map((id) => ({
                  id,
                  day: "2026-09-01",
                  score: 80,
                })),
              );
              expect(current.listingFor("oura." + stream)).toEqual({
                kind: "canonical",
                collectedAt: read.envelope.collectedAt,
              });
            }
            expect(
              db.prepare("SELECT * FROM data_files ORDER BY id").all(),
            ).toEqual(oldIndex);
            for (const stream of streams)
              expect(readFileSync(legacyPath + "." + stream, "utf8")).toBe(
                historical,
              );
            expect(
              db
                .prepare(
                  "SELECT COUNT(*) AS n FROM legacy_scope_takeover_verdicts",
                )
                .get(),
            ).toEqual({ n: 0 });
          };
          await verify();
          store.close();
          db = initializeDatabase(databasePath);
          store = createSqliteRecordStore(db);
          await verify();
          // Neither current receipt damage nor a mixed collection horizon is
          // repaired by the previously persisted replacement cursor.
          for (const update of [
            "generation=2",
            "live_count=99",
            "method='wrong'",
            "source_collected_at='2026-09-12T07:00:00.000Z'",
            "source_collected_at='2026-01-01T00:00:00.000Z'",
          ]) {
            db.prepare(
              "UPDATE pdpp_stream_completion SET " +
                update +
                " WHERE instance=? AND stream='readiness'",
            ).run("wholesale");
            const incomplete = makeView();
            expect((await incomplete.readLatest("oura.activity")).kind).toBe(
              "refused",
            );
            expect(incomplete.listingFor("oura.activity").kind).toBe("refused");
            db.prepare(
              "UPDATE pdpp_stream_completion SET generation=1,live_count=0,method='oura-browser',source_collected_at='2026-09-11T07:00:00.000Z' WHERE instance=? AND stream='readiness'",
            ).run("wholesale");
          }
          db.prepare(
            "DELETE FROM pdpp_stream_completion WHERE instance=? AND stream='readiness'",
          ).run("wholesale");
          const incomplete = makeView();
          expect((await incomplete.readLatest("oura.activity")).kind).toBe(
            "refused",
          );
          expect(incomplete.listingFor("oura.activity").kind).toBe("refused");
        } finally {
          store.close();
          rmSync(dir, { recursive: true, force: true });
        }
      },
    );
  }
});

describe("ChatGPT retained off-branch coverage over stored rows", () => {
  const source = "https://registry.pdpp.dev/sources/chatgpt";
  const scope = "chatgpt.conversations";
  const before = "2026-09-10T07:00:00.000Z";
  const after = "2026-09-11T07:00:00.000Z";
  let db: InstanceType<typeof Database>;
  let store: Store;

  beforeEach(() => {
    db = initializeDatabase(":memory:");
    store = createSqliteRecordStore(db);
    connect(store, "chat", "chatgpt", source);
  });
  afterEach(() => store.close());

  function put(
    stream: string,
    data: Record<string, unknown>,
    emittedAt = after,
    generation = 1,
  ) {
    const result = store.ingestBatch(
      [
        {
          instance: "chat",
          stream,
          key: String(data.id),
          data,
          emitted_at: emittedAt,
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "chatgpt", generation },
    );
    expect(result.rejected).toEqual([]);
  }

  const conversation = (current_node: string) => ({
    id: "conversation",
    title: "Synthetic branch switch",
    create_time: before,
    update_time: before,
    current_node,
    message_count_on_current_branch: 1,
  });
  const message = (id: string, on_current_branch: boolean) => ({
    id,
    conversation_id: "conversation",
    parent_id: null,
    role: "assistant",
    content_type: "text",
    content: id,
    create_time: before,
    model_slug: "synthetic",
    on_current_branch,
  });

  async function fixture({ healthy = false, unrelated = false } = {}) {
    put("conversations", conversation("old"), before);
    put("messages", message("old", true), before);
    if (healthy) {
      put(
        "conversations",
        {
          id: "healthy",
          title: "Healthy peer",
          create_time: before,
          update_time: before,
          current_node: "healthy:tip",
          message_count_on_current_branch: 1,
        },
        before,
      );
      put(
        "messages",
        {
          id: "healthy:tip",
          conversation_id: "healthy",
          parent_id: null,
          role: "assistant",
          content_type: "text",
          content: "healthy peer",
          create_time: before,
          model_slug: "synthetic",
          on_current_branch: true,
        },
        before,
      );
    }
    if (unrelated) {
      put(
        "conversations",
        {
          id: "unrelated",
          title: "Unrelated empty conversation",
          create_time: before,
          update_time: before,
          current_node: null,
          message_count_on_current_branch: 0,
        },
        before,
      );
    }
    const authority = createLegacyScopeAuthority(db);
    const config = {
      authority,
      records: store,
      configuredMethods: (sourceId: string) =>
        sourceId === source ? ["chatgpt"] : [],
    };
    const original = await createLegacyScopeView(config).readLatest(scope);
    expect(original.kind).toBe("canonical");
    if (original.kind !== "canonical")
      throw new Error("Expected original branch");
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run("chatgpt/conversations/old.json", scope, before, 1);
    const view = createLegacyScopeView({
      ...config,
      readLegacyHead: async () => original.envelope,
    });
    expect((await view.readLatest(scope)).kind).toBe("canonical");
    return { view, original, config };
  }

  function breakCurrentBranch() {
    put("messages", {
      ...message("conversation:tip", true),
      parent_id: "missing-parent",
    });
    put("conversations", {
      ...conversation("conversation:tip"),
      message_count_on_current_branch: 2,
    });
  }

  function replaceChatStream(
    stream: "conversations" | "messages",
    data: Record<string, unknown>[],
  ) {
    store.replaceStream({
      instance: "chat",
      stream,
      method: "chatgpt",
      generation: 1,
      primaryKey: ["id"],
      emittedAt: after,
      sourceCollectedAt: after,
      envelopes: data.map((row) => ({
        instance: "chat",
        stream,
        key: String(row.id),
        data: row,
        emitted_at: after,
      })),
    });
  }

  it("serves an empty payload when the only conversation has a receipted gap", async () => {
    const { view } = await fixture();
    breakCurrentBranch();

    const read = await view.readLatest(scope);
    expect(read.kind).toBe("canonical");
    if (read.kind !== "canonical") throw new Error("Expected canonical read");
    expect(read.envelope.data).toMatchObject({ conversations: [], total: 0 });
    expect(read.chatgptCoverageGaps).toHaveLength(1);
  });

  it("serves a healthy peer with an explicit, durable per-conversation gap", async () => {
    const { view, original, config } = await fixture({ healthy: true });
    breakCurrentBranch();

    const read = await view.readLatest(scope);
    expect(read.kind).toBe("canonical");
    if (read.kind !== "canonical") throw new Error("Expected canonical read");
    expect(read.envelope.data).toMatchObject({
      conversations: [{ id: "healthy" }],
      total: 1,
    });
    expect(read.chatgptCoverageGaps).toEqual([
      {
        conversationIdHash:
          "8b34dbc2c05eb4d7e25d48efeace82456b16cee760bcae80c157f52a3c2e787b",
        reason: "parent_not_stored/fallback_chain_incomplete",
        declaredCount: 2,
        walkedCount: 1,
      },
    ]);
    const displayVerdict = view.verdictFor(scope)[0]!;
    const displayedGap = read.chatgptCoverageGaps![0]!;
    expect(displayVerdict).toMatchObject({
      verdict: "covered",
      excludedConversations: [
        {
          ...displayedGap,
          conversationIdHash: displayedGap.conversationIdHash.slice(0, 12),
        },
      ],
      reason: {
        excludedConversations: [
          {
            ...displayedGap,
            conversationIdHash: displayedGap.conversationIdHash.slice(0, 12),
          },
        ],
      },
    });
    expect(
      config.authority.cachedVerdict(
        scope,
        "chat",
        1,
        displayVerdict.legacyVersionId,
        displayVerdict.canonicalCursor,
      )?.excludedConversations?.[0]?.conversationIdHash,
    ).toBe(displayedGap.conversationIdHash);

    const restarted = createLegacyScopeView({
      ...config,
      readLegacyHead: async () => original.envelope,
    });
    expect(await restarted.readLatest(scope)).toMatchObject({
      kind: "canonical",
      chatgptCoverageGaps: read.chatgptCoverageGaps,
    });
    expect(restarted.verdictFor(scope)[0]).toMatchObject({
      verdict: "covered",
      excludedConversations: [
        {
          ...displayedGap,
          conversationIdHash: displayedGap.conversationIdHash.slice(0, 12),
        },
      ],
    });
  });

  it("keeps a message tombstone refusal global when a conversation gap is present", async () => {
    const { view } = await fixture({ healthy: true });
    breakCurrentBranch();
    replaceChatStream("messages", [
      {
        ...message("conversation:tip", true),
        parent_id: "missing-parent",
      },
      {
        id: "healthy:tip",
        conversation_id: "healthy",
        parent_id: null,
        role: "assistant",
        content_type: "text",
        content: "healthy peer",
        create_time: before,
        model_slug: "synthetic",
        on_current_branch: true,
      },
    ]);

    expect(await view.readLatest(scope)).toMatchObject({
      kind: "refused",
      refusal: {
        status: "incomplete",
        reason: "canonical_view_incomplete",
      },
    });
  });

  it("does not let a gapped whole replacement prove deletion of another conversation", async () => {
    const { view } = await fixture({ healthy: true, unrelated: true });
    breakCurrentBranch();
    replaceChatStream("conversations", [
      {
        ...conversation("conversation:tip"),
        message_count_on_current_branch: 2,
      },
      {
        id: "healthy",
        title: "Healthy peer",
        create_time: before,
        update_time: before,
        current_node: "healthy:tip",
        message_count_on_current_branch: 1,
      },
    ]);
    replaceChatStream("messages", [
      message("old", true),
      {
        ...message("conversation:tip", true),
        parent_id: "missing-parent",
      },
      {
        id: "healthy:tip",
        conversation_id: "healthy",
        parent_id: null,
        role: "assistant",
        content_type: "text",
        content: "healthy peer",
        create_time: before,
        model_slug: "synthetic",
        on_current_branch: true,
      },
    ]);

    expect(store.listStreamCompletions("chat")).toHaveLength(2);
    expect(await view.readLatest(scope)).toMatchObject({
      kind: "refused",
      refusal: {
        status: "incomplete",
        reason: "canonical_view_incomplete",
      },
    });
    expect(view.verdictFor(scope)[0]).toMatchObject({
      verdict: "not_covered",
      reason: { reason: "missing_entity" },
    });
  });

  it.each(["old", "conversation:old"])(
    "covers retained %s after a branch switch without changing the served branch",
    async (oldId) => {
      const { view, original, config } = await fixture();
      put("messages", { ...message("old", false), content: "old" });
      if (oldId !== "old")
        put("messages", { ...message(oldId, false), content: "old" });
      put("messages", message("conversation:new", true));
      put("conversations", conversation("new"));
      const read = await view.readLatest(scope);
      expect(read.kind).toBe("canonical");
      if (read.kind !== "canonical")
        throw new Error("Retained branch was refused");
      expect(read.envelope.data).toMatchObject({
        conversations: [
          {
            id: "conversation",
            message_count: 1,
            messages: [{ id: "new", content: "conversation:new" }],
          },
        ],
      });
      expect(JSON.stringify(read.envelope.data)).not.toContain('"id":"old"');
      expect(view.verdictFor(scope)[0]).toMatchObject({
        verdict: "covered",
        reasonCounts: { missing_entity: 0, payload_growth: 0 },
      });
      // Bytes describe only the actual served candidate, not retained evidence.
      const verdict = view.verdictFor(scope)[0]!;
      expect(verdict).toMatchObject({
        legacyBytes: new TextEncoder().encode(
          JSON.stringify(original.envelope.data),
        ).length,
        canonicalBytes: new TextEncoder().encode(
          JSON.stringify(read.envelope.data),
        ).length,
      });
      expect(await view.readLatest(scope)).toEqual(read);
      const restarted = createLegacyScopeView({
        ...config,
        readLegacyHead: async () => original.envelope,
      });
      expect(await restarted.readLatest(scope)).toEqual(read);
    },
  );

  it.each(["text", "multimodal_text"])(
    "covers newer current-empty %s through ordinary field rules",
    async (content_type) => {
      const { view, original, config } = await fixture();
      put("messages", { ...message("old", true), content: "", content_type });
      put("conversations", { ...conversation("old"), update_time: after });
      const read = await view.readLatest(scope);
      expect(read.kind).toBe("canonical");
      if (read.kind !== "canonical")
        throw new Error("Expected explicit empty state");
      expect(read.envelope.data).toMatchObject({
        conversations: [
          {
            message_count: 1,
            messages: [{ id: "old", content: "", content_type }],
          },
        ],
      });
      expect(view.verdictFor(scope)[0]).toMatchObject({
        verdict: "covered",
        reasonCounts: { missing_entity: 0 },
      });
      expect(store.listStreamCompletions("chat")).toEqual([]);
      expect(await view.readLatest(scope)).toEqual(read);
      const restarted = createLegacyScopeView({
        ...config,
        readLegacyHead: async () => original.envelope,
      });
      expect(await restarted.readLatest(scope)).toEqual(read);
      // The current-empty witness cannot survive a later unknown source value.
      put("messages", { ...message("old", true), content: null });
      expect((await restarted.readLatest(scope)).kind).toBe("refused");
    },
  );

  it("rechecks the current-empty snapshot before confirming coverage", async () => {
    const { original, config } = await fixture();
    put("messages", { ...message("old", true), content: "" });
    put("conversations", { ...conversation("old"), update_time: after });
    const view = createLegacyScopeView({
      ...config,
      readLegacyHead: async () => {
        put("messages", { ...message("old", true), content: null });
        return original.envelope;
      },
    });
    expect(await view.readLatest(scope)).toMatchObject({
      kind: "refused",
      refusal: { reason: "store_inconsistent_read" },
    });
  });

  it("refuses a current-empty row whose declared blob is unavailable", async () => {
    const { original, config } = await fixture();
    const meta = store.storeBlobBytesForInstance({
      instance: "chat",
      method: "chatgpt",
      generation: 1,
      bytes: new TextEncoder().encode(JSON.stringify("source blob text")),
      mimeType: "application/json",
    });
    put("messages", {
      ...message("old", true),
      content: "",
      blob_ref: {
        blob_id: meta.blobId,
        sha256: meta.sha256,
        size_bytes: meta.sizeBytes,
        mime_type: meta.mimeType,
      },
    });
    put("conversations", { ...conversation("old"), update_time: after });
    const view = createLegacyScopeView({
      ...config,
      records: { ...store, getBlobBytes: () => undefined },
      declarations: createStreamDeclarationRegistry([
        {
          name: "messages",
          semantics: "mutable_state",
          primaryKey: ["id"],
          cursorField: "create_time",
          requiredFields: ["id"],
          schema: {
            properties: {
              content: { type: ["string", "null"] },
              blob_ref: {
                x_pdpp_blob_projects_field: "content",
                x_pdpp_blob_codec: "json-string-v1",
              },
            },
          },
        },
      ]),
      readLegacyHead: async () => original.envelope,
    });
    expect(await view.readLatest(scope)).toMatchObject({
      kind: "refused",
      refusal: { reason: "blob_backed_record_invalid" },
    });
  });

  it.each([
    "null",
    "missing content",
    "unsupported parts",
    "unsupported type",
    "unfetched detail",
    "absent parent",
    "equal messages",
    "older messages",
    "equal conversations",
    "older conversations",
    "changed creation",
    "changed role",
    "wrong parent",
    "preferred null",
  ])("refuses current-empty transition with %s", async (variant) => {
    const { view } = await fixture();
    const current: Record<string, unknown> = {
      ...message("old", true),
      content: "",
    };
    if (variant === "null") current.content = null;
    if (variant === "missing content" || variant === "unsupported parts") {
      delete current.content;
      if (variant === "unsupported parts") current.parts = [""];
    }
    if (variant === "unsupported type") current.content_type = "code";
    if (variant === "changed creation") current.create_time = after;
    if (variant === "changed role") current.role = "tool";
    if (variant === "wrong parent") current.conversation_id = "other";
    if (variant !== "unfetched detail") {
      put(
        "messages",
        current,
        variant === "equal messages"
          ? before
          : variant === "older messages"
            ? "2026-09-09T07:00:00.000Z"
            : after,
      );
    }
    put(
      "conversations",
      {
        ...conversation(variant === "unfetched detail" ? "unfetched" : "old"),
        update_time: after,
      },
      variant === "equal conversations"
        ? before
        : variant === "older conversations"
          ? "2026-09-09T07:00:00.000Z"
          : after,
    );
    if (variant === "preferred null") {
      put("messages", { ...current, id: "conversation:old", content: null });
    }
    if (variant === "absent parent") {
      store.replaceStream({
        instance: "chat",
        stream: "conversations",
        method: "chatgpt",
        generation: 1,
        primaryKey: ["id"],
        emittedAt: after,
        envelopes: [],
      });
    }
    const expectedKind =
      variant === "unfetched detail" || variant === "wrong parent"
        ? "canonical"
        : "refused";
    const firstRead = await view.readLatest(scope);
    expect(firstRead.kind).toBe(expectedKind);
    if (expectedKind === "canonical") {
      expect(firstRead.chatgptCoverageGaps).toHaveLength(1);
    }
    expect((await view.readLatest(scope)).kind).toBe(expectedKind);
  });

  it.each([
    "absent",
    "null",
    "empty",
    "deleted",
    "wrong conversation",
    "new generation",
    "wrong instance",
    "absent conversation",
    "prefixed null",
  ])("does not cover an off-branch node with %s evidence", async (variant) => {
    const { view } = await fixture();
    const prior = view
      .verdictFor(scope)
      .find((row) => row.instance === "chat" && row.generation === 1)!;
    let generation = 1;
    if (variant === "new generation") {
      store.resetInstanceBinding({
        instance: "chat",
        expectedMethod: "chatgpt",
        expectedGeneration: 1,
        nextMethod: "chatgpt",
      });
      generation = 2;
    } else if (
      variant === "absent" ||
      variant === "deleted" ||
      variant === "wrong instance"
    ) {
      db.prepare(
        variant !== "deleted"
          ? "DELETE FROM pdpp_records WHERE instance = ? AND stream = ? AND record_key = ?"
          : "UPDATE pdpp_records SET deleted = 1 WHERE instance = ? AND stream = ? AND record_key = ?",
      ).run("chat", "messages", "old");
      if (variant === "wrong instance") {
        connect(store, "foreign", "oura", OURA);
        const result = store.ingestBatch(
          [
            {
              instance: "foreign",
              stream: "messages",
              key: "old",
              data: message("old", false),
              emitted_at: after,
            },
          ],
          () => "mutable_state",
          () => ["id"],
          { method: "oura", generation: 1 },
        );
        expect(result.rejected).toEqual([]);
      }
    } else {
      put("messages", {
        ...message("old", false),
        content: variant === "null" ? null : variant === "empty" ? "" : "old",
        conversation_id:
          variant === "wrong conversation" ? "other" : "conversation",
      });
      if (variant === "prefixed null")
        put("messages", {
          ...message("conversation:old", false),
          content: null,
        });
    }
    put("messages", message("conversation:new", true), after, generation);
    put("conversations", conversation("new"), after, generation);
    if (variant === "absent conversation") {
      db.prepare(
        "DELETE FROM pdpp_records WHERE instance = ? AND stream = ? AND record_key = ?",
      ).run("chat", "conversations", "conversation");
      put("messages", {
        ...message("other:new", true),
        conversation_id: "other",
      });
      put("conversations", { ...conversation("new"), id: "other" });
    }
    const read = await view.readLatest(scope);
    if (variant === "empty") {
      expect(read.kind).toBe("canonical");
      expect(
        view
          .verdictFor(scope)
          .find(
            (row) => row.instance === "chat" && row.generation === generation,
          ),
      ).toMatchObject({ verdict: "covered" });
      return;
    }
    expect(read.kind).toBe("refused");
    const activeGeneration = view
      .verdictFor(scope)
      .find((row) => row.instance === "chat" && row.generation === generation);
    // A refusal can precede comparison and leave the prior cursor's positive
    // diagnostic row in the ledger. The public read must refuse; that
    // historical row is not evidence for the current cursor or generation.
    if (
      generation !== 1 ||
      variant === "absent" ||
      variant === "deleted" ||
      variant === "wrong instance" ||
      variant === "absent conversation"
    ) {
      expect(
        view
          .verdictFor(scope)
          .some(
            (row) =>
              row.instance === "chat" &&
              row.generation === generation &&
              row.canonicalCursor !== prior.canonicalCursor &&
              row.verdict === "covered",
          ),
      ).toBe(false);
    } else {
      expect(activeGeneration).toMatchObject({
        verdict: "not_covered",
        reasonCounts: { missing_entity: 1 },
      });
    }
  });

  it.each([
    ["both newer", after, after, before, true],
    ["conversation equal", before, after, before, false],
    ["messages equal", after, before, before, false],
    ["conversation older", "2026-09-09T07:00:00.000Z", after, before, false],
    ["messages older", after, "2026-09-09T07:00:00.000Z", before, false],
    ["invalid legacy", after, after, "invalid", false],
  ] as const)(
    "requires every stream to be newer: %s",
    async (_label, conversationTime, messageTime, legacyTime, expected) => {
      const { view } = await fixture();
      put("messages", message("old", false), messageTime);
      put("messages", message("conversation:new", true), messageTime);
      put("conversations", conversation("new"), conversationTime);
      if (legacyTime !== before)
        db.prepare(
          "UPDATE data_files SET collected_at = ? WHERE scope = ?",
        ).run(legacyTime, scope);
      expect((await view.readLatest(scope)).kind).toBe(
        expected ? "canonical" : "refused",
      );
      expect(view.verdictFor(scope)[0]).toMatchObject({
        comparisonCase: expected ? "canonical_newer" : "same_time",
        reasonCounts: { array_order: expected ? 0 : 1 },
      });
    },
  );

  it("does not let one receipt or the newest row stand in for all-stream freshness", async () => {
    const { view } = await fixture();
    put("messages", message("old", false), before);
    put("messages", message("conversation:new", true), after);
    store.replaceStream({
      instance: "chat",
      stream: "conversations",
      method: "chatgpt",
      generation: 1,
      primaryKey: ["id"],
      emittedAt: after,
      sourceCollectedAt: after,
      envelopes: [
        {
          instance: "chat",
          stream: "conversations",
          key: "conversation",
          data: conversation("new"),
          emitted_at: after,
        },
      ],
    });
    expect(store.listStreamCompletions("chat")).toHaveLength(1);
    expect((await view.readLatest(scope)).kind).toBe("refused");
    expect(view.verdictFor(scope)[0]).toMatchObject({
      comparisonCase: "same_time",
      reasonCounts: { array_order: 1 },
    });
  });

  it.each(["mutate", "delete", "generation", "instance"])(
    "invalidates a covered retained-only witness on %s with unchanged display data",
    async (change) => {
      const { view, config } = await fixture();
      put("messages", message("old", false));
      put("messages", message("conversation:new", true));
      put("conversations", conversation("new"));
      const covered = await view.readLatest(scope);
      expect(covered.kind).toBe("canonical");
      if (covered.kind !== "canonical")
        throw new Error("Expected retained coverage");
      const oldCursor = view.verdictFor(scope)[0]!.canonicalCursor;
      if (change === "mutate") {
        put("messages", {
          ...message("old", false),
          create_time: "2025-01-01T00:00:00Z",
        });
      } else if (change === "delete") {
        // Unreceipted replace keeps the active branch, tombstones only the retained node.
        store.replaceStream({
          instance: "chat",
          stream: "messages",
          method: "chatgpt",
          generation: 1,
          primaryKey: ["id"],
          emittedAt: after,
          envelopes: [
            {
              instance: "chat",
              stream: "messages",
              key: "conversation:new",
              data: message("conversation:new", true),
              emitted_at: after,
            },
          ],
        });
      } else if (change === "generation") {
        store.resetInstanceBinding({
          instance: "chat",
          expectedMethod: "chatgpt",
          expectedGeneration: 1,
          nextMethod: "chatgpt",
        });
        put("messages", message("conversation:new", true), after, 2);
        put("conversations", conversation("new"), after, 2);
      } else {
        store.deleteConnection("chat");
        connect(store, "replacement", "chatgpt", source);
        const result = store.ingestBatch(
          [
            {
              instance: "replacement",
              stream: "conversations",
              key: "conversation",
              data: conversation("new"),
              emitted_at: after,
            },
            {
              instance: "replacement",
              stream: "messages",
              key: "conversation:new",
              data: message("conversation:new", true),
              emitted_at: after,
            },
          ],
          () => "mutable_state",
          () => ["id"],
          { method: "chatgpt", generation: 1 },
        );
        expect(result.rejected).toEqual([]);
      }
      // A no-head view exposes the real current projection independently of parity.
      const display = await createLegacyScopeView({
        ...config,
        authority: {
          ...config.authority,
          eligibleLegacyHead: () => null,
          // This separate read measures projection bytes, not takeover authority.
          confirmRead: (_scope, _head, selectionIsCurrent) =>
            selectionIsCurrent(),
        },
      }).readLatest(scope);
      expect(display.kind).toBe("canonical");
      if (display.kind !== "canonical")
        throw new Error("Expected unchanged display");
      expect(display.envelope.data).toEqual(covered.envelope.data);
      expect(display.revision).not.toBe(covered.revision);
      expect((await view.readLatest(scope)).kind).toBe("refused");
      const selectedInstance = change === "instance" ? "replacement" : "chat";
      const selectedGeneration = change === "generation" ? 2 : 1;
      const verdict = view
        .verdictFor(scope)
        .find(
          (row) =>
            row.instance === selectedInstance &&
            row.generation === selectedGeneration,
        );
      if (change === "mutate" || change === "delete") {
        expect(verdict).toMatchObject({
          verdict: "not_covered",
          canonicalBytes: new TextEncoder().encode(
            JSON.stringify(covered.envelope.data),
          ).length,
        });
      } else {
        // Verdict rows are keyed by instance and generation. A prior positive
        // row remains historical under the old key; it cannot satisfy lookup
        // for the newly selected connection generation.
        expect(verdict?.canonicalCursor).not.toBe(oldCursor);
        expect(
          config.authority.cachedVerdict(
            scope,
            selectedInstance,
            selectedGeneration,
            view.verdictFor(scope)[0]!.legacyVersionId,
            oldCursor,
          ),
        ).toBeNull();
      }
    },
  );

  it("recomputes a rule-12 refused witness under rule 13", async () => {
    const { view, original, config } = await fixture();
    const prior = view.verdictFor(scope)[0]!;
    const authority = config.authority;
    const covered = authority.cachedVerdict(
      scope,
      "chat",
      1,
      prior.legacyVersionId,
      prior.canonicalCursor,
    )!;
    expect(covered.covered).toBe(true);
    put("messages", message("old", false));
    put("messages", message("conversation:new", true));
    put("conversations", conversation("new"));
    const lookup = authority.cachedVerdict.bind(authority);
    const seen: string[] = [];
    const restarted = createLegacyScopeView({
      ...config,
      authority: {
        ...authority,
        cachedVerdict(scope, instance, generation, version, cursor) {
          seen.push(cursor);
          const rule12 = cursor.replace(/:13:1\.5:262144$/, ":12:1.5:262144");
          expect(
            authority.confirmRead(
              scope,
              authority.eligibleLegacyHead(scope),
              () => true,
              "chatgpt",
              {
                instance,
                generation,
                writeClock: authority.writeClock(),
                arrivalRevision: authority.arrivalRevision(),
                canonicalCursor: rule12,
                coverage: {
                  ...covered,
                  covered: false,
                  reason: "missing_entity",
                  missingEntityCount: 1,
                  reasonCounts: { ...covered.reasonCounts, missing_entity: 1 },
                },
                cached: false,
              },
            ),
          ).toBe(true);
          return lookup(scope, instance, generation, version, cursor);
        },
      },
      readLegacyHead: async () => original.envelope,
    });
    expect((await restarted.readLatest(scope)).kind).toBe("canonical");
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatch(/:13:1\.5:262144$/);
    expect(restarted.verdictFor(scope)[0]).toMatchObject({
      verdict: "covered",
    });
  });

  it.each(["missing", "invalid"])(
    "fails closed when a stream's collection evidence is %s",
    async (failure) => {
      const { original, config } = await fixture();
      put("messages", message("old", false));
      put("messages", message("conversation:new", true));
      put("conversations", conversation("new"));
      const view = createLegacyScopeView({
        ...config,
        records: {
          ...store,
          listRecords(stream, query) {
            const page = store.listRecords(stream, query);
            return stream === "messages"
              ? {
                  ...page,
                  data: page.data.map((row) => ({
                    ...row,
                    emittedAt: failure === "missing" ? "" : "invalid",
                  })),
                }
              : page;
          },
        },
        readLegacyHead: async () => original.envelope,
      });
      expect(await view.readLatest(scope)).toMatchObject({
        kind: "refused",
        refusal: { reason: "invalid_collected_at" },
      });
    },
  );

  it("rechecks the retained-row snapshot before confirming coverage", async () => {
    const { original, config } = await fixture();
    put("messages", message("old", false));
    put("messages", message("conversation:new", true));
    put("conversations", conversation("new"));
    const view = createLegacyScopeView({
      ...config,
      readLegacyHead: async () => {
        put("messages", { ...message("old", false), content: null });
        return original.envelope;
      },
    });
    expect(await view.readLatest(scope)).toMatchObject({
      kind: "refused",
      refusal: { reason: "store_inconsistent_read" },
    });
  });
});
