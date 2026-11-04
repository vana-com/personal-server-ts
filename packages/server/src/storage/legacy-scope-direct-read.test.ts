// Synthetic projection/binding fixtures; real view, authority and tracker.
import Database from "better-sqlite3";
import { expect, it, vi } from "vitest";
import {
  createLegacyScopeView,
  type CreateLegacyScopeViewInput,
} from "../../../core/src/storage/legacy-scope-view.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { trackLegacyScopeMutations } from "./legacy-scope-revalidation-state.js";

const hooks = vi.hoisted(() => ({ project: vi.fn(), compare: vi.fn() }));
vi.mock("../../../core/src/storage/canonical-legacy-projection.js", () => ({
  CANONICAL_LEGACY_VIEW_CONTRACT: "swr-test/1",
  legacyConnectorKey: (source: string) => source,
  readCanonicalLegacyScope: hooks.project,
}));
vi.mock("../../../core/src/storage/legacy-scope-coverage.js", () => ({
  compareLegacyCoverage: hooks.compare,
}));
vi.mock("../../../core/src/storage/legacy-scope-entity-keys.js", () => ({
  LEGACY_SCOPE_ENTITY_KEYS: { "test.scope": ["id"] },
}));
vi.mock("../../../core/src/legacy-projection/index.js", () => {
  const profile = new Map([
    [
      "test.scope",
      {
        scope: "test.scope",
        pdppSource: "test",
        pdppStreams: ["rows"],
        primaryKey: ["id"],
        fieldsRead: [],
        provenance: [],
      },
    ],
  ]);
  return {
    LEGACY_SCOPE_BINDINGS: profile,
    ANTHROPIC_LIVE_BINDINGS: new Map(),
    GITHUB_BROWSER_BINDINGS: new Map(),
    META_040_BINDINGS: new Map(),
    OURA_BROWSER_BINDINGS: new Map(),
    STRAVA_BROWSER_BINDINGS: new Map(),
    legacyBindingsForProfile: () => profile,
  };
});
vi.mock("./legacy-scope-revalidator.js", () => ({
  legacyCoverageCandidates: () => [{ instance: "i", scopes: ["test.scope"] }],
}));

const scope = "test.scope";
const stamp = "2026-11-03T00:00:00.000Z";
const ceiling = 1_800_000;
function projected(value: string) {
  return {
    ok: true,
    complete: true,
    revision: value,
    envelope: { scope, collectedAt: stamp, data: { value } },
    diagnostics: { partialRows: [], omissions: [], unproven: [] },
    streamCollectionTimes: { rows: stamp },
    streamCompletionTimes: {},
  };
}
function fixture() {
  hooks.project.mockReset().mockResolvedValue(projected("old"));
  hooks.compare.mockReset().mockReturnValue({
    covered: true,
    comparisonCase: "same_time",
    reasonCounts: {},
    appliedExceptions: [],
    reason: null,
    missingEntityCount: 0,
    mismatchedFieldPaths: [],
    legacyBytes: 10,
    canonicalBytes: 10,
    byteDelta: 0,
  });
  const raw = new Database(":memory:");
  raw.exec(
    [
      "CREATE TABLE data_files (id INTEGER PRIMARY KEY,scope TEXT,path TEXT,version INTEGER,cas_revision INTEGER,collected_at TEXT,producer TEXT);",
      "INSERT INTO data_files VALUES (1,'test.scope','head.json',1,1,'2026-11-03T00:00:00.000Z',NULL);",
      "CREATE TABLE pdpp_instance_binding (instance TEXT PRIMARY KEY,source_id TEXT,method TEXT,deleted_at TEXT,generation INTEGER,reset_clock INTEGER);",
      "INSERT INTO pdpp_instance_binding VALUES ('i','source','test',NULL,1,0);",
      "CREATE TABLE pdpp_records (instance TEXT,stream TEXT,deleted INTEGER);",
      "INSERT INTO pdpp_records VALUES ('i','rows',0);",
      "CREATE TABLE pdpp_write_clock (id INTEGER PRIMARY KEY,value INTEGER);",
      "INSERT INTO pdpp_write_clock VALUES (1,7);",
      "CREATE TABLE pdpp_record_arrival_clock (id INTEGER PRIMARY KEY,value INTEGER);",
      "INSERT INTO pdpp_record_arrival_clock VALUES (1,9);",
      "CREATE TABLE legacy_scope_takeovers (scope TEXT,instance TEXT,generation INTEGER,method TEXT,superseded_version INTEGER,superseded_cas_revision INTEGER,superseded_collected_at TEXT,superseded_path TEXT,replacement_cursor TEXT,PRIMARY KEY(scope,instance,generation,superseded_path));",
      "INSERT INTO legacy_scope_takeovers VALUES ('test.scope','i',1,'test',1,1,'2026-11-03T00:00:00.000Z','head.json',NULL);",
      "CREATE TABLE legacy_scope_takeover_verdicts (scope TEXT,instance TEXT,generation INTEGER,legacy_version_id INTEGER,canonical_cursor TEXT,verdict TEXT,comparison_case TEXT,reason_counts_json TEXT,applied_exceptions_json TEXT,reason_json TEXT,legacy_bytes INTEGER,canonical_bytes INTEGER,byte_delta INTEGER,evaluated_at TEXT DEFAULT '2026-11-03T00:00:00.000Z',PRIMARY KEY(scope,instance,generation));",
    ].join("\n"),
  );
  let now = 100;
  const state = trackLegacyScopeMutations(raw, {
    ceilingMs: ceiling,
    now: () => now,
  });
  const authority = createLegacyScopeAuthority(state.db, state);
  const records = {
    getInstanceBinding: () => ({
      instance: "i",
      sourceId: "source",
      method: "test",
      generation: 1,
      resetClock: 0,
      deletedAt: null,
    }),
    listStreams: () => [{ stream: "rows", recordCount: 1, lastUpdated: stamp }],
    listStreamCompletions: () => [],
  } as unknown as NonNullable<CreateLegacyScopeViewInput["records"]>;
  const view = createLegacyScopeView({
    authority,
    records,
    configuredMethods: () => ["test"],
    readLegacyHead: async () =>
      projected("legacy").envelope as Awaited<
        ReturnType<NonNullable<CreateLegacyScopeViewInput["readLegacyHead"]>>
      >,
  });
  return {
    raw,
    state,
    authority,
    view,
    records,
    setTime: (value: number) => {
      now = value;
    },
    clocks: () => [authority.writeClock(), authority.arrivalRevision()],
    cursor: () => authority.verdictFor(scope)[0]?.canonicalCursor,
  };
}

it("invalidates dependency-only body reuse and refuses at the exact dirty ceiling", async () => {
  const f = fixture();
  try {
    expect(await f.view.readLatest(scope)).toMatchObject({
      kind: "canonical",
      revision: "old",
    });
    const before = f.cursor();
    const clocks = f.clocks();
    expect(f.view.listingFor(scope).kind).toBe("canonical");

    // Tracker signal from a blob/replica/quarantine-only change:
    // full dependency revision advances; row/arrival clocks do not.
    f.setTime(200);
    f.state.markDirty();
    hooks.project.mockResolvedValue(projected("new"));
    expect(await f.view.readLatest(scope)).toMatchObject({
      kind: "canonical",
      revision: "new",
    });
    expect(hooks.project).toHaveBeenCalledTimes(2);
    expect(f.clocks()).toEqual(clocks);
    expect(f.cursor()).not.toBe(before);
    expect(f.state.status("i", scope)?.dirty_since).toBeNull();

    f.setTime(300);
    f.state.markDirty();
    const dirtyRevision = f.state.revision("i");
    const saved = f.authority.verdictFor(scope)[0]!;
    const savedCoverage = f.authority.cachedVerdict(
      scope,
      "i",
      1,
      1,
      saved.canonicalCursor,
    )!;
    expect(f.view.listingFor(scope).kind).toBe("canonical");
    f.setTime(300 + ceiling - 1);
    expect(f.view.listingFor(scope).kind).toBe("canonical");
    f.setTime(300 + ceiling);
    hooks.project.mockResolvedValue({
      ok: false,
      status: "unavailable",
      reason: "store_inconsistent_read",
      detail: "dependency is no longer readable",
    });

    // Do not list at/after expiry before the GET: GET must enforce it itself.
    expect(await f.view.readLatest(scope)).toMatchObject({
      kind: "refused",
      refusal: { reason: "store_inconsistent_read" },
    });
    expect(hooks.project).toHaveBeenCalledTimes(3);
    expect(f.view.listingFor(scope).kind).toBe("refused");
    expect(f.state.revision("i")).toBe(dirtyRevision);
    expect(f.state.status("i", scope)?.dirty_since).toBe(300);
    expect(f.clocks()).toEqual(clocks);
    expect(
      f.authority.cachedVerdict(scope, "i", 1, 1, saved.canonicalCursor),
    ).toBeNull();
    expect(
      f.authority.confirmRead(
        scope,
        f.authority.eligibleLegacyHead(scope),
        () => true,
        "test",
        {
          instance: "i",
          generation: 1,
          writeClock: 7,
          arrivalRevision: 9,
          dependencyRevision: dirtyRevision,
          canonicalCursor: saved.canonicalCursor,
          coverage: savedCoverage,
          cached: true,
        },
      ),
    ).toBe(false);

    // At the same expired deadline, a genuinely fresh proof may recover.
    hooks.project.mockResolvedValue(projected("recovered"));
    expect(await f.view.readLatest(scope)).toMatchObject({
      kind: "canonical",
      revision: "recovered",
    });
    expect(f.state.status("i", scope)?.dirty_since).toBeNull();
    expect(f.view.listingFor(scope).kind).toBe("canonical");
  } finally {
    f.raw.close();
  }
});

it("rejects a fresh projection raced by a newer revision without clearing its dirty marker", async () => {
  const f = fixture();
  try {
    await f.view.readLatest(scope);
    const confirmedCursor = f.cursor();
    const clocks = f.clocks();
    f.setTime(200);
    f.state.markDirty();
    const captured = f.state.revision("i");
    let begin!: () => void;
    const begun = new Promise<void>((resolve) => {
      begin = resolve;
    });
    let release!: (value: ReturnType<typeof projected>) => void;
    hooks.project.mockImplementation(() => {
      begin();
      return new Promise<ReturnType<typeof projected>>((resolve) => {
        release = resolve;
      });
    });
    const pending = f.view.readLatest(scope);
    // A warm-cache bug must fail explicitly instead of leaving the projection
    // barrier pending until the runner times out.
    await Promise.race([
      begun,
      pending.then(() => {
        throw Error("Request reused the stale body instead of projecting");
      }),
    ]);

    f.setTime(201);
    f.state.markDirty();
    expect(f.state.revision("i")).toBe(captured + 1);
    const newerDirty = f.state.status("i", scope);
    release(projected("raced"));
    expect(await pending).toMatchObject({
      kind: "refused",
      refusal: { reason: "store_inconsistent_read" },
    });
    expect(f.cursor()).toBe(confirmedCursor);
    expect(f.state.status("i", scope)).toEqual(newerDirty);
    expect(newerDirty?.dirty_since).toBe(200);
    expect(f.clocks()).toEqual(clocks);

    // A subsequent projection captured at the new revision can recover.
    hooks.project.mockResolvedValue(projected("current"));
    expect(await f.view.readLatest(scope)).toMatchObject({
      kind: "canonical",
      revision: "current",
    });
    expect(f.state.status("i", scope)?.dirty_since).toBeNull();
    expect(f.state.revision("i")).toBe(captured + 1);
  } finally {
    f.raw.close();
  }
});

it.each([
  { diagnostic: "omissions", kind: "omitted", confirmation: "confirmed" },
  { diagnostic: "partialRows", kind: "partial", confirmation: "confirmed" },
  { diagnostic: "unproven", kind: "unproven", confirmation: "unconfirmed" },
] as const)(
  "marks $kind incompleteness as $confirmation when parity cannot be checked",
  async ({ diagnostic, kind, confirmation }) => {
    const f = fixture();
    try {
      const view = createLegacyScopeView({
        authority: f.authority,
        records: f.records,
        configuredMethods: () => ["test"],
      });
      hooks.project.mockResolvedValue({
        ...projected("current"),
        complete: false,
        diagnostics: {
          omissions: [],
          partialRows: [],
          unproven: [],
          [diagnostic]:
            diagnostic === "unproven"
              ? [{ stream: "rows", aspect: "record_order", reason: "unknown" }]
              : [{ stream: "rows", count: 1, reasons: ["incomplete row"] }],
        },
      });
      expect(await view.readLatest(scope)).toMatchObject({
        kind: "refused",
        refusal: {
          reason: "canonical_view_incomplete",
          confirmation,
          diagnostics: [{ stream: "rows", kind }],
        },
      });
    } finally {
      f.raw.close();
    }
  },
);
