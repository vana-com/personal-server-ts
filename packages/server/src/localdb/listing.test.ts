import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { SqlDriver, SqlValue } from "../../../core/src/localdb/driver.js";
import { createLocalListing } from "../../../core/src/localdb/listing.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import type {
  ReadDecision,
  ResolveInput,
} from "../../../core/src/stream-sync-read/service.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const mocks = vi.hoisted(() => ({
  resolve: vi.fn<(input: ResolveInput) => Promise<ReadDecision>>(),
  query: vi.fn(() => ({})),
  older: vi.fn(() => ({})),
}));

// These tests isolate listing policy; listing-alias-integration uses the real resolver.
vi.mock("../../../core/src/localdb/resolve.js", () => ({
  createLocalResolver: () => ({ resolve: mocks.resolve }),
}));
vi.mock("../../../core/src/localdb/query.js", () => ({
  createRecordQuery: mocks.query,
}));
vi.mock("../../../core/src/localdb/older-versions.js", () => ({
  createOlderVersions: mocks.older,
}));

const opened: SqlDriver[] = [];
const dirs: string[] = [];
const olderCounts = { served: 2, gone: 3, off: 4 };

async function fresh(
  options: { aliasScopes?: () => Iterable<string> } = {
    aliasScopes: () => ["example.summary"],
  },
) {
  const dir = mkdtempSync(join(process.cwd(), ".listing-test-"));
  dirs.push(dir);
  const db = openBetterSqlite3(join(dir, "db.sqlite"));
  opened.push(db);
  await openLocalDb(db, {
    owner: "0xabc",
    network: "test",
    deviceId: "listing-test",
  });
  const warn = vi.fn();
  const deps = {
    db,
    logger: { info: vi.fn(), warn },
    ownerAddress: "0xabc",
    now: () => 2000,
    newOp: () => "listing-op",
  } as unknown as LocalSyncDeps;
  const counts = vi.fn(() => olderCounts);
  return {
    db,
    warn,
    counts,
    listing: createLocalListing(
      {
        ...deps,
        aliasTargets: (scope) =>
          scope === "example.summary"
            ? [
                {
                  connector: "sample",
                  streams: ["items", "details"],
                  project: () => ({ ok: true as const, payload: {} }),
                },
              ]
            : [],
        ...options,
      },
      counts,
    ),
  };
}

async function seed(db: SqlDriver, control: "active" | "absent" = "active") {
  const local = control === "absent";
  await db.batch([
    {
      sql: "INSERT INTO connections(connection_id, connector, ns, control_state, control_version) VALUES ('c1', 'sample', '', ?, ?)",
      params: [control, local ? 0 : 2],
    },
    {
      sql: "INSERT INTO stream_state(connection_id, stream, primary_key, semantics, incremental, complete, head_version, head_generation, head_blob) VALUES ('c1', 'items', '[\"id\"]', 'mutable_state', 0, ?, ?, ?, ?)",
      params: [
        local ? 0 : 1,
        local ? 0 : 3,
        local ? null : 1,
        local ? null : "head",
      ],
    },
    {
      sql: "INSERT INTO records(connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256) VALUES ('c1', 'items', '01', 'one', 1234, 'run', '{}', 'fixture')",
    },
  ]);
}

function view(
  kind: "view" | "local_pending" = "view",
  body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("{}"));
      controller.close();
    },
  }),
): ReadDecision {
  const common = { connector: "sample", ns: "", cursor: "cursor", body };
  return kind === "view"
    ? { ...common, kind, served: { scope: "pdpp.sample~.items", version: 3 } }
    : { ...common, kind, complete: false };
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.resolve.mockReset().mockResolvedValue({ kind: "pass" });
});

afterEach(async () => {
  for (const db of opened.splice(0)) await db.close();
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

describe("local listing #597", () => {
  it("listing-alias-scopes-from-caller", async () => {
    const aliasScopes = vi.fn(function* () {
      yield "example.summary";
      yield "example.summary";
    });
    const { db, listing } = await fresh({ aliasScopes });
    await seed(db);
    mocks.resolve.mockImplementation(async () => view());
    const canRead = vi.fn(() => true);
    const expected = [
      {
        scope: "example.summary",
        connector: "sample",
        ns: "",
        records: null,
        updatedAt: 1234,
      },
      {
        scope: "pdpp.sample.items",
        connector: "sample",
        ns: "",
        records: 1,
        updatedAt: 1234,
      },
    ];

    expect(aliasScopes).not.toHaveBeenCalled();
    expect(await listing.listScopes({ canRead })).toEqual(expected);
    expect(canRead.mock.calls).toEqual([
      ["example.summary"],
      ["pdpp.sample.items"],
    ]);
    expect(await listing.listScopes({ canRead })).toEqual(expected);
    expect(aliasScopes).toHaveBeenCalledTimes(2);
  });

  it("listing-no-alias-without-caller", async () => {
    const { db, listing } = await fresh({});
    await seed(db);
    mocks.resolve.mockImplementation(async () => view());
    const canRead = vi.fn(() => true);

    expect(await listing.listScopes({ canRead })).toEqual([
      {
        scope: "pdpp.sample.items",
        connector: "sample",
        ns: "",
        records: 1,
        updatedAt: 1234,
      },
    ]);
    expect(canRead.mock.calls).toEqual([["pdpp.sample.items"]]);
    expect(mocks.resolve).toHaveBeenCalledTimes(1);
  });

  it("lists readable scopes only, with the grant filter before all checks", async () => {
    const { db, listing } = await fresh();
    await seed(db);
    const events: string[] = [];
    const allow = vi.fn(async (scope: string) => {
      events.push("grant:" + scope);
      await Promise.resolve();
      return scope === "pdpp.sample.items";
    });
    mocks.resolve.mockImplementation(async ({ scope }) => {
      events.push("resolve:" + scope);
      return view();
    });

    expect(await listing.listScopes({ canRead: async () => false })).toEqual(
      [],
    );
    expect(mocks.resolve).not.toHaveBeenCalled();
    expect(mocks.query).not.toHaveBeenCalled();
    expect(mocks.older).not.toHaveBeenCalled();

    expect(await listing.listScopes({ canRead: allow })).toEqual([
      {
        scope: "pdpp.sample.items",
        connector: "sample",
        ns: "",
        records: 1,
        updatedAt: 1234,
      },
    ]);
    expect(events).toEqual([
      "grant:example.summary",
      "grant:pdpp.sample.items",
      "resolve:pdpp.sample.items",
    ]);
    expect(mocks.resolve).toHaveBeenCalledTimes(1);
    expect(mocks.resolve).toHaveBeenCalledWith({
      scope: "pdpp.sample.items",
      connection: null,
      cursor: null,
      legacyFile: false,
      isOwnerView: true,
    });
  });

  it("skips and logs a throwing covered check while continuing other scopes", async () => {
    const { db, listing, warn } = await fresh();
    await seed(db);
    mocks.resolve.mockImplementation(async ({ scope }) => {
      if (scope === "example.summary") throw new Error("projection failed");
      return view();
    });
    expect(
      (await listing.listScopes({ canRead: () => true })).map((s) => s.scope),
    ).toEqual(["pdpp.sample.items"]);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(
      { scope: "example.summary" },
      "localdb listing: scope check failed",
    );
    warn.mockClear();
    mocks.resolve.mockClear();
    expect(
      await listing.listScopes({
        canRead: (scope) => {
          if (scope === "pdpp.sample.items") throw new Error("grant failed");
          return false;
        },
      }),
    ).toEqual([]);
    expect(mocks.resolve).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(
      { scope: "pdpp.sample.items" },
      "localdb listing: scope check failed",
    );
  });

  it("includes the owner's local-only scopes without registry heads", async () => {
    const { db, listing, counts } = await fresh();
    await seed(db, "absent");
    mocks.resolve.mockImplementation(async () => view("local_pending"));
    expect(
      await listing.listScopes({
        canRead: (scope) => scope === "pdpp.sample.items",
      }),
    ).toEqual([
      {
        scope: "pdpp.sample.items",
        connector: "sample",
        ns: "",
        records: 1,
        updatedAt: 1234,
      },
    ]);
    expect(mocks.resolve.mock.calls[0]?.[0].isOwnerView).toBe(true);
    expect(await listing.status()).toEqual({
      listed: true,
      connections: [
        {
          connector: "sample",
          ns: "",
          control: "absent",
          streams: {
            items: {
              tombstoned: false,
              live: false,
              complete: false,
              version: null,
              records: null,
            },
          },
        },
      ],
      issues: [],
      olderVersionReads: olderCounts,
    });
    expect(counts).toHaveBeenCalledTimes(1);
  });

  it("lists an alias only when its entire body can be built", async () => {
    const { db, listing, warn } = await fresh();
    await seed(db);
    const canRead = (scope: string) => scope === "example.summary";
    const makeBody = (fail: boolean) => {
      let part = 0;
      return new ReadableStream<Uint8Array>({
        pull(controller) {
          if (part++ === 0) {
            controller.enqueue(new TextEncoder().encode("{"));
          } else if (fail) {
            controller.error(new Error("late projection failure"));
          } else {
            controller.enqueue(new TextEncoder().encode("}"));
            controller.close();
          }
        },
      });
    };
    mocks.resolve.mockImplementation(async () => view("view", makeBody(true)));
    expect(await listing.listScopes({ canRead })).toEqual([]);
    expect(warn).toHaveBeenCalledTimes(1);

    mocks.resolve.mockResolvedValue({ kind: "unavailable", reason: "no_data" });
    expect(await listing.listScopes({ canRead })).toEqual([]);
    mocks.resolve.mockImplementation(async () => view("view", makeBody(false)));
    expect(await listing.listScopes({ canRead })).toEqual([
      {
        scope: "example.summary",
        connector: "sample",
        ns: "",
        records: null,
        updatedAt: 1234,
      },
    ]);
  });

  it("changes the cache key for every control-row and stream-head change", async () => {
    const { db, listing } = await fresh();
    await seed(db);
    const baseline = await listing.cacheKey();
    expect(await listing.cacheKey()).toBe(baseline);
    const [control] = await db.query("SELECT * FROM connections");
    const [head] = await db.query("SELECT * FROM stream_state");
    const controlChanges: Record<string, SqlValue> = {
      connection_id: "changed",
      connector: "other",
      ns: "0000000000000001",
      generation: 2,
      control_state: "foreign",
      control_version: 4,
      checkpoint: "next",
      label: "renamed",
      deleted_at: 2000,
    };
    const headChanges: Record<string, SqlValue> = {
      connection_id: "changed",
      stream: "other",
      primary_key: '["key"]',
      semantics: "append_only",
      incremental: 1,
      profile_key: "profile",
      profile_version: "2",
      complete: 0,
      needs_full: 1,
      floor_version: "2",
      floor_o: 10,
      floor_r: "floor",
      last_delete_version: 2,
      head_version: 4,
      head_generation: 2,
      head_data_hash: "hash",
      head_blob: "other-head",
      publish_watermark: 4,
    };
    for (const [table, original, changes] of [
      ["connections", control!, controlChanges],
      ["stream_state", head!, headChanges],
    ] as const) {
      for (const [column, value] of Object.entries(changes)) {
        await db.batch([
          { sql: `UPDATE ${table} SET ${column} = ?`, params: [value] },
        ]);
        expect(await listing.cacheKey(), table + "." + column).not.toBe(
          baseline,
        );
        await db.batch([
          {
            sql: `UPDATE ${table} SET ${column} = ?`,
            params: [original[column]!],
          },
        ]);
        expect(await listing.cacheKey()).toBe(baseline);
      }
    }
    await db.batch([
      {
        sql: "INSERT INTO connections(connection_id, connector, ns) VALUES ('empty', 'other', '')",
      },
    ]);
    const inserted = await listing.cacheKey();
    expect(inserted).not.toBe(baseline);
    await db.batch([
      { sql: "DELETE FROM connections WHERE connection_id = 'empty'" },
    ]);
    expect(await listing.cacheKey()).toBe(baseline);
    await db.batch([{ sql: "DELETE FROM stream_state" }]);
    expect(await listing.cacheKey()).not.toBe(baseline);
  });
});
