import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { SqlDriver, SqlValue } from "../../../core/src/localdb/driver.js";
import { createLocalListing } from "../../../core/src/localdb/listing.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { addConnection, addStream } from "./local-state-fixture.js";

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
  const project = vi.fn<(records: readonly unknown[]) => unknown>(() => ({
    ok: true as const,
    payload: {},
  }));
  return {
    db,
    warn,
    counts,
    project,
    listing: createLocalListing(
      {
        ...deps,
        aliasTargets: (scope) =>
          scope === "example.summary"
            ? [
                {
                  connector: "sample",
                  streams: ["items"],
                  project: project as never,
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
  await addConnection(db, "c1", "sample", { control, generation: 1 });
  await addStream(db, "c1", "items", {
    generation: 1,
    version: local ? 0 : 3,
    complete: !local,
    observedAt: 1000,
    stampBase: 1234,
    records: 1,
    profile: "sample",
  });
}

const iso = (ms: number) => new Date(ms).toISOString();
const the = (updatedAt = 1234) => ({
  scope: "pdpp.sample.items",
  connector: "sample",
  ns: "",
  records: 1,
  updatedAt,
  latestCollectedAt: iso(updatedAt),
});

beforeEach(() => {
  vi.clearAllMocks();
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
    const canRead = vi.fn(() => true);
    const expected = [
      {
        scope: "example.summary",
        connector: "sample",
        ns: "",
        records: null,
        aliasOf: "pdpp.sample.items",
        updatedAt: 1234,
        latestCollectedAt: iso(1234),
      },
      the(),
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
    const { db, listing, project } = await fresh({});
    await seed(db);
    const canRead = vi.fn(() => true);

    expect(await listing.listScopes({ canRead })).toEqual([the()]);
    expect(canRead.mock.calls).toEqual([["pdpp.sample.items"]]);
    expect(project).not.toHaveBeenCalled();
  });

  it("lists readable scopes only, with the grant filter before the alias projection", async () => {
    const { db, listing, project } = await fresh();
    await seed(db);
    const events: string[] = [];
    const allow = vi.fn(async (scope: string) => {
      events.push("grant:" + scope);
      await Promise.resolve();
      return scope === "pdpp.sample.items";
    });

    expect(await listing.listScopes({ canRead: async () => false })).toEqual(
      [],
    );
    expect(project).not.toHaveBeenCalled();

    expect(await listing.listScopes({ canRead: allow })).toEqual([the()]);
    expect(events).toEqual([
      "grant:example.summary",
      "grant:pdpp.sample.items",
    ]);
    expect(project).not.toHaveBeenCalled();
  });

  it("skips and logs a throwing covered check while continuing other scopes", async () => {
    const { db, listing, warn, project } = await fresh();
    await seed(db);
    project.mockImplementation(() => {
      throw new Error("projection failed");
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
    project.mockClear();
    expect(
      await listing.listScopes({
        canRead: (scope) => {
          if (scope === "pdpp.sample.items") throw new Error("grant failed");
          return false;
        },
      }),
    ).toEqual([]);
    expect(project).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(
      { scope: "pdpp.sample.items" },
      "localdb listing: scope check failed",
    );
  });

  it("lists no scope for a connection with no applied head, as a read serves none", async () => {
    const { db, listing, counts } = await fresh();
    await seed(db, "absent");
    expect(await listing.listScopes({ canRead: () => true })).toEqual([]);
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

  it("lists an alias only when its installed records project", async () => {
    const { db, listing, warn, project } = await fresh();
    await seed(db);
    const canRead = (scope: string) => scope === "example.summary";
    project.mockImplementation(() => {
      throw new Error("late projection failure");
    });
    expect(await listing.listScopes({ canRead })).toEqual([]);
    expect(warn).toHaveBeenCalledTimes(1);

    project.mockImplementation(() => ({
      ok: false,
      error: { kind: "unsupported" },
    }));
    expect(await listing.listScopes({ canRead })).toEqual([]);
    project.mockImplementation(() => ({ ok: true, payload: {} }));
    expect(await listing.listScopes({ canRead })).toEqual([
      {
        scope: "example.summary",
        connector: "sample",
        ns: "",
        records: null,
        aliasOf: "pdpp.sample.items",
        updatedAt: 1234,
        latestCollectedAt: iso(1234),
      },
    ]);
    expect(project.mock.calls[0]?.[0]).toEqual([
      { stream: "items", data: { id: "0", stream: "items" } },
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
