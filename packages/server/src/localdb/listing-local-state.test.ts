import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import {
  createLocalListing,
  type ListedScope,
} from "../../../core/src/localdb/listing.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { addConnection, addStream } from "./local-state-fixture.js";
import { referenceListScopes } from "./listing-reference.js";

const mocked = vi.hoisted(() => ({ apply: vi.fn(async () => []) }));
// The reference listing applies before it reads; with this no-op it sees the
// local state as it is, which is what the bounded listing reads too.
vi.mock("../../../core/src/localdb/apply.js", () => ({
  applyConnection: mocked.apply,
}));

const opened: SqlDriver[] = [];
afterEach(async () => {
  for (const db of opened.splice(0)) await db.close();
});
beforeEach(() => mocked.apply.mockClear());

/** A port that records every call; the listing must make none. */
function forbidden(name: string, calls: string[]) {
  return new Proxy(
    {},
    {
      get: (_target, method) => {
        if (typeof method === "symbol") return undefined;
        return (...args: unknown[]) => {
          calls.push(`${name}.${method}(${args.length})`);
          throw new Error(`listing called ${name}.${method}`);
        };
      },
    },
  );
}

async function fixture() {
  const sqlite = openBetterSqlite3(":memory:");
  const queries: string[] = [];
  const db: SqlDriver = {
    ...sqlite,
    info: sqlite.info,
    query: (sql, params) => {
      queries.push(sql);
      return sqlite.query(sql, params);
    },
    batch: (statements) => sqlite.batch(statements),
    close: () => sqlite.close(),
  };
  await openLocalDb(db, {
    owner: "0xabc",
    network: "test",
    deviceId: "listing-local-state",
  });
  opened.push(db);
  queries.length = 0; // count the listing's reads, not the migrations
  const portCalls: string[] = [];
  const queue = connectionQueue();
  const run = vi.spyOn(queue, "run");
  const warn = vi.fn();
  const deps = {
    db,
    queue,
    ownerAddress: "0xabc",
    registry: forbidden("registry", portCalls),
    blobs: forbidden("blobs", portCalls),
    keys: forbidden("keys", portCalls),
    signer: forbidden("signer", portCalls),
    logger: { info: vi.fn(), warn },
    now: () => 9000,
    newOp: () => "op",
  } as unknown as LocalSyncDeps;
  const project = vi.fn((records: readonly unknown[]) => ({
    ok: true as const,
    payload: { count: records.length },
  }));
  const aliases = {
    aliasScopes: () => ["fixture.summary", "fixture.broken"],
    aliasTargets: (scope: string) =>
      scope === "fixture.summary"
        ? [{ connector: "alpha", streams: ["a1", "a2"], project }]
        : scope === "fixture.broken"
          ? [
              {
                connector: "alpha",
                streams: ["a1"],
                project: () => ({
                  ok: false as const,
                  error: { kind: "unsupported" },
                }),
              },
            ]
          : [],
  };
  const withAliases = { ...deps, ...aliases };
  const counts = () => ({ served: 0, gone: 0, off: 0 });
  return {
    db,
    deps: withAliases,
    queries,
    portCalls,
    queueRun: run,
    warn,
    project,
    listing: createLocalListing(withAliases, counts),
  };
}

/** Several connections and streams, in every state a read can meet. */
async function seedBusyHost(db: SqlDriver) {
  await addConnection(db, "alpha1", "alpha");
  await addStream(db, "alpha1", "a1", {
    records: 3,
    stampBase: 2000,
    profile: "alpha",
  });
  await addStream(db, "alpha1", "a2", {
    records: 5,
    stampBase: 3000,
    observedAt: 7000,
    profile: "alpha",
  });
  // Two connections of one connector: the newer head wins (ns "" is older).
  await addConnection(db, "beta1", "beta");
  await addStream(db, "beta1", "b1", { records: 2, observedAt: 5000 });
  await addConnection(db, "beta2", "beta", { ns: "aaaaaaaaaaaaaaaa" });
  await addStream(db, "beta2", "b1", {
    records: 4,
    observedAt: 9000,
    stampBase: 4000,
  });
  // One complete stream and one that is not.
  await addConnection(db, "gamma1", "gamma");
  await addStream(db, "gamma1", "g1", { records: 1 });
  await addStream(db, "gamma1", "g2", { records: 6, complete: false });
  // Not served: deleted, tombstoned, foreign, absent, other generation.
  await addConnection(db, "delta1", "delta", { control: "deleted" });
  await addStream(db, "delta1", "d1");
  await addConnection(db, "delta2", "delta2", { deletedAt: 100 });
  await addStream(db, "delta2", "d1");
  await addConnection(db, "eps1", "eps");
  await addStream(db, "eps1", "e1", { lastDeleteVersion: 3 });
  await addConnection(db, "zeta1", "zeta", { control: "foreign" });
  await addStream(db, "zeta1", "z1");
  await addConnection(db, "eta1", "eta", { control: "absent" });
  await addStream(db, "eta1", "h1", { version: 0, complete: false });
  await addConnection(db, "theta1", "theta", { generation: 3 });
  await addStream(db, "theta1", "t1", { generation: 2 });
}

const everything = () => true;
/** The old list predates `latestCollectedAt`; compare everything else. */
const withoutIso = (listed: readonly ListedScope[]) =>
  listed.map(({ latestCollectedAt: _iso, ...rest }) => rest);
const scopesOf = (listed: readonly ListedScope[]) => listed.map((s) => s.scope);

describe("bounded local scope list", () => {
  it("lists the scopes, counts and times the old list gave when local state is current", async () => {
    const f = await fixture();
    await seedBusyHost(f.db);
    const expected = await referenceListScopes(f.deps, everything);
    const listed = await f.listing.listScopes({ canRead: everything });
    expect(withoutIso(listed)).toEqual(expected);
    // Not vacuous: the fixture lists real scopes and leaves the rest out.
    expect(withoutIso(listed)).toEqual([
      {
        scope: "fixture.summary",
        connector: "alpha",
        ns: "",
        records: null,
        updatedAt: 7000,
      },
      {
        scope: "pdpp.alpha.a1",
        connector: "alpha",
        ns: "",
        records: 3,
        updatedAt: 5000,
      },
      {
        scope: "pdpp.alpha.a2",
        connector: "alpha",
        ns: "",
        records: 5,
        updatedAt: 7000,
      },
      {
        scope: "pdpp.beta.b1",
        connector: "beta",
        ns: "aaaaaaaaaaaaaaaa",
        records: 4,
        updatedAt: 9000,
      },
      {
        scope: "pdpp.gamma.g1",
        connector: "gamma",
        ns: "",
        records: 1,
        updatedAt: 5000,
      },
    ]);
    expect(f.warn).not.toHaveBeenCalled();
  });

  it("applies the grant filter per scope, as the old list did", async () => {
    const f = await fixture();
    await seedBusyHost(f.db);
    const canRead = (scope: string) => scope.startsWith("pdpp.alpha.");
    expect(withoutIso(await f.listing.listScopes({ canRead }))).toEqual(
      await referenceListScopes(f.deps, canRead),
    );
    expect(f.project).not.toHaveBeenCalled();
  });

  it("makes no registry, blob, key, signer, apply or queue call and reads no record body", async () => {
    const f = await fixture();
    await seedBusyHost(f.db);
    // A registry that is ahead of local state changes nothing: it is not asked.
    await f.listing.listScopes({ canRead: (s) => s.startsWith("pdpp.") });
    expect(f.portCalls).toEqual([]);
    expect(mocked.apply).not.toHaveBeenCalled();
    expect(f.queueRun).not.toHaveBeenCalled();
    expect(f.queries.filter((sql) => /\bbody\b/.test(sql))).toEqual([]);
    // Including the alias path, which reads local records to build its body.
    await f.listing.listScopes({ canRead: everything });
    expect(f.portCalls).toEqual([]);
    expect(mocked.apply).not.toHaveBeenCalled();
    expect(f.queueRun).not.toHaveBeenCalled();
  });

  it("lists a complete stream and not an incomplete one", async () => {
    const f = await fixture();
    await addConnection(f.db, "c1", "sample");
    await addStream(f.db, "c1", "items", { complete: false });
    expect(
      scopesOf(await f.listing.listScopes({ canRead: everything })),
    ).toEqual([]);
    await f.db.batch([
      { sql: "UPDATE stream_versions SET complete = 1" },
      { sql: "UPDATE stream_state SET complete = 1" },
    ]);
    expect(
      scopesOf(await f.listing.listScopes({ canRead: everything })),
    ).toEqual(["pdpp.sample.items"]);
  });

  it("does not list the streams of a deleted connection", async () => {
    const f = await fixture();
    await addConnection(f.db, "c1", "sample");
    await addStream(f.db, "c1", "items");
    expect(
      scopesOf(await f.listing.listScopes({ canRead: everything })),
    ).toEqual(["pdpp.sample.items"]);
    await f.db.batch([
      { sql: "UPDATE connections SET control_state = 'deleted'" },
    ]);
    expect(await f.listing.listScopes({ canRead: everything })).toEqual([]);
    await f.db.batch([
      {
        sql: "UPDATE connections SET control_state = 'active', deleted_at = 5",
      },
    ]);
    expect(await f.listing.listScopes({ canRead: everything })).toEqual([]);
    await f.db.batch([
      { sql: "UPDATE connections SET deleted_at = NULL" },
      { sql: "UPDATE stream_state SET last_delete_version = 2" },
    ]);
    expect(await f.listing.listScopes({ canRead: everything })).toEqual([]);
  });

  it("runs the underlying reads once for eight overlapping calls, and re-reads afterwards", async () => {
    const f = await fixture();
    await seedBusyHost(f.db);
    await f.listing.listScopes({ canRead: everything });
    const perCall = f.queries.length;
    expect(perCall).toBeGreaterThan(0);
    f.queries.length = 0;

    const results = await Promise.all(
      Array.from({ length: 8 }, (_, i) =>
        f.listing.listScopes({
          // Each caller has its own authority; the shared read does not leak it.
          canRead: (scope) => i % 2 === 0 || scope.startsWith("pdpp.alpha."),
        }),
      ),
    );
    expect(f.queries.length).toBe(perCall);
    expect(withoutIso(results[0]!)).toEqual(
      await referenceListScopes(f.deps, everything),
    );
    expect(scopesOf(results[1]!)).toEqual(["pdpp.alpha.a1", "pdpp.alpha.a2"]);
    expect(results[2]).toEqual(results[0]);

    // Once settled nothing is cached: new local state shows on the next call.
    await addConnection(f.db, "late", "late");
    await addStream(f.db, "late", "l1");
    expect(
      scopesOf(await f.listing.listScopes({ canRead: everything })),
    ).toContain("pdpp.late.l1");
  });

  it("does not grow its query count with the number of scopes", async () => {
    const f = await fixture();
    await addConnection(f.db, "c0", "c0");
    await addStream(f.db, "c0", "s0");
    await f.listing.listScopes({ canRead: everything });
    const one = f.queries.length;
    f.queries.length = 0;
    for (let i = 1; i < 12; i++) {
      await addConnection(f.db, `c${i}`, `c${i}`);
      await addStream(f.db, `c${i}`, "s0");
      await addStream(f.db, `c${i}`, "s1");
    }
    f.queries.length = 0;
    expect((await f.listing.listScopes({ canRead: everything })).length).toBe(
      23,
    );
    expect(f.queries.length).toBe(one);
  });

  it("serves the installed image when a retained head is newer, without fetching it", async () => {
    const f = await fixture();
    await addConnection(f.db, "alpha1", "alpha");
    await addStream(f.db, "alpha1", "a1", { profile: "alpha", version: 2 });
    await addStream(f.db, "alpha1", "a2", { profile: "alpha", version: 2 });
    // A newer complete version the installed head has not caught up with.
    await f.db.batch([
      {
        sql: "INSERT INTO stream_versions(connection_id, stream, version, generation, head_blob, head_format, record_count, observed_at, complete, kind) VALUES ('alpha1', 'a1', 3, 2, 'newer', 3, 1, 8000, 1, 'applied')",
      },
    ]);
    const listed = await f.listing.listScopes({ canRead: everything });
    expect(scopesOf(listed)).toEqual([
      "fixture.broken",
      "fixture.summary",
      "pdpp.alpha.a1",
      "pdpp.alpha.a2",
    ]);
    expect(f.portCalls).toEqual([]);
    // Aliases are listed without projecting records a read would not serve.
    expect(f.project).not.toHaveBeenCalled();
  });

  it("carries latestCollectedAt as the ISO form of updatedAt, and omits it with no times", async () => {
    const f = await fixture();
    await seedBusyHost(f.db);
    const listed = await f.listing.listScopes({ canRead: everything });
    expect(listed.length).toBeGreaterThan(0);
    for (const entry of listed) {
      expect(entry.updatedAt).not.toBeNull();
      expect(entry.latestCollectedAt).toBe(
        new Date(entry.updatedAt!).toISOString(),
      );
    }
    expect(
      listed.find((s) => s.scope === "pdpp.beta.b1")?.latestCollectedAt,
    ).toBe("1970-01-01T00:00:09.000Z");

    // A served stream with no record and no installed-head time has no time.
    await addConnection(f.db, "bare1", "bare");
    await addStream(f.db, "bare1", "b1", { records: 0, version: 3 });
    await f.db.batch([
      {
        sql: "UPDATE stream_state SET head_version = 2 WHERE connection_id = 'bare1'",
      },
    ]);
    const bare = (await f.listing.listScopes({ canRead: everything })).find(
      (s) => s.scope === "pdpp.bare.b1",
    );
    expect(bare).toEqual({
      scope: "pdpp.bare.b1",
      connector: "bare",
      ns: "",
      records: 0,
      updatedAt: null,
    });
    expect(bare).not.toHaveProperty("latestCollectedAt");
  });
});
