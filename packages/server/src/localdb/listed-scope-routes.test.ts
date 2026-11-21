import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "../../../core/src/api/index.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import type {
  AliasDiagnostic,
  LocalAliasTarget,
} from "../../../core/src/localdb/resolve.js";
import { createLocalSync } from "../../../core/src/localdb/sync.js";
import type { StreamSyncFiles } from "../../../core/src/stream-sync/ports.js";
import {
  createStorageAccess,
  DEFAULT_STORAGE_ACCESS_POLICY,
} from "../../../core/src/stream-sync/storage-retry.js";
import { createMemoryDataStorage } from "../../../core/src/test-utils/memory-storage.js";
import { createFsStreamSyncFiles } from "../stream-sync/fs-files.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

// The resolver applies registry heads before it reads; the rows below are
// already installed, so there is nothing to fetch.
vi.mock("../../../core/src/localdb/apply.js", () => ({
  applyConnection: vi.fn(async () => []),
}));

/**
 * One naming contract, four consumers: every name `GET /v1/data` lists must
 * answer on every route that takes a scope name. The fixture uses neutral
 * names and covers each kind of listed name:
 *
 * - `pdpp.<connector>.<stream>`: the logical stream names;
 * - `plain.items`: a short alias whose connector key equals its source id;
 * - `acme.events`, `acme.window`: short aliases whose connector key
 *   (`acme-browser`) differs from the source id, one serving a window of
 *   two streams from its parent stream.
 */
const OWNER = "0x0000000000000000000000000000000000000001";
const project = (records: readonly unknown[]) => ({
  ok: true as const,
  payload: { records },
});
const ALIASES: Record<string, readonly LocalAliasTarget[]> = {
  "plain.items": [{ connector: "plain", streams: ["items"], project }],
  "acme.events": [{ connector: "acme-browser", streams: ["events"], project }],
  "acme.window": [
    {
      connector: "acme-browser",
      streams: ["events", "details"],
      servedStream: "events",
      windowed: true,
      project,
    },
  ],
};
const ALL_NAMES = [
  "acme.events",
  "acme.window",
  "pdpp.acme-browser.details",
  "pdpp.acme-browser.events",
  "pdpp.plain.items",
  "plain.items",
];

const drivers: SqlDriver[] = [];
const spoolDirs: string[] = [];
afterEach(async () => {
  for (const driver of drivers.splice(0)) await driver.close();
  for (const dir of spoolDirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

/** A spool on a directory of its own, as the server keeps one. */
async function newSpool(): Promise<StreamSyncFiles> {
  const dir = await mkdtemp(join(tmpdir(), "listed-scope-spool-"));
  spoolDirs.push(dir);
  return createFsStreamSyncFiles(dir);
}

const get = (deps: PersonalServerDataApiDeps, path: string) =>
  handlePersonalServerDataRequest(
    new Request(`https://server.example/v1/data${path}`),
    deps,
    { basePath: "/v1/data" },
  );

const baseDeps = {
  auth: {
    authorizeOwner: vi.fn(async () => undefined),
    authorizeBuilderList: vi.fn(async () => undefined),
    authorizeBuilderRead: vi.fn(async () => ({ grantId: "owner" })),
  },
  accessLogWriter: { write: vi.fn(async () => undefined) },
  logger: { debug: vi.fn(), error: vi.fn(), warn: vi.fn(), info: vi.fn() },
  serverOwner: OWNER,
  now: () => new Date(5000),
  createLogId: () => "log",
};

async function switchedFixture(
  aliases: Record<string, readonly LocalAliasTarget[]> = ALIASES,
  host: {
    /** The host's alias spool: the server has one, Lite has none. */
    readonly spool?: StreamSyncFiles;
    readonly authorizeBuilderRead?: typeof baseDeps.auth.authorizeBuilderRead;
  } = {},
) {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: "0xabc",
    network: "test",
    deviceId: "listed-scope-routes",
  });
  drivers.push(db);
  const poison = new Proxy(
    {},
    {
      get() {
        throw new Error("unexpected access");
      },
    },
  );
  const sync = createLocalSync(
    {
      db,
      queue: connectionQueue(),
      ownerAddress: "0xabc",
      registry: poison,
      // Alias reads take their memory from the governor; nothing else is used.
      blobs: { governor: createStorageAccess(DEFAULT_STORAGE_ACCESS_POLICY) },
      keys: poison,
      signer: poison,
      logger: { info() {}, warn() {} },
      now: () => 5000,
      newOp: () => "op",
    } as unknown as LocalSyncDeps,
    {
      aliasScopes: () => Object.keys(aliases),
      aliasTargets: (scope) => aliases[scope] ?? [],
      aliasSpool: host.spool,
      resolveArtifact: () => null,
    },
  );
  const deps = {
    ...baseDeps,
    auth: {
      ...baseDeps.auth,
      ...(host.authorizeBuilderRead
        ? { authorizeBuilderRead: host.authorizeBuilderRead }
        : {}),
    },
    history: sync.history,
    streamSyncRead: {
      resolve: sync.resolver.resolve,
      resolveStreaming: sync.resolver.resolveStreaming,
      listScopes: sync.listing.listScopes,
    },
    accountMode: { read: () => "switched" as const },
    accountStorageMode: { owner: OWNER, read: () => "switched" as const },
    storage: new Proxy({} as PersonalServerDataApiDeps["storage"], {
      get: () => {
        throw new Error("Unexpected legacy storage access");
      },
    }),
  } as unknown as PersonalServerDataApiDeps;

  async function seed(
    connector: string,
    id: string,
    streams: Record<string, number[]>,
  ) {
    await db.batch([
      {
        sql: "INSERT INTO connections(connection_id, connector, ns, generation, control_state) VALUES (?, ?, '', 1, 'active')",
        params: [id, connector],
      },
    ]);
    for (const [stream, versions] of Object.entries(streams)) {
      const head = Math.max(...versions);
      for (const version of versions) {
        await db.batch([
          {
            sql: "INSERT INTO stream_versions(connection_id, stream, version, generation, head_blob, head_format, record_count, observed_at, complete, kind) VALUES (?, ?, ?, 1, ?, 3, 1, ?, 1, 'applied')",
            params: [
              id,
              stream,
              version,
              `${stream}-${version}`,
              version * 1000,
            ],
          },
        ]);
      }
      await db.batch([
        {
          sql: `INSERT INTO stream_state(connection_id, stream, primary_key, semantics, incremental, profile_key, profile_version, complete, last_delete_version, head_version, head_generation, head_data_hash, head_blob)
                VALUES (?, ?, '["id"]', 'mutable_state', 0, ?, '1.0.0', 1, 0, ?, 1, ?, ?)`,
          params: [
            id,
            stream,
            connector,
            head,
            `hash-${stream}`,
            `${stream}-${head}`,
          ],
        },
        {
          sql: "INSERT INTO records(connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256) VALUES (?, ?, 'hash', 'key', 1000, 'run', ?, 'body-hash')",
          params: [id, stream, JSON.stringify({ id: "key" })],
        },
      ]);
    }
  }
  return { deps, seed };
}

async function listed(deps: PersonalServerDataApiDeps): Promise<string[]> {
  const response = await get(deps, "?limit=100");
  expect(response.status).toBe(200);
  const body = (await response.json()) as { scopes: { scope: string }[] };
  return body.scopes.map((row) => row.scope).sort();
}

describe("every scope GET /v1/data lists answers on every scope route", () => {
  it("serves the same names on read, versions and lineage (switched)", async () => {
    const { deps, seed } = await switchedFixture();
    await seed("plain", "c1", { items: [1, 2] });
    await seed("acme-browser", "c2", { events: [3, 4], details: [7, 8, 9] });

    const names = await listed(deps);
    // Guards the fixture: it must list every kind of name.
    expect(names).toEqual(ALL_NAMES);

    const refused: string[] = [];
    for (const name of names) {
      for (const route of ["", "/versions?limit=200&offset=0", "/lineage"]) {
        const response = await get(deps, `/${name}${route}`);
        if (response.status !== 200) {
          refused.push(`${name}${route} -> ${response.status}`);
        }
        await response.body?.cancel();
      }
    }
    expect(refused).toEqual([]);
  });

  it("reports stream-sync on every non-empty page of a switched GET /v1/data listing", async () => {
    const { deps, seed } = await switchedFixture();
    await seed("plain", "c1", { items: [1] });
    await seed("acme-browser", "c2", { events: [3], details: [7] });

    const scopes: string[] = [];
    const limit = 2;
    for (let offset = 0; offset < ALL_NAMES.length; offset += limit) {
      const response = await get(deps, `?limit=${limit}&offset=${offset}`);
      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        listingStore: string;
        scopes: { scope: string }[];
        total: number;
        limit: number;
        offset: number;
      };
      expect(body).toMatchObject({
        listingStore: "stream-sync",
        total: ALL_NAMES.length,
        limit,
        offset,
      });
      expect(body.scopes.map((row) => row.scope)).toEqual(
        ALL_NAMES.slice(offset, offset + limit),
      );
      scopes.push(...body.scopes.map((row) => row.scope));
    }
    expect(scopes).toEqual(ALL_NAMES);
  });

  it("lists the version of the stream the alias serves", async () => {
    const { deps, seed } = await switchedFixture();
    await seed("plain", "c1", { items: [1, 2] });
    await seed("acme-browser", "c2", { events: [3, 4], details: [7, 8, 9] });

    const versionsOf = async (name: string) => {
      const response = await get(deps, `/${name}/versions?limit=200`);
      expect(response.status, name).toBe(200);
      return (await response.json()) as {
        scope: string;
        versions: { version: number; fileId: null }[];
        total: number;
      };
    };
    const logical = await versionsOf("pdpp.acme-browser.events");
    // Only the version a read serves: no older one has a body.
    expect(logical.versions.map((v) => v.version)).toEqual([4]);
    for (const name of ["acme.events", "acme.window"]) {
      // The same page as the logical name of the stream it serves, under the
      // name that was asked for. `details` (7-9) is never the answer.
      expect(await versionsOf(name), name).toEqual({ ...logical, scope: name });
    }
    expect(
      (await versionsOf("plain.items")).versions.map((v) => v.version),
    ).toEqual([2]);
  });

  it("answers an alias with no stream data as 404, like its read", async () => {
    const { deps, seed } = await switchedFixture();
    await seed("plain", "c1", { items: [1] });
    for (const route of ["", "/versions", "/lineage"]) {
      const response = await get(deps, `/acme.events${route}`);
      expect(response.status, route).toBe(404);
      await response.body?.cancel();
    }
  });

  it("answers an alias of a deleted connection as 410, like its read", async () => {
    const { deps, seed } = await switchedFixture();
    await seed("acme-browser", "c2", { events: [3, 4] });
    const db = drivers[0]!;
    await db.batch([
      { sql: "UPDATE connections SET control_state = 'deleted'" },
    ]);
    for (const route of ["", "/versions", "/lineage"]) {
      const response = await get(deps, `/acme.events${route}`);
      expect(response.status, route).toBe(410);
      await response.body?.cancel();
    }
  });

  it("serves a stored legacy file on read and versions (unswitched)", async () => {
    const deps = {
      ...baseDeps,
      storage: createMemoryDataStorage(),
      accountStorageMode: { owner: OWNER, read: () => "unswitched" as const },
    } as unknown as PersonalServerDataApiDeps;
    for (const version of ["1", "2"]) {
      const written = await handlePersonalServerDataRequest(
        new Request("https://server.example/legacy.items", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ version }),
        }),
        deps,
      );
      expect(written.status).toBe(201);
    }
    const names = await listed(deps);
    expect(names).toEqual(["legacy.items"]);
    for (const route of ["", "/versions?limit=200&offset=0"]) {
      const response = await get(deps, `/legacy.items${route}`);
      expect(response.status, route).toBe(200);
      await response.body?.cancel();
    }
  });
});

describe("an alias read whose projection dropped rows", () => {
  const dropped = {
    kind: "records_dropped" as const,
    scope: "plain.items",
    stream: "items",
    count: 2,
    reasons: ["invalid id"],
  };
  const withDiagnostics = (diagnostics: readonly AliasDiagnostic[]) => ({
    "plain.items": [
      {
        connector: "plain",
        streams: ["items"],
        project: (records: readonly unknown[]) => ({
          ok: true as const,
          payload: { records },
          diagnostics,
        }),
      },
    ],
  });

  it("refuses as incomplete and names the dropped rows, never a short 200", async () => {
    const { deps, seed } = await switchedFixture(withDiagnostics([dropped]));
    await seed("plain", "c1", { items: [1] });
    const response = await get(deps, "/plain.items");
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({
      error: "CANONICAL_VIEW_UNAVAILABLE",
      status: "incomplete",
      reason: "canonical_view_incomplete",
      diagnostics: [
        { stream: "items", kind: "dropped", detail: "2 rows: invalid id" },
      ],
    });
  });

  it("refuses rows the source reports short of detail", async () => {
    const { deps, seed } = await switchedFixture(
      withDiagnostics([{ ...dropped, kind: "records_partial" }]),
    );
    await seed("plain", "c1", { items: [1] });
    const response = await get(deps, "/plain.items");
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({
      diagnostics: [{ kind: "partial" }],
    });
  });

  it("is left out of the GET /v1/data listing, beside the logical stream it reads", async () => {
    for (const kind of ["records_dropped", "records_partial"] as const) {
      const { deps, seed } = await switchedFixture(
        withDiagnostics([{ ...dropped, kind }]),
      );
      await seed("plain", "c1", { items: [1] });
      expect(await listed(deps), kind).toEqual(["pdpp.plain.items"]);
    }
  });

  it("stays in the listing when its only diagnostic is stream_missing", async () => {
    const { deps, seed } = await switchedFixture(
      withDiagnostics([
        { kind: "stream_missing", scope: "plain.items", stream: "x" },
      ]),
    );
    await seed("plain", "c1", { items: [1] });
    expect(await listed(deps)).toEqual(["pdpp.plain.items", "plain.items"]);
  });

  it("still serves a projection with no dropped or partial rows", async () => {
    const { deps, seed } = await switchedFixture(
      withDiagnostics([
        { kind: "stream_missing", scope: "plain.items", stream: "x" },
      ]),
    );
    await seed("plain", "c1", { items: [1] });
    const response = await get(deps, "/plain.items");
    expect(response.status).toBe(200);
    await response.body?.cancel();
  });
});

/**
 * A host with no spool (Lite) builds an alias read in memory, as main does,
 * and refuses one whose stored bytes exceed 64 MiB. The status and the error
 * code are main's own: this test runs unchanged on main.
 */
describe("a switched alias read above 64 MiB, on a host with no spool", () => {
  it("answers 503 TOO_LARGE", async () => {
    const { deps, seed } = await switchedFixture();
    await seed("plain", "c1", { items: [1] });
    await drivers[0]!.batch([
      {
        sql: "UPDATE records SET body = ? WHERE connection_id = 'c1' AND stream = 'items'",
        params: [
          JSON.stringify({ id: "key", pad: "y".repeat(65 * 1024 * 1024) }),
        ],
      },
    ]);
    const response = await get(deps, "/plain.items");
    expect(response.status).toBe(503);
    const body = (await response.json()) as {
      error: { code: number; errorCode: string; message: string };
    };
    expect(body.error).toMatchObject({ code: 503, errorCode: "TOO_LARGE" });
  }, 60_000);
});

/**
 * A windowed alias: parents with one child each, and a profile beside the
 * array. Its output is small, whatever the children weigh.
 */
const windowedTree: LocalAliasTarget = {
  connector: "tree",
  streams: ["parents", "kids"],
  window: {
    parentStream: "parents",
    parentKey: "id",
    childStream: "kids",
    childKey: "parent",
    arrayKey: "items",
    sumKeys: ["kids"],
    parentOrder: (a, b) => String(a.id).localeCompare(String(b.id)),
  },
  project: (records) => {
    const parents = records.filter((r) => r.stream === "parents");
    return {
      ok: true as const,
      payload: {
        profile: { name: "tree" },
        items: parents.map((p) => p.data),
        kids: records.length - parents.length,
      },
    };
  },
};

/** The tree's rows: `parents` parents, each with one child of `kidBytes` of text. */
async function seedTree(
  fixture: Awaited<ReturnType<typeof switchedFixture>>,
  parents: number,
  kidBytes: number,
) {
  await fixture.seed("tree", "c1", { parents: [1], kids: [1] });
  const db = drivers[0]!;
  await db.batch([{ sql: "DELETE FROM records" }]);
  const rows = (stream: string, body: (i: number) => unknown) =>
    Array.from({ length: parents }, (_, i) => ({
      sql: "INSERT INTO records(connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256) VALUES ('c1', ?, ?, ?, 1000, 'run', ?, 'body-hash')",
      params: [
        stream,
        `${stream}-${String(i).padStart(4, "0")}`,
        `${stream}${i}`,
        JSON.stringify(body(i)),
      ],
    }));
  await db.batch(
    rows("parents", (i) => ({ id: `p${String(i).padStart(4, "0")}` })),
  );
  await db.batch(
    rows("kids", (i) => ({
      id: `k${i}`,
      parent: `p${String(i).padStart(4, "0")}`,
      pad: "y".repeat(kidBytes),
    })),
  );
}

/**
 * The listing and the read decide on one predicate: whether a body can be
 * built here. A host with no spool (Lite) builds a windowed alias in memory
 * and refuses one above 64 MiB; a host with a spool pages it into a file.
 */
describe("the listing and the read agree on a windowed alias above 64 MiB", () => {
  const aliases = { "tree.items": [windowedTree] };
  const MiB = 1024 * 1024;

  for (const host of [
    { name: "Lite (no spool)", spool: false, served: false },
    { name: "the server (spool)", spool: true, served: true },
  ]) {
    it(`${host.name}: lists it exactly when it serves it`, async () => {
      const fixture = await switchedFixture(aliases, {
        spool: host.spool ? await newSpool() : undefined,
      });
      await seedTree(fixture, 65, MiB);
      const names = await listed(fixture.deps);
      const response = await get(fixture.deps, "/tree.items");
      const served = response.status === 200;
      await response.body?.cancel();
      expect(names.includes("tree.items")).toBe(served);
      expect(served).toBe(host.served);
      if (!host.served) expect(response.status).toBe(503);
    }, 120_000);
  }
});

/**
 * The body is written to the spool before settlement runs. A settlement that
 * fails must not leave that file behind.
 */
describe("a read whose settlement fails leaves nothing in the spool", () => {
  it("removes the file of the body it will not serve", async () => {
    const spool = await newSpool();
    const fixture = await switchedFixture(
      { "tree.items": [windowedTree] },
      {
        spool,
        // The check before the read passes; the settlement after it throws.
        authorizeBuilderRead: vi.fn(
          async (input: { metadataOnly?: boolean }) => {
            if (!input.metadataOnly) throw new Error("settlement failed");
            return { grantId: "owner" };
          },
        ) as typeof baseDeps.auth.authorizeBuilderRead,
      },
    );
    await seedTree(fixture, 3, 1000);
    const response = await get(fixture.deps, "/tree.items").catch(() => null);
    expect(response?.status).not.toBe(200);
    await response?.body?.cancel();
    expect(await spool.list("")).toEqual([]);
  });
});

/**
 * The spooled body is for the consumer that streams it to a client. An
 * in-process read (MCP) reads the body whole to check or parse it, so it takes
 * main's capped path: a request that was small cannot exhaust the heap on an
 * alias main refused.
 */
describe("an in-process read of a windowed alias above 64 MiB", () => {
  const aliases = { "tree.items": [windowedTree] };

  it("answers 503 TOO_LARGE, as main does, and never reads the body whole", async () => {
    const spool = await newSpool();
    const fixture = await switchedFixture(aliases, { spool });
    await seedTree(fixture, 65, 1024 * 1024);
    const validateBody = vi.fn(async () => undefined);
    const response = await handlePersonalServerDataRequest(
      new Request("https://server.example/v1/data/tree.items"),
      fixture.deps,
      {
        basePath: "/v1/data",
        inProcess: { onServed: vi.fn(), validateBody },
      },
    );
    expect(response.status).toBe(503);
    expect(
      ((await response.json()) as { error: { errorCode: string } }).error
        .errorCode,
    ).toBe("TOO_LARGE");
    expect(validateBody).not.toHaveBeenCalled();
    expect(await spool.list("")).toEqual([]);
    // The same alias, streamed to a client, is served from the spool.
    const streamed = await get(fixture.deps, "/tree.items");
    expect(streamed.status).toBe(200);
    await streamed.body?.cancel();
  }, 120_000);
});
