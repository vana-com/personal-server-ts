import { afterEach, describe, expect, it, vi } from "vitest";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "../../../core/src/api/index.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import type { LocalAliasTarget } from "../../../core/src/localdb/resolve.js";
import { createLocalSync } from "../../../core/src/localdb/sync.js";
import { createMemoryDataStorage } from "../../../core/src/test-utils/memory-storage.js";
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
afterEach(async () => {
  for (const driver of drivers.splice(0)) await driver.close();
});

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

async function switchedFixture() {
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
      blobs: poison,
      keys: poison,
      signer: poison,
      logger: { info() {}, warn() {} },
      now: () => 5000,
      newOp: () => "op",
    } as unknown as LocalSyncDeps,
    {
      aliasScopes: () => Object.keys(ALIASES),
      aliasTargets: (scope) => ALIASES[scope] ?? [],
      resolveArtifact: () => null,
      declaredStreams: () => [],
      olderVersionReads: () => true,
    },
  );
  const deps = {
    ...baseDeps,
    history: sync.history,
    streamSyncRead: {
      resolve: sync.resolver.resolve,
      listScopes: sync.listing.listScopes,
      olderVersions: sync.olderVersions,
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

  it("lists the versions of the stream the alias serves", async () => {
    const { deps, seed } = await switchedFixture();
    await seed("plain", "c1", { items: [1, 2] });
    await seed("acme-browser", "c2", { events: [3, 4], details: [7, 8, 9] });

    const versionsOf = async (name: string) => {
      const response = await get(deps, `/${name}/versions?limit=200`);
      expect(response.status, name).toBe(200);
      return (await response.json()) as {
        scope: string;
        versions: { version: number; fileId: string }[];
        total: number;
      };
    };
    const logical = await versionsOf("pdpp.acme-browser.events");
    expect(logical.versions.map((v) => v.version)).toEqual([4, 3]);
    for (const name of ["acme.events", "acme.window"]) {
      // The same page as the logical name of the stream it serves, under the
      // name that was asked for. `details` (7-9) is never the answer.
      expect(await versionsOf(name), name).toEqual({ ...logical, scope: name });
    }
    expect(
      (await versionsOf("plain.items")).versions.map((v) => v.version),
    ).toEqual([2, 1]);
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
