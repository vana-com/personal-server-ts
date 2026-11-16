/**
 * `GET /v1/streams/:stream/records` on the Lite runtime and on the Node
 * route serve the same pages for one switched store, from one core handler.
 *
 * Real: the Lite runtime and its Web3Signed owner auth, the Node Hono route,
 * the database composition (heads, SQLite apply) and the linked RecordQuery.
 * Stubbed: the PDPP token resolver on the Node side.
 */
import { afterEach, describe, expect, it } from "vitest";
import { PDPP_VERSION } from "@opendatalabs/personal-server-ts-core/pdpp-version";
import {
  createModeAuthority,
  createMemoryModeRecordStore,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import {
  connectionQueue,
  openLocalDb,
  type LocalSync,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { createStreamDeclarationRegistry } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createMemoryRecordStore } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import { createPsLiteRuntime, createWeb3SignedPsLiteAuth } from "./runtime.js";
import {
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { openBetterSqlite3 } from "../../server/src/localdb/better-sqlite3-driver.js";
import { remoteFixture } from "../../server/src/localdb/apply-fixture.js";
import { createServerLocalSync } from "../../server/src/localdb/sync.js";
import { pdppRecordsRoutes } from "../../server/src/routes/pdpp-records.js";

const ORIGIN = "https://ps-lite.local";
const owner = createTestWallet(7);
const CONNECTOR = "meta";
const SOURCE_ID = "https://registry.test/connectors/meta";
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

const POSTS = ["p1", "p2", "p3", "p4", "p5"].map((id, index) => ({
  id,
  caption: `caption ${id}`,
  like_count: index,
}));

async function switchedStore(): Promise<LocalSync> {
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const remote = await remoteFixture(keys, CONNECTOR);
  await remote.head("posts", POSTS, {
    profile: { key: CONNECTOR, version: "1" },
  });
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: owner.address,
    network: "test",
    deviceId: "lite-records",
  });
  drivers.push(db);
  let op = 0;
  const local = createServerLocalSync(
    {
      db,
      queue: connectionQueue(),
      ownerAddress: owner.address,
      registry: remote.registry,
      blobs: remote.storage,
      keys,
      signer: { signAddData: async () => "0x00" },
      logger: { info() {}, warn() {} },
      now: () => 100,
      newOp: () => String(++op),
    },
    {
      resolveArtifact: () => undefined,
      declaredStreams: (connector) =>
        connector === CONNECTOR ? ["posts"] : [],
      olderVersionReads: () => true,
    },
  );
  await local.apply();
  return local;
}

async function liteRuntime(local: LocalSync) {
  const authority = createModeAuthority({
    store: createMemoryModeRecordStore(),
  });
  await authority.ready;
  await authority.submitEvidence({ owner: owner.address, state: "on" });
  const accessLogSink = {
    async write() {},
    async read() {
      return { logs: [], total: 0, limit: 50, offset: 0 };
    },
  };
  return createPsLiteRuntime({
    accountModeAuthority: authority,
    active: true,
    storage: createMemoryPsLiteStorage(),
    accessLogReader: accessLogSink,
    accessLogWriter: accessLogSink,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
    serverOwner: owner.address,
    localSync: async () => local,
    auth: createWeb3SignedPsLiteAuth({
      origin: ORIGIN,
      ownerAddress: owner.address,
    }),
  });
}

async function liteGet(
  runtime: Awaited<ReturnType<typeof liteRuntime>>,
  pathAndQuery: string,
): Promise<Response> {
  const auth = await buildWeb3SignedHeader({
    wallet: owner,
    aud: ORIGIN,
    method: "GET",
    uri: pathAndQuery.split("?")[0]!,
  });
  return runtime.fetch(
    new Request(`${ORIGIN}${pathAndQuery}`, {
      headers: { Authorization: auth },
    }),
  );
}

/** The Node route over the same store, with an unscoped owner token. */
function nodeApp(local: LocalSync, token = {}) {
  return pdppRecordsRoutes({
    store: createMemoryRecordStore(),
    auth: createFixtureAuthorizationService({
      owner: {
        active: true,
        tokenKind: "owner",
        subjectId: "sub_1",
        ...token,
      },
    }),
    declarations: createStreamDeclarationRegistry([
      {
        name: "posts",
        semantics: "mutable_state",
        primaryKey: ["id"],
        cursorField: "id",
        requiredFields: ["id"],
      },
    ]),
    ownerSubjectId: "sub_1",
    accountStorageMode: { owner: "sub_1", read: () => "switched" },
    recordQuery: local.recordsFor((connector) => ({
      connector,
      namespace: "",
    })),
    instancesForSubject: () => [CONNECTOR],
    instancesForSource: (_subject, sourceId) =>
      sourceId === SOURCE_ID ? [CONNECTOR] : [],
    sourceIdForConnector: (connector) =>
      connector === CONNECTOR ? SOURCE_ID : undefined,
  });
}

async function nodeGet(
  app: ReturnType<typeof nodeApp>,
  pathAndQuery: string,
): Promise<Response> {
  return app.request(pathAndQuery.replace(/^\/v1/, ""), {
    headers: { Authorization: "Bearer owner" },
  });
}

describe("GET /v1/streams/:stream/records on the Lite runtime", () => {
  it("serves the switched owner's first page and a next cursor", async () => {
    const runtime = await liteRuntime(await switchedStore());
    const res = await liteGet(
      runtime,
      `/v1/streams/posts/records?limit=2&source=${CONNECTOR}`,
    );
    expect(res.status, await res.clone().text()).toBe(200);
    const body = await res.json();
    expect(body.object).toBe("list");
    expect(body.data.map((row: { id: string }) => row.id)).toEqual([
      "p1",
      "p2",
    ]);
    expect(body.has_more).toBe(true);
    expect(typeof body.next_cursor).toBe("string");
  });

  it("refuses a read that names no source, as Node refuses an unscoped token", async () => {
    const local = await switchedStore();
    const lite = await liteGet(
      await liteRuntime(local),
      "/v1/streams/posts/records?limit=2",
    );
    const node = await nodeGet(
      nodeApp(local),
      "/v1/streams/posts/records?limit=2",
    );
    expect(lite.status).toBe(403);
    expect(node.status).toBe(403);
    expect(await lite.json()).toEqual(
      expect.objectContaining({
        error: expect.objectContaining({ code: "grant_stream_not_allowed" }),
      }),
    );
  });
});

describe("Node and Lite serve identical pages for one store", () => {
  it("returns the same bodies for the same query string, page after page", async () => {
    const local = await switchedStore();
    const runtime = await liteRuntime(local);
    const app = nodeApp(local);
    let cursor: string | undefined;
    const seen: string[] = [];
    for (let page = 0; page < 5; page++) {
      const query =
        `limit=2&source=${CONNECTOR}` +
        (cursor ? `&cursor=${encodeURIComponent(cursor)}` : "");
      const path = `/v1/streams/posts/records?${query}`;
      const [lite, node] = [
        await liteGet(runtime, path),
        await nodeGet(app, path),
      ];
      expect(lite.status).toBe(200);
      expect(node.status).toBe(200);
      const liteBody = await lite.json();
      expect(liteBody).toEqual(await node.json());
      seen.push(...liteBody.data.map((row: { id: string }) => row.id));
      cursor = liteBody.next_cursor;
      if (!liteBody.has_more) break;
    }
    expect(seen).toEqual(POSTS.map((post) => post.id));
  });

  it.each([
    ["an undeclared stream", "/v1/streams/nope/records?source=meta"],
    ["an unknown source", "/v1/streams/posts/records?source=other"],
    ["no source", "/v1/streams/posts/records?limit=2"],
    ["an empty source", "/v1/streams/posts/records?source="],
  ])("answers %s with the same status and body", async (_name, path) => {
    const local = await switchedStore();
    const lite = await liteGet(await liteRuntime(local), path);
    const node = await nodeGet(nodeApp(local), path);
    const withoutRequestId = (body: { error: Record<string, unknown> }) => ({
      error: { ...body.error, request_id: undefined },
    });
    expect(lite.status).toBe(node.status);
    expect(withoutRequestId(await lite.json())).toEqual(
      withoutRequestId(await node.json()),
    );
  });
});

describe("PDPP-Version negotiation on both hosts", () => {
  /** A store whose record queries are counted. */
  async function countedStore() {
    const base = await switchedStore();
    const calls = { queries: 0 };
    const counted = Object.create(base) as LocalSync;
    counted.recordsFor = ((link: Parameters<LocalSync["recordsFor"]>[0]) => {
      const query = base.recordsFor(link);
      return Object.create(query, {
        listRecords: {
          value: (...args: unknown[]) => {
            calls.queries++;
            return (query.listRecords as (...a: unknown[]) => unknown)(...args);
          },
        },
      });
    }) as LocalSync["recordsFor"];
    return { local: counted, calls };
  }

  async function get(
    host: "lite" | "node",
    local: LocalSync,
    version: string | undefined,
    path = `/v1/streams/posts/records?source=${CONNECTOR}`,
  ) {
    const headers: Record<string, string> =
      version === undefined ? {} : { "PDPP-Version": version };
    if (host === "node") {
      return nodeApp(local).request(path.replace(/^\/v1/, ""), {
        headers: { Authorization: "Bearer owner", ...headers },
      });
    }
    const runtime = await liteRuntime(local);
    const auth = await buildWeb3SignedHeader({
      wallet: owner,
      aud: ORIGIN,
      method: "GET",
      uri: path.split("?")[0]!,
    });
    return runtime.fetch(
      new Request(`${ORIGIN}${path}`, {
        headers: { Authorization: auth, ...headers },
      }),
    );
  }

  it.each(["lite", "node"] as const)(
    "%s: serves a missing or supported version",
    async (host) => {
      for (const version of [undefined, PDPP_VERSION]) {
        const { local, calls } = await countedStore();
        const response = await get(host, local, version);
        expect(response.status).toBe(200);
        expect(calls.queries).toBeGreaterThan(0);
      }
    },
  );

  it("refuses an unsupported version with the same answer and no query", async () => {
    const [lite, node] = [await countedStore(), await countedStore()];
    const liteResponse = await get("lite", lite.local, "9999-01-01");
    const nodeResponse = await get("node", node.local, "9999-01-01");
    expect(liteResponse.status).toBe(400);
    expect(liteResponse.status).toBe(nodeResponse.status);
    const strip = (body: { error: Record<string, unknown> }) => ({
      error: { ...body.error, request_id: undefined },
    });
    expect(strip(await liteResponse.json())).toEqual(
      strip(await nodeResponse.json()),
    );
    expect(lite.calls.queries).toBe(0);
    expect(node.calls.queries).toBe(0);
  });

  const sameTail = `https://unconfigured.invalid/another-source/${CONNECTOR}`;

  it("refuses a source id that only shares a connector's last segment, with no query", async () => {
    const path = `/v1/streams/posts/records?source=${encodeURIComponent(sameTail)}`;
    const [lite, node] = [await countedStore(), await countedStore()];
    const liteResponse = await get("lite", lite.local, undefined, path);
    const nodeResponse = await get("node", node.local, undefined, path);
    expect(liteResponse.status).toBe(403);
    expect(nodeResponse.status).toBe(403);
    expect(lite.calls.queries).toBe(0);
    expect(node.calls.queries).toBe(0);
  });

  it("refuses the configured canonical id on Lite, which holds no source ids; Node serves it", async () => {
    const path = `/v1/streams/posts/records?source=${encodeURIComponent(SOURCE_ID)}`;
    const [lite, node] = [await countedStore(), await countedStore()];
    const liteResponse = await get("lite", lite.local, undefined, path);
    const nodeResponse = await get("node", node.local, undefined, path);
    expect(liteResponse.status).toBe(403);
    expect(lite.calls.queries).toBe(0);
    expect(nodeResponse.status).toBe(200);
  });
});
