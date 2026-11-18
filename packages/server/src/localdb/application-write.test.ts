import type { ApplicationEnvelope } from "@opendatalabs/personal-server-ts-core/localdb";
import { pino } from "pino";
import { dataRoutes } from "../routes/data.js";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import {
  fixedOwnedAccountStorageMode,
  fixedLegacyWriteSeal,
  fixedModeAuthority,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  createPsLiteRuntime,
  createWeb3SignedPsLiteAuth,
} from "../../../lite/src/runtime.js";
import {
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
  createMemoryPsLiteAccessLogStore,
} from "../../../lite/src/test-support/memory.js";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  createLocalSync,
  type LocalSyncDeps,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { createWriteSessionAuthorization as createAuthorization } from "@opendatalabs/personal-server-ts-core/write";
import { remoteFixture } from "./apply-fixture.test-utils.js";
import { sha256 } from "@noble/hashes/sha2";
import { toHex } from "@opendatalabs/personal-server-ts-stream-sync";
import { afterEach, expect, it, vi } from "vitest";
import {
  connectionQueue,
  openLocalDb,
  type SqlDriver,
} from "../../../core/src/localdb/index.js";
import {
  createWriteSessionAuthorization,
  createInMemoryWriteSessionStore,
  createInMemoryWriteProofReplayStore,
  hashWriteSessionToken,
} from "@opendatalabs/personal-server-ts-core/write";
import type { GatewayGrantResponse } from "@opendatalabs/vana-sdk/browser";
import * as grantStore from "../../../core/src/localdb/application-grants.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const owner = `0x${"12".repeat(20)}` as const;
const wallet = createTestWallet(0);
const builder = wallet.address;
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

function grant(
  overrides: Partial<GatewayGrantResponse> = {},
): GatewayGrantResponse {
  return {
    id: "application-grant",
    grantVersion: "1",
    grantorAddress: owner,
    granteeId: "registered-app",
    scopes: ["write:notes.items"],
    expiresAt: null,
    revokedAt: null,
    expired: false,
    ...overrides,
  } as GatewayGrantResponse;
}
async function fixture(
  identityOwner = owner as string,
  signingWallet = wallet,
  network = "test",
  path = ":memory:",
) {
  const db = await openLocalDb(openBetterSqlite3(path), {
    owner: identityOwner,
    network,
    deviceId: "application-test",
  });
  drivers.push(db);
  const sessions = createInMemoryWriteSessionStore();
  await sessions.create({
    tokenHash: await hashWriteSessionToken("test-token"),
    builderAddress: signingWallet.address,
    grantId: "application-grant",
    writeScopes: ["notes.items"],
    createdAt: new Date().toISOString(),
    expiresAtMs: Date.now() + 60_000,
  });
  return { db, sessions, queue: connectionQueue() };
}

it("records an observed revocation through authorization before refusing the write", async () => {
  const f = await fixture();
  const observations = grantStore.createApplicationGrantStore(f.db);
  const auth = createWriteSessionAuthorization({
    serverOrigin: "https://server.example",
    serverOwner: owner,
    sessionStore: f.sessions,
    replayStore: createInMemoryWriteProofReplayStore(),
    policyPorts: {
      authSessionVerifier: {
        getBuilder: vi.fn().mockResolvedValue({ id: "registered-app" }),
      },
      grantVerifier: {
        getGrant: vi
          .fn()
          .mockResolvedValue(grant({ revokedAt: "2026-01-01T00:00:00Z" })),
      },
      grantObservations: observations,
    },
  });
  await expect(
    auth.authorizeSessionWrite({
      request: new Request("https://server.example/notes.items", {
        method: "POST",
        headers: { authorization: "Bearer test-token" },
        body: "{}",
      }),
      scope: "notes.items",
    }),
  ).rejects.toMatchObject({ errorCode: "GRANT_REVOKED" });
  const tables = await f.db.query(
    "SELECT name FROM sqlite_master WHERE name='application_grants'",
  );
  expect(tables).toHaveLength(1);
  expect(
    await f.db.query(
      "SELECT grant_id, revision, status FROM application_grants",
    ),
  ).toEqual([
    { grant_id: "application-grant", revision: "1", status: "revoked" },
  ]);
});

async function applicationFixture(
  options: {
    semantics?: "append_only" | "mutable_state";
    wallet?: typeof wallet;
    owner?: string;
    network?: string;
    path?: string;
    shared?: Awaited<ReturnType<typeof fixture>>;
  } = {},
) {
  const signingWallet = options.wallet ?? wallet;
  const applicationOwner = options.owner ?? owner;
  const builder = signingWallet.address;
  const f =
    options.shared ??
    (await fixture(
      applicationOwner,
      signingWallet,
      options.network,
      options.path,
    ));
  if (options.shared)
    await f.sessions.create({
      tokenHash: await hashWriteSessionToken("test-token"),
      builderAddress: builder,
      grantId: "application-grant",
      writeScopes: ["notes.items"],
      createdAt: new Date().toISOString(),
      expiresAtMs: Date.now() + 60_000,
    });
  const source = `urn:vana:builder:${builder.toLowerCase()}`;
  const document = JSON.stringify({
    source: { kind: "provider_native", id: source },
    declaration_version: "revision-one",
    streams: [
      {
        name: "items",
        semantics: options.semantics ?? "mutable_state",
        primary_key: ["id"],
        schema: {
          type: "object",
          properties: { id: { type: "string" }, value: { type: "string" } },
          required: ["id"],
        },
      },
    ],
  });
  const digest = toHex(sha256(new TextEncoder().encode(document)));
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const remote = await remoteFixture(keys);
  let op = 0;
  const wake = vi.fn();
  const deps: LocalSyncDeps = {
    db: f.db,
    keys,
    registry: remote.registry,
    blobs: remote.storage,
    queue: f.queue,
    ownerAddress: applicationOwner as `0x${string}`,
    signer: { signAddData: async () => "0x00" },
    logger: { info: vi.fn(), warn: vi.fn() },
    now: () => Date.now(),
    newOp: () => `application-${++op}`,
    recordsCommitted: wake,
  };
  const sync = createLocalSync(deps, {
    resolveArtifact: async () => null,
    resolveApplicationDeclaration: async () => ({
      document,
      scopeBindings: { "notes.items": ["items"] },
      writer: builder,
      bindingRevision: "binding-one",
    }),
  });
  let observed = grant({ grantorAddress: applicationOwner });
  const auth = createAuthorization({
    serverOrigin: "https://server.example",
    serverOwner: applicationOwner as `0x${string}`,
    sessionStore: f.sessions,
    replayStore: createInMemoryWriteProofReplayStore(),
    policyPorts: {
      authSessionVerifier: {
        getBuilder: vi.fn().mockResolvedValue({ id: "registered-app" }),
      },
      grantVerifier: { getGrant: async () => observed },
    },
  });
  const envelope = {
    mutationId: "mutation-one",
    declaration: { digest },
    record: {
      stream: "items",
      key: "one",
      data: { id: "one", value: "first" },
      emitted_at: "2026-01-01T00:00:00Z",
    },
  };
  let nonce = 0;
  async function authorize(input: ApplicationEnvelope = envelope) {
    const body = JSON.stringify(input);
    const signature = await buildWeb3SignedHeader({
      wallet: signingWallet,
      aud: "https://server.example",
      method: "POST",
      uri: "/notes.items",
      body: new TextEncoder().encode(body),
      grantId: "application-grant",
      nonce: `proof-${++nonce}`,
    });
    return auth.authorizeApplicationWrite(
      {
        request: new Request("https://server.example/notes.items", {
          method: "POST",
          headers: {
            authorization: "Bearer test-token",
            "content-type": "application/json",
            "x-vana-write-signature": signature,
          },
          body,
        }),
        scope: "notes.items",
      },
      sync.applications,
      input,
    );
  }
  return {
    ...f,
    sync,
    deps,
    auth,
    observedGrant: () => observed,
    authorize,
    envelope,
    wake,
    revoke: async () => {
      observed = grant({ revokedAt: "2026-01-01T00:00:00Z" });
      await sync.applications.grants.record({
        grantId: observed.id,
        revision: observed.grantVersion,
        status: "revoked",
        expiresAt: null,
        observedAt: Date.now(),
      });
    },
  };
}

it("refuses an authorized mutation if a revocation is observed before its commit", async () => {
  const f = await applicationFixture();
  const authorized = await f.authorize();
  expect(authorized && "mutation" in authorized).toBe(true);
  if (!authorized || !("mutation" in authorized))
    throw new Error("missing mutation");
  await f.revoke();
  await expect(
    f.sync.applications.commit(authorized.mutation),
  ).rejects.toThrow();
  expect(await f.db.query("SELECT * FROM records")).toEqual([]);
  expect(await f.db.query("SELECT * FROM application_receipts")).toEqual([]);
  expect(f.wake).not.toHaveBeenCalled();
});

it("recovers the committed receipt after revocation without creating another mutation", async () => {
  const f = await applicationFixture();
  const authorized = await f.authorize();
  if (!authorized || !("mutation" in authorized))
    throw new Error("missing mutation");
  const receipt = await f.sync.applications.commit(authorized.mutation);
  await f.revoke();
  expect(await f.authorize()).toEqual({ receipt });
  expect(await f.db.query("SELECT count(*) AS n FROM records")).toEqual([
    { n: 1 },
  ]);
  expect(await f.db.query("SELECT count(*) AS n FROM record_changes")).toEqual([
    { n: 1 },
  ]);
  expect(f.wake).toHaveBeenCalledTimes(1);
});

async function commit(
  f: Awaited<ReturnType<typeof applicationFixture>>,
  input: ApplicationEnvelope = f.envelope,
) {
  const authorized = await f.authorize(input);
  if (!authorized) throw new Error("missing authorization");
  return "receipt" in authorized
    ? authorized.receipt
    : f.sync.applications.commit(authorized.mutation);
}

it("replays the same semantic request and conflicts on changed content", async () => {
  const f = await applicationFixture();
  const first = await commit(f);
  expect(await commit(f)).toEqual(first);
  await expect(
    commit(f, {
      ...f.envelope,
      record: { ...f.envelope.record, data: { id: "one", value: "changed" } },
    }),
  ).rejects.toMatchObject({ errorCode: "APPLICATION_MUTATION_CONFLICT" });
  expect(await f.db.query("SELECT count(*) AS n FROM record_changes")).toEqual([
    { n: 1 },
  ]);
});

it("refuses a capability after its source is rebound and emits no second change", async () => {
  const f = await applicationFixture();
  await commit(f);
  const authorized = await f.authorize({ ...f.envelope, mutationId: "next" });
  if (!authorized || !("mutation" in authorized))
    throw new Error("missing mutation");
  await f.sync.applications.bindings.record({
    sourceId: `urn:vana:builder:${builder.toLowerCase()}`,
    writer: builder,
    revision: "binding-two",
  });
  await expect(
    f.sync.applications.commit(authorized.mutation),
  ).rejects.toMatchObject({ errorCode: "APPLICATION_AUTHORITY_CHANGED" });
  expect(
    await f.db.query("SELECT count(*) AS n FROM application_receipts"),
  ).toEqual([{ n: 1 }]);
});

it("rolls back records, receipts and blobs together when blob admission fails", async () => {
  const f = await applicationFixture();
  const bytes = [1, 2, 3];
  const hash = toHex(sha256(new Uint8Array(bytes)));
  const input = {
    ...f.envelope,
    record: {
      ...f.envelope.record,
      data: {
        ...f.envelope.record.data,
        attachment: {
          blob_ref: {
            blob_id: `sha256:${hash}`,
            sha256: hash,
            mime_type: "application/octet-stream",
            size_bytes: bytes.length,
          },
        },
      },
    },
    blobs: [{ sha256: hash, mimeType: "application/octet-stream", bytes }],
  };
  const authorized = await f.authorize(input);
  if (!authorized || !("mutation" in authorized))
    throw new Error("missing mutation");
  await f.db.batch([
    {
      sql: "CREATE TEMP TRIGGER fail_blob BEFORE INSERT ON main.blobs BEGIN SELECT RAISE(ABORT,'injected_blob_failure'); END",
    },
  ]);
  await expect(f.sync.applications.commit(authorized.mutation)).rejects.toThrow(
    "injected_blob_failure",
  );
  for (const table of ["records", "application_receipts", "blobs", "blob_refs"])
    expect(await f.db.query(`SELECT count(*) AS n FROM ${table}`)).toEqual([
      { n: 0 },
    ]);
  expect(f.wake).not.toHaveBeenCalled();
  await f.db.batch([{ sql: "DROP TRIGGER fail_blob" }]);
  await f.sync.applications.commit(authorized.mutation);
  for (const table of ["records", "application_receipts", "blobs", "blob_refs"])
    expect(await f.db.query(`SELECT count(*) AS n FROM ${table}`)).toEqual([
      { n: 1 },
    ]);
});

it("rejects a forged capability and a capability from another runtime", async () => {
  const f = await applicationFixture();
  const other = await applicationFixture();
  await expect(
    f.sync.applications.commit({ kind: "authorized-application-mutation" }),
  ).rejects.toMatchObject({ errorCode: "UNAUTHORIZED_APPLICATION_MUTATION" });
  const authorized = await f.authorize();
  if (!authorized || !("mutation" in authorized))
    throw new Error("missing mutation");
  await expect(
    other.sync.applications.commit(authorized.mutation),
  ).rejects.toMatchObject({ errorCode: "UNAUTHORIZED_APPLICATION_MUTATION" });
});

it("refuses append-only replacement at an existing key", async () => {
  const f = await applicationFixture({ semantics: "append_only" });
  await commit(f);
  await expect(
    commit(f, {
      ...f.envelope,
      mutationId: "changed",
      record: { ...f.envelope.record, data: { id: "one", value: "changed" } },
    }),
  ).rejects.toMatchObject({ errorCode: "APPLICATION_APPEND_ONLY" });
  expect(await f.db.query("SELECT body FROM records")).toEqual([
    { body: '{"id":"one","value":"first"}' },
  ]);
});

it("namespaces equal mutation IDs by authenticated source, owner and network", async () => {
  const fixtures = await Promise.all([
    applicationFixture(),
    applicationFixture({ wallet: createTestWallet(1) }),
    applicationFixture({ owner: `0x${"56".repeat(20)}` }),
    applicationFixture({ network: "other-network" }),
  ]);
  for (const f of fixtures) {
    const receipt = await commit(f);
    expect(receipt.mutationId).toBe("mutation-one");
    expect(await f.db.query("SELECT count(*) AS n FROM records")).toEqual([
      { n: 1 },
    ]);
  }
  // Two writers in the same database must also have independent receipts.
  const [a, b] = fixtures;
  const rows = await b!.db.query("SELECT * FROM application_receipts");
  expect(rows[0]!.source_id).not.toBe(
    (await a!.db.query("SELECT source_id FROM application_receipts"))[0]!
      .source_id,
  );
});

it("permits two authenticated applications to reuse an ID in one owner database", async () => {
  const a = await applicationFixture();
  const first = await commit(a);
  const b = await applicationFixture({
    shared: a,
    wallet: createTestWallet(1),
  });
  const second = await commit(b);
  expect(second.recordRef.source).not.toBe(first.recordRef.source);
  expect(
    await a.db.query("SELECT count(*) AS n FROM application_receipts"),
  ).toEqual([{ n: 2 }]);
  expect(await a.db.query("SELECT count(*) AS n FROM records")).toEqual([
    { n: 2 },
  ]);
});

it("fences a revocation recorded while the commit batch is waiting to enter SQLite", async () => {
  const f = await applicationFixture();
  const authorization = await f.authorize();
  if (!authorization || !("mutation" in authorization))
    throw new Error("missing mutation");
  let entered!: () => void;
  let release!: () => void;
  const waiting = new Promise<void>((r) => {
    entered = r;
  });
  const gate = new Promise<void>((r) => {
    release = r;
  });
  const batch = f.db.batch.bind(f.db);
  const spy = vi.spyOn(f.db, "batch").mockImplementation(async (statements) => {
    if (
      statements.some((s) => s.sql.includes("INSERT INTO application_guard"))
    ) {
      entered();
      await gate;
    }
    return batch(statements);
  });
  const committing = f.sync.applications.commit(authorization.mutation);
  try {
    await waiting;
    await f.revoke();
  } finally {
    release();
  }
  await expect(committing).rejects.toMatchObject({
    errorCode: "APPLICATION_AUTHORITY_CHANGED",
  });
  spy.mockRestore();
  expect(await f.db.query("SELECT count(*) AS n FROM records")).toEqual([
    { n: 0 },
  ]);
});

it("reopens the database and returns the durable receipt without a second journal entry", async () => {
  const root = await mkdtemp(join(tmpdir(), "application-receipt-"));
  try {
    const a = await applicationFixture({ path: join(root, "owner.sqlite") });
    const first = await commit(a);
    await a.db.close();
    drivers.splice(drivers.indexOf(a.db), 1);
    const b = await applicationFixture({ path: join(root, "owner.sqlite") });
    expect(await commit(b)).toEqual(first);
    expect(
      await b.db.query("SELECT count(*) AS n FROM record_changes"),
    ).toEqual([{ n: 1 }]);
    expect(
      (await b.db.query("SELECT emitted_at FROM application_receipts"))[0]!
        .emitted_at,
    ).toBe(a.envelope.record.emitted_at);
    await b.db.close();
    drivers.splice(drivers.indexOf(b.db), 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

it.each(["node", "lite"] as const)(
  "routes a signed canonical application write before the legacy fence on %s",
  async (host) => {
    const f = await applicationFixture();
    const root = await mkdtemp(join(tmpdir(), "application-route-"));
    const legacyDb = initializeDatabase(":memory:");
    const index = createIndexManager(legacyDb);
    const gateway = {
      getBuilder: async () => ({ id: "registered-app" }),
      getGrant: async () => f.observedGrant(),
    };
    try {
      const path = host === "node" ? "/notes.items" : "/v1/data/notes.items";
      const node =
        host === "node"
          ? dataRoutes({
              localSync: async () => f.sync,
              accountStorageMode: fixedOwnedAccountStorageMode(
                "switched",
                owner,
              ),
              legacyWriteSeal: fixedLegacyWriteSeal("switched", owner),
              indexManager: index,
              hierarchyOptions: { dataDir: root },
              logger: pino({ level: "silent" }),
              serverOrigin: "https://server.example",
              serverOwner: owner,
              gateway: gateway as never,
              accessLogWriter: { write: async () => {} },
              writeSessionStore: f.sessions,
            })
          : undefined;
      const lite =
        host === "lite"
          ? createPsLiteRuntime({
              localSync: async () => f.sync,
              storage: createMemoryPsLiteStorage(),
              gateway: gateway as never,
              accountModeAuthority: fixedModeAuthority("switched"),
              serverOrigin: "https://server.example",
              serverOwner: owner,
              auth: createWeb3SignedPsLiteAuth({
                origin: "https://server.example",
                ownerAddress: owner,
                dataReadPolicyPorts: {
                  authSessionVerifier: gateway as never,
                  grantVerifier: gateway,
                },
                writeSessions: {
                  store: f.sessions,
                  replayStore: createInMemoryWriteProofReplayStore(),
                  policyPorts: {
                    authSessionVerifier: gateway as never,
                    grantVerifier: gateway,
                  },
                },
              }),
              writeSessionStore: f.sessions,
              tokenStore: createMemoryPsLiteTokenStore(),
              accessLogReader: createMemoryPsLiteAccessLogStore(),
              accessLogWriter: { write: async () => {} },
              saveConfig: async () => {},
              stateCapabilities: { config: "memory" },
              active: true,
            })
          : undefined;
      let nonce = 0;
      async function send(body: unknown) {
        const text = JSON.stringify(body);
        const proof = await buildWeb3SignedHeader({
          wallet,
          aud: "https://server.example",
          method: "POST",
          uri: path,
          body: new TextEncoder().encode(text),
          grantId: "application-grant",
          nonce: `route-${++nonce}`,
        });
        const req = new Request(`https://server.example${path}`, {
          method: "POST",
          headers: {
            authorization: "Bearer test-token",
            "content-type": "application/json",
            "x-vana-write-signature": proof,
          },
          body: text,
        });
        return node ? node.request(req) : lite!.fetch(req);
      }
      const response = await send(f.envelope);
      expect(response.status, await response.clone().text()).toBe(201);
      const receipt = await response.json();
      expect((await send(f.envelope)).status).toBe(201);
      expect(
        await f.sync.query.getRecord({
          connectionId: receipt.recordRef.instance,
          stream: "items",
          recordKey: "one",
        }),
      ).toMatchObject({ body: '{"id":"one","value":"first"}' });
      const bytes = [4, 5, 6];
      const hash = toHex(sha256(new Uint8Array(bytes)));
      const file = await send({
        ...f.envelope,
        mutationId: "file-one",
        record: {
          ...f.envelope.record,
          data: {
            ...f.envelope.record.data,
            blob_ref: {
              blob_id: `sha256:${hash}`,
              sha256: hash,
              mime_type: "application/pdf",
              size_bytes: bytes.length,
            },
          },
        },
        blobs: [{ sha256: hash, mimeType: "application/pdf", bytes }],
      });
      expect(file.status, await file.clone().text()).toBe(201);
      expect(Array.from((await f.sync.blobs.get(hash))!.bytes)).toEqual(bytes);
      const old = await send({ note: "old-format" });
      expect(old.status).toBe(426);
      expect(index.countByScope("notes.items")).toBe(0);
      expect(
        await f.db.query("SELECT count(*) AS n FROM record_changes"),
      ).toEqual([{ n: 2 }]);
    } finally {
      index.close();
      await rm(root, { recursive: true, force: true });
    }
  },
);

it.each(["stream", "key", "operation", "declaration", "blob"])(
  "binds the receipt to the semantic %s",
  async (field) => {
    const f = await applicationFixture();
    await commit(f);
    const changed = structuredClone(f.envelope) as ApplicationEnvelope;
    const input =
      field === "stream"
        ? { ...changed, record: { ...changed.record, stream: "other" } }
        : field === "key"
          ? { ...changed, record: { ...changed.record, key: "other" } }
          : field === "operation"
            ? {
                ...changed,
                record: { ...changed.record, op: "delete" as const },
              }
            : field === "declaration"
              ? { ...changed, declaration: { digest: "0".repeat(64) } }
              : {
                  ...changed,
                  blobs: [
                    {
                      sha256: "0".repeat(64),
                      mimeType: "text/plain",
                      bytes: [],
                    },
                  ],
                };
    await expect(f.authorize(input)).rejects.toMatchObject({
      errorCode: "APPLICATION_MUTATION_CONFLICT",
    });
    expect(
      await f.db.query("SELECT count(*) AS n FROM application_receipts"),
    ).toEqual([{ n: 1 }]);
  },
);

it("publishes application changes through the existing connection log and reads them on another database", async () => {
  const f = await applicationFixture();
  const result = await commit(f);
  const publication = await f.sync.publish();
  expect(
    publication.connections.every((c) => c.error === null),
    JSON.stringify(publication),
  ).toBe(true);
  expect(
    (await f.db.query("SELECT head_version FROM stream_state"))[0]!
      .head_version,
  ).toBeGreaterThan(0);
  const other = await fixture();
  const replica = createLocalSync(
    { ...f.deps, db: other.db, queue: other.queue },
    { resolveArtifact: async () => null },
  );
  await replica.apply();
  const changes = await replica.query.getRecord({
    connectionId: result.recordRef.instance,
    stream: "items",
    recordKey: "one",
  });
  expect(changes?.body).toBe('{"id":"one","value":"first"}');
});

it("refuses a record naming missing file bytes without persisting a receipt", async () => {
  const f = await applicationFixture();
  const hash = "0".repeat(64);
  const input = {
    ...f.envelope,
    record: {
      ...f.envelope.record,
      data: {
        ...f.envelope.record.data,
        blob_ref: {
          blob_id: `sha256:${hash}`,
          sha256: hash,
          mime_type: "text/plain",
          size_bytes: 3,
        },
      },
    },
  };
  await expect(commit(f, input)).rejects.toMatchObject({
    errorCode: "APPLICATION_BLOB_UNAVAILABLE",
  });
  expect(await f.db.query("SELECT count(*) AS n FROM records")).toEqual([
    { n: 0 },
  ]);
  expect(
    await f.db.query("SELECT count(*) AS n FROM application_receipts"),
  ).toEqual([{ n: 0 }]);
});

it("fences a source rebind before the first record commit", async () => {
  const f = await applicationFixture();
  const authorization = await f.authorize();
  if (!authorization || !("mutation" in authorization))
    throw new Error("missing mutation");
  await f.sync.applications.bindings.record({
    sourceId: `urn:vana:builder:${builder.toLowerCase()}`,
    writer: builder,
    revision: "binding-two",
  });
  await expect(
    f.sync.applications.commit(authorization.mutation),
  ).rejects.toMatchObject({ errorCode: "APPLICATION_AUTHORITY_CHANGED" });
  expect(await f.db.query("SELECT count(*) AS n FROM records")).toEqual([
    { n: 0 },
  ]);
});

it("journals a mutable-record tombstone with the deletion's stamp", async () => {
  const f = await applicationFixture();
  await commit(f);
  await commit(f, {
    ...f.envelope,
    mutationId: "delete-one",
    record: { ...f.envelope.record, op: "delete" },
  });
  const rows = await f.db.query(
    "SELECT op,explicit_delete,stamp_r FROM record_changes ORDER BY seq DESC LIMIT 1",
  );
  expect(rows[0]).toMatchObject({ op: "remove", explicit_delete: 1 });
  expect(await f.db.query("SELECT * FROM records")).toEqual([]);
  const tombstones = await f.db.query("SELECT stamp_r FROM record_tombstones");
  expect(rows[0]!.stamp_r).toBe(tombstones[0]!.stamp_r);
});
