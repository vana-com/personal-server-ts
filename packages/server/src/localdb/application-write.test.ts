import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { createLocalSync } from "../../../core/src/localdb/sync.js";
import { createWriteSessionAuthorization as createAuthorization } from "../../../core/src/write/authorize.js";
import { remoteFixture } from "./apply-fixture.test-utils.js";
import { sha256 } from "@noble/hashes/sha2";
import { toHex } from "@opendatalabs/personal-server-ts-stream-sync";
import { afterEach, expect, it, vi } from "vitest";
import {
  connectionQueue,
  openLocalDb,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
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
async function fixture() {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner,
    network: "test",
    deviceId: "application-test",
  });
  drivers.push(db);
  const sessions = createInMemoryWriteSessionStore();
  await sessions.create({
    tokenHash: await hashWriteSessionToken("test-token"),
    builderAddress: builder,
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

async function applicationFixture() {
  const f = await fixture();
  const source = `urn:vana:builder:${builder.toLowerCase()}`;
  const document = JSON.stringify({
    source: { kind: "provider_native", id: source },
    declaration_version: "revision-one",
    streams: [
      {
        name: "items",
        semantics: "mutable_state",
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
  const sync = createLocalSync(
    {
      db: f.db,
      keys,
      registry: remote.registry,
      blobs: remote.storage,
      queue: f.queue,
      ownerAddress: owner,
      signer: { signAddData: async () => "0x00" },
      logger: { info: vi.fn(), warn: vi.fn() },
      now: () => Date.now(),
      newOp: () => `application-${++op}`,
      recordsCommitted: wake,
    },
    {
      resolveArtifact: async () => null,
      resolveApplicationDeclaration: async () => ({
        document,
        writer: builder,
        bindingRevision: "binding-one",
      }),
    },
  );
  let observed = grant();
  const auth = createAuthorization({
    serverOrigin: "https://server.example",
    serverOwner: owner,
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
  async function authorize(input = envelope) {
    const body = JSON.stringify(input);
    const signature = await buildWeb3SignedHeader({
      wallet,
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
