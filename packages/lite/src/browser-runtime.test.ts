/**
 * Proves `createIndexedDbPsLiteRuntime` composes its identity/config/sync/auth
 * over INJECTED persistence ports (the Mobile native path) instead of the
 * browser IndexedDB defaults — without a browser storage dependency in the test
 * environment. Browser defaults remain exercised by the existing suite.
 */

import { createUnswitchedIndexedDbPsLiteRuntime } from "./test-support/unswitched-runtime.js";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { signOwnerMasterKey } from "@opendatalabs/personal-server-ts-core/keys";
import { createIndexedDbPsLiteRuntime } from "./browser-runtime.js";
import { createIndexedDbStreamSyncFiles } from "./stream-sync-files.js";
import { startPersonalServer } from "./client.js";
import { createBearerTokenPsLiteAuth } from "./runtime.js";
import type { ModeRecordStore } from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import type { PsLitePersistenceBundle } from "./persistence.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import type { GatewayGrantResponse } from "@opendatalabs/vana-sdk/browser";
import {
  createInMemoryMcpConnectionStore,
  createInMemoryMcpOAuthAuthorizationStore,
} from "@opendatalabs/personal-server-ts-core/mcp";

let ownerAddress: `0x${string}`;
let ownerSignature: `0x${string}`;

afterEach(() => {
  vi.unstubAllGlobals();
});

beforeAll(async () => {
  const account = privateKeyToAccount(`0x${"11".repeat(32)}`);
  ownerAddress = account.address;
  ownerSignature = await signOwnerMasterKey(account);
});

function memoryBundle(): PsLitePersistenceBundle {
  const accessLog = createMemoryPsLiteAccessLogStore();
  return {
    storage: createMemoryPsLiteStorage(),
    state: createMemoryPsLiteStateStore(),
    tokens: createMemoryPsLiteTokenStore(),
    accessLog,
    mcpConnections: createInMemoryMcpConnectionStore(),
    mcpOAuthAuthorizations: createInMemoryMcpOAuthAuthorizationStore(),
    relayTlsIdentity: {
      read: () => null,
      write: () => {},
    },
  };
}

function build(bundle: PsLitePersistenceBundle) {
  return createUnswitchedIndexedDbPsLiteRuntime({
    ownerAddress,
    ownerSignature,
    persistence: bundle,
    gateway: createMockPsLiteGateway(),
    auth: createBearerTokenPsLiteAuth({
      ownerToken: "owner-token",
      builderToken: "builder-token",
    }),
    active: true,
    configDefaults: {
      gateway: { url: "https://gateway.local" },
      sync: { enabled: false },
    },
  });
}

describe("createIndexedDbPsLiteRuntime persistence injection", () => {
  it("rejects a partial bundle instead of mixing native and IndexedDB stores", async () => {
    await expect(
      createIndexedDbPsLiteRuntime({
        ownerAddress,
        ownerSignature,
        persistence: {} as PsLitePersistenceBundle,
      }),
    ).rejects.toThrow(
      "PS Lite persistence bundle must be complete; missing storage, state, tokens, accessLog, mcpConnections, mcpOAuthAuthorizations, relayTlsIdentity",
    );
  });

  it("uses the injected ports and persists identity into the injected state store", async () => {
    const bundle = memoryBundle();
    const built = await build(bundle);

    // The factory returned the injected instances, not IndexedDB defaults.
    expect(built.stateStore).toBe(bundle.state);
    expect(built.storage).toBe(bundle.storage);
    expect(built.tokenStore).toBe(bundle.tokens);
    expect(built.accessLogStore).toBe(bundle.accessLog);

    // Identity was created + persisted through the injected state store, with
    // the existing AES-GCM record shape (byte-compatible, no app-level crypto).
    const persisted = await bundle.state.get<{
      encryptedPrivateKey: { algorithm: string };
      address: string;
    }>("server-identity-v1");
    expect(persisted?.encryptedPrivateKey.algorithm).toBe("AES-GCM");
    expect(persisted?.address).toBe(built.identity.account.address);
  });

  it("uses a complete bundle without touching browser persistence globals", async () => {
    const unavailable = new Proxy(
      {},
      {
        get() {
          throw new Error("browser persistence must not be accessed");
        },
      },
    );
    vi.stubGlobal("indexedDB", unavailable);
    vi.stubGlobal("localStorage", unavailable);
    vi.stubGlobal("navigator", { storage: unavailable });
    const bundle = memoryBundle();

    const server = await startPersonalServer({
      ownerAddress,
      ownerSignature,
      persistence: bundle,
      gateway: createMockPsLiteGateway(),
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      active: true,
      configDefaults: {
        gateway: { url: "https://gateway.local" },
        sync: { enabled: false },
      },
      relay: false,
    });

    await expect(server.ready()).resolves.toMatchObject({ status: "ready" });
    await server.stop();
  });

  it("serves data through the injected storage across a runtime restart", async () => {
    const bundle = memoryBundle();

    const first = await build(bundle);
    const write = await first.runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        method: "POST",
        headers: {
          Authorization: "Bearer owner-token",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username: "native_user" }),
      }),
    );
    expect(write.status).toBe(201);

    // A second runtime over the SAME injected bundle sees the persisted data:
    // durability comes from the native store, not the runtime instance.
    const rebooted = await build(bundle);
    const list = await rebooted.runtime.fetch(
      new Request("https://ps.local/v1/data", {
        headers: { Authorization: "Bearer owner-token" },
      }),
    );
    expect(list.status).toBe(200);
    await expect(list.json()).resolves.toMatchObject({
      scopes: [{ scope: "instagram.profile" }],
      total: 1,
    });
  });
});

describe("createIndexedDbPsLiteRuntime browser defaults", () => {
  it("preserves data across restarts using the default IndexedDB stores", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const dbName = "ps-lite-browser-defaults";
    const options = {
      ownerAddress,
      ownerSignature,
      dbName,
      storageDbName: `${dbName}-storage`,
      gateway: createMockPsLiteGateway(),
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      active: true,
      configDefaults: {
        gateway: { url: "https://gateway.local" },
        sync: { enabled: false },
      },
    };

    const first = await createUnswitchedIndexedDbPsLiteRuntime(options);
    const write = await first.runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile", {
        method: "POST",
        headers: {
          Authorization: "Bearer owner-token",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username: "browser_user" }),
      }),
    );
    expect(write.status).toBe(201);

    const restarted = await createUnswitchedIndexedDbPsLiteRuntime(options);
    const list = await restarted.runtime.fetch(
      new Request("https://ps.local/v1/data", {
        headers: { Authorization: "Bearer owner-token" },
      }),
    );
    expect(list.status).toBe(200);
    await expect(list.json()).resolves.toMatchObject({
      scopes: [{ scope: "instagram.profile" }],
      total: 1,
    });
  });
});

describe("createIndexedDbPsLiteRuntime run intake", () => {
  const options = (extra: Record<string, unknown>) => ({
    ownerAddress,
    ownerSignature,
    dbName: `ps-lite-intake-${Math.random()}`,
    storageDbName: `ps-lite-intake-storage-${Math.random()}`,
    gateway: createMockPsLiteGateway(),
    auth: createBearerTokenPsLiteAuth({
      ownerToken: "owner-token",
      builderToken: "builder-token",
    }),
    active: true,
    ...extra,
  });
  const digest = `sha256:${"ab".repeat(32)}`;
  const begin = (
    owner: string,
    intake: NonNullable<
      Awaited<
        ReturnType<typeof createIndexedDbPsLiteRuntime>
      >["streamSyncIntake"]
    >,
    artifactDigest: string,
  ) =>
    intake.begin("r1", {
      connector: "c",
      artifactDigest,
      owner: { address: owner, leaseId: null },
      observedAt: Date.now(),
    });

  it("exposes the sync manager's intake and resolves digests from the host table", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const resolve = vi.fn((d: string) =>
      d === digest ? { connector: "c", version: "1", streams: [] } : null,
    );
    const { streamSyncIntake } = await createUnswitchedIndexedDbPsLiteRuntime(
      options({
        streamSyncDeclarations: resolve,
        streamSyncFiles: () =>
          createIndexedDbStreamSyncFiles({
            dbName: "intake-files",
            factory: new IDBFactory(),
            keyRange: IDBKeyRange,
          }),
        configDefaults: {
          gateway: { url: "https://gateway.local" },
          sync: { enabled: true },
          streamSync: { write: true },
        },
      }),
    );
    expect(streamSyncIntake).not.toBeNull();
    const unknown = `sha256:${"cd".repeat(32)}`;
    await expect(
      begin(ownerAddress, streamSyncIntake!, unknown),
    ).rejects.toMatchObject({ code: "unknown_artifact" });
    expect(resolve).toHaveBeenCalledWith(unknown);
  });

  it("is null with streamSync.write off", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const { streamSyncIntake } = await createUnswitchedIndexedDbPsLiteRuntime(
      options({
        configDefaults: {
          gateway: { url: "https://gateway.local" },
          sync: { enabled: true },
        },
      }),
    );
    expect(streamSyncIntake).toBeNull();
  });
});

describe("createIndexedDbPsLiteRuntime own-write reads", () => {
  it("reads back a run this device collected, through the runtime's data route", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    // An empty registry: listings are empty, single reads are 404, and every
    // POST commits. The run is then this device's own unpublished rows.
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        if ((init?.method ?? "GET") === "POST")
          return new Response(null, { status: 201 });
        if (String(input).includes("/v1/data?"))
          return Response.json({
            data: { dataPoints: [] },
            pagination: { hasMore: false, nextCursor: null },
          });
        return new Response(null, { status: 404 });
      }),
    );
    const dbName = `ps-lite-own-reads-${Math.random()}`;
    const { runtime, streamSyncWriter } =
      await createUnswitchedIndexedDbPsLiteRuntime({
        ownerAddress,
        ownerSignature,
        dbName,
        storageDbName: `${dbName}-storage`,
        gateway: createMockPsLiteGateway(),
        auth: createBearerTokenPsLiteAuth({
          ownerToken: "owner-token",
          builderToken: "builder-token",
        }),
        active: true,
        streamSyncFiles: () =>
          createIndexedDbStreamSyncFiles({
            dbName: `${dbName}-streams`,
            factory: new IDBFactory(),
            keyRange: IDBKeyRange,
          }),
        configDefaults: {
          gateway: { url: "https://gateway.local" },
          sync: { enabled: true },
          streamSync: { write: true, read: true },
        },
      });
    const writer = streamSyncWriter!;
    await writer.refreshControls();
    await writer.beginRun({
      runId: "run-1",
      connector: "acme",
      userConnect: false,
      observedAt: Date.now(),
      identity: "none",
      checkpointUsed: null,
    });
    await writer.declareStream("run-1", "items", {
      primaryKey: ["id"],
      profile: { key: null, version: "1.0.0" },
    });
    await writer.append("run-1", "items", { id: "a", v: 1 });
    await writer.finishRun("run-1", {
      checkpointCandidate: { cursor: "run-1" },
    });

    const read = await runtime.fetch(
      new Request("https://ps.local/v1/data/pdpp.acme.items", {
        headers: { Authorization: "Bearer owner-token" },
      }),
    );
    expect(read.status).toBe(200);
    await expect(read.json()).resolves.toMatchObject({
      data: { records: [{ id: "a", v: 1 }] },
    });
  });
});

describe("createIndexedDbPsLiteRuntime write sessions", () => {
  it("mounts the write-session handshake by default and skips it for a caller-owned auth adapter", async () => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const base = {
      ownerAddress,
      ownerSignature,
      gateway: createMockPsLiteGateway(),
      active: true,
      configDefaults: {
        gateway: { url: "https://gateway.local" },
        sync: { enabled: false },
      },
    };
    const handshake = (runtime: {
      fetch: (req: Request) => Promise<Response>;
    }) =>
      runtime.fetch(
        new Request("https://ps.local/v1/write/session", { method: "POST" }),
      );

    // Default wiring: the route exists, and refuses an unauthenticated
    // handshake rather than 404ing as if delegated writes were unsupported.
    const withDefaults = await createUnswitchedIndexedDbPsLiteRuntime({
      ...base,
      dbName: "ps-lite-write-default",
      storageDbName: "ps-lite-write-default-storage",
    });
    expect((await handshake(withDefaults.runtime)).status).toBe(401);

    // A caller that brings its own auth adapter owns the wiring: we must not
    // mint tokens that adapter has never heard of.
    const withOwnAuth = await createUnswitchedIndexedDbPsLiteRuntime({
      ...base,
      dbName: "ps-lite-write-own-auth",
      storageDbName: "ps-lite-write-own-auth-storage",
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
    });
    expect((await handshake(withOwnAuth.runtime)).status).toBe(404);
  });
});

describe("createIndexedDbPsLiteRuntime data listings", () => {
  it("scopes a builder's listing via the default adapter's grantLister when no grantId is presented", async () => {
    const builder = createTestWallet(1);
    const grant = (overrides: Partial<GatewayGrantResponse>) =>
      ({
        id: "grant-1",
        grantorAddress: ownerAddress,
        granteeId: "builder-1",
        scopes: ["instagram.*"],
        status: "confirmed",
        addedAt: "2026-05-08T00:00:00.000Z",
        expiresAt: null,
        expired: false,
        revokedAt: null,
        revocationSignature: null,
        paymentStatus: "paid",
        paidAt: null,
        paidBy: null,
        grantVersion: "1",
        settleTxHash: null,
        settleSubmittedAt: null,
        revocationTxHash: null,
        revocationSubmittedAt: null,
        fee: {
          asset: "0x0000000000000000000000000000000000000000",
          registrationFee: "0",
          dataAccessFee: "0",
          totalDue: "0",
        },
        ...overrides,
      }) as GatewayGrantResponse;
    const listGrantsByUser = vi.fn(async () => [
      grant({}),
      grant({ id: "grant-other", granteeId: "builder-2", scopes: ["*"] }),
    ]);
    const getGrant = vi.fn(async () => null);
    const { runtime } = await createUnswitchedIndexedDbPsLiteRuntime({
      ownerAddress,
      ownerSignature,
      persistence: memoryBundle(),
      gateway: {
        ...createMockPsLiteGateway(),
        listGrantsByUser,
        getGrant,
        async getBuilder(address: string) {
          return address.toLowerCase() === builder.address.toLowerCase()
            ? {
                id: "builder-1",
                ownerAddress: builder.address,
                granteeAddress: builder.address,
                publicKey: "0x04",
                appUrl: "https://builder.local",
                addedAt: "2026-05-08T00:00:00.000Z",
              }
            : null;
        },
      },
      // No `auth`: the factory's own Web3Signed adapter (with grantLister).
      accessToken: "control-plane-token",
      serverOrigin: "https://ps.local",
      active: true,
      configDefaults: {
        gateway: { url: "https://gateway.local" },
        sync: { enabled: false },
      },
    });

    for (const scope of ["instagram.profile", "twitter.posts"]) {
      const write = await runtime.fetch(
        new Request(`https://ps.local/v1/data/${scope}`, {
          method: "POST",
          headers: {
            Authorization: "Bearer control-plane-token",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ scope }),
        }),
      );
      expect(write.status).toBe(201);
    }

    const builderList = await runtime.fetch(
      new Request("https://ps.local/v1/data", {
        headers: {
          Authorization: await buildWeb3SignedHeader({
            wallet: builder,
            aud: "https://ps.local",
            method: "GET",
            uri: "/v1/data",
          }),
        },
      }),
    );
    expect(builderList.status).toBe(200);
    await expect(builderList.json()).resolves.toMatchObject({
      scopes: [{ scope: "instagram.profile" }],
      total: 1,
    });
    expect(listGrantsByUser).toHaveBeenCalledWith(ownerAddress);
    expect(getGrant).not.toHaveBeenCalled();

    // The control-plane token is owner-equivalent: full listing, no lookup.
    listGrantsByUser.mockClear();
    const controlPlaneList = await runtime.fetch(
      new Request("https://ps.local/v1/data", {
        headers: { Authorization: "Bearer control-plane-token" },
      }),
    );
    expect(controlPlaneList.status).toBe(200);
    await expect(controlPlaneList.json()).resolves.toMatchObject({
      scopes: [{ scope: "instagram.profile" }, { scope: "twitter.posts" }],
      total: 2,
    });
    expect(listGrantsByUser).not.toHaveBeenCalled();
  });
});

describe("the account-mode records of a runtime over injected persistence", () => {
  const plain = (
    bundle: PsLitePersistenceBundle,
    accountModeStore?: ModeRecordStore,
  ) =>
    createIndexedDbPsLiteRuntime({
      ownerAddress,
      ownerSignature,
      persistence: bundle,
      accountModeStore,
      gateway: createMockPsLiteGateway(),
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      active: true,
      configDefaults: {
        gateway: { url: "https://gateway.local" },
        sync: { enabled: false },
      },
    });
  const answer = (
    runtime: Awaited<ReturnType<typeof plain>>,
    state: "on" | "off",
  ) =>
    runtime.accountModeAuthority.submitEvidence({
      owner: ownerAddress,
      authOwner: ownerAddress,
      state,
      fetchStartedAt: Date.now(),
      rawStatus: 200,
    });

  // LITE_MEMORY_MODE_STORE
  it("has no durable mode store of its own, so it decides nothing: an On is not kept and no Off is ever believed", async () => {
    const bundle = memoryBundle();
    const first = await plain(bundle);
    expect(await answer(first, "on")).toMatchObject({
      kind: "refuse",
      code: "ACCOUNT_MODE_STORE_OWNED",
      status: 503,
    });
    await first.accountModeAuthority.close();
    const second = await plain(bundle);
    expect(await answer(second, "off")).toMatchObject({
      kind: "refuse",
      status: 503,
    });
    const owner = ownerAddress;
    expect(second.accountModeAuthority.read(owner).kind).toBe("refuse");
    expect(
      (await second.accountModeAuthority.commitLegacy(owner, "op", () => 1)).ok,
    ).toBe(false);
  });

  it("keeps an On through a restart when the host injects a durable store, and a later Off is refused", async () => {
    const { createMemoryModeRecordStore } =
      await import("@opendatalabs/personal-server-ts-core/sync/account-mode");
    const store = createMemoryModeRecordStore();
    const bundle = memoryBundle();
    const first = await plain(bundle, store);
    expect((await answer(first, "on")).kind).toBe("streams");
    await first.accountModeAuthority.close();
    const second = await plain(bundle, store);
    expect((await answer(second, "off")).kind).toBe("streams");
    expect(
      (
        await second.accountModeAuthority.commitLegacy(
          ownerAddress,
          "op",
          () => 1,
        )
      ).ok,
    ).toBe(false);
  });
});
