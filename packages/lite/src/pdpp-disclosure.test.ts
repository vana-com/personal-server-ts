/**
 * PS Lite: a legacy chain grant reads actual legacy files only.
 *
 * The real Lite runtime over its real persistent storage port. The owner
 * writes a legacy file, then a PDPP-stamped version of the same data. A live
 * chain grant must not read the PDPP version through `/v1/data` or MCP, while
 * the owner reads it and the same grant still reads the legacy file.
 */
import { describe, expect, it, vi } from "vitest";
import type {
  Builder,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";
import {
  approveMcpConnection,
  createInMemoryMcpConnectionStore,
  createMcpConnection,
} from "@opendatalabs/personal-server-ts-core/mcp";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { encodeDataBlockCursor } from "@opendatalabs/personal-server-ts-core/storage/blocks";
import { createScopeDeletionTracker } from "@opendatalabs/personal-server-ts-core/sync";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import { createPsLiteRuntime, createWeb3SignedPsLiteAuth } from "./runtime.js";
import { createPersistentPsLiteStorage } from "./storage.js";
import {
  createMemoryPsLiteDataFileStore,
  createMemoryPsLitePersistence,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";

const ORIGIN = "https://ps-lite.local";
const owner = createTestWallet(7);
const builder = createTestWallet(8);
const GRANT_ID = "grant-lite-1";
const SECRET = "pdpp-only-score-99";
const LEGACY = "legacy-file-row";
const gatewayConfig = {
  url: "https://gateway.test",
  chainId: 14800,
  contracts: {
    dataRegistry: "0x0000000000000000000000000000000000000001",
    dataPortabilityPermissions: "0x0000000000000000000000000000000000000002",
    dataPortabilityServer: "0x0000000000000000000000000000000000000003",
    dataPortabilityGrantees: "0x0000000000000000000000000000000000000004",
  },
} as const;

function gatewayFor(granteeAddress: `0x${string}`): GatewayClient {
  const grant = {
    id: GRANT_ID,
    grantorAddress: owner.address,
    granteeId: granteeAddress,
    scopes: ["instagram.*"],
    status: "confirmed",
    addedAt: "2026-01-21T10:00:00.000Z",
    expiresAt: null,
    expired: false,
    revokedAt: null,
    paymentStatus: "paid",
    grantVersion: "1",
  } as unknown as GatewayGrantResponse;
  const registered: Builder = {
    id: granteeAddress,
    ownerAddress: owner.address,
    granteeAddress,
    publicKey: "0x04",
    appUrl: "https://app.test",
    addedAt: "2026-01-21T10:00:00.000Z",
  };
  return {
    isRegisteredBuilder: vi.fn().mockResolvedValue(true),
    getBuilder: vi.fn().mockResolvedValue(registered),
    getGrant: vi.fn().mockResolvedValue(grant),
    listGrantsByUser: vi.fn().mockResolvedValue([]),
    getSchemaForScope: vi.fn().mockResolvedValue(null),
    getServer: vi.fn().mockResolvedValue(null),
    getDataPoint: vi.fn().mockResolvedValue(null),
    listDataPointsByOwner: vi
      .fn()
      .mockResolvedValue({ dataPoints: [], cursor: null }),
    getSchema: vi.fn().mockResolvedValue(null),
    registerServer: vi.fn().mockResolvedValue({ alreadyRegistered: false }),
    registerDataPoint: vi.fn().mockResolvedValue({ dataPointId: "0xdp" }),
    createGrant: vi.fn().mockResolvedValue({ grantId: GRANT_ID }),
    revokeGrant: vi.fn().mockResolvedValue(undefined),
  } as unknown as GatewayClient;
}

async function boot(
  granteeAddress: `0x${string}`,
  extra: Partial<Parameters<typeof createPsLiteRuntime>[0]> = {},
) {
  const gateway = gatewayFor(granteeAddress);
  const storage = await createPersistentPsLiteStorage(
    { kind: "custom" },
    createMemoryPsLitePersistence(),
    createMemoryPsLiteDataFileStore(),
  );
  const mcpConnectionStore = createInMemoryMcpConnectionStore();
  const runtime = createPsLiteRuntime({
    active: true,
    storage,
    config: { gateway: gatewayConfig },
    gateway,
    serverSigner: {
      signGrantRegistration: vi
        .fn()
        .mockResolvedValue("0xgrantsig" as `0x${string}`),
    },
    accessLogReader: {
      read: async () => ({ logs: [], total: 0, limit: 50, offset: 0 }),
    },
    accessLogWriter: { write: async () => undefined },
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
    serverOwner: owner.address,
    mcpConnectionStore,
    auth: createWeb3SignedPsLiteAuth({
      origin: ORIGIN,
      ownerAddress: owner.address,
      dataReadPolicyPorts: {
        authSessionVerifier: gateway,
        grantVerifier: gateway,
      },
    }),
    ...extra,
  });
  return { runtime, storage, mcpConnectionStore };
}

type Runtime = Awaited<ReturnType<typeof boot>>["runtime"];

async function ownerWrite(
  runtime: Runtime,
  scope: string,
  body: Record<string, unknown>,
  producer?: "pdpp-projector",
) {
  const raw = JSON.stringify(body);
  const response = await runtime.fetch(
    new Request(`${ORIGIN}/v1/data/${scope}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: await buildWeb3SignedHeader({
          wallet: owner,
          aud: ORIGIN,
          method: "POST",
          uri: `/v1/data/${scope}`,
          body: new TextEncoder().encode(raw),
        }),
        ...(producer ? { "Vana-Producer": producer } : {}),
      },
      body: raw,
    }),
  );
  expect(response.status, await response.clone().text()).toBe(201);
}

async function signedGet(
  runtime: Runtime,
  wallet: ReturnType<typeof createTestWallet>,
  scope: string,
  query = "",
) {
  return runtime.fetch(
    new Request(`${ORIGIN}/v1/data/${scope}${query}`, {
      headers: {
        Authorization: await buildWeb3SignedHeader({
          wallet,
          aud: ORIGIN,
          method: "GET",
          uri: `/v1/data/${scope}`,
          ...(wallet === owner ? {} : { grantId: GRANT_ID }),
        }),
      },
    }),
  );
}

/** A legacy file, then a PDPP-stamped version of the same data. */
async function seed(runtime: Runtime, storage: DataStoragePort) {
  await ownerWrite(runtime, "instagram.profile", { rows: [{ id: LEGACY }] });
  const legacyAt = storage.findEntry({
    scope: "instagram.profile",
  })!.collectedAt;
  await ownerWrite(
    runtime,
    "instagram.profile",
    { rows: [{ id: LEGACY, score: SECRET }] },
    "pdpp-projector",
  );
  return { legacyAt };
}

describe("PS Lite GET /v1/data/:scope with a live chain grant", () => {
  it("refuses the PDPP version, latest and by ?at=, and still serves the legacy file", async () => {
    const { runtime, storage } = await boot(builder.address);
    const { legacyAt } = await seed(runtime, storage);
    const pdppAt = storage.findEntry({
      scope: "instagram.profile",
    })!.collectedAt;

    for (const query of ["", `?at=${encodeURIComponent(pdppAt)}`]) {
      const read = await signedGet(
        runtime,
        builder,
        "instagram.profile",
        query,
      );
      const text = await read.text();
      expect(read.status, text).toBe(403);
      expect(JSON.parse(text)).toMatchObject({
        error: { errorCode: "GRANT_REQUIRED" },
      });
      expect(text).not.toContain(SECRET);
    }

    // Positive controls on the same data.
    const owned = await signedGet(runtime, owner, "instagram.profile");
    expect(owned.status).toBe(200);
    expect(await owned.text()).toContain(SECRET);
    const legacy = await signedGet(
      runtime,
      builder,
      "instagram.profile",
      `?at=${encodeURIComponent(legacyAt)}`,
    );
    const legacyText = await legacy.text();
    expect(legacy.status, legacyText).toBe(200);
    expect(legacyText).toContain(LEGACY);
    expect(legacyText).not.toContain(SECRET);
  });
});

describe("PS Lite MCP connection with a live chain grant", () => {
  async function connection(
    extra: Partial<Parameters<typeof createPsLiteRuntime>[0]> = {},
  ) {
    const mcpConnectionStore = createInMemoryMcpConnectionStore();
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store: mcpConnectionStore, publicOrigin: ORIGIN },
    );
    const record = (await mcpConnectionStore.getById(created.connectionId))!;
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: GRANT_ID, scopes: ["instagram.*"] }],
      },
      { store: mcpConnectionStore },
    );
    const booted = await boot(record.granteeAddress, {
      mcpConnectionStore,
      ...extra,
    });
    const call = async (name: string, args: Record<string, unknown>) => {
      const response = await booted.runtime.fetch(
        new Request(
          `${ORIGIN}/mcp/${encodeURIComponent(created.connectionToken)}`,
          {
            method: "POST",
            headers: {
              Accept: "application/json, text/event-stream",
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              jsonrpc: "2.0",
              id: 1,
              method: "tools/call",
              params: { name, arguments: args },
            }),
          },
        ),
      );
      expect(response.status).toBe(200);
      return response.text();
    };
    return { ...booted, call };
  }

  it("read_scope refuses the PDPP version and still reads the legacy file", async () => {
    const { runtime, storage, call } = await connection();
    const { legacyAt } = await seed(runtime, storage);

    const latest = await call("read_scope", { scope: "instagram.profile" });
    expect(latest).not.toContain(SECRET);
    expect(latest).toContain("GRANT_REQUIRED");

    const legacy = await call("read_scope", {
      scope: "instagram.profile",
      cursor: encodeDataBlockCursor({
        scope: "instagram.profile",
        collectedAt: legacyAt,
        blockIndex: 0,
      }),
    });
    expect(legacy).toContain(LEGACY);
    expect(legacy).not.toContain(SECRET);
  });

  it("refuses a read of a scope the owner deleted, like /v1/data", async () => {
    const scopeDeletions = createScopeDeletionTracker({
      serverOwner: owner.address,
    });
    const { runtime, call } = await connection({ scopeDeletions });
    await ownerWrite(runtime, "instagram.posts", { rows: [{ id: LEGACY }] });
    scopeDeletions.markDeleted("instagram.posts", {
      deletedAt: "2099-01-01T00:00:00.000Z",
      version: "9",
    });

    const read = await call("read_scope", { scope: "instagram.posts" });
    expect(read).toContain("DATA_DELETED");
    expect(read).not.toContain(LEGACY);
  });
});
