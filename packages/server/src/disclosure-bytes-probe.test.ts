/**
 * The disclosure decision is made on the bytes a non-owner read returns, not
 * on the index row chosen before them.
 *
 * Real Node storage and routes. Each probe makes the row chosen at
 * authorization differ from the bytes the read then serves: a fileId of
 * another scope, a version written while the chain grant is verified, or a
 * legacy version deleted and written again as PDPP data at the same scope
 * and collectedAt. A live chain grant must never receive the PDPP bytes.
 */
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Hono } from "hono";
import pino from "pino";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  Builder,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";
import {
  approveMcpConnection,
  createInMemoryMcpConnectionStore,
  createMcpConnection,
  type McpConnectionStore,
} from "@opendatalabs/personal-server-ts-core/mcp";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { buildDataBlocksAsync } from "@opendatalabs/personal-server-ts-core/storage/blocks";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { initializeDatabase } from "./storage/index-schema.js";
import { createIndexManager } from "./storage/index-manager.js";
import { createNodeDataStorage } from "./storage/node-data-storage.js";
import { dataRoutes } from "./routes/data.js";
import { mcpStreamableHttpRoutes } from "./routes/mcp.js";

const logger = pino({ level: "silent" });
const ORIGIN = "http://localhost:8080";
const owner = createTestWallet(0);
const builder = createTestWallet(5);
const GRANT_ID = "grant-probe";
const SECRET = "pdpp-only-score-99";
const AT = "2026-09-01T00:00:00.000Z";
const gatewayConfig = {
  chainId: 14800,
  contracts: {
    dataRegistry: "0x0000000000000000000000000000000000000001",
    dataPortabilityPermissions: "0x0000000000000000000000000000000000000002",
    dataPortabilityServer: "0x0000000000000000000000000000000000000003",
    dataPortabilityGrantees: "0x0000000000000000000000000000000000000004",
  },
} as const;

/** Native PDPP bytes: `$pdpp` import metadata inside `data`. */
function nativeEnvelope(scope: string, collectedAt = AT): DataFileEnvelope {
  return {
    version: "1.0",
    scope,
    collectedAt,
    data: {
      id: "a1",
      score: SECRET,
      $pdpp: { version: 1, sourceId: "https://registry.pdpp.dev/oura" },
    },
  } as DataFileEnvelope;
}

function legacyEnvelope(scope: string, collectedAt = AT): DataFileEnvelope {
  return {
    version: "1.0",
    scope,
    collectedAt,
    data: { id: "legacy-row" },
  } as DataFileEnvelope;
}

let dataDir: string;
let indexManager: IndexManager;
let storage: DataStoragePort;
let duringAuth: (() => Promise<void>) | undefined;

function gatewayFor(granteeAddress: `0x${string}`): GatewayClient {
  const grant = {
    id: GRANT_ID,
    grantorAddress: owner.address,
    granteeId: granteeAddress,
    scopes: ["oura.*"],
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
    // The chain grant check is a gateway round trip; storage can change
    // while it is in flight.
    getGrant: vi.fn(async () => {
      const hook = duringAuth;
      duringAuth = undefined;
      await hook?.();
      return grant;
    }),
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

/** Publish and index a version with its block sidecar, as sync does. */
async function put(envelope: DataFileEnvelope, fileId: string | null = null) {
  const written = await storage.writeEnvelope(envelope);
  const built = await buildDataBlocksAsync({
    scope: envelope.scope,
    collectedAt: envelope.collectedAt,
    content: envelope,
  });
  await storage.writeBlockManifest?.(
    envelope.scope,
    envelope.collectedAt,
    built.manifest,
    built.blocks,
  );
  return storage.insertEntry({
    fileId,
    path: written.relativePath,
    scope: envelope.scope,
    collectedAt: envelope.collectedAt,
    sizeBytes: written.sizeBytes,
  });
}

/** Delete a version and publish other bytes at the same scope+collectedAt. */
async function replaceAt(next: DataFileEnvelope) {
  const fileId = "file-replaced";
  storage.updateFileId(
    indexManager.findClosestByScope(next.scope, next.collectedAt)!.path,
    fileId,
  );
  await storage.deleteByFileId(fileId);
  await put(next);
}

beforeEach(async () => {
  dataDir = await mkdtemp(join(tmpdir(), "disclosure-bytes-"));
  indexManager = createIndexManager(initializeDatabase(":memory:"));
  storage = createNodeDataStorage({
    indexManager,
    hierarchyOptions: { dataDir },
  });
  duringAuth = undefined;
});

afterEach(async () => {
  indexManager.close();
  await rm(dataDir, { recursive: true, force: true });
});

function app() {
  return dataRoutes({
    indexManager,
    hierarchyOptions: { dataDir },
    logger,
    serverOrigin: ORIGIN,
    serverOwner: owner.address,
    gateway: gatewayFor(builder.address),
    accessLogWriter: { write: async () => undefined },
  });
}

async function signedGet(
  wallet: ReturnType<typeof createTestWallet>,
  path: string,
) {
  const [pathname] = path.split("?");
  return app().request(path, {
    headers: {
      Authorization: await buildWeb3SignedHeader({
        wallet,
        aud: ORIGIN,
        method: "GET",
        uri: pathname!,
        ...(wallet === owner ? {} : { grantId: GRANT_ID }),
      }),
    },
  });
}

describe("GET /v1/data/:scope decides on the bytes it serves", () => {
  it("P1-a: a fileId of another scope never reads this scope's PDPP bytes", async () => {
    await put(legacyEnvelope("oura.sleep"), "file-sleep");
    await put(nativeEnvelope("oura.activity"));

    const read = await signedGet(builder, "/oura.activity?fileId=file-sleep");
    const text = await read.text();
    expect(read.status, text).not.toBe(200);
    expect(text).not.toContain(SECRET);

    // Controls: the fileId still names its own scope's legacy file, and the
    // owner reads the PDPP version.
    const own = await signedGet(builder, "/oura.sleep?fileId=file-sleep");
    expect(own.status).toBe(200);
    expect(await own.text()).toContain("legacy-row");
    const owned = await signedGet(owner, "/oura.activity");
    expect(owned.status).toBe(200);
    expect(await owned.text()).toContain(SECRET);
  });

  it("P1-b: a PDPP version written while the grant is verified is not served", async () => {
    duringAuth = async () => {
      await put(nativeEnvelope("oura.activity"));
    };
    const read = await signedGet(builder, "/oura.activity");
    const text = await read.text();
    expect(read.status, text).toBe(403);
    expect(text).not.toContain(SECRET);

    // Control: a legacy version written the same way is served.
    duringAuth = async () => {
      await put(legacyEnvelope("oura.sleep"));
    };
    const legacy = await signedGet(builder, "/oura.sleep");
    expect(legacy.status).toBe(200);
    expect(await legacy.text()).toContain("legacy-row");
  });

  it("P2-a: a legacy version rewritten as PDPP during authorization is not served", async () => {
    await put(legacyEnvelope("oura.activity"));
    for (const path of ["/oura.activity", `/oura.activity?at=${AT}`]) {
      duringAuth = () => replaceAt(nativeEnvelope("oura.activity"));
      const read = await signedGet(builder, path);
      const text = await read.text();
      expect(read.status, `${path}: ${text}`).toBe(403);
      expect(text).not.toContain(SECRET);
      await replaceAt(legacyEnvelope("oura.activity"));
    }

    // Control: the legacy version itself is served.
    const legacy = await signedGet(builder, "/oura.activity");
    expect(legacy.status).toBe(200);
    expect(await legacy.text()).toContain("legacy-row");
  });

  it("P2-c: a non-owner version listing withholds PDPP producer provenance", async () => {
    const raw = JSON.stringify({ id: "a1" });
    const payloadSha = createHash("sha256").update(raw).digest("hex");
    const provenance = {
      projector_version: "1",
      declaration_digest: "sha256:fixture",
      inputs: [{ stream: "activity", changes_since_token: "token-opaque-xyz" }],
      payload_sha256: payloadSha,
    };
    const ingest = await app().request("/oura.activity", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Vana-Producer": "pdpp-projector",
        "Vana-Producer-Provenance": Buffer.from(
          JSON.stringify(provenance),
        ).toString("base64url"),
        Authorization: await buildWeb3SignedHeader({
          wallet: owner,
          aud: ORIGIN,
          method: "POST",
          uri: "/oura.activity",
          body: new TextEncoder().encode(raw),
        }),
      },
      body: raw,
    });
    expect(ingest.status).toBe(201);

    const listed = await signedGet(builder, "/oura.activity/versions");
    expect(listed.status).toBe(200);
    const text = await listed.text();
    expect(text).not.toContain("token-opaque-xyz");
    expect(text).not.toContain(payloadSha);
    expect(JSON.parse(text).versions[0]).toMatchObject({
      producer: "pdpp-projector",
      producer_provenance: null,
    });
    const owned = await signedGet(owner, "/oura.activity/versions");
    expect(JSON.parse(await owned.text()).versions[0]).toMatchObject({
      producer_provenance: provenance,
    });
  });
});

describe("storage derives provenance itself", () => {
  it("P2-d: insertEntry ignores a caller's pdppOrigin and reads the bytes", async () => {
    const written = await storage.writeEnvelope(
      nativeEnvelope("oura.activity"),
    );
    const inserted = await storage.insertEntry({
      fileId: null,
      path: written.relativePath,
      scope: "oura.activity",
      collectedAt: AT,
      sizeBytes: written.sizeBytes,
      pdppOrigin: false,
    });
    expect(inserted.pdppOrigin).toBe(true);
    expect(storage.findEntry({ scope: "oura.activity" })?.pdppOrigin).toBe(
      true,
    );
  });
});

describe("MCP block reads decide on the blocks they serve", () => {
  let connections: McpConnectionStore;
  beforeEach(() => {
    connections = createInMemoryMcpConnectionStore();
  });

  it("P2-a: blocks of a version rewritten as PDPP during authorization are not served", async () => {
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store: connections, publicOrigin: ORIGIN },
    );
    const record = (await connections.getById(created.connectionId))!;
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: GRANT_ID, scopes: ["oura.*"] }],
      },
      { store: connections },
    );
    const root = new Hono();
    root.route(
      "/mcp",
      mcpStreamableHttpRoutes({
        logger,
        serverOrigin: ORIGIN,
        serverOwner: owner.address,
        gateway: gatewayFor(record.granteeAddress),
        gatewayConfig,
        accessLogWriter: { write: async () => undefined },
        connectionStore: connections,
        indexManager,
        hierarchyOptions: { dataDir },
      }),
    );
    const call = async (name: string) => {
      const response = await root.request(
        `/mcp/${encodeURIComponent(created.connectionToken)}`,
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
            params: { name, arguments: { scope: "oura.activity" } },
          }),
        },
      );
      return response.text();
    };

    await put(legacyEnvelope("oura.activity"));
    duringAuth = () => replaceAt(nativeEnvelope("oura.activity"));
    const read = await call("read_scope");
    expect(read).not.toContain(SECRET);
    expect(read).toContain("GRANT_REQUIRED");

    // Control: the legacy blocks are served.
    await replaceAt(legacyEnvelope("oura.activity"));
    const legacy = await call("read_scope");
    expect(legacy).toContain("legacy-row");
  });
});
