import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer as createNetServer } from "node:net";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { startPersonalServer } from "./client.js";

const ownerWallet = createTestWallet(8);
let cleanupFns: Array<() => Promise<void>> = [];

afterEach(async () => {
  await Promise.all(cleanupFns.map((cleanup) => cleanup()));
  cleanupFns = [];
});

function createGateway(overrides: Partial<GatewayClient> = {}): GatewayClient {
  return {
    isRegisteredBuilder: vi.fn().mockResolvedValue(false),
    getBuilder: vi.fn().mockResolvedValue(null),
    getGrant: vi.fn().mockResolvedValue(null),
    listGrantsByUser: vi.fn().mockResolvedValue([]),
    getSchemaForScope: vi.fn().mockResolvedValue({
      id: "0xschema1",
      ownerAddress: ownerWallet.address,
      name: "instagram.profile",
      definitionUrl: "https://ipfs.io/ipfs/QmTestSchema",
      scope: "instagram.profile",
      addedAt: "2026-05-08T00:00:00.000Z",
    }),
    getServer: vi.fn().mockResolvedValue(null),
    getFile: vi.fn().mockResolvedValue(null),
    listFilesSince: vi.fn().mockResolvedValue({ files: [], cursor: null }),
    getSchema: vi.fn().mockResolvedValue(null),
    registerServer: vi.fn().mockResolvedValue({
      alreadyRegistered: false,
      serverId: "server-1",
    }),
    registerFile: vi.fn().mockResolvedValue({ fileId: "file-1" }),
    createGrant: vi.fn().mockResolvedValue({ grantId: "grant-1" }),
    revokeGrant: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

async function createOwnerSignature(): Promise<`0x${string}`> {
  return ownerWallet.signMessage("vana-master-key-v1");
}

async function getFreePort(): Promise<number> {
  const server = createNetServer();
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  await new Promise<void>((resolve, reject) => {
    server.close((err?: Error) => {
      if (err) reject(err);
      else resolve();
    });
  });
  if (!address || typeof address === "string") {
    throw new Error("Could not allocate a test port");
  }
  return address.port;
}

async function startTestServer(gateway = createGateway()) {
  const rootPath = await mkdtemp(join(tmpdir(), "ps-client-"));
  const port = await getFreePort();
  const config = ServerConfigSchema.parse({
    server: { port, origin: `http://localhost:${port}` },
    logging: { level: "fatal", pretty: false },
    devUi: { enabled: false },
    sync: { enabled: false, lastProcessedTimestamp: null },
    tunnel: { enabled: false },
  });
  const ps = await startPersonalServer({
    rootPath,
    config,
    ownerSignature: await createOwnerSignature(),
    gatewayClient: gateway,
    localApproval: false,
    startBackgroundServices: false,
  });
  cleanupFns.push(async () => {
    await ps.stop();
    await rm(rootPath, { recursive: true, force: true });
  });
  return { ps, gateway, port };
}

describe("startPersonalServer node handle", () => {
  it("rejects port 0 because public handle URLs must be concrete", async () => {
    await expect(startPersonalServer({ port: 0 })).rejects.toThrow(
      "port: 0 is not supported",
    );
  });

  it("starts, reports identity, and prepares registration", async () => {
    const { ps, port } = await startTestServer();

    const info = await ps.ready();
    expect(info).toMatchObject({
      kind: "node",
      status: "ready",
      ownerAddress: ownerWallet.address,
      urls: {
        local: `http://127.0.0.1:${port}`,
        apiOrigin: `http://localhost:${port}`,
        registration: `http://localhost:${port}`,
      },
    });
    expect(info.server?.address).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(info.server?.publicKey).toMatch(/^0x04/);

    const registration = await ps.prepareRegistration();
    expect(registration.candidate).toMatchObject({
      ownerAddress: ownerWallet.address,
      serverAddress: info.server?.address,
      publicKey: info.server?.publicKey,
      serverUrl: `http://localhost:${port}`,
    });
  });

  it("submits registration through the configured gateway", async () => {
    const gateway = createGateway();
    const { ps } = await startTestServer(gateway);
    const registration = await ps.prepareRegistration();

    await expect(
      ps.submitRegistration({ signature: "0xregistration" }),
    ).resolves.toEqual({ alreadyRegistered: false, serverId: "server-1" });
    expect(gateway.registerServer).toHaveBeenCalledWith({
      ...registration.candidate,
      signature: "0xregistration",
    });
  });

  it("posts data through the public handle", async () => {
    const { ps } = await startTestServer();

    await expect(
      ps.postData(
        "instagram.profile",
        { username: "vana_debug" },
        { signMessage: ownerWallet.signMessage },
      ),
    ).resolves.toMatchObject({
      scope: "instagram.profile",
      status: "stored",
    });
  });

  it("exposes typed data and sync helpers through the public handle", async () => {
    const { ps } = await startTestServer();
    const auth = { signMessage: ownerWallet.signMessage };

    await ps.postData("instagram.profile", { username: "vana_debug" }, auth);

    await expect(ps.listData({ auth, limit: 10 })).resolves.toMatchObject({
      scopes: [{ scope: "instagram.profile" }],
    });
    await expect(
      ps.listVersions("instagram.profile", { auth, limit: 1 }),
    ).resolves.toMatchObject({
      scope: "instagram.profile",
      versions: [{ fileId: null }],
    });
    await expect(
      ps.readData("instagram.profile", { auth }),
    ).resolves.toMatchObject({
      scope: "instagram.profile",
      data: { username: "vana_debug" },
    });
    await expect(ps.syncStatus({ auth })).resolves.toMatchObject({
      enabled: false,
      running: false,
    });
    await expect(ps.syncNow({ auth })).resolves.toMatchObject({
      status: "disabled",
    });
  });

  it("preserves Request method and body when fetch applies init overrides", async () => {
    const { ps, port } = await startTestServer();
    const origin = `http://localhost:${port}`;
    const body = new TextEncoder().encode(
      JSON.stringify({ username: "vana_debug" }),
    );
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: origin,
      method: "POST",
      uri: "/v1/data/instagram.profile",
      body,
    });

    const response = await ps.fetch(
      new Request("https://ignored.example/v1/data/instagram.profile", {
        method: "POST",
        body,
      }),
      {
        headers: {
          Authorization: auth,
          "Content-Type": "application/json",
        },
      },
    );

    expect(response.status).toBe(201);
    await expect(response.json()).resolves.toMatchObject({
      scope: "instagram.profile",
    });
  });

  it("stops idempotently", async () => {
    const { ps } = await startTestServer();

    await ps.stop();
    await ps.stop();

    await expect(ps.info()).resolves.toMatchObject({ status: "stopped" });
  });
});
