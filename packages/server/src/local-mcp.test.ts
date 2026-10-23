import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer as createNetServer, type Server } from "node:net";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createTestWallet } from "@opendatalabs/personal-server-ts-core/test-utils";
import { startPersonalServer } from "./client.js";

// A local MCP client (Maple, Claude Code) reaches the server on the loopback
// auth listener while a tunnel client reaches the main listener. Both serve
// the same app, so these tests drive real sockets on both.

const ownerWallet = createTestWallet(8);
const APPROVAL_URL = "https://app.vana.org/mcp/approve";
const PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource/mcp";

interface LocalServer {
  /** `config.server.origin`: what tunnel clients are told today. */
  publicOrigin: string;
  /** Main listener, the port the tunnel forwards to. */
  main: string;
  /** Loopback auth listener. */
  loopback: string;
}

let cleanupFns: Array<() => Promise<void>> = [];

afterEach(async () => {
  await Promise.all(cleanupFns.map((cleanup) => cleanup()));
  cleanupFns = [];
  vi.unstubAllEnvs();
});

function createGateway(): GatewayClient {
  return {
    isRegisteredBuilder: vi.fn().mockResolvedValue(false),
    getBuilder: vi.fn().mockResolvedValue(null),
    getGrant: vi.fn().mockResolvedValue(null),
    listGrantsByUser: vi.fn().mockResolvedValue([]),
    getSchemaForScope: vi.fn().mockResolvedValue(null),
    getServer: vi.fn().mockResolvedValue(null),
    getFile: vi.fn().mockResolvedValue(null),
    listFilesSince: vi.fn().mockResolvedValue({ files: [], cursor: null }),
    getSchema: vi.fn().mockResolvedValue(null),
    registerServer: vi.fn(),
    registerFile: vi.fn(),
    createGrant: vi.fn(),
    revokeGrant: vi.fn(),
  };
}

/** Holds every probe socket open until all are bound so the ports differ. */
async function freePorts(count: number): Promise<number[]> {
  const servers: Server[] = Array.from({ length: count }, () =>
    createNetServer(),
  );
  await Promise.all(
    servers.map(
      (server) =>
        new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve)),
    ),
  );
  const ports = servers.map((server) => {
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("Could not allocate a test port");
    }
    return address.port;
  });
  await Promise.all(
    servers.map(
      (server) => new Promise<void>((resolve) => server.close(() => resolve())),
    ),
  );
  return ports;
}

async function startLocalServer(): Promise<LocalServer> {
  const rootPath = await mkdtemp(join(tmpdir(), "ps-local-mcp-"));
  const [port, loopbackPort] = await freePorts(2);
  vi.stubEnv("LOCAL_AUTH_PORT", String(loopbackPort));
  const publicOrigin = `http://localhost:${port}`;
  const config = ServerConfigSchema.parse({
    server: { port, origin: publicOrigin },
    logging: { level: "fatal", pretty: false },
    devUi: { enabled: false },
    sync: { enabled: false, lastProcessedTimestamp: null },
    tunnel: { enabled: false },
  });
  const ps = await startPersonalServer({
    rootPath,
    config,
    ownerSignature: await ownerWallet.signMessage("vana-master-key-v1"),
    gatewayClient: createGateway(),
    mcpOAuthApprovalUrl: APPROVAL_URL,
    startBackgroundServices: false,
  });
  cleanupFns.push(async () => {
    await ps.stop();
    await rm(rootPath, { recursive: true, force: true });
  });
  return {
    publicOrigin,
    main: `http://127.0.0.1:${port}`,
    loopback: `http://127.0.0.1:${loopbackPort}`,
  };
}

/** Every URL an MCP client learns from discovery, as one comparable shape. */
async function discoveredUrls(listener: string) {
  const challenge = await fetch(`${listener}/mcp`, { method: "POST" });
  const resource = await (
    await fetch(`${listener}${PROTECTED_RESOURCE_PATH}`)
  ).json();
  const authServer = await (
    await fetch(`${listener}/.well-known/oauth-authorization-server`)
  ).json();
  return {
    challenge: challenge.headers.get("www-authenticate"),
    resource: resource.resource,
    authorizationServers: resource.authorization_servers,
    issuer: authServer.issuer,
    authorizationEndpoint: authServer.authorization_endpoint,
    tokenEndpoint: authServer.token_endpoint,
    registrationEndpoint: authServer.registration_endpoint,
  };
}

function expectedUrls(origin: string) {
  return {
    challenge: `Bearer resource_metadata="${origin}${PROTECTED_RESOURCE_PATH}", scope="vana:read"`,
    resource: `${origin}/mcp`,
    authorizationServers: [origin],
    issuer: origin,
    authorizationEndpoint: `${origin}/mcp/oauth/authorize`,
    tokenEndpoint: `${origin}/mcp/oauth/token`,
    registrationEndpoint: `${origin}/mcp/oauth/register`,
  };
}

describe("local MCP over the loopback listener", () => {
  it("keeps telling main-listener (tunnel) clients the public origin", async () => {
    const server = await startLocalServer();

    expect(await discoveredUrls(server.main)).toEqual(
      expectedUrls(server.publicOrigin),
    );
  });

  // Baseline: discovery ignores the listener and names the public origin.
  it.fails(
    "tells loopback clients the loopback origin in every discovery URL",
    async () => {
      const server = await startLocalServer();

      expect(await discoveredUrls(server.loopback)).toEqual(
        expectedUrls(server.loopback),
      );
    },
  );
});
