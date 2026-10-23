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
const REDIRECT_URI = "http://127.0.0.1:33418/callback";

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

async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return Buffer.from(digest).toString("base64url");
}

/** DCR + authorize on one listener; returns the owner approval redirect. */
async function authorize(listener: string, verifier: string): Promise<URL> {
  const registered = await (
    await fetch(`${listener}/mcp/oauth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_name: "Local agent",
        redirect_uris: [REDIRECT_URI],
      }),
    })
  ).json();
  const query = new URLSearchParams({
    response_type: "code",
    client_id: registered.client_id,
    redirect_uri: REDIRECT_URI,
    code_challenge: await pkceChallenge(verifier),
    code_challenge_method: "S256",
  });
  const response = await fetch(`${listener}/mcp/oauth/authorize?${query}`, {
    redirect: "manual",
  });
  return new URL(response.headers.get("location")!);
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
  const approval = await authorize(listener, "discovery-verifier");
  return {
    challenge: challenge.headers.get("www-authenticate"),
    resource: resource.resource,
    authorizationServers: resource.authorization_servers,
    issuer: authServer.issuer,
    authorizationEndpoint: authServer.authorization_endpoint,
    tokenEndpoint: authServer.token_endpoint,
    registrationEndpoint: authServer.registration_endpoint,
    approvalPsOrigin: approval.searchParams.get("ps_origin"),
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
    approvalPsOrigin: origin,
  };
}

describe("local MCP over the loopback listener", () => {
  it("keeps telling main-listener (tunnel) clients the public origin", async () => {
    const server = await startLocalServer();

    expect(await discoveredUrls(server.main)).toEqual(
      expectedUrls(server.publicOrigin),
    );
  });

  it("tells loopback clients the loopback origin in every discovery URL", async () => {
    const server = await startLocalServer();

    expect(await discoveredUrls(server.loopback)).toEqual(
      expectedUrls(server.loopback),
    );
  });

  // RFC 9728: the advertised resource must equal the URL the client used.
  it("names the loopback host the client used (localhost or 127.0.0.1)", async () => {
    const server = await startLocalServer();
    const localhost = server.loopback.replace("127.0.0.1", "localhost");

    expect(await discoveredUrls(localhost)).toEqual(expectedUrls(localhost));
  });
});
