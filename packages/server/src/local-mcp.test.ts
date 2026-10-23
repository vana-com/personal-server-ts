import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { request as httpRequest, type IncomingHttpHeaders } from "node:http";
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
const ACCESS_TOKEN = "local-mcp-owner-token";
const VERIFIER = "local-mcp-pkce-verifier";
const CLIENT_NAME = "Local agent";

interface LocalServer {
  /** `config.server.origin`: what tunnel clients are told today. */
  publicOrigin: string;
  /** Main listener, the port the tunnel forwards to. */
  main: string;
  /** Loopback auth listener. */
  loopback: string;
  stop: () => Promise<void>;
}

let cleanupFns: Array<() => Promise<void>> = [];

afterEach(async () => {
  for (const cleanup of cleanupFns) await cleanup();
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

async function tempRoot(): Promise<string> {
  const rootPath = await mkdtemp(join(tmpdir(), "ps-local-mcp-"));
  cleanupFns.push(() => rm(rootPath, { recursive: true, force: true }));
  return rootPath;
}

/** Pass `rootPath` to restart over the same persisted state. */
async function startLocalServer(rootPath?: string): Promise<LocalServer> {
  const root = rootPath ?? (await tempRoot());
  const [port, loopbackPort] = await freePorts(2);
  vi.stubEnv("LOCAL_AUTH_PORT", String(loopbackPort));
  vi.stubEnv("PS_ACCESS_TOKEN", ACCESS_TOKEN);
  const publicOrigin = `http://localhost:${port}`;
  const config = ServerConfigSchema.parse({
    server: { port, origin: publicOrigin },
    logging: { level: "fatal", pretty: false },
    devUi: { enabled: false },
    sync: { enabled: false, lastProcessedTimestamp: null },
    tunnel: { enabled: false },
  });
  const ps = await startPersonalServer({
    rootPath: root,
    config,
    ownerSignature: await ownerWallet.signMessage("vana-master-key-v1"),
    gatewayClient: createGateway(),
    mcpOAuthApprovalUrl: APPROVAL_URL,
    startBackgroundServices: false,
  });
  // First, so every server stops before its root is removed.
  cleanupFns.unshift(() => ps.stop());
  return {
    publicOrigin,
    main: `http://127.0.0.1:${port}`,
    loopback: `http://127.0.0.1:${loopbackPort}`,
    stop: () => ps.stop(),
  };
}

async function ownerGet(listener: string, path: string) {
  const response = await fetch(`${listener}${path}`, {
    headers: { Authorization: `Bearer ${ACCESS_TOKEN}` },
  });
  return response.json();
}

async function pkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return Buffer.from(digest).toString("base64url");
}

async function register(listener: string): Promise<string> {
  const registered = await (
    await fetch(`${listener}/mcp/oauth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_name: CLIENT_NAME,
        redirect_uris: [REDIRECT_URI],
      }),
    })
  ).json();
  return registered.client_id;
}

/** Authorize on one listener (registering first unless given a client); returns the owner approval redirect. */
async function authorize(
  listener: string,
  registeredClientId?: string,
): Promise<{ clientId: string; approval: URL }> {
  const clientId = registeredClientId ?? (await register(listener));
  const query = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    code_challenge: await pkceChallenge(VERIFIER),
    code_challenge_method: "S256",
  });
  const response = await fetch(`${listener}/mcp/oauth/authorize?${query}`, {
    redirect: "manual",
  });
  return {
    clientId,
    approval: new URL(response.headers.get("location")!),
  };
}

/** Full OAuth flow on one listener: the owner approves, the client redeems. */
async function connect(listener: string): Promise<string> {
  const { clientId, approval } = await authorize(listener);
  const authorizationId = approval.searchParams.get("mcp_authorization");
  const approved = await fetch(
    `${approval.searchParams.get("ps_origin")}/v1/mcp/oauth/authorizations/${authorizationId}/approve`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ACCESS_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        grants: [{ grantId: "grant-local", scopes: ["chatgpt.history"] }],
      }),
    },
  );
  const code = new URL((await approved.json()).redirectTo).searchParams.get(
    "code",
  );
  const token = await fetch(`${listener}/mcp/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: code!,
      code_verifier: VERIFIER,
      client_id: clientId,
      redirect_uri: REDIRECT_URI,
    }),
  });
  return (await token.json()).access_token;
}

/** One MCP call with a bearer; the status says whether the token resolved. */
async function listTools(url: string, accessToken: string): Promise<number> {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  await response.body?.cancel();
  return response.status;
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
  const { approval } = await authorize(listener);
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

/** Raw HTTP so the test controls Host, Origin and fetch metadata exactly. */
function rawRequest(
  url: string,
  headers: Record<string, string> = {},
  method = "GET",
): Promise<{ status: number; headers: IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(url, { method, headers }, (res) => {
      res.resume();
      res.on("end", () =>
        resolve({ status: res.statusCode ?? 0, headers: res.headers }),
      );
    });
    req.on("error", reject);
    req.end();
  });
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

  it("refuses rebinding and cross-site requests on the loopback listener only", async () => {
    const server = await startLocalServer();
    const port = new URL(server.loopback).port;
    const hostile = [
      { host: `attacker.example:${port}` },
      { origin: "https://attacker.example" },
      { origin: `http://localhost:${port}` },
      { "sec-fetch-site": "cross-site" },
    ];
    const routes = [
      ["POST", "/mcp"],
      ["POST", "/mcp/oauth/register"],
      ["GET", PROTECTED_RESOURCE_PATH],
      ["GET", "/.well-known/oauth-authorization-server"],
    ];

    for (const [method, path] of routes) {
      for (const headers of hostile) {
        const loopback = await rawRequest(
          `${server.loopback}${path}`,
          headers,
          method,
        );
        expect(loopback.status, `${path} ${JSON.stringify(headers)}`).toBe(404);
      }
      const tunnel = await rawRequest(
        `${server.main}${path}`,
        { origin: "https://attacker.example" },
        method,
      );
      expect(tunnel.status, path).not.toBe(404);
    }

    const sameOrigin = await rawRequest(
      `${server.loopback}${PROTECTED_RESOURCE_PATH}`,
      { origin: server.loopback, "sec-fetch-site": "same-origin" },
    );
    expect(sameOrigin.status).toBe(200);
  });

  it("binds a loopback-authorized token to the loopback listener", async () => {
    const server = await startLocalServer();
    const token = await connect(server.loopback);

    expect(await listTools(`${server.loopback}/mcp`, token)).toBe(200);
    expect(await listTools(`${server.main}/mcp`, token)).toBe(401);
    expect(await listTools(`${server.main}/mcp/${token}`, token)).toBe(401);
  });

  it("binds a tunnel-authorized token to the main listener", async () => {
    const server = await startLocalServer();
    const token = await connect(server.main);

    expect(await listTools(`${server.main}/mcp`, token)).toBe(200);
    expect(await listTools(`${server.loopback}/mcp`, token)).toBe(401);
  });

  it("names the connection after a client registered before a restart", async () => {
    const rootPath = await tempRoot();
    const before = await startLocalServer(rootPath);
    const clientId = await register(before.loopback);
    await before.stop();

    const server = await startLocalServer(rootPath);
    const { approval } = await authorize(server.loopback, clientId);
    const view = await ownerGet(
      server.loopback,
      `/v1/mcp/oauth/authorizations/${approval.searchParams.get("mcp_authorization")}`,
    );
    const { connections } = await ownerGet(
      server.loopback,
      "/v1/mcp/connections",
    );

    expect(view.clientName).toBe(CLIENT_NAME);
    expect(
      connections.find(
        (connection: { id: string }) => connection.id === view.connectionId,
      )?.displayName,
    ).toBe(CLIENT_NAME);
  });

  // Native clients need no CORS and the gate refuses every foreign origin,
  // so a wildcard grant would only widen what a browser page may read.
  it("keeps loopback MCP out of the wildcard CORS, tunnel MCP in it", async () => {
    const server = await startLocalServer();
    const allowOrigin = "access-control-allow-origin";

    const loopback = await rawRequest(
      `${server.loopback}${PROTECTED_RESOURCE_PATH}`,
      { origin: server.loopback },
    );
    expect(loopback.status).toBe(200);
    expect(loopback.headers[allowOrigin]).toBeUndefined();

    const tunnel = await rawRequest(
      `${server.main}${PROTECTED_RESOURCE_PATH}`,
      {
        origin: "https://claude.ai",
      },
    );
    expect(tunnel.status).toBe(200);
    expect(tunnel.headers[allowOrigin]).toBe("*");
  });
});
