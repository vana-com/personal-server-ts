/**
 * Device login over real sockets: the main listener and the loopback
 * approval listener bound the way `index.ts` binds them, driven with real
 * HTTP requests so the socket-level checks (which listener accepted the
 * connection) are exercised, not simulated.
 */
import { request as httpRequest } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { AddressInfo } from "node:net";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import pino from "pino";
import type { Hono } from "hono";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { createTestWallet } from "@opendatalabs/personal-server-ts-core/test-utils";
import { createApp } from "./app.js";
import { listenHttpServer, type NodeServer } from "./listen.js";
import { sessions } from "./routes/auth-device.js";
import { initializeDatabase } from "./storage/index-schema.js";
import {
  createIndexManager,
  type IndexManager,
} from "./storage/index-manager.js";
import type { TokenStore } from "./token-store.js";

const ownerWallet = createTestWallet(0);

function createMockTokenStore(): TokenStore {
  const tokens = new Set<string>();
  return {
    getTokens: vi.fn(async () => Array.from(tokens)),
    isValid: vi.fn(async (token: string) => tokens.has(token)),
    addToken: vi.fn(async (token: string) => {
      tokens.add(token);
    }),
    removeToken: vi.fn(async (token: string) => {
      tokens.delete(token);
    }),
  };
}

interface HttpResult {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

/** Real HTTP request; `host` overrides the Host header independently of the TCP target. */
function send(params: {
  port: number;
  method: string;
  path: string;
  headers?: Record<string, string>;
}): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: "127.0.0.1",
        port: params.port,
        method: params.method,
        path: params.path,
        headers: params.headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf-8"),
          }),
        );
      },
    );
    req.on("error", reject);
    req.end();
  });
}

describe("device login on real listeners", () => {
  let tempDir: string;
  let indexManager: IndexManager;
  let tokenStore: TokenStore;
  let mainServer: NodeServer;
  let approvalServer: NodeServer;
  let mainPort: number;
  let approvalPort: number;
  let app: Hono | undefined;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "device-login-listeners-"));
    indexManager = createIndexManager(initializeDatabase(":memory:"));
    tokenStore = createMockTokenStore();

    // Bind first (ephemeral ports), build the app once the ports are known.
    const fetch = (req: Request, env: unknown) => {
      if (!app) throw new Error("app not ready");
      return app.fetch(req, env as never);
    };
    mainServer = await listenHttpServer({ fetch, port: 0 });
    mainPort = (mainServer.address() as AddressInfo).port;
    approvalServer = await listenHttpServer({
      fetch,
      port: 0,
      hostname: "127.0.0.1",
    });
    approvalPort = (approvalServer.address() as AddressInfo).port;

    app = createApp({
      logger: pino({ level: "silent" }),
      version: "0.0.1",
      startedAt: new Date(),
      indexManager,
      hierarchyOptions: { dataDir: join(tempDir, "data") },
      serverOrigin: `http://localhost:${mainPort}`,
      localApprovalOrigin: `http://127.0.0.1:${approvalPort}`,
      localApprovalPort: approvalPort,
      serverPort: mainPort,
      serverOwner: ownerWallet.address,
      gateway: {} as GatewayClient,
      accessLogWriter: { write: vi.fn().mockResolvedValue(undefined) },
      accessLogReader: {
        read: vi
          .fn()
          .mockResolvedValue({ logs: [], total: 0, limit: 50, offset: 0 }),
      },
      tokenStore,
    });
  });

  afterAll(async () => {
    await new Promise((r) => mainServer.close(r));
    await new Promise((r) => approvalServer.close(r));
    indexManager.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  beforeEach(() => {
    sessions.clear();
    vi.mocked(tokenStore.addToken).mockClear();
  });

  /** What the CLI on this machine does: plain POST to the main port. */
  async function initFromCli(): Promise<URL> {
    const res = await send({
      port: mainPort,
      method: "POST",
      path: "/auth/device",
      headers: { host: `localhost:${mainPort}` },
    });
    expect(res.status).toBe(200);
    return new URL((JSON.parse(res.body) as { login: string }).login);
  }

  it("gives a CLI on this machine a login URL on the loopback approval listener", async () => {
    const login = await initFromCli();
    expect(login.origin).toBe(`http://127.0.0.1:${approvalPort}`);
    expect(login.pathname).toBe("/auth/device/approve");
  });

  it("does not treat an absolute-form loopback request line with a public Host as local", async () => {
    // Node builds the request URL from an absolute-form request line and
    // ignores Host; a forwarder passing the line through must not make a
    // remote session look local.
    const res = await send({
      port: mainPort,
      method: "POST",
      path: `http://localhost:${mainPort}/auth/device`,
      headers: { host: "abc.tunnel.example" },
    });
    expect(res.status).toBe(200);
    const login = new URL((JSON.parse(res.body) as { login: string }).login);
    expect(login.origin).not.toBe(`http://127.0.0.1:${approvalPort}`);
  });

  it("approves on the approval listener with no Origin header", async () => {
    const login = await initFromCli();

    const res = await send({
      port: approvalPort,
      method: "POST",
      path: `${login.pathname}${login.search}`,
      headers: { host: login.host },
    });

    expect(res.status).toBe(200);
    expect(JSON.parse(res.body)).toEqual({ status: "approved" });
    expect(tokenStore.addToken).toHaveBeenCalledTimes(1);
  });

  it("refuses the signature-free approval on the MAIN port even with the approval listener's Host", async () => {
    const login = await initFromCli();

    // Same machine, same Host string, but the TCP connection is to the
    // main (tunneled) port. Only the accepting socket tells them apart.
    const res = await send({
      port: mainPort,
      method: "POST",
      path: `${login.pathname}${login.search}`,
      headers: { host: `127.0.0.1:${approvalPort}` },
    });

    expect(res.status).toBe(403);
    expect(tokenStore.addToken).not.toHaveBeenCalled();
    expect(sessions.get(login.searchParams.get("session")!)!.status).toBe(
      "pending",
    );

    // ...and the page served there offers only the wallet flow.
    const page = await send({
      port: mainPort,
      method: "GET",
      path: `${login.pathname}${login.search}`,
      headers: { host: `127.0.0.1:${approvalPort}` },
    });
    expect(page.status).toBe(200);
    expect(page.body).toContain(
      "const LOCAL_APPROVAL_SHORTCUT_ENABLED = false;",
    );
  });

  it("refuses a cross-site Origin on the approval listener", async () => {
    const login = await initFromCli();

    const res = await send({
      port: approvalPort,
      method: "POST",
      path: `${login.pathname}${login.search}`,
      headers: { host: login.host, origin: "https://evil.example" },
    });

    expect(res.status).toBe(403);
    expect(tokenStore.addToken).not.toHaveBeenCalled();
  });

  it("renders the one-click page on the approval listener, unframeable", async () => {
    const login = await initFromCli();

    const page = await send({
      port: approvalPort,
      method: "GET",
      path: `${login.pathname}${login.search}`,
      headers: { host: login.host },
    });

    expect(page.status).toBe(200);
    expect(page.body).toContain(
      "const LOCAL_APPROVAL_SHORTCUT_ENABLED = true;",
    );
    expect(page.headers["x-frame-options"]).toBe("DENY");
    expect(page.headers["content-security-policy"]).toContain(
      "frame-ancestors 'none'",
    );
  });
});
