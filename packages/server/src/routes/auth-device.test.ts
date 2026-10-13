import { describe, it, expect, beforeEach, vi } from "vitest";
import { Hono } from "hono";
import { authDeviceRoutes, sessions } from "./auth-device.js";
import type { TokenStore } from "../token-store.js";
import pino from "pino";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";

const SERVER_ORIGIN = "http://localhost:8080";
const TEST_REMOTE_ADDR_HEADER = "x-test-remote-addr";
const MAIN_PORT = 8080;
const APPROVAL_PORT = 34127;
// Node socket of a connection accepted by the loopback approval listener
// (what @hono/node-server exposes as `c.env.incoming.socket`).
const VIA_APPROVAL_LISTENER = {
  incoming: {
    socket: { localPort: APPROVAL_PORT, localAddress: "127.0.0.1" },
  },
};
const ownerWallet = createTestWallet(0);
const SERVER_OWNER = ownerWallet.address;

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

function createApp(options?: {
  tokenStore?: TokenStore;
  accessToken?: string;
  devToken?: string;
  serverOwner?: `0x${string}`;
  localApprovalOrigin?: string;
}) {
  const serverOwner =
    options && "serverOwner" in options ? options.serverOwner : SERVER_OWNER;
  return authDeviceRoutes({
    logger: pino({ level: "silent" }),
    serverOrigin: SERVER_ORIGIN,
    localApprovalOrigin: options?.localApprovalOrigin,
    localApprovalPort: APPROVAL_PORT,
    serverPort: MAIN_PORT,
    serverOwner,
    tokenStore: options?.tokenStore ?? createMockTokenStore(),
    accessToken: options?.accessToken,
    devToken: options?.devToken,
    getRemoteAddress: (c) => c.req.header(TEST_REMOTE_ADDR_HEADER),
  });
}

function request(
  app: ReturnType<typeof authDeviceRoutes>,
  path: string,
  init?: RequestInit,
) {
  return app.request(new Request(`${SERVER_ORIGIN}${path}`, init));
}

describe("POST /auth/device", () => {
  beforeEach(() => {
    sessions.clear();
  });

  it("returns login URL and poll endpoint", async () => {
    const app = createApp();
    const res = await request(app, "/", { method: "POST" });
    expect(res.status).toBe(200);

    const body = await res.json();
    expect(body.login).toMatch(
      /^http:\/\/localhost:8080\/auth\/device\/approve\?session=.+$/,
    );
    expect(body.poll.endpoint).toBe("/auth/device/poll");
    expect(body.poll.token).toBeDefined();
    expect(body.poll.token.length).toBe(64); // 32 bytes hex
  });

  it("creates a session in the sessions map", async () => {
    const app = createApp();
    await request(app, "/", { method: "POST" });
    expect(sessions.size).toBe(1);
  });

  it("returns a dedicated loopback approval URL for localhost login initiation", async () => {
    const app = createApp({
      localApprovalOrigin: "http://127.0.0.1:34127",
    });
    const res = await request(app, "/", {
      method: "POST",
      headers: { [TEST_REMOTE_ADDR_HEADER]: "127.0.0.1" },
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.login).toMatch(
      /^http:\/\/127\.0\.0\.1:34127\/auth\/device\/approve\?session=.+$/,
    );
    expect(body.poll.endpoint).toBe("/auth/device/poll");
  });

  it("keeps public approval URLs on the public origin", async () => {
    const app = createApp({
      localApprovalOrigin: "http://127.0.0.1:34127",
    });

    const res = await app.request(
      new Request("https://ps.alice.com/", { method: "POST" }),
    );

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.login).toMatch(
      /^https:\/\/ps\.alice\.com\/auth\/device\/approve\?session=.+$/,
    );
  });

  it("requires a configured server owner", async () => {
    const app = createApp({ serverOwner: undefined });
    const res = await request(app, "/", { method: "POST" });

    expect(res.status).toBe(500);
    expect((await res.json()).error.errorCode).toBe("SERVER_NOT_CONFIGURED");
    expect(sessions.size).toBe(0);
  });
});

describe("GET /auth/device/poll", () => {
  beforeEach(() => {
    sessions.clear();
  });

  it("returns 400 if no token parameter", async () => {
    const app = createApp();
    const res = await request(app, "/poll", { method: "GET" });
    expect(res.status).toBe(400);
  });

  it("returns expired (404) for unknown token", async () => {
    const app = createApp();
    const res = await request(app, "/poll?token=nonexistent", {
      method: "GET",
    });
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.status).toBe("expired");
  });

  it("returns pending (404) for a new session", async () => {
    const app = createApp();

    // Initiate login
    const initRes = await request(app, "/", { method: "POST" });
    const { poll } = await initRes.json();

    const res = await request(app, `/poll?token=${poll.token}`, {
      method: "GET",
    });
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.status).toBe("pending");
  });

  it("returns 429 if polled too quickly", async () => {
    const app = createApp();

    const initRes = await request(app, "/", { method: "POST" });
    const { poll } = await initRes.json();

    // First poll
    await request(app, `/poll?token=${poll.token}`, { method: "GET" });

    // Second poll immediately — should be rate limited
    const res = await request(app, `/poll?token=${poll.token}`, {
      method: "GET",
    });
    expect(res.status).toBe(429);
  });

  it("returns authorized (200) after session is approved, then deletes session", async () => {
    const app = createApp();

    // Initiate
    const initRes = await request(app, "/", { method: "POST" });
    const initBody = await initRes.json();
    const sessionId = new URL(initBody.login).searchParams.get("session")!;
    const pollToken = initBody.poll.token;

    // Simulate approval (set session directly since we can't easily fake localhost)
    const session = sessions.get(sessionId)!;
    session.status = "approved";
    session.accessToken = "vana_ps_test_token_123";
    session.lastPollAt = 0; // reset so poll succeeds

    const res = await request(app, `/poll?token=${pollToken}`, {
      method: "GET",
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe("authorized");
    expect(body.server).toBe(SERVER_ORIGIN);
    expect(body.address).toBe(SERVER_OWNER);
    expect(body.access_token).toBe("vana_ps_test_token_123");
    expect(body.expires_at).toBeUndefined();

    // Session should be deleted after retrieval
    expect(sessions.has(sessionId)).toBe(false);
  });
});

describe("GET /auth/device/approve", () => {
  beforeEach(() => {
    sessions.clear();
  });

  it("returns 400 if no session parameter", async () => {
    const app = createApp();
    const res = await request(app, "/approve", { method: "GET" });
    expect(res.status).toBe(400);
  });

  it("returns 404 for unknown session", async () => {
    const app = createApp();
    const res = await request(app, "/approve?session=nonexistent", {
      method: "GET",
    });
    expect(res.status).toBe(404);
  });

  it("returns HTML approval page for valid session", async () => {
    const app = createApp();

    const initRes = await request(app, "/", { method: "POST" });
    const initBody = await initRes.json();
    const sessionId = new URL(initBody.login).searchParams.get("session")!;

    const res = await request(app, `/approve?session=${sessionId}`, {
      method: "GET",
    });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("A CLI tool is requesting access");
    expect(html).toContain(SERVER_ORIGIN);
    expect(html).toContain(SERVER_OWNER);
    expect(html).toContain("Approve");
  });

  it("shows the requested server origin even when approval happens on the loopback channel", async () => {
    const app = createApp({
      localApprovalOrigin: "http://127.0.0.1:34127",
    });

    const initRes = await request(app, "/", { method: "POST" });
    const initBody = await initRes.json();
    const sessionId = new URL(initBody.login).searchParams.get("session")!;

    const res = await app.request(
      new Request(`http://127.0.0.1:34127/approve?session=${sessionId}`, {
        method: "GET",
      }),
      undefined,
      VIA_APPROVAL_LISTENER,
    );

    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(SERVER_ORIGIN);
    expect(html).not.toContain("127.0.0.1:34127</dd>");
  });

  it("forbids framing of the approval, success and error pages", async () => {
    const app = createApp();
    const initRes = await request(app, "/", { method: "POST" });
    const sessionId = new URL((await initRes.json()).login).searchParams.get(
      "session",
    )!;

    const approve = await request(app, `/approve?session=${sessionId}`);
    sessions.get(sessionId)!.status = "approved";
    const success = await request(app, `/approve?session=${sessionId}`);
    const missing = await request(app, "/approve");
    const unknown = await request(app, "/approve?session=nonexistent");

    for (const res of [approve, success, missing, unknown]) {
      expect(res.headers.get("x-frame-options")).toBe("DENY");
      expect(res.headers.get("content-security-policy")).toBe(
        "frame-ancestors 'none'",
      );
    }
    expect(await success.text()).toContain("Device authorized!");
    expect(missing.status).toBe(400);
    expect(unknown.status).toBe(404);
  });

  it("returns success page if session already approved", async () => {
    const app = createApp();

    const initRes = await request(app, "/", { method: "POST" });
    const initBody = await initRes.json();
    const sessionId = new URL(initBody.login).searchParams.get("session")!;

    // Mark as approved
    sessions.get(sessionId)!.status = "approved";

    const res = await request(app, `/approve?session=${sessionId}`, {
      method: "GET",
    });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Device authorized!");
  });
});

describe("POST /auth/device/approve", () => {
  beforeEach(() => {
    sessions.clear();
  });

  it("returns 400 if no session parameter", async () => {
    const app = createApp();
    const res = await request(app, "/approve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    expect(res.status).toBe(400);
  });

  it("returns 404 for unknown session", async () => {
    const app = createApp();
    const res = await request(app, "/approve?session=nonexistent", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    expect(res.status).toBe(404);
  });

  it("rejects non-localhost requests with 403", async () => {
    const app = createApp();

    const initRes = await request(app, "/", { method: "POST" });
    const initBody = await initRes.json();
    const sessionId = new URL(initBody.login).searchParams.get("session")!;

    const res = await request(app, `/approve?session=${sessionId}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        [TEST_REMOTE_ADDR_HEADER]: "203.0.113.5",
      },
    });
    expect(res.status).toBe(403);
    expect((await res.json()).error.message).toContain(
      "Remote approval requires owner wallet authentication",
    );
  });

  it("approves remote requests signed by the owner wallet", async () => {
    const tokenStore = createMockTokenStore();
    const app = createApp({ tokenStore });

    const initRes = await request(app, "/", { method: "POST" });
    const initBody = await initRes.json();
    const sessionId = new URL(initBody.login).searchParams.get("session")!;
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "POST",
      uri: "/approve",
    });

    const res = await request(app, `/approve?session=${sessionId}`, {
      method: "POST",
      headers: {
        Authorization: auth,
        [TEST_REMOTE_ADDR_HEADER]: "203.0.113.5",
      },
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "approved" });
    expect(tokenStore.addToken).toHaveBeenCalledTimes(1);
  });

  it("rejects remote approvals signed by a non-owner wallet", async () => {
    const app = createApp();

    const initRes = await request(app, "/", { method: "POST" });
    const initBody = await initRes.json();
    const sessionId = new URL(initBody.login).searchParams.get("session")!;
    const auth = await buildWeb3SignedHeader({
      wallet: createTestWallet(1),
      aud: SERVER_ORIGIN,
      method: "POST",
      uri: "/approve",
    });

    const res = await request(app, `/approve?session=${sessionId}`, {
      method: "POST",
      headers: {
        Authorization: auth,
        [TEST_REMOTE_ADDR_HEADER]: "203.0.113.5",
      },
    });

    expect(res.status).toBe(401);
    expect((await res.json()).error.errorCode).toBe("NOT_OWNER");
  });

  it("approves session for localhost requests", async () => {
    const tokenStore = createMockTokenStore();
    const app = createApp({
      tokenStore,
      localApprovalOrigin: "http://127.0.0.1:34127",
    });

    const initRes = await request(app, "/", {
      method: "POST",
      headers: { [TEST_REMOTE_ADDR_HEADER]: "127.0.0.1" },
    });
    const initBody = await initRes.json();
    const sessionId = new URL(initBody.login).searchParams.get("session")!;

    const res = await app.request(
      new Request(`http://127.0.0.1:34127/approve?session=${sessionId}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [TEST_REMOTE_ADDR_HEADER]: "127.0.0.1",
        },
      }),
      undefined,
      VIA_APPROVAL_LISTENER,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "approved" });
    expect(tokenStore.addToken).toHaveBeenCalledTimes(1);
    expect(tokenStore.addToken).toHaveBeenCalledWith(
      expect.stringMatching(/^vana_ps_/),
      {
        expiresAt: expect.any(String),
      },
    );
  });

  it("does not auto-approve on the public localhost listener", async () => {
    const app = createApp({
      localApprovalOrigin: "http://127.0.0.1:34127",
    });

    const initRes = await request(app, "/", { method: "POST" });
    const initBody = await initRes.json();
    const sessionId = new URL(initBody.login).searchParams.get("session")!;

    const res = await request(app, `/approve?session=${sessionId}`, {
      method: "POST",
      headers: {
        [TEST_REMOTE_ADDR_HEADER]: "127.0.0.1",
      },
    });

    expect(res.status).toBe(403);
    expect((await res.json()).error.message).toContain(
      "Remote approval requires owner wallet authentication",
    );
  });

  it("does not trust localhost peer addresses for public-origin approvals", async () => {
    const app = createApp();

    const initRes = await app.request(
      new Request("https://ps.alice.com/", { method: "POST" }),
    );
    const initBody = await initRes.json();
    const sessionId = new URL(initBody.login).searchParams.get("session")!;

    const res = await app.request(
      new Request(`https://ps.alice.com/approve?session=${sessionId}`, {
        method: "POST",
        headers: {
          [TEST_REMOTE_ADDR_HEADER]: "127.0.0.1",
        },
      }),
    );

    expect(res.status).toBe(403);
    expect((await res.json()).error.message).toContain(
      "Remote approval requires owner wallet authentication",
    );
  });

  it("accepts owner-signed approval for public origins even when proxied locally", async () => {
    const app = createApp();

    const initRes = await app.request(
      new Request("https://ps.alice.com/", { method: "POST" }),
    );
    const initBody = await initRes.json();
    const sessionId = new URL(initBody.login).searchParams.get("session")!;
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: "https://ps.alice.com",
      method: "POST",
      uri: "/approve",
    });

    const res = await app.request(
      new Request(`https://ps.alice.com/approve?session=${sessionId}`, {
        method: "POST",
        headers: {
          Authorization: auth,
          [TEST_REMOTE_ADDR_HEADER]: "127.0.0.1",
        },
      }),
    );

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "approved" });
  });

  it("approves session for ::1 (IPv6 localhost)", async () => {
    const app = createApp({
      localApprovalOrigin: "http://127.0.0.1:34127",
    });

    const initRes = await request(app, "/", {
      method: "POST",
      headers: { [TEST_REMOTE_ADDR_HEADER]: "127.0.0.1" },
    });
    const initBody = await initRes.json();
    const sessionId = new URL(initBody.login).searchParams.get("session")!;

    const res = await app.request(
      new Request(`http://127.0.0.1:34127/approve?session=${sessionId}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [TEST_REMOTE_ADDR_HEADER]: "::1",
        },
      }),
      undefined,
      VIA_APPROVAL_LISTENER,
    );
    expect(res.status).toBe(200);
  });

  it("returns already_approved for double approval", async () => {
    const app = createApp({
      localApprovalOrigin: "http://127.0.0.1:34127",
    });

    const initRes = await request(app, "/", {
      method: "POST",
      headers: { [TEST_REMOTE_ADDR_HEADER]: "127.0.0.1" },
    });
    const initBody = await initRes.json();
    const sessionId = new URL(initBody.login).searchParams.get("session")!;

    // First approval
    await app.request(
      new Request(`http://127.0.0.1:34127/approve?session=${sessionId}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [TEST_REMOTE_ADDR_HEADER]: "127.0.0.1",
        },
      }),
      undefined,
      VIA_APPROVAL_LISTENER,
    );

    // Second approval
    const res = await app.request(
      new Request(`http://127.0.0.1:34127/approve?session=${sessionId}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [TEST_REMOTE_ADDR_HEADER]: "127.0.0.1",
        },
      }),
      undefined,
      VIA_APPROVAL_LISTENER,
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe("already_approved");
  });
});

describe("POST /auth/device/approve local shortcut hardening", () => {
  const LOCAL_APPROVAL_ORIGIN = "http://127.0.0.1:34127";

  beforeEach(() => {
    sessions.clear();
  });

  // The CLI on the same machine: plain Node fetch from a loopback peer to a
  // loopback URL, no browser headers.
  async function initLocalSession(app: ReturnType<typeof authDeviceRoutes>) {
    const res = await request(app, "/", {
      method: "POST",
      headers: { [TEST_REMOTE_ADDR_HEADER]: "127.0.0.1" },
    });
    const body = await res.json();
    return new URL(body.login).searchParams.get("session")!;
  }

  function approveLocally(
    app: ReturnType<typeof authDeviceRoutes>,
    sessionId: string,
    headers: Record<string, string> = {},
    origin = LOCAL_APPROVAL_ORIGIN,
  ) {
    return app.request(
      new Request(`${origin}/approve?session=${sessionId}`, {
        method: "POST",
        headers: { [TEST_REMOTE_ADDR_HEADER]: "127.0.0.1", ...headers },
      }),
      undefined,
      VIA_APPROVAL_LISTENER,
    );
  }

  it("approves a locally initiated session with no Origin header", async () => {
    const tokenStore = createMockTokenStore();
    const app = createApp({
      tokenStore,
      localApprovalOrigin: LOCAL_APPROVAL_ORIGIN,
    });
    const sessionId = await initLocalSession(app);

    const res = await approveLocally(app, sessionId);

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "approved" });
    expect(tokenStore.addToken).toHaveBeenCalledTimes(1);
    expect(sessions.get(sessionId)!.status).toBe("approved");
  });

  it("approves from the approval page's own origin", async () => {
    const tokenStore = createMockTokenStore();
    const app = createApp({
      tokenStore,
      localApprovalOrigin: LOCAL_APPROVAL_ORIGIN,
    });
    const sessionId = await initLocalSession(app);

    const res = await approveLocally(app, sessionId, {
      Origin: LOCAL_APPROVAL_ORIGIN,
      "Sec-Fetch-Site": "same-origin",
    });

    expect(res.status).toBe(200);
    expect(tokenStore.addToken).toHaveBeenCalledTimes(1);
  });

  it("rejects a cross-origin Origin header on the local channel", async () => {
    const tokenStore = createMockTokenStore();
    const app = createApp({
      tokenStore,
      localApprovalOrigin: LOCAL_APPROVAL_ORIGIN,
    });
    const sessionId = await initLocalSession(app);

    const res = await approveLocally(app, sessionId, {
      Origin: "https://example.com",
    });

    expect([401, 403]).toContain(res.status);
    expect(tokenStore.addToken).not.toHaveBeenCalled();
    expect(sessions.get(sessionId)!.status).toBe("pending");
  });

  it("rejects Sec-Fetch-Site: cross-site on the local channel", async () => {
    const tokenStore = createMockTokenStore();
    const app = createApp({
      tokenStore,
      localApprovalOrigin: LOCAL_APPROVAL_ORIGIN,
    });
    const sessionId = await initLocalSession(app);

    const res = await approveLocally(app, sessionId, {
      "Sec-Fetch-Site": "cross-site",
    });

    expect([401, 403]).toContain(res.status);
    expect(tokenStore.addToken).not.toHaveBeenCalled();
    expect(sessions.get(sessionId)!.status).toBe("pending");
  });

  it("rejects a non-loopback Host (DNS rebinding) even when it is the configured channel", async () => {
    const tokenStore = createMockTokenStore();
    const app = createApp({
      tokenStore,
      localApprovalOrigin: "http://evil.example:34127",
    });
    const sessionId = await initLocalSession(app);

    const res = await approveLocally(
      app,
      sessionId,
      {},
      "http://evil.example:34127",
    );

    expect([401, 403]).toContain(res.status);
    expect(tokenStore.addToken).not.toHaveBeenCalled();
    expect(sessions.get(sessionId)!.status).toBe("pending");
  });

  it("requires the owner signature for sessions initiated through a public origin", async () => {
    const tokenStore = createMockTokenStore();
    const app = createApp({
      tokenStore,
      localApprovalOrigin: LOCAL_APPROVAL_ORIGIN,
    });
    // Tunneled request: frpc connects from loopback, Host is the public name.
    const initRes = await app.request(
      new Request("https://ps.alice.com/", {
        method: "POST",
        headers: { [TEST_REMOTE_ADDR_HEADER]: "127.0.0.1" },
      }),
    );
    const sessionId = new URL((await initRes.json()).login).searchParams.get(
      "session",
    )!;

    const res = await approveLocally(app, sessionId);

    expect([401, 403]).toContain(res.status);
    expect(tokenStore.addToken).not.toHaveBeenCalled();
    expect(sessions.get(sessionId)!.status).toBe("pending");
  });

  it("requires the owner signature for sessions initiated by a non-loopback peer", async () => {
    const tokenStore = createMockTokenStore();
    const app = createApp({
      tokenStore,
      localApprovalOrigin: LOCAL_APPROVAL_ORIGIN,
    });
    // LAN peer addressing the main port as "localhost".
    const initRes = await request(app, "/", {
      method: "POST",
      headers: { [TEST_REMOTE_ADDR_HEADER]: "192.168.1.20" },
    });
    const sessionId = new URL((await initRes.json()).login).searchParams.get(
      "session",
    )!;

    const res = await approveLocally(app, sessionId);

    expect([401, 403]).toContain(res.status);
    expect(tokenStore.addToken).not.toHaveBeenCalled();
  });

  it("requires the owner signature for sessions initiated from another browser origin", async () => {
    const tokenStore = createMockTokenStore();
    const app = createApp({
      tokenStore,
      localApprovalOrigin: LOCAL_APPROVAL_ORIGIN,
    });
    const initRes = await request(app, "/", {
      method: "POST",
      headers: {
        [TEST_REMOTE_ADDR_HEADER]: "127.0.0.1",
        Origin: "https://example.com",
      },
    });
    const sessionId = new URL((await initRes.json()).login).searchParams.get(
      "session",
    )!;

    const res = await approveLocally(app, sessionId);

    expect([401, 403]).toContain(res.status);
    expect(tokenStore.addToken).not.toHaveBeenCalled();
  });

  it("refuses the shortcut on the main port even with the approval listener's Host", async () => {
    const tokenStore = createMockTokenStore();
    const app = createApp({
      tokenStore,
      localApprovalOrigin: LOCAL_APPROVAL_ORIGIN,
    });
    const sessionId = await initLocalSession(app);
    // Same Host string as the approval channel, but the connection was
    // accepted by the main (tunneled) listener.
    const viaMainPort = {
      incoming: {
        socket: { localPort: MAIN_PORT, localAddress: "127.0.0.1" },
      },
    };

    const res = await app.request(
      new Request(`${LOCAL_APPROVAL_ORIGIN}/approve?session=${sessionId}`, {
        method: "POST",
        headers: { [TEST_REMOTE_ADDR_HEADER]: "127.0.0.1" },
      }),
      undefined,
      viaMainPort,
    );
    expect(res.status).toBe(403);
    expect(tokenStore.addToken).not.toHaveBeenCalled();

    const page = await app.request(
      new Request(`${LOCAL_APPROVAL_ORIGIN}/approve?session=${sessionId}`),
      undefined,
      viaMainPort,
    );
    expect(await page.text()).toContain(
      "const LOCAL_APPROVAL_SHORTCUT_ENABLED = false;",
    );
  });

  it("refuses the shortcut when no socket information is available", async () => {
    const tokenStore = createMockTokenStore();
    const app = createApp({
      tokenStore,
      localApprovalOrigin: LOCAL_APPROVAL_ORIGIN,
    });
    const sessionId = await initLocalSession(app);

    const res = await app.request(
      new Request(`${LOCAL_APPROVAL_ORIGIN}/approve?session=${sessionId}`, {
        method: "POST",
        headers: { [TEST_REMOTE_ADDR_HEADER]: "127.0.0.1" },
      }),
    );

    expect(res.status).toBe(403);
    expect(tokenStore.addToken).not.toHaveBeenCalled();
  });

  it("accepts an owner-signed approval of a tunneled session at the public origin", async () => {
    const tokenStore = createMockTokenStore();
    // Mounted like app.ts so the signed path is the real one.
    const app = new Hono().route(
      "/auth/device",
      createApp({ tokenStore, localApprovalOrigin: LOCAL_APPROVAL_ORIGIN }),
    );
    // Tunneled: frpc connects from loopback to the main port, public Host.
    const viaTunnel = {
      incoming: {
        socket: {
          localPort: MAIN_PORT,
          localAddress: "127.0.0.1",
          remoteAddress: "127.0.0.1",
        },
      },
    };
    const initRes = await app.request(
      new Request("https://ps.alice.com/auth/device", { method: "POST" }),
      undefined,
      viaTunnel,
    );
    const login = new URL((await initRes.json()).login);
    expect(login.origin).toBe("https://ps.alice.com");
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: "https://ps.alice.com",
      method: "POST",
      uri: "/auth/device/approve",
    });

    const res = await app.request(
      new Request(`${login.origin}${login.pathname}${login.search}`, {
        method: "POST",
        headers: { Authorization: auth, Origin: "https://ps.alice.com" },
      }),
      undefined,
      viaTunnel,
    );

    expect(res.status).toBe(200);
    expect(tokenStore.addToken).toHaveBeenCalledTimes(1);
  });

  it("renders the wallet approval page for sessions that cannot use the shortcut", async () => {
    const app = createApp({ localApprovalOrigin: LOCAL_APPROVAL_ORIGIN });
    const initRes = await app.request(
      new Request("https://ps.alice.com/", { method: "POST" }),
    );
    const sessionId = new URL((await initRes.json()).login).searchParams.get(
      "session",
    )!;

    const res = await app.request(
      new Request(`${LOCAL_APPROVAL_ORIGIN}/approve?session=${sessionId}`),
    );

    expect(res.status).toBe(200);
    expect(await res.text()).toContain(
      "const LOCAL_APPROVAL_SHORTCUT_ENABLED = false;",
    );
  });
});

describe("full login flow", () => {
  beforeEach(() => {
    sessions.clear();
  });

  it("complete flow: initiate -> approve -> poll -> get token", async () => {
    const tokenStore = createMockTokenStore();
    const app = createApp({
      tokenStore,
      localApprovalOrigin: "http://127.0.0.1:34127",
    });

    // 1. Initiate login
    const initRes = await request(app, "/", {
      method: "POST",
      headers: { [TEST_REMOTE_ADDR_HEADER]: "127.0.0.1" },
    });
    expect(initRes.status).toBe(200);
    const initBody = await initRes.json();

    const sessionId = new URL(initBody.login).searchParams.get("session")!;
    const pollToken = initBody.poll.token;

    // 2. Poll — should be pending
    const pollRes1 = await request(app, `/poll?token=${pollToken}`, {
      method: "GET",
    });
    expect(pollRes1.status).toBe(404);
    const pollBody1 = await pollRes1.json();
    expect(pollBody1.status).toBe("pending");

    // 3. Approve (localhost)
    // Reset lastPollAt so we can poll again
    sessions.get(sessionId)!.lastPollAt = 0;

    const approveRes = await app.request(
      new Request(`http://127.0.0.1:34127/approve?session=${sessionId}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [TEST_REMOTE_ADDR_HEADER]: "127.0.0.1",
        },
      }),
      undefined,
      VIA_APPROVAL_LISTENER,
    );
    expect(approveRes.status).toBe(200);

    // 4. Poll — should be authorized
    const pollRes2 = await request(app, `/poll?token=${pollToken}`, {
      method: "GET",
    });
    expect(pollRes2.status).toBe(200);
    const pollBody2 = await pollRes2.json();
    expect(pollBody2.status).toBe("authorized");
    expect(pollBody2.server).toBe(SERVER_ORIGIN);
    expect(pollBody2.address).toBe(SERVER_OWNER);
    expect(pollBody2.access_token).toMatch(/^vana_ps_/);
    expect(pollBody2.expires_at).toEqual(expect.any(String));

    // 5. Poll again — session should be gone
    const pollRes3 = await request(app, `/poll?token=${pollToken}`, {
      method: "GET",
    });
    expect(pollRes3.status).toBe(404);
    const pollBody3 = await pollRes3.json();
    expect(pollBody3.status).toBe("expired");
  });
});

describe("POST /auth/device/token", () => {
  it("requires owner authentication", async () => {
    const app = createApp({ accessToken: "vana_ps_control_plane" });

    const res = await app.request("/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: "vana_ps_cli_token" }),
    });

    expect(res.status).toBe(401);
    expect((await res.json()).error.errorCode).toBe("MISSING_AUTH");
  });

  it("allows control-plane tokens to add CLI session tokens", async () => {
    const controlPlaneToken = "vana_ps_control_plane";
    const tokenStore = createMockTokenStore();
    const app = createApp({ tokenStore, accessToken: controlPlaneToken });
    const expiresAt = new Date(Date.now() + 60_000).toISOString();

    const res = await app.request("/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${controlPlaneToken}`,
      },
      body: JSON.stringify({
        token: "vana_ps_cli_token",
        expires_at: expiresAt,
      }),
    });

    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ status: "created" });
    expect(tokenStore.addToken).toHaveBeenCalledWith("vana_ps_cli_token", {
      expiresAt,
    });
  });

  it("rejects normal CLI session tokens for token minting", async () => {
    const tokenStore = createMockTokenStore();
    await tokenStore.addToken("vana_ps_cli_session");
    const app = createApp({ tokenStore });

    const res = await app.request("/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer vana_ps_cli_session",
      },
      body: JSON.stringify({ token: "vana_ps_new_cli_token" }),
    });

    expect(res.status).toBe(403);
    expect((await res.json()).error.message).toContain(
      "Only control-plane tokens can provision",
    );
  });

  it("rejects Web3Signed owner auth for token provisioning", async () => {
    const tokenStore = createMockTokenStore();
    const app = createApp({ tokenStore });
    const requestBody = JSON.stringify({ token: "vana_ps_new_cli_token" });
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "POST",
      uri: "/token",
      body: new TextEncoder().encode(requestBody),
    });

    const res = await app.request("/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: auth,
      },
      body: requestBody,
    });

    expect(res.status).toBe(403);
    expect((await res.json()).error.message).toContain(
      "Only control-plane tokens can provision",
    );
  });

  it("rejects dev-token bypass for token provisioning", async () => {
    const tokenStore = createMockTokenStore();
    const app = createApp({
      tokenStore,
      devToken: "local-dev-token",
    });

    const res = await app.request("/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer local-dev-token",
      },
      body: JSON.stringify({ token: "vana_ps_new_cli_token" }),
    });

    expect(res.status).toBe(403);
    expect((await res.json()).error.message).toContain(
      "Only control-plane tokens can provision",
    );
  });
});

describe("DELETE /auth/device/token", () => {
  beforeEach(() => {
    sessions.clear();
  });

  it("requires a Bearer token", async () => {
    const app = createApp();

    const res = await app.request("/token", {
      method: "DELETE",
    });

    expect(res.status).toBe(401);
    expect((await res.json()).error.message).toContain("Missing Bearer token");
  });

  it("revokes a valid CLI session token", async () => {
    const tokenStore = createMockTokenStore();
    await tokenStore.addToken("vana_ps_cli_session");
    const app = createApp({ tokenStore });

    const res = await app.request("/token", {
      method: "DELETE",
      headers: {
        Authorization: "Bearer vana_ps_cli_session",
      },
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "revoked" });
    expect(tokenStore.isValid).toHaveBeenCalledWith("vana_ps_cli_session");
    expect(tokenStore.removeToken).toHaveBeenCalledWith("vana_ps_cli_session");
  });

  it("does not mutate the token store for unknown bearer values", async () => {
    const tokenStore = createMockTokenStore();
    const app = createApp({ tokenStore });

    const res = await app.request("/token", {
      method: "DELETE",
      headers: {
        Authorization: "Bearer vana_ps_unknown",
      },
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "revoked" });
    expect(tokenStore.isValid).toHaveBeenCalledWith("vana_ps_unknown");
    expect(tokenStore.removeToken).not.toHaveBeenCalled();
  });
});
