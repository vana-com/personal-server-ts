/**
 * Login Flow v2 — Nextcloud-style device login for self-hosted CLI authentication.
 *
 * POST /auth/device         — Initiate a login session
 * GET  /auth/device/poll    — Poll for completion (token= query param)
 * GET  /auth/device/approve — HTML approval page (session= query param)
 * POST /auth/device/approve — Approve the session (session= query param)
 */

// Load the Hono ContextVariableMap augmentation (auth/authMechanism/etc.) so
// c.get("authMechanism") is typed in this route's compilation.
import "../hono-context.js";
import { randomBytes } from "node:crypto";
import { Hono, type Context } from "hono";
import type { Logger } from "pino";
import {
  verifyWeb3Signed,
  type VerifiedAuth,
} from "@opendatalabs/vana-sdk/node";
import {
  approveDeviceSessionContract,
  createMemoryDeviceSessionStore,
  DEVICE_POLL_INTERVAL_MS,
  DEVICE_SESSION_TTL_MS,
  initiateDeviceSessionContract,
  pollDeviceSessionContract,
  provisionDeviceTokenContract,
  revokeDeviceTokenContract,
  type DeviceSessionStore,
} from "@opendatalabs/personal-server-ts-core/contracts";
import {
  NotOwnerError,
  ProtocolError,
} from "@opendatalabs/personal-server-ts-core/errors";
import type { TokenStore } from "../token-store.js";
import {
  createWeb3AuthMiddleware,
  mapSdkAuthError,
} from "../middleware/web3-auth.js";
import { createOwnerCheckMiddleware } from "../middleware/owner-check.js";

export interface LoginV2Deps {
  logger: Logger;
  serverOrigin: string | (() => string);
  localApprovalOrigin?: string | (() => string | undefined);
  serverOwner?: `0x${string}`;
  tokenStore: TokenStore;
  devToken?: string;
  accessToken?: string;
  allowInteractiveLogin?: boolean;
  getRemoteAddress?: (c: Context) => string | undefined;
}

type InspectableDeviceSessionStore = DeviceSessionStore & {
  clear(): void;
  readonly size: number;
  has(sessionId: string): boolean;
};

function createInspectableDeviceSessionStore(): InspectableDeviceSessionStore {
  const store = createMemoryDeviceSessionStore();
  const sessionIds = new Set<string>();
  return {
    create(input) {
      const session = store.create(input);
      sessionIds.add(session.sessionId);
      return session;
    },
    get(sessionId) {
      return store.get(sessionId);
    },
    findByPollToken(pollToken) {
      return store.findByPollToken(pollToken);
    },
    delete(sessionId) {
      store.delete(sessionId);
      sessionIds.delete(sessionId);
    },
    purgeExpired(now) {
      store.purgeExpired(now);
      for (const sessionId of Array.from(sessionIds)) {
        if (!store.get(sessionId)) sessionIds.delete(sessionId);
      }
    },
    clear() {
      for (const sessionId of Array.from(sessionIds)) {
        store.delete(sessionId);
      }
      sessionIds.clear();
    },
    get size() {
      return sessionIds.size;
    },
    has(sessionId: string) {
      return store.get(sessionId) !== undefined;
    },
  };
}

/** In-memory session store (short-lived device authorization state). */
const sessions = createInspectableDeviceSessionStore();

function getRequestOrigin(c: Context): string {
  return new URL(c.req.url).origin;
}

function getRequestPath(c: Context): string {
  return new URL(c.req.url).pathname;
}

function resolveOrigin(
  origin: string | (() => string | undefined) | undefined,
): string | undefined {
  return typeof origin === "function" ? origin() : origin;
}

function isLocalhostRequest(remoteAddr: string | undefined): boolean {
  if (!remoteAddr) return false;
  return (
    remoteAddr === "127.0.0.1" ||
    remoteAddr === "::1" ||
    remoteAddr === "localhost" ||
    remoteAddr.startsWith("127.") ||
    remoteAddr === "::ffff:127.0.0.1"
  );
}

function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname === "::1" ||
    hostname === "127.0.0.1" ||
    hostname.startsWith("127.")
  );
}

function isLocalhostOrigin(origin: string): boolean {
  try {
    return isLoopbackHost(new URL(origin).hostname);
  } catch {
    return false;
  }
}

function getSocketRemoteAddress(c: Context): string | undefined {
  // Access Node.js socket via Hono's env bindings when running on the real server.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (c.env as any)?.incoming?.socket?.remoteAddress;
}

function usesLocalApprovalChannel(c: Context, deps: LoginV2Deps): boolean {
  const localApprovalOrigin = resolveOrigin(deps.localApprovalOrigin);
  if (!localApprovalOrigin) {
    return false;
  }

  return getRequestOrigin(c) === localApprovalOrigin;
}

function getApprovalOrigin(c: Context, deps: LoginV2Deps): string {
  const requestOrigin = getRequestOrigin(c);
  const localApprovalOrigin = resolveOrigin(deps.localApprovalOrigin);

  if (localApprovalOrigin && isLocalhostOrigin(requestOrigin)) {
    return localApprovalOrigin;
  }

  return requestOrigin;
}

async function verifyRemoteOwnerApproval(
  c: Context,
  serverOwner: `0x${string}` | undefined,
): Promise<VerifiedAuth | Response> {
  if (!serverOwner) {
    return c.json(
      {
        error: {
          code: 500,
          errorCode: "SERVER_NOT_CONFIGURED",
          message:
            "Server owner address not configured. Set VANA_MASTER_KEY_SIGNATURE environment variable.",
        },
      },
      500,
    );
  }

  const authHeader = c.req.header("authorization");
  if (!authHeader) {
    return c.json(
      {
        error: {
          code: 403,
          message:
            "Remote approval requires owner wallet authentication. " +
            "Connect the server owner wallet and try again.",
        },
      },
      403,
    );
  }

  try {
    const auth = await verifyWeb3Signed({
      headerValue: authHeader,
      expectedOrigin: getRequestOrigin(c),
      expectedMethod: c.req.method,
      expectedPath: getRequestPath(c),
      bodyBytes:
        c.req.method === "GET" || c.req.method === "HEAD"
          ? undefined
          : new Uint8Array(await c.req.raw.clone().arrayBuffer()),
    });

    if (auth.signer.toLowerCase() !== serverOwner.toLowerCase()) {
      const err = new NotOwnerError({
        signer: auth.signer,
        expected: serverOwner,
      });
      return c.json(err.toJSON(), 401);
    }

    return auth;
  } catch (err) {
    const authError = mapSdkAuthError(err);
    if (authError) return c.json(authError.toJSON(), authError.code as 401);
    if (err instanceof ProtocolError) {
      return c.json(err.toJSON(), err.code as 401 | 403);
    }
    throw err;
  }
}

export function authDeviceRoutes(deps: LoginV2Deps): Hono {
  const app = new Hono();
  const allowInteractiveLogin = deps.allowInteractiveLogin !== false;
  const web3Auth = createWeb3AuthMiddleware({
    serverOrigin: deps.serverOrigin,
    devToken: deps.devToken,
    accessToken: deps.accessToken,
    tokenStore: deps.tokenStore,
    serverOwner: deps.serverOwner,
  });
  const ownerCheck = createOwnerCheckMiddleware(deps.serverOwner);

  if (allowInteractiveLogin) {
    // POST /  — Initiate login flow (no auth required)
    app.post("/", (c) => {
      const sessionId = randomBytes(32).toString("hex");
      const pollToken = randomBytes(32).toString("hex");
      const result = initiateDeviceSessionContract({
        sessionStore: sessions,
        serverOwner: deps.serverOwner,
        requestOrigin: getRequestOrigin(c),
        approvalOrigin: getApprovalOrigin(c, deps),
        sessionId,
        pollToken,
        now: Date.now(),
      });

      deps.logger.info({ sessionId }, "Login flow initiated");
      return c.json(result.body, result.status as 200 | 500);
    });

    // GET /poll  — Poll for completion
    app.get("/poll", (c) => {
      const result = pollDeviceSessionContract({
        sessionStore: sessions,
        pollToken: c.req.query("token") ?? null,
        serverOwner: deps.serverOwner,
        now: Date.now(),
      });
      if (result.status === 200) {
        const body = result.body as { server?: string };
        deps.logger.info(
          { server: body.server },
          "Login flow completed — token delivered",
        );
      }
      return c.json(result.body, result.status as 200 | 400 | 404 | 429 | 500);
    });

    // GET /approve  — HTML approval page
    app.get("/approve", (c) => {
      sessions.purgeExpired(Date.now());

      const sessionId = c.req.query("session");
      if (!sessionId) {
        return c.html(errorPage("Missing session parameter"), 400);
      }

      const session = sessions.get(sessionId);
      if (!session) {
        return c.html(errorPage("Session expired or invalid"), 404);
      }

      if (session.status === "approved") {
        return c.html(successPage());
      }

      const owner = deps.serverOwner ?? "unknown";
      const localApprovalShortcutEnabled = usesLocalApprovalChannel(c, deps);

      return c.html(
        approvePage(
          session.requestedServerOrigin,
          owner,
          sessionId,
          localApprovalShortcutEnabled,
        ),
      );
    });

    // POST /approve  — Approve the session
    app.post("/approve", async (c) => {
      sessions.purgeExpired(Date.now());

      const sessionId = c.req.query("session");
      if (!sessionId) {
        return c.json(
          { error: { code: 400, message: "Missing session parameter" } },
          400,
        );
      }

      const session = sessions.get(sessionId);
      if (!session) {
        return c.json(
          { error: { code: 404, message: "Session expired or invalid" } },
          404,
        );
      }

      if (session.status === "approved") {
        return c.json({ status: "already_approved" });
      }

      // v1: localhost auto-approve — user is physically at the server.
      // SECURITY: Use the direct TCP peer address, NOT X-Forwarded-For
      // or X-Real-IP headers which are trivially spoofable by remote attackers.
      const remoteAddr =
        deps.getRemoteAddress?.(c) ?? getSocketRemoteAddress(c);
      const allowLocalShortcut =
        usesLocalApprovalChannel(c, deps) &&
        isLocalhostRequest(remoteAddr as string | undefined);

      if (!allowLocalShortcut) {
        const approvalAuth = await verifyRemoteOwnerApproval(
          c,
          deps.serverOwner,
        );
        if (approvalAuth instanceof Response) {
          deps.logger.warn(
            { remoteAddr, sessionId },
            "Remote approval rejected",
          );
          return approvalAuth;
        }

        deps.logger.info(
          { remoteAddr, sessionId, signer: approvalAuth.signer },
          "Remote approval authenticated with owner wallet",
        );
      }

      const accessToken = `vana_ps_${randomBytes(32).toString("hex")}`;
      const result = await approveDeviceSessionContract({
        sessionStore: sessions,
        tokenStore: deps.tokenStore,
        sessionId,
        serverOwner: deps.serverOwner,
        accessToken,
        now: Date.now(),
      });

      deps.logger.info({ sessionId }, "Login flow approved — token generated");
      return c.json(result.body, result.status as 200 | 400 | 404 | 500);
    });
  }

  // POST /token — add a CLI token to the store (control-plane authenticated)
  app.post("/token", web3Auth, ownerCheck, async (c) => {
    if (c.get("authMechanism") !== "control-plane-token") {
      return c.json(
        {
          error: {
            code: 403,
            message:
              "Only control-plane tokens can provision Personal Server session tokens",
          },
        },
        403,
      );
    }

    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json(
        { error: { code: 400, message: "Request body must be valid JSON" } },
        400,
      );
    }

    const result = await provisionDeviceTokenContract({
      tokenStore: deps.tokenStore,
      body,
      now: Date.now(),
    });
    if (result.status !== 201) {
      return c.json(result.body, result.status as 400);
    }
    deps.logger.info("CLI token added via POST /token");
    return c.json(result.body, 201);
  });

  // ── Token revocation ──────────────────────────────────────────────
  // Called by `vana logout` to invalidate the token server-side.

  app.delete("/token", async (c) => {
    const authHeader = c.req.header("authorization");
    const result = await revokeDeviceTokenContract({
      tokenStore: deps.tokenStore,
      bearerToken: authHeader?.startsWith("Bearer ")
        ? authHeader.slice(7)
        : null,
    });
    if (result.status !== 200) {
      return c.json(result.body, result.status as 401);
    }
    deps.logger.info("Token revoked via DELETE /token");
    return c.json(result.body);
  });

  return app;
}

// ── HTML pages ──────────────────────────────────────────────────────

function approvePage(
  origin: string,
  owner: string,
  sessionId: string,
  localApprovalShortcutEnabled: boolean,
): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorize CLI — Personal Server</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f5f5f5; color: #1a1a1a;
      display: flex; justify-content: center; align-items: center;
      min-height: 100vh; padding: 1rem;
    }
    .card {
      background: #fff; border-radius: 12px; padding: 2rem;
      max-width: 420px; width: 100%;
      box-shadow: 0 2px 8px rgba(0,0,0,.08);
    }
    h1 { font-size: 1.25rem; margin-bottom: 1.5rem; }
    .info { background: #f8f9fa; border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem; font-size: 0.875rem; }
    .info dt { color: #666; margin-bottom: 0.25rem; }
    .info dd { font-family: monospace; word-break: break-all; margin-bottom: 0.75rem; }
    .info dd:last-child { margin-bottom: 0; }
    .btn {
      display: block; width: 100%; padding: 0.75rem 1.5rem;
      background: #2563eb; color: #fff; border: none; border-radius: 8px;
      font-size: 1rem; font-weight: 500; cursor: pointer;
      transition: background 0.15s;
    }
    .btn:hover { background: #1d4ed8; }
    .btn:disabled { background: #94a3b8; cursor: not-allowed; }
    #status { text-align: center; margin-top: 1rem; font-size: 0.875rem; color: #666; }
    .hint { margin-top: 1rem; font-size: 0.875rem; color: #666; line-height: 1.5; }
  </style>
</head>
<body>
  <div class="card">
    <h1>A CLI tool is requesting access to your Personal Server</h1>
    <dl class="info">
      <dt>Server</dt>
      <dd>${escapeHtml(origin)}</dd>
      <dt>Owner</dt>
      <dd>${escapeHtml(owner)}</dd>
    </dl>
    <button class="btn" id="approveBtn" onclick="approve()">Approve</button>
    <div id="status"></div>
    <p class="hint" id="hint"></p>
  </div>
  <script>
    const SESSION_ID = ${JSON.stringify(sessionId)};
    const OWNER_ADDRESS = ${JSON.stringify(owner)};
    const LOCAL_APPROVAL_SHORTCUT_ENABLED = ${JSON.stringify(localApprovalShortcutEnabled)};
    const EMPTY_BODY_SHA256 =
      "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    function base64urlEncodeUtf8(input) {
      const bytes = new TextEncoder().encode(input);
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      return btoa(binary).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
    }

    function utf8ToHex(input) {
      const bytes = new TextEncoder().encode(input);
      return (
        "0x" +
        Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")
      );
    }

    async function signPersonalMessage(message, address) {
      const hexMessage = utf8ToHex(message);
      try {
        return await window.ethereum.request({
          method: "personal_sign",
          params: [hexMessage, address],
        });
      } catch (err) {
        return window.ethereum.request({
          method: "personal_sign",
          params: [address, hexMessage],
        });
      }
    }

    async function buildRemoteApprovalHeader() {
      if (!window.ethereum) {
        throw new Error("No wallet found in this browser. Open this page in a wallet-enabled browser.");
      }

      const accounts = await window.ethereum.request({
        method: "eth_requestAccounts",
      });
      const signer = accounts && accounts[0];
      if (!signer) {
        throw new Error("No wallet account available.");
      }
      if (signer.toLowerCase() !== OWNER_ADDRESS.toLowerCase()) {
        throw new Error(
          "Connected wallet does not match the Personal Server owner."
        );
      }

      const now = Math.floor(Date.now() / 1000);
      const payload = {
        aud: window.location.origin,
        bodyHash: EMPTY_BODY_SHA256,
        exp: now + 300,
        iat: now,
        method: "POST",
        uri: window.location.pathname,
      };
      const orderedPayload = {};
      for (const key of Object.keys(payload).sort()) {
        orderedPayload[key] = payload[key];
      }
      const payloadBase64 = base64urlEncodeUtf8(JSON.stringify(orderedPayload));
      const signature = await signPersonalMessage(payloadBase64, signer);
      return "Web3Signed " + payloadBase64 + "." + signature;
    }

    const remoteApproval = !LOCAL_APPROVAL_SHORTCUT_ENABLED;
    const btn = document.getElementById("approveBtn");
    const status = document.getElementById("status");
    const hint = document.getElementById("hint");

    if (remoteApproval) {
      btn.textContent = "Connect wallet and approve";
      hint.textContent =
        "Remote approvals require a signature from the Personal Server owner wallet.";
    } else {
      hint.textContent =
        "This browser is on the same machine as the Personal Server, so approval stays local.";
    }

    async function approve() {
      btn.disabled = true;
      btn.textContent = remoteApproval ? 'Signing...' : 'Authorizing...';
      status.textContent = "";
      try {
        const headers = {};
        if (remoteApproval) {
          headers["Authorization"] = await buildRemoteApprovalHeader();
          btn.textContent = 'Authorizing...';
        }

        const res = await fetch('/auth/device/approve?session=' + encodeURIComponent(SESSION_ID), {
          method: 'POST',
          headers,
        });
        if (res.ok) {
          document.querySelector('.card').innerHTML =
            '<h1 style="color:#16a34a">Device authorized!</h1>' +
            '<p style="margin-top:1rem;color:#666">You can close this tab.</p>';
        } else {
          const data = await res.json();
          status.textContent = data.error?.message || 'Authorization failed';
          status.style.color = '#dc2626';
          btn.disabled = false;
          btn.textContent = 'Approve';
        }
      } catch (err) {
        status.textContent = 'Network error — please try again';
        status.style.color = '#dc2626';
        btn.disabled = false;
        btn.textContent = 'Approve';
      }
    }
  </script>
</body>
</html>`;
}

function successPage(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorized — Personal Server</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f5f5f5; color: #1a1a1a;
      display: flex; justify-content: center; align-items: center;
      min-height: 100vh;
    }
    .card {
      background: #fff; border-radius: 12px; padding: 2rem;
      max-width: 420px; text-align: center;
      box-shadow: 0 2px 8px rgba(0,0,0,.08);
    }
    h1 { color: #16a34a; font-size: 1.25rem; }
    p { margin-top: 1rem; color: #666; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Device authorized!</h1>
    <p>You can close this tab.</p>
  </div>
</body>
</html>`;
}

function errorPage(message: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Error — Personal Server</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f5f5f5; color: #1a1a1a;
      display: flex; justify-content: center; align-items: center;
      min-height: 100vh;
    }
    .card {
      background: #fff; border-radius: 12px; padding: 2rem;
      max-width: 420px; text-align: center;
      box-shadow: 0 2px 8px rgba(0,0,0,.08);
    }
    h1 { color: #dc2626; font-size: 1.25rem; }
    p { margin-top: 1rem; color: #666; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Error</h1>
    <p>${escapeHtml(message)}</p>
  </div>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Export for testing
export {
  sessions,
  DEVICE_SESSION_TTL_MS as SESSION_TTL_MS,
  DEVICE_POLL_INTERVAL_MS as POLL_INTERVAL_MS,
};

/**
 * Read-only adapter exposing the device-flow session map to the standard
 * RFC 8628 token endpoint (`POST /oauth/token` with
 * `grant_type=urn:ietf:params:oauth:grant-type:device_code`). The
 * `pollToken` issued at `POST /auth/device` is the OAuth2 `device_code`.
 */
export function createDeviceSessionLookup() {
  return {
    findByDeviceCode(deviceCode: string) {
      sessions.purgeExpired(Date.now());
      const session = sessions.findByPollToken(deviceCode);
      if (!session) return null;
      return {
        status: session.status,
        accessToken: session.accessToken,
        accessTokenExpiresAt: session.accessTokenExpiresAt,
        sessionId: session.sessionId,
      };
    },
    consume(sessionId: string) {
      sessions.delete(sessionId);
    },
  };
}
