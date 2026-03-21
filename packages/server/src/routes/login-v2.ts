/**
 * Login Flow v2 — Nextcloud-style device login for self-hosted CLI authentication.
 *
 * POST /login/v2         — Initiate a login session
 * GET  /login/v2/poll    — Poll for completion (token= query param)
 * GET  /login/v2/approve — HTML approval page (session= query param)
 * POST /login/v2/approve — Approve the session (session= query param)
 */

import { randomBytes } from "node:crypto";
import { Hono } from "hono";
import type { Logger } from "pino";
import type { TokenStore } from "../token-store.js";

export interface LoginV2Deps {
  logger: Logger;
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  tokenStore: TokenStore;
}

interface LoginSession {
  sessionId: string;
  pollToken: string;
  status: "pending" | "approved" | "expired";
  accessToken?: string;
  createdAt: number;
  lastPollAt: number;
}

const SESSION_TTL_MS = 5 * 60 * 1000; // 5 minutes
const POLL_INTERVAL_MS = 5 * 1000; // 5 seconds minimum between polls

/** In-memory session store (short-lived, no persistence needed). */
const sessions = new Map<string, LoginSession>();

/** Look up session by poll token. */
function findByPollToken(token: string): LoginSession | undefined {
  for (const session of sessions.values()) {
    if (session.pollToken === token) return session;
  }
  return undefined;
}

/** Purge expired sessions. */
function purgeExpired(): void {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (now - session.createdAt > SESSION_TTL_MS) {
      sessions.delete(id);
    }
  }
}

function resolveOrigin(origin: string | (() => string)): string {
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

export function loginV2Routes(deps: LoginV2Deps): Hono {
  const app = new Hono();

  // POST /  — Initiate login flow (no auth required)
  app.post("/", (c) => {
    purgeExpired();

    const sessionId = randomBytes(32).toString("hex");
    const pollToken = randomBytes(32).toString("hex");
    const origin = resolveOrigin(deps.serverOrigin);

    const session: LoginSession = {
      sessionId,
      pollToken,
      status: "pending",
      createdAt: Date.now(),
      lastPollAt: 0,
    };
    sessions.set(sessionId, session);

    deps.logger.info({ sessionId }, "Login flow initiated");

    return c.json({
      login: `${origin}/login/v2/approve?session=${sessionId}`,
      poll: {
        endpoint: "/login/v2/poll",
        token: pollToken,
      },
    });
  });

  // GET /poll  — Poll for completion
  app.get("/poll", (c) => {
    purgeExpired();

    const token = c.req.query("token");
    if (!token) {
      return c.json(
        { error: { code: 400, message: "Missing token parameter" } },
        400,
      );
    }

    const session = findByPollToken(token);

    if (!session) {
      return c.json({ status: "expired" }, 404);
    }

    // Check if session has expired
    if (Date.now() - session.createdAt > SESSION_TTL_MS) {
      sessions.delete(session.sessionId);
      return c.json({ status: "expired" }, 404);
    }

    // Rate limit polling
    const now = Date.now();
    if (now - session.lastPollAt < POLL_INTERVAL_MS) {
      return c.json(
        {
          error: {
            code: 429,
            message: `Too many requests. Poll every ${POLL_INTERVAL_MS / 1000} seconds.`,
          },
        },
        429,
      );
    }
    session.lastPollAt = now;

    if (session.status === "pending") {
      return c.json({ status: "pending" }, 404);
    }

    if (session.status === "approved" && session.accessToken) {
      const origin = resolveOrigin(deps.serverOrigin);

      // Return token once, then delete session
      const response = {
        status: "authorized",
        server: origin,
        access_token: session.accessToken,
      };
      sessions.delete(session.sessionId);

      deps.logger.info(
        { sessionId: session.sessionId },
        "Login flow completed — token delivered",
      );

      return c.json(response, 200);
    }

    // Shouldn't reach here, but just in case
    return c.json({ status: "pending" }, 404);
  });

  // GET /approve  — HTML approval page
  app.get("/approve", (c) => {
    purgeExpired();

    const sessionId = c.req.query("session");
    if (!sessionId) {
      return c.html(errorPage("Missing session parameter"), 400);
    }

    const session = sessions.get(sessionId);
    if (!session) {
      return c.html(errorPage("Session expired or invalid"), 404);
    }

    if (Date.now() - session.createdAt > SESSION_TTL_MS) {
      sessions.delete(sessionId);
      return c.html(errorPage("Session expired"), 410);
    }

    if (session.status === "approved") {
      return c.html(successPage());
    }

    const origin = resolveOrigin(deps.serverOrigin);
    const owner = deps.serverOwner ?? "unknown";

    return c.html(approvePage(origin, owner, sessionId));
  });

  // POST /approve  — Approve the session
  app.post("/approve", async (c) => {
    purgeExpired();

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

    if (Date.now() - session.createdAt > SESSION_TTL_MS) {
      sessions.delete(sessionId);
      return c.json({ error: { code: 410, message: "Session expired" } }, 410);
    }

    if (session.status === "approved") {
      return c.json({ status: "already_approved" });
    }

    // v1: localhost auto-approve — user is physically at the server.
    // SECURITY: Use the direct TCP peer address, NOT X-Forwarded-For
    // or X-Real-IP headers which are trivially spoofable by remote attackers.
    // Access Node.js socket via Hono's env bindings.
    const remoteAddr: string | undefined =
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (c.env as any)?.incoming?.socket?.remoteAddress;

    if (!isLocalhostRequest(remoteAddr as string | undefined)) {
      deps.logger.warn(
        { remoteAddr, sessionId },
        "Non-localhost approve attempt rejected",
      );
      return c.json(
        {
          error: {
            code: 403,
            message:
              "Remote approval requires wallet authentication (not implemented in v1). " +
              "Please approve from the same machine running the Personal Server.",
          },
        },
        403,
      );
    }

    // Generate a new access token
    const accessToken = `vana_ps_${randomBytes(32).toString("hex")}`;

    // Store the token persistently
    await deps.tokenStore.addToken(accessToken);

    // Mark session as approved
    session.status = "approved";
    session.accessToken = accessToken;

    deps.logger.info({ sessionId }, "Login flow approved — token generated");

    return c.json({ status: "approved" });
  });

  // ── Token revocation ──────────────────────────────────────────────
  // Called by `vana logout` to invalidate the token server-side.

  app.delete("/token", async (c) => {
    const authHeader = c.req.header("authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return c.json(
        { error: { code: 401, message: "Missing Bearer token" } },
        401,
      );
    }

    const token = authHeader.slice(7);
    await deps.tokenStore.removeToken(token);

    deps.logger.info("Token revoked via DELETE /token");
    return c.json({ status: "revoked" }); // idempotent — no error if token doesn't exist
  });

  return app;
}

// ── HTML pages ──────────────────────────────────────────────────────

function approvePage(origin: string, owner: string, sessionId: string): string {
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
  </div>
  <script>
    async function approve() {
      const btn = document.getElementById('approveBtn');
      const status = document.getElementById('status');
      btn.disabled = true;
      btn.textContent = 'Authorizing...';
      try {
        const res = await fetch('/login/v2/approve?session=${escapeHtml(sessionId)}', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
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
export { sessions, SESSION_TTL_MS, POLL_INTERVAL_MS };
