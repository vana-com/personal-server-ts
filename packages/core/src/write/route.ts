/**
 * The write-session handshake, as a runtime-agnostic request handler.
 *
 * `POST /v1/write/session`: a registered builder proves control of its key and
 * of a write-grant with a Web3Signed proof (the same handshake shape as the
 * self-signing MCP session) and gets a short-lived bearer token. That token
 * then gates delegated writes on the EXISTING ingest endpoint
 * (`POST /v1/data/:scope`) and the derivative question routes. The Personal
 * Server keeps signing AddData as the owner; the builder never holds the owner
 * key.
 *
 * This lived in the Node server as a Hono route (packages/server/src/routes/
 * write-session.ts) and reached for `node:crypto` for two things: a sha-256 of
 * the proof header, and 32 random bytes for the token. Both have Web Crypto
 * equivalents, so the handshake is expressed here over plain `Request` /
 * `Response` and BOTH builds mount the same handler — the Node route is a Hono
 * wrapper around it, and the browser runtime dispatches to it directly. There
 * is one implementation of who may open a write session.
 */

import { authenticateRequest } from "../auth/index.js";
import type { SessionTokenVerifierPort } from "../auth/index.js";
import { ProtocolError } from "../errors/catalog.js";
import { hashConnectionToken } from "../mcp/connection-api.js";
import type {
  AuthSessionVerifierPort,
  GrantVerifierPort,
} from "../ports/index.js";
import {
  createWriteSession,
  type WriteProofReplayStore,
  type WriteSessionStore,
} from "./session.js";

export interface WriteSessionRouteLogger {
  info?(payload: Record<string, unknown>, message: string): void;
  error?(payload: Record<string, unknown>, message: string): void;
}

export interface HandleWriteSessionRequestDeps {
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  /**
   * The store the redeeming routes read from. One store is wired into the
   * handshake and into the API auth adapter; see createApp / the PS-Lite
   * runtime.
   */
  sessionStore: WriteSessionStore;
  /** Replay guard for the HANDSHAKE proof (distinct from per-write proofs). */
  replayStore?: WriteProofReplayStore;
  authSessionVerifier: AuthSessionVerifierPort;
  grantVerifier: GrantVerifierPort;
  devToken?: string;
  accessToken?: string;
  tokenStore?: SessionTokenVerifierPort;
  /** Overridable for tests; defaults to `vana_write_` + 32 random bytes. */
  randomToken?: () => string;
  ttlMs?: number;
  now?: () => number;
  logger?: WriteSessionRouteLogger;
}

export interface WriteSessionResponseBody {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  /** Write patterns, `write:` prefix stripped. */
  scope: string;
}

function jsonError(status: number, errorCode: string, message: string) {
  return { error: { code: status, errorCode, message } };
}

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/**
 * Only ProtocolErrors are client-facing. Anything else (gateway, store,
 * runtime failures) is logged with its cause and answered generically so
 * internal details never reach the caller. Same mapping as the core data
 * handler.
 */
function internalError(
  logger: WriteSessionRouteLogger | undefined,
  err: unknown,
  stage: string,
): Response {
  logger?.error?.(
    { err, stage },
    "Write session handshake failed with an unexpected error",
  );
  return jsonResponse(
    jsonError(500, "INTERNAL_ERROR", "Internal server error"),
    500,
  );
}

function defaultRandomToken(): string {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  return `vana_write_${hex}`;
}

/**
 * Handle one `POST /v1/write/session` request. The caller has already matched
 * the method and path; anything reaching here is treated as the handshake.
 */
export async function handleWriteSessionRequest(
  request: Request,
  deps: HandleWriteSessionRequestDeps,
): Promise<Response> {
  // Fail closed: minting a session requires this server's owner to bind the
  // grant to (createWriteSession rejects wrong-owner grants).
  if (!deps.serverOwner) {
    return jsonResponse(
      jsonError(500, "SERVER_NOT_CONFIGURED", "Server owner is not configured"),
      500,
    );
  }

  let authResult;
  try {
    authResult = await authenticateRequest({
      request,
      serverOrigin: deps.serverOrigin,
      devToken: deps.devToken,
      accessToken: deps.accessToken,
      sessionTokenVerifier: deps.tokenStore,
      serverOwner: deps.serverOwner,
    });
  } catch (err) {
    if (!(err instanceof ProtocolError)) {
      return internalError(deps.logger, err, "authenticate");
    }
    return jsonResponse(
      jsonError(401, "WRITE_SESSION_AUTH_FAILED", err.message),
      401,
    );
  }

  // A bearer credential (dev token, control-plane token, CLI session) proves
  // nothing about the builder's key, so it can never open a write session.
  if (authResult.mechanism !== "web3-signed") {
    return jsonResponse(
      jsonError(
        401,
        "WRITE_SESSION_PROOF_REQUIRED",
        "POST /v1/write/session requires a Web3Signed proof signed by the builder key",
      ),
      401,
    );
  }

  const grantId = authResult.auth.payload.grantId;
  if (!grantId) {
    return jsonResponse(
      jsonError(
        400,
        "GRANT_ID_REQUIRED",
        "The Web3Signed proof must carry a grantId (the write-grant issued to the builder)",
      ),
      400,
    );
  }

  // Replay guard: bind to a digest of the exact proof header, remembered
  // until the proof's own expiry (a replay only matters while still valid).
  const proofHeader = request.headers.get("authorization") ?? "";
  const proofId = await hashConnectionToken(proofHeader);
  const expSec = authResult.auth.payload.exp;
  const expiresAtMs =
    (typeof expSec === "number"
      ? expSec
      : Math.floor(Date.now() / 1000) + 300) * 1000;

  try {
    const session = await createWriteSession(
      {
        builderAddress: authResult.auth.signer,
        grantId,
        proof: { id: proofId, expiresAtMs },
      },
      {
        store: deps.sessionStore,
        authSessionVerifier: deps.authSessionVerifier,
        grantVerifier: deps.grantVerifier,
        serverOwner: deps.serverOwner,
        randomToken: deps.randomToken ?? defaultRandomToken,
        ...(deps.ttlMs === undefined ? {} : { ttlMs: deps.ttlMs }),
        ...(deps.now === undefined ? {} : { now: deps.now }),
        ...(deps.replayStore === undefined
          ? {}
          : { replayStore: deps.replayStore }),
      },
    );
    deps.logger?.info?.(
      {
        builder: authResult.auth.signer,
        grantId: session.grantId,
        writeScopes: session.writeScopes,
      },
      "Write session minted",
    );
    const body: WriteSessionResponseBody = {
      access_token: session.accessToken,
      token_type: "Bearer",
      expires_in: session.expiresInSeconds,
      // Write patterns, prefix stripped — what POST /v1/data/:scope will
      // accept under this token.
      scope: session.writeScopes.join(" "),
    };
    return jsonResponse(body, 200);
  } catch (err) {
    if (err instanceof ProtocolError) {
      return jsonResponse(err.toJSON(), err.code);
    }
    return internalError(deps.logger, err, "create-session");
  }
}
