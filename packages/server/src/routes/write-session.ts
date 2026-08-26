/**
 * Write API session route — POST /v1/write/session.
 *
 * The builder proves control of its key + write-grant with a Web3Signed proof
 * (same handshake shape as the self-signing MCP session, routes/mcp.ts) and
 * gets a short-lived bearer token. The token then gates delegated writes on
 * the EXISTING ingest endpoint (POST /v1/data/:scope) — see api-auth.ts
 * authorizeWrite. The PS keeps signing AddData as the owner; the builder
 * never holds the owner key.
 */

import { createHash, randomBytes } from "node:crypto";
import { Hono } from "hono";
import type { Logger } from "pino";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { authenticateRequest } from "@opendatalabs/personal-server-ts-core/auth";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import {
  createInMemoryWriteProofReplayStore,
  createWriteSession,
  type WriteProofReplayStore,
  type WriteSessionStore,
} from "@opendatalabs/personal-server-ts-core/write";
import type { TokenStore } from "../token-store.js";

export interface WriteSessionRouteDeps {
  logger: Logger;
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  gateway: GatewayClient;
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore;
  /**
   * Session store shared with the data routes (api-auth authorizeWrite reads
   * the tokens this route mints). The caller wires ONE store into both.
   */
  sessionStore: WriteSessionStore;
  /** Defaults to a per-route in-memory replay guard. */
  proofReplayStore?: WriteProofReplayStore;
}

function jsonError(status: number, errorCode: string, message: string) {
  return {
    error: { code: status, errorCode, message },
  };
}

/**
 * Only ProtocolErrors are client-facing. Anything else (gateway, store,
 * runtime failures) is logged with its cause and answered generically so
 * internal details never reach the caller. Same mapping as the core data
 * handler.
 */
function internalError(logger: Logger, err: unknown, stage: string) {
  logger.error(
    { err, stage },
    "Write session handshake failed with an unexpected error",
  );
  return jsonError(500, "INTERNAL_ERROR", "Internal server error");
}

export function writeSessionRoutes(deps: WriteSessionRouteDeps): Hono {
  const app = new Hono();
  const proofReplayStore =
    deps.proofReplayStore ?? createInMemoryWriteProofReplayStore();

  app.post("/session", async (c) => {
    // Fail closed: minting a session requires this server's owner to bind
    // the grant to (createWriteSession rejects wrong-owner grants).
    if (!deps.serverOwner) {
      return c.json(
        jsonError(
          500,
          "SERVER_NOT_CONFIGURED",
          "Server owner is not configured",
        ),
        500,
      );
    }
    let authResult;
    try {
      authResult = await authenticateRequest({
        request: c.req.raw,
        serverOrigin: deps.serverOrigin,
        devToken: deps.devToken,
        accessToken: deps.accessToken,
        sessionTokenVerifier: deps.tokenStore,
        serverOwner: deps.serverOwner,
      });
    } catch (err) {
      if (!(err instanceof ProtocolError)) {
        return c.json(internalError(deps.logger, err, "authenticate"), 500);
      }
      return c.json(
        jsonError(401, "WRITE_SESSION_AUTH_FAILED", err.message),
        401,
      );
    }
    if (authResult.mechanism !== "web3-signed") {
      return c.json(
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
      return c.json(
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
    const proofHeader = c.req.raw.headers.get("authorization") ?? "";
    const proofId = createHash("sha256").update(proofHeader).digest("hex");
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
          authSessionVerifier: deps.gateway,
          grantVerifier: deps.gateway,
          serverOwner: deps.serverOwner,
          randomToken: () => `vana_write_${randomBytes(32).toString("hex")}`,
          replayStore: proofReplayStore,
        },
      );
      deps.logger.info(
        {
          builder: authResult.auth.signer,
          grantId: session.grantId,
          writeScopes: session.writeScopes,
        },
        "Write session minted",
      );
      return c.json({
        access_token: session.accessToken,
        token_type: "Bearer",
        expires_in: session.expiresInSeconds,
        // Write patterns, prefix stripped — what POST /v1/data/:scope will
        // accept under this token.
        scope: session.writeScopes.join(" "),
      });
    } catch (err) {
      if (err instanceof ProtocolError) {
        return c.json(err.toJSON(), err.code as 400 | 401 | 403 | 404);
      }
      return c.json(internalError(deps.logger, err, "create-session"), 500);
    }
  });

  return app;
}
