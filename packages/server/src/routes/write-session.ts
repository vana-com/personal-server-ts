/**
 * Write API session route — POST /v1/write/session.
 *
 * The builder proves control of its key + write-grant with a Web3Signed proof
 * (same handshake shape as the self-signing MCP session, routes/mcp.ts) and
 * gets a short-lived bearer token. The token then gates delegated writes on
 * the EXISTING ingest endpoint (POST /v1/data/:scope) — see api-auth.ts
 * authorizeWrite. The PS keeps signing AddData as the owner; the builder
 * never holds the owner key.
 *
 * The handshake itself is runtime-agnostic and lives in core
 * (write/route.ts), so the browser build mounts the identical logic. This file
 * is only the Hono mounting and this build's dependency wiring.
 */

import { Hono } from "hono";
import type { Logger } from "pino";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import {
  createInMemoryWriteProofReplayStore,
  handleWriteSessionRequest,
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

export function writeSessionRoutes(deps: WriteSessionRouteDeps): Hono {
  const app = new Hono();
  const proofReplayStore =
    deps.proofReplayStore ?? createInMemoryWriteProofReplayStore();

  app.post("/session", (c) =>
    handleWriteSessionRequest(c.req.raw, {
      serverOrigin: deps.serverOrigin,
      serverOwner: deps.serverOwner,
      sessionStore: deps.sessionStore,
      replayStore: proofReplayStore,
      authSessionVerifier: deps.gateway,
      grantVerifier: deps.gateway,
      devToken: deps.devToken,
      accessToken: deps.accessToken,
      tokenStore: deps.tokenStore,
      logger: deps.logger,
    }),
  );

  return app;
}
