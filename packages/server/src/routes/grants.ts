/**
 * Grants routes — GET / (owner), POST / (create grant), POST /verify (public).
 */

import { Hono, type Context } from "hono";
import type { Logger } from "pino";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import {
  createGrantContract,
  listGrantsContract,
  verifyGrantContract,
  type ContractResult,
} from "@opendatalabs/personal-server-ts-core/contracts";
import type { ServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import type { TokenStore } from "../token-store.js";
import { createWeb3AuthMiddleware } from "../middleware/web3-auth.js";
import { createOwnerCheckMiddleware } from "../middleware/owner-check.js";

export interface GrantsRouteDeps {
  logger: Logger;
  gateway: GatewayClient;
  serverOwner?: `0x${string}`;
  serverOrigin: string | (() => string);
  devToken?: string;
  tokenStore?: TokenStore;
  serverSigner?: ServerSigner;
}

function sendResult(c: Context, result: ContractResult) {
  return c.json(result.body, result.status as 200 | 201 | 400 | 404 | 500);
}

export function grantsRoutes(deps: GrantsRouteDeps): Hono {
  const app = new Hono();

  const web3Auth = createWeb3AuthMiddleware({
    serverOrigin: deps.serverOrigin,
    devToken: deps.devToken,
    tokenStore: deps.tokenStore,
    serverOwner: deps.serverOwner,
  });
  const ownerCheck = createOwnerCheckMiddleware(deps.serverOwner);

  // GET / — list all grants for the server owner (owner auth required)
  app.get("/", web3Auth, ownerCheck, async (c) => {
    return sendResult(
      c,
      await listGrantsContract({
        gateway: deps.gateway,
        serverOwner: deps.serverOwner,
      }),
    );
  });

  // POST / — create a grant (owner-only, called by Desktop App)
  app.post("/", web3Auth, ownerCheck, async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json(
        { error: "INVALID_BODY", message: "Invalid JSON body" },
        400,
      );
    }

    return sendResult(
      c,
      await createGrantContract({
        gateway: deps.gateway,
        serverOwner: deps.serverOwner,
        serverSigner: deps.serverSigner,
        body,
      }),
    );
  });

  // POST /verify — public endpoint, no auth required
  app.post("/verify", async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json(
        { error: "INVALID_BODY", message: "Invalid JSON body" },
        400,
      );
    }

    return sendResult(c, await verifyGrantContract(body));
  });

  return app;
}
