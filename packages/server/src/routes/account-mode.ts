/**
 * Account-mode evidence from a host (the Account's answer, per owner).
 *
 *   POST /v1/account-mode/evidence
 *     body {owner, state: "on"|"off"|"unknown", fetchStartedAt, rawStatus}
 *     -> 200 {decision: "streams"|"legacy"|"refuse", importRequired, code?, status?}
 *
 * Only the owner may call it. The authenticated owner is this server's owner;
 * a body that names any other owner changes no state and answers a refusal.
 * A host that has no answer posts `state: "unknown"`, which changes nothing and
 * returns the decision, so it doubles as a read.
 *
 * The HTTP status is 200 whenever the body was understood, even when the
 * decision is a refusal: the refusal is the answer, not a failure of the
 * request. `importRequired` is true once, on the answer that latches On for an
 * owner whose legacy store holds data.
 */

import { Hono } from "hono";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import {
  decisionBody,
  parseEvidenceBody,
  type ModeAuthority,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import type { TokenStore } from "../token-store.js";
import { createServerApiAuth } from "../api-auth.js";

export interface AccountModeRouteDeps {
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  gateway: GatewayClient;
  devToken?: string;
  accessToken?: string;
  tokenStore?: TokenStore;
  accountModeAuthority: ModeAuthority;
}

export function accountModeRoutes(deps: AccountModeRouteDeps): Hono {
  const app = new Hono();
  const auth = createServerApiAuth({
    serverOrigin: deps.serverOrigin,
    serverOwner: deps.serverOwner,
    gateway: deps.gateway,
    devToken: deps.devToken,
    accessToken: deps.accessToken,
    tokenStore: deps.tokenStore,
  });

  app.post("/evidence", async (c) => {
    await auth.authorizeOwner(c.req.raw);
    const body = parseEvidenceBody(await c.req.json().catch(() => null));
    if (!body) {
      throw new ProtocolError(
        400,
        "INVALID_ACCOUNT_MODE_EVIDENCE",
        "Body must be {owner, state, fetchStartedAt, rawStatus}",
      );
    }
    // authorizeOwner succeeded, so the caller is this server's owner.
    const decision = await deps.accountModeAuthority.submitEvidence({
      ...body,
      authOwner: deps.serverOwner ?? "",
    });
    return c.json(decisionBody(decision));
  });

  return app;
}
