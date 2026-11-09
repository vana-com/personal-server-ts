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
 * request. `importRequired` is true on every answer for an owner whose first
 * On was saved with legacy data present, until the host reports the import
 * done.
 *
 *   POST /v1/account-mode/import-done
 *     body {owner}
 *     -> 200 {decision, importRequired, code?, status?}
 *
 * The host calls it once it has imported its legacy data into streams. The
 * module saves the clean record before it opens stream writes (which are
 * refused with 503 IMPORT_PENDING until then). Idempotent: for an owner with
 * no pending import it changes nothing.
 */

import { Hono } from "hono";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import {
  decisionBody,
  normalizeOwner,
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

  app.post("/import-done", async (c) => {
    await auth.authorizeOwner(c.req.raw);
    const body = (await c.req.json().catch(() => null)) as {
      owner?: unknown;
    } | null;
    if (!body || typeof body.owner !== "string") {
      throw new ProtocolError(
        400,
        "INVALID_ACCOUNT_MODE_IMPORT_DONE",
        "Body must be {owner}",
      );
    }
    // The caller is this server's owner; another owner's import is not theirs
    // to report, and changes nothing.
    const decision =
      normalizeOwner(body.owner) === normalizeOwner(deps.serverOwner)
        ? await deps.accountModeAuthority.importDone(body.owner)
        : deps.accountModeAuthority.read(body.owner);
    return c.json(decisionBody(decision));
  });

  return app;
}
