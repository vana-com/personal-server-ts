/**
 * Account-mode evidence from a host (the Account's answer, per owner).
 *
 *   POST /v1/account-mode/evidence
 *     body {owner, state: "on"|"off"|"unknown", generation?}
 *     -> 200 {decision: "streams"|"legacy"}
 *     -> 503 | 426 {decision: "refuse", code, status}
 *
 * Only the owner may call it, and only about the owner: a body that names any
 * other owner is answered 403 before the module is asked anything. A host that
 * has no answer posts `state: "unknown"`, which changes nothing and returns the
 * decision, so it doubles as a read. Fields the first hosts also send
 * (fetchStartedAt, rawStatus) are ignored. The HTTP status is the decision's
 * own: 200 for streams and legacy, and 503 (retryable, `Retry-After: 5`)
 * before the owner's first answer.
 *
 * POST only (405 otherwise, with `Allow: POST`), a body of at most 16 KiB
 * (413 above it), and a flat JSON object of at most 8 plain values (400
 * otherwise).
 */

import { Hono, type Context } from "hono";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import {
  decisionBody,
  normalizeOwner,
  parseEvidenceBody,
  type ModeAuthority,
  type ModeDecision,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import type { TokenStore } from "../token-store.js";
import { createServerApiAuth } from "../api-auth.js";
import { createBodyLimit } from "../middleware/body-limit.js";

/** A real body is under 200 bytes; this is the ceiling, not the norm. */
const MAX_BODY_BYTES = 16 * 1024;
/** More than a few plain fields is not an evidence or import-done body. */
const MAX_BODY_KEYS = 8;
/** An address is 42 characters; the record store allows 100. */
const MAX_OWNER_LENGTH = 100;
/** Seconds a client waits before it asks again after a 503. */
const RETRY_AFTER_SECONDS = "5";

/**
 * A JSON object whose values are all strings, numbers, booleans or null, with
 * a bounded number of keys. Nothing nested is ever walked.
 */
function flatBody(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const entries = Object.entries(value);
  if (entries.length > MAX_BODY_KEYS) return null;
  for (const [, v] of entries) {
    if (v !== null && typeof v === "object") return null;
  }
  return value as Record<string, unknown>;
}

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

  /** Answer with the decision's own HTTP status. */
  function answer(c: Context, decision: ModeDecision): Response {
    if (decision.kind !== "refuse") return c.json(decisionBody(decision), 200);
    if (decision.status === 503) c.header("Retry-After", RETRY_AFTER_SECONDS);
    return c.json(decisionBody(decision), decision.status);
  }

  /**
   * The body's owner, which must be this server's owner. Any other value is
   * refused before the module is asked about it.
   */
  function boundOwner(owner: unknown): string {
    if (typeof owner !== "string" || owner.length > MAX_OWNER_LENGTH) {
      throw new ProtocolError(
        400,
        "INVALID_ACCOUNT_MODE_OWNER",
        "Body owner must be a string of at most 100 characters",
      );
    }
    if (
      !deps.serverOwner ||
      normalizeOwner(owner) !== normalizeOwner(deps.serverOwner)
    ) {
      throw new ProtocolError(
        403,
        "ACCOUNT_MODE_OWNER_MISMATCH",
        "This server only takes account mode for its own owner",
      );
    }
    return owner;
  }

  async function readBody(c: Context): Promise<Record<string, unknown>> {
    const body = flatBody(await c.req.json().catch(() => null));
    if (!body) {
      throw new ProtocolError(
        400,
        "INVALID_ACCOUNT_MODE_BODY",
        "Body must be a flat JSON object",
      );
    }
    return body;
  }

  for (const path of ["/evidence"]) {
    app.use(path, createBodyLimit(MAX_BODY_BYTES));
  }

  app.post("/evidence", async (c) => {
    await auth.authorizeOwner(c.req.raw);
    const raw = await readBody(c);
    boundOwner(raw.owner);
    const body = parseEvidenceBody(raw);
    if (!body) {
      throw new ProtocolError(
        400,
        "INVALID_ACCOUNT_MODE_EVIDENCE",
        "Body must be {owner, state, generation?}",
      );
    }
    // The caller is this server's owner and so is the body's owner.
    return answer(c, await deps.accountModeAuthority.submitEvidence(body));
  });

  for (const path of ["/evidence"]) {
    app.all(path, (c) => {
      c.header("Allow", "POST");
      return c.json(
        new ProtocolError(
          405,
          "METHOD_NOT_ALLOWED",
          "Method not allowed",
        ).toJSON(),
        405,
      );
    });
  }

  return app;
}
