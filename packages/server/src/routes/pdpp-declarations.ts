/**
 * Declaration submission (§5 declaration acceptance).
 *
 * `POST /pdpp/declarations` — offer a SourceDeclaration and get an accept or a
 * refusal, in this server lifetime.
 *
 * ## Why this route exists
 *
 * The AS already had a real validator (`parseDeclaration`) and a real trust
 * policy (the connector gate), but both ran only at construction: declarations
 * came from `config.pdpp.declarationPaths`, were parsed once, and were pinned.
 * Asking "would you accept this document?" therefore meant editing config and
 * restarting the process. That is not merely inconvenient — it makes the
 * question unanswerable. A restart-per-submission puts a control and its
 * negative case in two different server lifetimes, so what gets measured is
 * what survives a reboot, not what the AS refuses at an acceptance surface.
 *
 * ## Why it is operator-authenticated and NOT client-reachable
 *
 * A declaration asserts authority over a source: which streams exist, which
 * fields they have, what an owner is consenting to when they approve a grant
 * against it. A client that can submit its own declaration can declare itself
 * authority over any source and then request a grant against the shape it
 * just invented, which defeats the entire §5 trust model. So the credential
 * here is the operator's — the same authority that may edit
 * `declarationPaths` — and never a client token. Absent a configured operator
 * credential the route refuses everything, because a submission surface that
 * fails open is worse than no submission surface.
 *
 * ## The response contract
 *
 * Acceptance is `200` with the snapshot now retained for the key, so a caller
 * can see what is actually held rather than inferring it from a bare 204.
 * Refusal is `400` with `{ error, error_description }`, where `error` is the
 * `DeclarationFailureCode` the validator produced. Acceptance is idempotent
 * for an identical resubmission: a positive control has to be runnable twice.
 */

import { Hono } from "hono";
import { timingSafeEqual } from "node:crypto";
import type { Logger } from "pino";
import type { MutableDeclarationRegistry } from "../pdpp/declaration-registry.js";

export interface PdppDeclarationRouteDeps {
  logger: Logger;
  registry: MutableDeclarationRegistry;
  /**
   * The connector inventory, for the response's benefit only — the registry
   * applies the gate itself. Kept in the deps so a caller can see the two are
   * meant to agree.
   */
  supportedConnectors: string[];
  /**
   * The operator credential. Undefined disables the route entirely (every
   * request is refused), which is the safe reading of "no credential
   * configured" for a surface that decides what this server trusts.
   */
  operatorToken?: string;
}

export function pdppDeclarationRoutes(deps: PdppDeclarationRouteDeps): Hono {
  const app = new Hono();

  app.post("/declarations", async (c) => {
    if (!authorized(c.req.header("authorization"), deps.operatorToken)) {
      return c.json(
        {
          error: "unauthorized",
          error_description:
            "Declaration submission requires the operator credential",
        },
        401,
        { "Cache-Control": "no-store" },
      );
    }

    // Read the raw bytes, not a parsed body. The digest a producer's envelope
    // is later checked against is taken over exactly what was submitted, so
    // re-serializing a parsed object here would change the digest for
    // formatting alone and quietly break verification.
    const document = await c.req.text();

    const result = deps.registry.submit(document);
    if (!result.ok) {
      deps.logger.warn(
        { code: result.failure.code, reason: result.failure.message },
        "PDPP declaration refused",
      );
      return c.json(
        {
          error: result.failure.code,
          error_description: result.failure.message,
        },
        400,
        { "Cache-Control": "no-store" },
      );
    }

    deps.logger.info(
      {
        sourceId: result.snapshot.source_id,
        version: result.snapshot.version,
        digest: result.snapshot.digest.slice(0, 12),
      },
      "PDPP declaration retained",
    );

    // What is retained for this key after the call — clause 5.8-4's retention
    // half stays observable without a second request.
    return c.json(
      {
        source_id: result.snapshot.source_id,
        source_kind: result.snapshot.source_kind,
        version: result.snapshot.version,
        digest: result.snapshot.digest,
        streams: result.snapshot.streams.map((s) => s.name),
      },
      200,
      { "Cache-Control": "no-store" },
    );
  });

  return app;
}

/**
 * Constant-time bearer comparison. A submission surface that decides what the
 * server trusts is worth not leaking its credential a byte at a time.
 */
function authorized(header: string | undefined, expected?: string): boolean {
  if (!expected) return false;
  if (!header?.toLowerCase().startsWith("bearer ")) return false;
  const presented = Buffer.from(header.slice(7).trim());
  const secret = Buffer.from(expected);
  if (presented.length !== secret.length) return false;
  return timingSafeEqual(presented, secret);
}
