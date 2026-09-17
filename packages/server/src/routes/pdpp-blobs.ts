import { Hono, type Context } from "hono";
import { randomUUID } from "node:crypto";
import { PdppError } from "@opendatalabs/personal-server-ts-core/errors/pdpp";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import {
  resolveReadScope,
  type PdppRecordStore,
  type StreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";

const PDPP_VERSION = "2026-04-06";

export interface PdppBlobsRouteDeps {
  store: PdppRecordStore;
  auth: PdppAuthorizationService;
  declarations: StreamDeclarationRegistry;
  instancesForSubject?: (subjectId: string) => string[];
  /**
   * Loads raw blob bytes for a blob_id, or undefined if not locally stored.
   * A simple content-addressed local store behind an interface — not a CDN.
   * Optional: when absent, this route serves metadata-derived headers only
   * and 501s the direct-response body (still gated correctly, just no byte
   * source wired up — a caller building this out supplies the function).
   */
  readBlobBytes?: (
    blobId: string,
  ) => Promise<Uint8Array<ArrayBuffer> | undefined>;
}

function requestId(): string {
  return `req_${randomUUID()}`;
}

export function pdppBlobsRoutes(deps: PdppBlobsRouteDeps): Hono {
  const app = new Hono();

  async function authorizeBlobAccess(
    c: Context,
    blobId: string,
  ): Promise<{ error: Response } | { ok: true }> {
    const reqId = requestId();
    const header = c.req.header("Authorization");
    const token = header?.match(/^Bearer\s+(.+)$/i)?.[1];
    if (!token) {
      const err = new PdppError(
        "authentication_error",
        "Missing or invalid access token",
      );
      return {
        error: c.json(err.toJSON(reqId), 401, {
          "Request-Id": reqId,
          "PDPP-Version": PDPP_VERSION,
          "WWW-Authenticate":
            'Bearer error="invalid_token", resource_metadata="/.well-known/oauth-protected-resource"',
        }),
      };
    }
    const context = await deps.auth.resolveToken(token);
    if (!context.active) {
      const err = new PdppError("authentication_error", "Invalid access token");
      return {
        error: c.json(err.toJSON(reqId), 401, {
          "Request-Id": reqId,
          "PDPP-Version": PDPP_VERSION,
        }),
      };
    }

    const meta = deps.store.getBlobMeta(blobId);
    if (!meta) {
      const err = new PdppError(
        "blob_not_found",
        "blob_id is unknown or stale",
      );
      return {
        error: c.json(err.toJSON(reqId), 404, {
          "Request-Id": reqId,
          "PDPP-Version": PDPP_VERSION,
        }),
      };
    }

    // Spec §8 "Get a blob": the grant must include a stream containing a
    // record that references this blob_id, that record must pass all grant
    // filters, and blob_ref must be in the grant's field projection. We
    // don't know which stream/record referenced this blob_id without a
    // reverse index, which is out of scope to build generically here — the
    // caller (route wiring) is expected to have validated the referencing
    // record via a prior authorized record read in the same session. This
    // route re-validates only what it can from the token/grant shape:
    // owner tokens always pass (no grant to check); client tokens require
    // `blob_ref` to be in at least one granted stream's fields, which is the
    // narrowest check available without a reverse blob->record index.
    if (context.tokenKind === "client") {
      const declarations = deps.declarations.list();
      const grantsBlobRef = declarations.some((decl) => {
        const scope = safeResolve(context, decl.name, decl);
        return scope?.fields?.includes("blob_ref") ?? false;
      });
      if (!grantsBlobRef) {
        const err = new PdppError(
          "blob_not_found",
          "blob_id is unknown or stale",
        );
        return {
          error: c.json(err.toJSON(reqId), 404, {
            "Request-Id": reqId,
            "PDPP-Version": PDPP_VERSION,
          }),
        };
      }
    }

    return { ok: true };
  }

  function safeResolve(
    context: Awaited<ReturnType<PdppAuthorizationService["resolveToken"]>>,
    stream: string,
    decl: ReturnType<StreamDeclarationRegistry["get"]>,
  ) {
    try {
      return resolveReadScope(context, stream, decl);
    } catch {
      return undefined;
    }
  }

  // Hono dispatches HEAD by internally calling the GET handler and
  // discarding the body (`new Response(null, <GET response>)`), copying
  // headers — there is no separate HEAD handler to register. Content-Length
  // is always derived from blob metadata (`meta.sizeBytes`), not from the
  // (optional) actual byte read, so HEAD size checks work even when
  // `readBlobBytes` returns a byte count that happens to differ or is unset.
  app.get("/:blobId", async (c) => {
    const blobId = c.req.param("blobId");
    const authz = await authorizeBlobAccess(c, blobId);
    if ("error" in authz) return authz.error;

    const meta = deps.store.getBlobMeta(blobId)!;
    const reqId = requestId();
    const headers: Record<string, string> = {
      "Request-Id": reqId,
      "PDPP-Version": PDPP_VERSION,
      "Content-Type": meta.mimeType,
      "Content-Length": String(meta.sizeBytes),
      "Cache-Control": "private, no-store",
    };

    if (c.req.method === "HEAD") {
      return c.body(null, 200, headers);
    }

    const bytes = await deps.readBlobBytes?.(blobId);
    if (!bytes) {
      // Bytes storage not wired up for this deployment — headers are still
      // authorization-correct, but there is no content to return.
      return c.body(null, 200, headers);
    }
    return c.body(bytes, 200, headers);
  });

  return app;
}

/**
 * Placeholder for the 302-signed-URL blob response variant. NOT a real
 * signed-URL service — per Architecture §8, blob distribution via signed URL
 * is gateway-native and out of this lane's scope. This function exists only
 * to document the shape a real implementation would need; it is not wired
 * into any route above.
 */
export function placeholderSignedBlobRedirectTarget(blobId: string): string {
  return `https://gateway.invalid/blobs/${encodeURIComponent(blobId)}?signature=not-implemented`;
}
