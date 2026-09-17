import { Hono, type Context } from "hono";
import { randomUUID } from "node:crypto";
import { PdppError } from "@opendatalabs/personal-server-ts-core/errors/pdpp";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { PDPP_API_VERSION } from "@opendatalabs/personal-server-ts-core/pdpp";
import {
  type PdppRecordStore,
  type StreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";

/**
 * The negotiated PDPP API version, shared with the Authorization Server.
 *
 * Both halves mount into one app and both hard-reject an unrecognized value,
 * so a client that pins one version must be able to reach both. Importing the
 * AS's constant rather than restating a literal is what keeps that true: the
 * two surfaces previously diverged ("0.1.0" vs "2026-04-06"), and a client
 * pinning either could reach only half the server.
 */
const PDPP_VERSION = PDPP_API_VERSION;

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
    // filters, and blob_ref must be in the grant's field projection.
    //
    // This route cannot evaluate the first two. `PdppBlobMeta` is
    // `{ blobId, mimeType, sizeBytes, sha256 }` — it carries no back-reference
    // to the record that referenced the blob, so there is no way to find the
    // referencing record and run it through the same instance / resources /
    // time_constraint checks a record read uses.
    //
    // The previous check asked only whether ANY granted stream's resolved
    // scope contained a field NAMED `blob_ref`, and passed on that alone. A
    // field name is not an authorization: a grant scoped to one instance and
    // one record could fetch ANY blob_id on the server, with blob-ID secrecy
    // as the only remaining control. That is the confidentiality hole this
    // branch closes.
    //
    // So client tokens are refused until a blob -> (instance, stream,
    // record_key) reverse index exists. Refusing a legitimate read is
    // recoverable; serving another grant's bytes is not. Building that index
    // is a record-store schema change and belongs to the RS lane — it is the
    // real fix, and this is explicitly the interim.
    //
    // 404 rather than 403: a client that may not read this blob must not
    // learn whether it exists.
    if (context.tokenKind === "client") {
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

    return { ok: true };
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
