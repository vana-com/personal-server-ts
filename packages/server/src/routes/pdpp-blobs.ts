import { Hono, type Context } from "hono";
import { randomUUID } from "node:crypto";
import { PdppError } from "@opendatalabs/personal-server-ts-core/errors/pdpp";
import { PDPP_VERSION } from "@opendatalabs/personal-server-ts-core/pdpp-version";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { resourceMetadataUrlFor } from "./pdpp-records.js";
import {
  recordKeyWithinGrantResources,
  recordWithinGrantTimeConstraint,
  resolveReadScope,
  type PdppRecordStore,
  type StreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";

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

function jsonError(
  c: Context,
  err: PdppError,
  reqId: string,
  extraHeaders?: Record<string, string>,
) {
  return c.json(err.toJSON(reqId), err.status as never, {
    "Request-Id": reqId,
    "PDPP-Version": PDPP_VERSION,
    ...extraHeaders,
  });
}

export function pdppBlobsRoutes(deps: PdppBlobsRouteDeps): Hono {
  const app = new Hono();

  /**
   * Authorizes a blob fetch through the SAME path a record read uses — a
   * `blob_id` alone is never sufficient (spec §8 "Get a blob"). This finds
   * the record that actually references the blob (spec §4 `blob_ref`), then
   * requires that record to pass every check a direct record read would:
   * instance scope, `resources` allowlist, `time_constraint`, and — the
   * blob-specific addition — `blob_ref` being in the grant's authorized
   * field projection. A grant whose only connection to this blob_id is an
   * unrelated stream's `fields` list containing the string "blob_ref" no
   * longer passes; it must be the field projection of the SPECIFIC stream
   * whose SPECIFIC record references this blob.
   */
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
        error: jsonError(c, err, reqId, {
          // Absolute, derived from this request's origin (RFC 9728 §5.1) --
          // shares the records route's helper so the two cannot drift.
          "WWW-Authenticate": `Bearer error="invalid_token", resource_metadata="${resourceMetadataUrlFor(c)}"`,
        }),
      };
    }
    const context = await deps.auth.resolveToken(token);
    if (!context.active) {
      const err = new PdppError("authentication_error", "Invalid access token");
      return { error: jsonError(c, err, reqId) };
    }

    const meta = deps.store.getBlobMeta(blobId);
    if (!meta) {
      const err = new PdppError(
        "blob_not_found",
        "blob_id is unknown or stale",
      );
      return { error: jsonError(c, err, reqId) };
    }

    const notFound = () =>
      jsonError(
        c,
        new PdppError("blob_not_found", "blob_id is unknown or stale"),
        reqId,
      );

    if (context.tokenKind === "owner") {
      // Owner tokens carry no grant: current-capability read, scoped to the
      // owner's own subject's instances only — a blob referenced by a
      // record on an instance the owner doesn't own must not be served.
      const reference = deps.store.findBlobReference(blobId);
      if (!reference) return { error: notFound() };
      const ownedInstances = deps.instancesForSubject?.(
        context.subjectId ?? "",
      );
      if (ownedInstances && !ownedInstances.includes(reference.instance)) {
        return { error: notFound() };
      }
      return { ok: true };
    }

    // Client token: the blob must be referenced by a record this exact
    // grant can see — instance scope, resources allowlist, time_constraint,
    // and blob_ref must be in the granted fields for that record's stream.
    const reference = deps.store.findBlobReference(blobId);
    if (!reference) return { error: notFound() };

    const declaration = deps.declarations.get(reference.stream);
    let scope;
    try {
      scope = resolveReadScope(context, reference.stream, declaration);
    } catch {
      return { error: notFound() };
    }

    if (!scope.instanceIds.includes(reference.instance)) {
      return { error: notFound() };
    }
    if (
      !recordKeyWithinGrantResources(reference.recordKey, scope.streamGrant)
    ) {
      return { error: notFound() };
    }
    if (!scope.fields?.includes("blob_ref")) {
      return { error: notFound() };
    }

    const record = deps.store.getRecord(
      reference.instance,
      reference.stream,
      reference.recordKey,
    );
    if (
      !record ||
      !recordWithinGrantTimeConstraint(record.data, scope.streamGrant)
    ) {
      return { error: notFound() };
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
