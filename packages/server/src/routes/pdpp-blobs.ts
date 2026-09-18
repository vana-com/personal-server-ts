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
   * Optional: when absent or throwing, GET fails closed with `api_error` (500) instead of a fabricated 200.
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
  // Every 401 carries the challenge, not just the missing-token branch: a
  // client holding a STALE token is exactly who needs the pointer back to the
  // metadata document in order to re-authorize.
  const headers: Record<string, string> = {
    "Request-Id": reqId,
    "PDPP-Version": PDPP_VERSION,
    ...(err.status === 401 && {
      "WWW-Authenticate": `Bearer error="invalid_token", resource_metadata="${resourceMetadataUrlFor(c)}"`,
    }),
    ...extraHeaders,
  };
  return c.json(err.toJSON(reqId), err.status as never, headers);
}

export function pdppBlobsRoutes(deps: PdppBlobsRouteDeps): Hono {
  const app = new Hono();

  /**
   * Authorizes a blob fetch through the same path a record read uses (spec §8): finds the
   * record referencing this blob_id, then applies instance scope, resources, time_constraint,
   * and requires blob_ref in that record's specific granted field projection.
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

  // Hono dispatches HEAD via the GET handler and discards the body, so no separate HEAD handler is
  // needed. Content-Length always comes from blob metadata, not the actual byte read.
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

    let bytes: Uint8Array<ArrayBuffer> | undefined;
    try {
      bytes = await deps.readBlobBytes?.(blobId);
    } catch {
      // A throwing reader must not leak past this route to app.ts's generic
      // handler, which returns a different (legacy) error shape. Map it to
      // the same fail-closed api_error without exposing the reader's detail.
      return jsonError(
        c,
        new PdppError("api_error", "Blob bytes are not available"),
        reqId,
      );
    }
    if (bytes === undefined) {
      // No byte source wired up, or the store lost the bytes for an
      // otherwise-known blob -- distinct from a genuine zero-byte blob.
      return jsonError(
        c,
        new PdppError("api_error", "Blob bytes are not available"),
        reqId,
      );
    }
    if (bytes.byteLength !== meta.sizeBytes) {
      // The declared Content-Length must never silently misrepresent the
      // returned body. Fail closed rather than let a stale/corrupt
      // sizeBytes lie to the client about how much data follows.
      return jsonError(
        c,
        new PdppError("api_error", "Stored blob size does not match metadata"),
        reqId,
      );
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
