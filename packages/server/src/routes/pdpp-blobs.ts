import { Hono, type Context } from "hono";
import { randomUUID } from "node:crypto";
import { PdppError } from "@opendatalabs/personal-server-ts-core/errors/pdpp";
import { PDPP_VERSION } from "@opendatalabs/personal-server-ts-core/pdpp-version";
import type {
  PdppAuthorizationService,
  PdppTokenContext,
} from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import {
  deliver,
  leasedStream,
  type DeliveryLease,
} from "@opendatalabs/personal-server-ts-core/policy";
import {
  bearerErrorResponse,
  type PdppProtocolProfile,
} from "../pdpp/bearer-response.js";
import {
  pdppBearerReadLease,
  recordKeyWithinGrantResources,
  recordWithinGrantTimeConstraint,
  resolveReadScope,
  type PdppRecordStore,
  type StreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";

export interface PdppBlobsRouteDeps {
  protocolProfile?: PdppProtocolProfile;
  store: PdppRecordStore;
  auth: PdppAuthorizationService;
  declarations: StreamDeclarationRegistry;
  instancesForSubject?: (subjectId: string) => string[];
  instancesForSource?: (subjectId: string, sourceId: string) => string[];
  isConnectionAvailable?: (instance: string) => boolean;
  /**
   * Loads raw blob bytes for a blob_id, or undefined if not locally stored.
   * Optional: when absent or throwing, GET fails closed with `api_error` (500) instead of a fabricated 200.
   */
  readBlobBytes?: (
    blobId: string,
  ) => Promise<Uint8Array<ArrayBuffer> | undefined>;
}

/** Bytes released per delivery boundary of a blob body. */
export const BLOB_DELIVERY_CHUNK_BYTES = 64 * 1024;

/** The blob bytes as a stream of `BLOB_DELIVERY_CHUNK_BYTES` parts. */
function chunkedBytes(
  bytes: Uint8Array<ArrayBuffer>,
): ReadableStream<Uint8Array> {
  let offset = 0;
  return new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        if (offset >= bytes.byteLength) {
          controller.close();
          return;
        }
        const end = Math.min(
          offset + BLOB_DELIVERY_CHUNK_BYTES,
          bytes.byteLength,
        );
        controller.enqueue(bytes.subarray(offset, end));
        offset = end;
      },
    },
    { highWaterMark: 0 },
  );
}

/** A lease refusal as a PDPP error; anything unexpected fails closed. */
function toLeaseRefusal(err: unknown): PdppError {
  return err instanceof PdppError
    ? err
    : new PdppError("api_error", "Blob delivery could not be authorized");
}

function requestId(): string {
  return `req_${randomUUID()}`;
}

export function pdppBlobsRoutes(deps: PdppBlobsRouteDeps): Hono {
  function jsonError(
    c: Context,
    err: PdppError,
    reqId: string,
    options?: Parameters<typeof bearerErrorResponse>[4],
  ) {
    return bearerErrorResponse(c, err, reqId, deps.protocolProfile, options);
  }
  const app = new Hono();

  /** The read's lease; it holds the read to the grant's connections. */
  function blobLease(token: string, context: PdppTokenContext): DeliveryLease {
    return pdppBearerReadLease(deps.auth, token, context, {
      ...(deps.isConnectionAvailable && {
        isConnectionAvailable: deps.isConnectionAvailable,
      }),
    });
  }

  /**
   * Release a response through the read's lease (see `deliver`). Headers
   * disclose the blob's size and type, so the headers of a GET or a HEAD are
   * released through it too, before any body part.
   */
  async function release(
    c: Context,
    lease: DeliveryLease,
    reqId: string,
    build: () => Response,
  ): Promise<Response> {
    try {
      return await deliver(lease, build);
    } catch (err) {
      const refusal = toLeaseRefusal(err);
      return jsonError(c, refusal, reqId, {
        inactiveBearer: refusal.code === "authentication_error",
      });
    }
  }

  /**
   * Authorizes a blob fetch through the same path a record read uses (spec §8): finds every
   * record referencing this blob_id, then grants access if ANY one passes instance scope,
   * resources, time_constraint, and has blob_ref in its record's specific granted field
   * projection. Identical bytes can be referenced by more than one record, so an inaccessible
   * reference must not hide an accessible one.
   */
  async function authorizeBlobAccess(
    c: Context,
    blobId: string,
  ): Promise<{ error: Response } | { ok: true; lease: DeliveryLease }> {
    const reqId = requestId();
    const header = c.req.header("Authorization");
    const token = header?.match(/^Bearer\s+(.+)$/i)?.[1];
    if (!token) {
      const err = new PdppError(
        "authentication_error",
        "Missing or invalid access token",
      );
      return {
        error: jsonError(c, err, reqId),
      };
    }
    const context = await deps.auth.resolveToken(token);
    if (!context.active) {
      const err = new PdppError("authentication_error", "Invalid access token");
      return { error: jsonError(c, err, reqId, { inactiveBearer: true }) };
    }

    // DELETE removes the grant's record references and claim rows. Check its
    // connection before blob metadata so callers still get the K7 refusal.
    if (context.tokenKind !== "owner") {
      const grantInstances = (context.grant?.streams ?? []).flatMap(
        (stream) => stream.instance_ids,
      );
      if (
        grantInstances.some(
          (instance) => deps.isConnectionAvailable?.(instance) === false,
        )
      ) {
        const err = new PdppError(
          "instance_unavailable",
          "The connection for this grant is unavailable",
        );
        return { error: jsonError(c, err, reqId) };
      }
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

    // Identical blob bytes can legitimately be referenced by more than one
    // record or instance (e.g. re-ingested via a different stream). Access
    // is granted if ANY visible reference passes its authorization check —
    // an inaccessible reference must never hide an accessible one.
    const references = deps.store.findBlobReferences(blobId);
    if (references.length === 0) return { error: notFound() };

    if (context.tokenKind === "owner") {
      // Owner tokens carry no grant: current-capability read, scoped to the
      // owner's selected live instances when the token has an instance list.
      // A source scope must not widen that explicit selection.
      // Fail closed: a missing resolver, a missing subjectId, or an empty
      // owned list must all deny rather than fall back to "visible to
      // everyone" — mirrors the record routes' `?? []` default.
      if (!context.subjectId) return { error: notFound() };
      const currentInstances = deps.instancesForSubject?.(context.subjectId);
      const sourceInstances = context.sourceId
        ? (deps.instancesForSource?.(context.subjectId, context.sourceId) ?? [])
        : (currentInstances ?? []);
      const ownedInstances = context.instanceIds
        ? context.instanceIds.filter((instance) =>
            sourceInstances.includes(instance),
          )
        : context.sourceId
          ? sourceInstances
          : [];
      const visible = references.some((reference) =>
        ownedInstances.includes(reference.instance),
      );
      if (!visible) return { error: notFound() };
      return {
        ok: true,
        lease: blobLease(token, context),
      };
    }

    // Client token: the blob must be referenced by a record this exact
    // grant can see — instance scope, resources allowlist, time_constraint,
    // and blob_ref must be in the granted fields for that record's stream.
    for (const reference of references) {
      const declaration = deps.declarations.forInstance(
        reference.instance,
        reference.stream,
      );
      let scope;
      try {
        scope = resolveReadScope(context, reference.stream, declaration);
      } catch {
        continue;
      }

      if (!scope.instanceIds.includes(reference.instance)) continue;
      if (
        !recordKeyWithinGrantResources(reference.recordKey, scope.streamGrant)
      ) {
        continue;
      }
      if (!scope.fields?.includes("blob_ref")) continue;

      const record = deps.store.getRecord(
        reference.instance,
        reference.stream,
        reference.recordKey,
      );
      if (
        !record ||
        !recordWithinGrantTimeConstraint(record.data, scope.streamGrant)
      ) {
        continue;
      }

      return {
        ok: true,
        lease: blobLease(token, context),
      };
    }

    return { error: notFound() };
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
      return release(c, authz.lease, reqId, () => c.body(null, 200, headers));
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
    // The headers, then each part, are released only through the read's
    // lease: a grant that ends mid-download errors the body before the next
    // part.
    return release(c, authz.lease, reqId, () =>
      c.body(leasedStream(authz.lease, chunkedBytes(bytes)), 200, headers),
    );
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
