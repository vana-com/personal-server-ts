import type { PdppTokenContext } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import type { ReplicaReader } from "@opendatalabs/personal-server-ts-core/replication/visibility-policy";
import { Hono, type Context } from "hono";
import { randomUUID } from "node:crypto";
import { PdppError } from "@opendatalabs/personal-server-ts-core/errors/pdpp";
import { PDPP_VERSION } from "@opendatalabs/personal-server-ts-core/pdpp-version";
import {
  pdppVersionFailure,
  pdppVersionMiddleware,
  versionedHeaders,
} from "./pdpp-version-negotiation.js";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import {
  PdppAuthorizationUnavailableError,
  storedInstanceFor,
} from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import type { PdppChainEnforcementPort } from "./pdpp-records.js";
import { resourceMetadataUrlFor } from "./pdpp-records.js";
import { parseRecordQuery } from "./pdpp-record-query.js";
import {
  recordKeyWithinGrantResources,
  recordWithinGrantTimeConstraint,
  resolveReadScope,
  type PdppRecordStore,
  type PdppReplicaReadStore,
  type StreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";

export type BlobReadStore = Pick<
  PdppReplicaReadStore,
  "getBlobMeta" | "findBlobReferences" | "getRecord" | "getBlobBytes"
> & {
  validate?: () => Promise<boolean>;
  withReadSnapshot?<T>(read: () => T): T;
};
export interface PdppBlobsRouteDeps {
  /** The canonical store. Bytes are always loaded through the reader port. */
  store: PdppRecordStore;
  /**
   * Reader capability that authorizes every blob read. The app host
   * (`createApp`) always supplies it. Absent only when the route runs without
   * a host, in tests: then every token class reads `store`.
   */
  reads?: (reader: ReplicaReader) => BlobReadStore;
  prepareReads?: (
    context: PdppTokenContext,
    blobId: string,
  ) => Promise<BlobReadStore>;
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
  /**
   * Design 2 (Vana-6.1): the same chain gate the record routes apply. A
   * client blob read needs its grant's chain entry live, exactly like a
   * record read; owner reads are not gated.
   */
  chainEnforcement?: PdppChainEnforcementPort;
}

function requestId(): string {
  return `req_${randomUUID()}`;
}

/** A §4 `blob_ref` value naming `blobId`. */
function isBlobRefTo(value: unknown, blobId: string): boolean {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    (value as { blob_id?: unknown }).blob_id === blobId
  );
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
  const headers: Record<string, string> = versionedHeaders(
    c,
    {
      "Request-Id": reqId,
      ...(err.status === 401 && {
        "WWW-Authenticate": `Bearer error="invalid_token", resource_metadata="${resourceMetadataUrlFor(c)}"`,
      }),
      ...extraHeaders,
    },
    PDPP_VERSION,
  );
  if (err instanceof PdppAuthorizationUnavailableError) {
    headers["Retry-After"] = String(err.retryAfterSeconds);
  }
  return c.json(err.toJSON(reqId), err.status as never, headers);
}

export function pdppBlobsRoutes(deps: PdppBlobsRouteDeps): Hono {
  const app = new Hono();
  // Every failure on this route answers the unified §8 error body; a fault
  // is `api_error`, never the legacy handler's shape (RS item 6).
  app.onError((error, c) =>
    jsonError(
      c,
      error instanceof PdppError
        ? error
        : new PdppError("api_error", "Internal server error"),
      requestId(),
    ),
  );
  // The blob endpoint is a Core RS operation, so it negotiates PDPP-Version
  // like every other one (spec-core §8; RS item 11).
  app.use(
    "*",
    // Every path of this router is the Core blob operation.
    pdppVersionMiddleware(requestId),
  );
  const readsFor = deps.reads ?? (() => deps.store);

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
  ): Promise<
    | { error: Response }
    | {
        ok: true;
        store: BlobReadStore;
        meta: NonNullable<ReturnType<BlobReadStore["getBlobMeta"]>>;
        runIfReadable(read: () => void): Promise<boolean>;
        readBytes(): Uint8Array | undefined | Promise<Uint8Array | undefined>;
      }
  > {
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
    let context;
    try {
      context = await deps.auth.resolveToken(token);
    } catch (error) {
      if (!(error instanceof PdppAuthorizationUnavailableError)) throw error;
      return { error: jsonError(c, error, reqId) };
    }
    if (!context.active) {
      const err = new PdppError("authentication_error", "Invalid access token");
      return { error: jsonError(c, err, reqId) };
    }
    // Version is reported only once the token is active (spec-core §8).
    const versionFailure = pdppVersionFailure(c);
    if (versionFailure) return { error: jsonError(c, versionFailure, reqId) };

    // spec-core §8 "Get a blob": unknown parameters are a 400 (RS item 10),
    // and `instance_id` is REQUIRED on every blob request: "The resource
    // server MUST reject a blob request without it with 400
    // `invalid_request`" (RS items 18, 23).
    let instanceId: string;
    try {
      const query = parseRecordQuery(c.req.url, "getBlob");
      if (query.instanceId === undefined) {
        throw new PdppError(
          "invalid_request",
          "instance_id is required on every blob request",
          { param: "instance_id" },
        );
      }
      // AS item 29: a client names its pairwise handle.
      instanceId = storedInstanceFor(context, query.instanceId);
    } catch (error) {
      if (!(error instanceof PdppError)) throw error;
      return { error: jsonError(c, error, reqId) };
    }

    // Design 2: the chain gate, before any blob metadata is looked at, so a
    // client whose chain entry is gone learns nothing about the blob.
    if (deps.chainEnforcement && context.tokenKind === "client") {
      const grantId = context.grant?.grant_id;
      const decision = grantId
        ? await deps.chainEnforcement.authorize({
            clientId: context.clientId ?? "",
            pdppGrantId: grantId,
          })
        : ({
            ok: false,
            retryable: false,
            reason: "No chain binding for this grant",
          } as const);
      if (!decision.ok) {
        if (decision.retryable)
          return {
            error: jsonError(
              c,
              new PdppError(
                "api_error",
                "Chain authorization could not be verified",
              ),
              reqId,
              { "Retry-After": "5" },
            ),
          };
        return {
          error: jsonError(
            c,
            new PdppError("grant_revoked", decision.reason),
            reqId,
          ),
        };
      }
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

    const store: BlobReadStore = deps.prepareReads
      ? await deps.prepareReads(context, blobId)
      : readsFor(context.tokenKind === "owner" ? "owner" : "grant");
    const authorizedMeta = () => {
      const meta = store.getBlobMeta(blobId);
      if (!meta) return undefined;
      // A blob_id is unique only within one instance: only references in
      // the selected instance count (spec-core §8 "Get a blob").
      const references = store
        .findBlobReferences(blobId)
        .filter((reference) => reference.instance === instanceId);
      if (context.tokenKind === "owner") {
        if (!context.subjectId) return undefined;
        const currentInstances = deps.instancesForSubject?.(context.subjectId);
        const sourceInstances = context.sourceId
          ? (deps.instancesForSource?.(context.subjectId, context.sourceId) ??
            [])
          : (currentInstances ?? []);
        const ownedInstances = context.instanceIds
          ? context.instanceIds.filter((instance) =>
              sourceInstances.includes(instance),
            )
          : context.sourceId
            ? sourceInstances
            : [];
        return references.some((reference) =>
          ownedInstances.includes(reference.instance),
        )
          ? meta
          : undefined;
      }

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
        )
          continue;
        const record = store.getRecord(
          reference.instance,
          reference.stream,
          reference.recordKey,
        );
        if (
          !record ||
          record.deleted ||
          !recordWithinGrantTimeConstraint(record.data, scope.streamGrant)
        )
          continue;
        // spec-core §8 "Get a blob" check 3: the field that holds the
        // reference is in the grant's authorized projection. The field is
        // found by its blob_ref shape (`{ blob_id, ... }`), not by the name
        // `blob_ref` (RS item 18).
        const granted = new Set(scope.fields ?? []);
        if (
          !Object.entries(record.data).some(
            ([field, value]) =>
              granted.has(field) && isBlobRefTo(value, blobId),
          )
        )
          continue;
        return meta;
      }
      return undefined;
    };
    const inSnapshot = <T>(read: () => T) =>
      store.withReadSnapshot ? store.withReadSnapshot(read) : read();
    const meta =
      store.validate && !(await store.validate())
        ? undefined
        : inSnapshot(authorizedMeta);
    const notFound = () =>
      jsonError(
        c,
        new PdppError("blob_not_found", "blob_id is unknown or stale"),
        reqId,
      );
    if (!meta) return { error: notFound() };
    return {
      ok: true,
      store,
      meta,
      runIfReadable: async (read) => {
        if (store.validate && !(await store.validate())) return false;
        return inSnapshot(() => {
          if (!authorizedMeta()) return false;
          read();
          return true;
        });
      },
      readBytes: () => {
        if (!deps.reads && deps.readBlobBytes)
          return authorizedMeta() ? deps.readBlobBytes(blobId) : undefined;
        return inSnapshot(() =>
          authorizedMeta() ? store.getBlobBytes(blobId) : undefined,
        );
      },
    };
  }

  // Hono dispatches HEAD via the GET handler and discards the body, so no separate HEAD handler is
  // needed. Content-Length always comes from blob metadata, not the actual byte read.
  app.get("/:blobId", async (c) => {
    const blobId = c.req.param("blobId");
    const authz = await authorizeBlobAccess(c, blobId);
    if ("error" in authz) return authz.error;

    const meta = authz.meta;
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

    let bytes: Uint8Array | undefined;
    try {
      bytes = await authz.readBytes();
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
    const chunkSize = 64 * 1024;
    let offset = 0;
    const body = new ReadableStream<Uint8Array>(
      {
        async pull(controller) {
          if (offset >= bytes.byteLength) {
            controller.close();
            return;
          }
          const end = Math.min(offset + chunkSize, bytes.byteLength);
          const chunk = bytes.subarray(offset, end);
          if (!(await authz.runIfReadable(() => controller.enqueue(chunk)))) {
            controller.error(new Error("blob visibility changed during read"));
            return;
          }
          offset = end;
        },
      },
      { highWaterMark: 0 },
    );
    return c.body(body, 200, headers);
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
