/**
 * `DELETE /v1/owner/connectors/:connectorId`: the one way an owner deletes a
 * source's data once the account has moved to stream sync. The Node server
 * and the Lite runtime both answer through this handler, so the two cannot
 * disagree about what the route refuses.
 *
 * The account's storage mode is read once per request from one port
 * (`StorageModeRead`, the read shape of `AccountStorageMode`). An unswitched
 * account keeps the per-scope loop, so this route refuses it with
 * `NOT_SWITCHED` and changes nothing; a mode that cannot be read answers a
 * retryable 503, never a guess. The per-scope DELETE refusal is not here: the
 * storage-mode change owns it, after owner authorization.
 *
 * Answers:
 *   202 { deleteId, fenced, deleteStatus }
 *                               the delete intent is durable; the landing runs
 *                               in the writer and retries until it lands. The
 *                               delete is the control tombstone (the fence),
 *                               and the request waits for it: `fenced: true`
 *                               means the registry confirmed it, so every
 *                               other surface already sees the source as
 *                               deleted. `fenced: false` means the registry
 *                               has not confirmed it (unreachable, refused,
 *                               or slower than the writer's first resume
 *                               wait, 5 s by default): the delete is only
 *                               saved here, other surfaces still see the
 *                               source, and what they publish before the
 *                               fence lands ends with its lifetime. When the
 *                               registry lists no control row of the
 *                               connector, the writer purges this device's
 *                               local state and the delete is already done
 *                               (`fenced: true`)
 *   400 INVALID_CONNECTOR       the id is not a connector key
 *   400 INVALID_LIFETIME        `?lifetime=` is not one this server named
 *   409 CONNECTION_LIFETIME_CHANGED
 *                               `?lifetime=` names a connection the connector
 *                               no longer holds: it was connected again since
 *                               the person chose to delete. Nothing changed
 *   409 NOT_SWITCHED            the account has not moved to stream sync
 *   503 ACCOUNT_MODE_UNKNOWN    the storage mode cannot be read yet; retry
 *   503 STREAM_SYNC_UNAVAILABLE no stream-sync writer is wired on this host
 *
 * `?lifetime=<token>` is optional. A caller that keeps a delete to send again
 * (Desktop's recovery) reads the token with `GET /v1/owner/connectors/:id` when
 * the person confirms, and sends it on every send: the delete then ends that
 * connection and no later one. A send already ended by this delete answers 202
 * `fenced: true`, with nothing written. Without it the delete ends whatever
 * is connected now.
 *
 *   GET /v1/owner/connectors/:connectorId
 *     200 { lifetime, deleteStatus }
 *                               the lifetime the connector holds now; the same
 *                               refusals as the delete answer before it
 *
 * `deleteStatus` is what is left of the connector's delete on this server, in
 * three parts (`ConnectionDeleteStatus`, `localdb/delete-status.ts`): `fence`
 * (the control tombstone), `legacy` (the legacy copy at the gateway and in
 * storage) and `storage` (the stream-sync objects). Each is `done`, `pending`
 * (finishes on its own) or `blocked` with a reason (it does not). A caller
 * says "deleted" only when all three are `done`, and polls the GET to watch
 * them. Absent when the writer cannot report it.
 *
 * Every refusal has the one error shape of the API, the `ProtocolError`
 * envelope: `{ error: { code, errorCode, message } }`.
 */

import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  ConnectionLifetimeChanged,
  InvalidConnectionLifetime,
} from "../localdb/delete-lifetime.js";
import type { ConnectionDeleteStatus } from "../localdb/delete-status.js";

/**
 * What the route needs of the account's storage mode: the read shape of
 * `AccountStorageMode`, so a host passes that one instance.
 */
export interface StorageModeRead {
  read(requestOwner?: string): "switched" | "unswitched" | "unknown";
}

/** The writer's side of the route: persist the intent, then answer. */
export interface ConnectionDeletePort {
  /**
   * Rejects `ConnectionLifetimeChanged` for a lifetime the connector no longer
   * holds and `InvalidConnectionLifetime` for a token it never named.
   */
  requestConnectionDelete(
    connector: string,
    request?: { readonly lifetime?: string },
  ): Promise<{ readonly deleteId: string; readonly fenced: boolean }>;
  /** The lifetime the connector's live control rows hold now. */
  readConnectionLifetime?(connector: string): Promise<string>;
  /** What is left of the connector's delete here (`ConnectionDeleteStatus`). */
  deleteStatus?(connector: string): Promise<ConnectionDeleteStatus>;
  /**
   * The same, from what this device holds with no network read: the POST's
   * answer, which waits for the fences only and not for a registry.
   */
  deleteStatusSnapshot?(connector: string): Promise<ConnectionDeleteStatus>;
}

export interface OwnerConnectorDeleteDeps {
  /** Throws the host's auth error for anyone but the owner. */
  authorizeOwner(request: Request): Promise<void>;
  /** The account's storage mode, read at the moment of the request. */
  mode: StorageModeRead;
  /** The owner this server answers for, passed to the mode read. */
  owner?: string;
  /** Absent on a host that does not run stream sync. */
  connectionDelete: ConnectionDeletePort | null | undefined;
}

/** A refusal in the API's one error shape (the `ProtocolError` envelope). */
export function ownerConnectorRefusal(
  status: number,
  errorCode: string,
  message: string,
): Response {
  return new Response(
    JSON.stringify({ error: { code: status, errorCode, message } }),
    {
      status,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store",
      },
    },
  );
}

function accepted(
  deleteId: string,
  fenced: boolean,
  deleteStatus: ConnectionDeleteStatus | undefined,
): Response {
  return new Response(JSON.stringify({ deleteId, fenced, deleteStatus }), {
    status: 202,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
    },
  });
}

/** A connector key is any non-empty name without `~`, as the scope grammar reads it. */
function isConnectorKey(connectorId: string): boolean {
  try {
    controlScope(connectorId, "");
    return true;
  } catch {
    return false;
  }
}

/**
 * What the two routes refuse before they ask the writer: the owner, a bad id,
 * the storage mode, a missing writer. `null` when the request may go on.
 */
async function refusalBeforeWriter(
  request: Request,
  connectorId: string | null,
  deps: OwnerConnectorDeleteDeps,
): Promise<Response | null> {
  await deps.authorizeOwner(request);
  if (connectorId === null || !isConnectorKey(connectorId)) {
    return ownerConnectorRefusal(
      400,
      "INVALID_CONNECTOR",
      "connectorId is not a connector key",
    );
  }
  const mode = deps.mode.read(deps.owner);
  if (mode === "unknown") {
    return ownerConnectorRefusal(
      503,
      "ACCOUNT_MODE_UNKNOWN",
      "This server cannot tell yet whether the account has moved to stream sync. Retry shortly.",
    );
  }
  if (mode !== "switched") {
    return ownerConnectorRefusal(
      409,
      "NOT_SWITCHED",
      "This account has not moved to stream sync. Delete each scope of the source instead.",
    );
  }
  return null;
}

const unavailable = () =>
  ownerConnectorRefusal(
    503,
    "STREAM_SYNC_UNAVAILABLE",
    "Stream sync is not running on this server.",
  );

/**
 * `connectorId` is the path segment decoded strictly; a host passes `null`
 * when it cannot be decoded (a malformed percent-escape), which answers 400
 * after owner authorization like any other bad id. A host never falls back to
 * the raw segment: that would name a connector the owner did not write.
 */
export async function handleOwnerConnectorDelete(
  request: Request,
  connectorId: string | null,
  deps: OwnerConnectorDeleteDeps,
): Promise<Response> {
  const refusal = await refusalBeforeWriter(request, connectorId, deps);
  if (refusal) return refusal;
  if (!deps.connectionDelete) return unavailable();
  const lifetime = new URL(request.url).searchParams.get("lifetime");
  try {
    const started =
      lifetime === null
        ? await deps.connectionDelete.requestConnectionDelete(connectorId!)
        : await deps.connectionDelete.requestConnectionDelete(connectorId!, {
            lifetime,
          });
    const deleteStatus = await deps.connectionDelete.deleteStatusSnapshot?.(
      connectorId!,
    );
    return accepted(started.deleteId, started.fenced, deleteStatus);
  } catch (error) {
    if (error instanceof ConnectionLifetimeChanged) {
      return ownerConnectorRefusal(
        409,
        "CONNECTION_LIFETIME_CHANGED",
        "The source was connected again after this delete was chosen. Nothing was deleted.",
      );
    }
    if (error instanceof InvalidConnectionLifetime) {
      return ownerConnectorRefusal(
        400,
        "INVALID_LIFETIME",
        "lifetime is not one this server named",
      );
    }
    throw error;
  }
}

/**
 * `GET /v1/owner/connectors/:connectorId`: the lifetime the connector holds
 * now, for a caller that will send a delete of it more than once. Answers what
 * the delete answers before it asks the writer.
 */
export async function handleOwnerConnectorLifetime(
  request: Request,
  connectorId: string | null,
  deps: OwnerConnectorDeleteDeps,
): Promise<Response> {
  const refusal = await refusalBeforeWriter(request, connectorId, deps);
  if (refusal) return refusal;
  const read = deps.connectionDelete?.readConnectionLifetime;
  if (!read) return unavailable();
  const lifetime = await read.call(deps.connectionDelete, connectorId!);
  const deleteStatus = await deps.connectionDelete?.deleteStatus?.(
    connectorId!,
  );
  return new Response(JSON.stringify({ lifetime, deleteStatus }), {
    status: 200,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
    },
  });
}
