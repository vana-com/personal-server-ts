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
 *   202 { deleteId }            the delete intent is durable; the landing runs
 *                               in the writer and retries until it lands. When
 *                               the registry lists nothing of the connector,
 *                               the writer purges this device's local state
 *                               and the delete is already done. A reconnect
 *                               that lands before the delete keeps its data:
 *                               the delete skips what the reconnect moved
 *   400 INVALID_CONNECTOR       the id is not a connector key
 *   409 NOT_SWITCHED            the account has not moved to stream sync
 *   503 ACCOUNT_MODE_UNKNOWN    the storage mode cannot be read yet; retry
 *   503 STREAM_SYNC_UNAVAILABLE no stream-sync writer is wired on this host
 *   503 CONNECTOR_NOT_VERIFIED  the registry holds a pin of the connector, no
 *                               stream row, and this host verified no manifest
 *                               naming its streams; retry once it has
 *
 * Every refusal has the one error shape of the API, the `ProtocolError`
 * envelope: `{ error: { code, errorCode, message } }`.
 */

import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";
import { ConnectorNotVerifiedError } from "../localdb/delete.js";

/**
 * What the route needs of the account's storage mode: the read shape of
 * `AccountStorageMode`, so a host passes that one instance.
 */
export interface StorageModeRead {
  read(requestOwner?: string): "switched" | "unswitched" | "unknown";
}

/** The writer's side of the route: persist the intent, then answer. */
export interface ConnectionDeletePort {
  requestConnectionDelete(
    connector: string,
  ): Promise<{ readonly deleteId: string }>;
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

function accepted(deleteId: string): Response {
  return new Response(JSON.stringify({ deleteId }), {
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
  if (!deps.connectionDelete) {
    return ownerConnectorRefusal(
      503,
      "STREAM_SYNC_UNAVAILABLE",
      "Stream sync is not running on this server.",
    );
  }
  try {
    const started =
      await deps.connectionDelete.requestConnectionDelete(connectorId);
    return accepted(started.deleteId);
  } catch (error) {
    if (error instanceof ConnectorNotVerifiedError) {
      return ownerConnectorRefusal(
        503,
        "CONNECTOR_NOT_VERIFIED",
        "This server has not verified the source's streams yet, so it cannot delete the source safely. Retry shortly.",
      );
    }
    throw error;
  }
}
