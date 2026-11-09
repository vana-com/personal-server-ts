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
 *                               and the delete is already done
 *   400 INVALID_CONNECTOR       the id is not a connector key
 *   409 NOT_SWITCHED            the account has not moved to stream sync
 *   503 ACCOUNT_MODE_UNKNOWN    the storage mode cannot be read yet; retry
 *   503 STREAM_SYNC_UNAVAILABLE no stream-sync writer is wired on this host
 */

import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";

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

function json(status: number, body: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
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

export async function handleOwnerConnectorDelete(
  request: Request,
  connectorId: string,
  deps: OwnerConnectorDeleteDeps,
): Promise<Response> {
  await deps.authorizeOwner(request);
  if (!isConnectorKey(connectorId)) {
    return json(400, {
      error: "INVALID_CONNECTOR",
      message: "connectorId is not a connector key",
    });
  }
  const mode = deps.mode.read(deps.owner);
  if (mode === "unknown") {
    return json(503, {
      error: "ACCOUNT_MODE_UNKNOWN",
      message:
        "This server cannot tell yet whether the account has moved to stream sync. Retry shortly.",
    });
  }
  if (mode !== "switched") {
    return json(409, {
      error: "NOT_SWITCHED",
      message:
        "This account has not moved to stream sync. Delete each scope of the source instead.",
    });
  }
  if (!deps.connectionDelete) {
    return json(503, {
      error: "STREAM_SYNC_UNAVAILABLE",
      message: "Stream sync is not running on this server.",
    });
  }
  const started =
    await deps.connectionDelete.requestConnectionDelete(connectorId);
  return json(202, { deleteId: started.deleteId });
}
