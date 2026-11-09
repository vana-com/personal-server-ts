/**
 * `DELETE /v1/owner/connectors/:connectorId`: the one way an owner deletes a
 * source's data once the account has moved to stream sync. The Node server
 * and the Lite runtime both answer through this handler, so the two cannot
 * disagree about what the route refuses.
 *
 * The switch is the one the legacy write gate reads (`LegacyWriteSwitch`).
 * An unswitched account keeps the per-scope loop, so this route refuses it
 * with `NOT_SWITCHED` and changes nothing.
 *
 * Answers:
 *   202 { deleteId }            the delete intent is durable; the landing runs
 *                               in the writer and retries until it lands. When
 *                               the registry lists nothing of the connector,
 *                               the writer purges this device's local state
 *                               and the delete is already done
 *   400 INVALID_CONNECTOR       the id is not a connector key
 *   409 NOT_SWITCHED            the account has not moved to stream sync
 *   503 STREAM_SYNC_UNAVAILABLE no stream-sync writer is wired on this host
 */

import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";
import type { LegacyWriteSwitch } from "./legacy-write-gate.js";

/** The writer's side of the route: persist the intent, then answer. */
export interface ConnectionDeletePort {
  requestConnectionDelete(
    connector: string,
  ): Promise<{ readonly deleteId: string }>;
}

export interface OwnerConnectorDeleteDeps {
  /** Throws the host's auth error for anyone but the owner. */
  authorizeOwner(request: Request): Promise<void>;
  /** The account's switch, read at the moment of the request. */
  switched: LegacyWriteSwitch;
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
  if (!deps.switched()) {
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

/**
 * The refusal for a per-scope `DELETE` on a switched account. The source's
 * data is deleted per connector, so no part of a connection can be deleted
 * through a scope. Returns `null` when the delete may proceed. The caller is
 * authorized first: an unauthenticated caller learns nothing of the switch
 * (`authorizeOwner` throws the host's auth error).
 */
export async function refuseScopeDelete(
  request: Request,
  switched: LegacyWriteSwitch | undefined,
  authorizeOwner: (request: Request) => Promise<void>,
): Promise<Response | null> {
  if (!switched || !switched()) return null;
  await authorizeOwner(request);
  return json(409, {
    error: "USE_CONNECTOR_DELETE",
    message:
      "This account has moved to stream sync. Delete a source with DELETE /v1/owner/connectors/:connectorId.",
  });
}
