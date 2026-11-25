/**
 * `DELETE /v1/owner/connectors/:connectorId/legacy`: retire a source's legacy
 * (pre-switch) copy and nothing else. `DELETE /v1/owner/connectors/:id` also
 * retires it, but only behind the connection's own delete, and it ends the
 * connection; after a delete that was never sent and a reconnect, that would
 * remove the new connection's data. This route leaves the connection, its
 * stream and its records alone.
 *
 * It takes no scope and no body: the retirement is of the legacy scopes the
 * server binds to the connector, at the gateway heads it reads when the
 * request is first made. A repeat, or a restart, resumes the same intent
 * (`localdb/legacy-retire-intent.ts`).
 *
 * Answers (the same refusals as the connector delete, before the writer):
 *   202 { retireId, legacy }    the intent is durable and retiring has begun
 *   400 INVALID_CONNECTOR       the id is not a connector key
 *   409 NOT_SWITCHED            the account has not moved to stream sync
 *   503 ACCOUNT_MODE_UNKNOWN    the storage mode cannot be read yet; retry
 *   503 LEGACY_RETIRE_UNAVAILABLE
 *                               this host cannot reach the legacy side now
 *   503 STREAM_SYNC_UNAVAILABLE no stream-sync writer is wired on this host
 *
 *   GET /v1/owner/connectors/:connectorId/legacy
 *     200 { retireId, legacy }  what is left of it
 *     404 NO_LEGACY_RETIREMENT  the connector has no such intent
 *
 * `legacy` is `{ state: "done" }` only after every bound scope was tombstoned
 * at the gateway, the tombstone is final and storage answered for every slot
 * of the scope's history; `{ state: "pending" }` while finality or storage
 * retries; `{ state: "blocked", reason }` when a gateway refusal or a head
 * that is not the pinned one (`legacy_head_changed`) will not change by
 * retrying.
 */

import {
  LegacyRetireNotAdmitted,
  LegacyRetireUnavailable,
} from "../localdb/legacy-retire-intent.js";
import {
  jsonNoStore,
  ownerConnectorRefusal,
  refusalBeforeWriter,
  unavailable,
  type OwnerConnectorDeleteDeps,
} from "./owner-connector-delete.js";

export async function handleOwnerLegacyRetire(
  request: Request,
  connectorId: string | null,
  deps: OwnerConnectorDeleteDeps,
): Promise<Response> {
  const refusal = await refusalBeforeWriter(request, connectorId, deps);
  if (refusal) return refusal;
  const port = deps.connectionDelete;
  if (!port?.requestLegacyRetire || !port.legacyRetireStatus)
    return unavailable();
  try {
    const { retireId } = await port.requestLegacyRetire(connectorId!);
    const status = await port.legacyRetireStatus(connectorId!);
    return jsonNoStore(202, {
      retireId,
      legacy: status?.legacy ?? { state: "pending" },
    });
  } catch (error) {
    if (error instanceof LegacyRetireNotAdmitted)
      return error.mode === "unknown"
        ? ownerConnectorRefusal(
            503,
            "ACCOUNT_MODE_UNKNOWN",
            "This server cannot tell yet whether the account has moved to stream sync. Retry shortly.",
          )
        : ownerConnectorRefusal(
            409,
            "NOT_SWITCHED",
            "This account has not moved to stream sync. Delete each scope of the source instead.",
          );
    if (error instanceof LegacyRetireUnavailable)
      return ownerConnectorRefusal(
        503,
        "LEGACY_RETIRE_UNAVAILABLE",
        "This server cannot reach the legacy copy now. Retry shortly.",
      );
    throw error;
  }
}

export async function handleOwnerLegacyRetireStatus(
  request: Request,
  connectorId: string | null,
  deps: OwnerConnectorDeleteDeps,
): Promise<Response> {
  const refusal = await refusalBeforeWriter(request, connectorId, deps);
  if (refusal) return refusal;
  const read = deps.connectionDelete?.legacyRetireStatus;
  if (!read) return unavailable();
  const status = await read.call(deps.connectionDelete, connectorId!);
  if (!status)
    return ownerConnectorRefusal(
      404,
      "NO_LEGACY_RETIREMENT",
      "No legacy retirement of this source was requested.",
    );
  return jsonNoStore(200, status);
}
