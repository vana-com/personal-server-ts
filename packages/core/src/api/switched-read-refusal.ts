/**
 * The typed answer for a switched account on a path that has no stream answer.
 *
 * Once an account has moved to stream sync, stream data is the only store, so
 * a route that can only read legacy files (or the canonical view) must say so
 * instead of serving them. The mode decision itself lives in
 * `account-storage-mode.ts`; this file only shapes the refusal.
 */

export const STREAM_SYNC_LEGACY_READ_UNAVAILABLE_CODE =
  "STREAM_SYNC_LEGACY_READ_UNAVAILABLE";
export const STREAM_SYNC_LEGACY_READ_UNAVAILABLE_STATUS = 409;

export function streamSyncLegacyReadUnavailableResponse(
  message: string,
): Response {
  return new Response(
    JSON.stringify({
      error: {
        code: STREAM_SYNC_LEGACY_READ_UNAVAILABLE_STATUS,
        errorCode: STREAM_SYNC_LEGACY_READ_UNAVAILABLE_CODE,
        message,
      },
    }),
    {
      status: STREAM_SYNC_LEGACY_READ_UNAVAILABLE_STATUS,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store",
      },
    },
  );
}

export const USE_CONNECTOR_DELETE_CODE = "USE_CONNECTOR_DELETE";

/**
 * The answer to a per-scope delete on a switched account. The apps reroute on
 * this code, so it is one body for every per-scope delete.
 */
export function useConnectorDeleteResponse(): Response {
  return new Response(
    JSON.stringify({
      error: USE_CONNECTOR_DELETE_CODE,
      message:
        "This account has moved to stream sync. Delete a source with DELETE /v1/owner/connectors/:connectorId.",
    }),
    {
      status: 409,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store",
      },
    },
  );
}
