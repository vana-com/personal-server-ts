/**
 * The answer to a legacy scope delete on an account that has moved to stream
 * sync.
 *
 * A legacy delete removes legacy rows and the gateway's copy. On a switched
 * account the stream rows are the data, and a legacy delete leaves them
 * readable, so a 200 would say "deleted" about data that is still there. The
 * route refuses instead and points the client at the connector delete, which
 * erases the stream rows. This is the answer for a refused delete only; a
 * refused legacy write is `updateRequiredResponse` (426).
 */

export const USE_CONNECTOR_DELETE_CODE = "USE_CONNECTOR_DELETE";
export const USE_CONNECTOR_DELETE_STATUS = 409;
export const USE_CONNECTOR_DELETE_MESSAGE =
  "This account has moved to stream sync. Nothing was deleted. Delete the connection to erase its records.";

export function switchedDeleteRefusalResponse(): Response {
  return new Response(
    JSON.stringify({
      error: {
        code: USE_CONNECTOR_DELETE_STATUS,
        errorCode: USE_CONNECTOR_DELETE_CODE,
        message: USE_CONNECTOR_DELETE_MESSAGE,
      },
    }),
    {
      status: USE_CONNECTOR_DELETE_STATUS,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store",
      },
    },
  );
}
