/**
 * The one check that refuses a legacy-format write once an account has moved
 * to stream sync.
 *
 * Switch state: the server already holds it locally as `streamSync.write`,
 * which its host sets from the Account setting (`GET /api/v1/me/stream-sync`)
 * before each launch. A caller passes that state in; this module never reads
 * config or the network.
 *
 * Who is refused: a legacy write that does not declare itself stream-sync
 * aware. A client built for stream sync sends `Vana-Stream-Sync-Client: 1` on
 * every legacy write it still makes; a client built before stream sync cannot
 * send it. The header is a capability declaration, not a credential: it
 * decides which message the caller gets, never what the caller may read.
 */

export const UPDATE_REQUIRED_CODE = "update_required";
export const UPDATE_REQUIRED_STATUS = 426;
export const STREAM_SYNC_CLIENT_HEADER = "vana-stream-sync-client";

export const UPDATE_REQUIRED_MESSAGE =
  "This account has moved to stream sync. Update the Vana app to keep syncing. The data already on this device is untouched.";

/** The switch state a server reads at the moment of the write. */
export type LegacyWriteSwitch = () => boolean;

export function declaresStreamSyncClient(request: Request): boolean {
  return request.headers.get(STREAM_SYNC_CLIENT_HEADER) === "1";
}

/**
 * The refusal for a legacy write, or `null` when the write may proceed.
 * `switchedOn` absent means no gate was wired: every write proceeds.
 */
export function refuseLegacyWrite(
  request: Request,
  switchedOn: LegacyWriteSwitch | undefined,
): Response | null {
  if (!switchedOn || !switchedOn()) return null;
  if (declaresStreamSyncClient(request)) return null;
  return updateRequiredResponse();
}

/**
 * The 426 that refuses a legacy write (or a data-set delete) once the account
 * has moved to stream sync. Both error shapes the legacy surface uses, so an
 * old client reads the message from whichever field it already knows.
 */
export function updateRequiredResponse(): Response {
  return new Response(
    JSON.stringify({
      error: {
        code: UPDATE_REQUIRED_STATUS,
        errorCode: UPDATE_REQUIRED_CODE,
        message: UPDATE_REQUIRED_MESSAGE,
      },
      errorCode: UPDATE_REQUIRED_CODE,
      message: UPDATE_REQUIRED_MESSAGE,
    }),
    {
      status: UPDATE_REQUIRED_STATUS,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store",
        upgrade: "vana-stream-sync",
      },
    },
  );
}
