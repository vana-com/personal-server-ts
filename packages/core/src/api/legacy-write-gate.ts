/**
 * The one check that refuses a legacy-format write unless the account has a
 * fresh explicit Off.
 *
 * The gate reads the owner-bound `AccountStorageMode`, the same instance the
 * read selector reads, so it holds no state of its own. Three answers:
 * - `unswitched`: the write may proceed.
 * - `switched`: refused with 426, from every caller. No request header and no
 *   delegated builder signature exempts a write. A client built for stream
 *   sync that still makes a legacy write is refused too.
 * - `unknown`, or no mode wired: refused with a retryable 503
 *   (`ACCOUNT_MODE_UNKNOWN`). A missing answer is never permission.
 *
 * This is an admission check. The write that follows must still pass the
 * module's commit seal (`ModeAuthority.commitLegacy`) at its durable step.
 */

import {
  accountModeUnknownResponse,
  type OwnedAccountStorageMode,
} from "./account-storage-mode.js";

export const UPDATE_REQUIRED_CODE = "update_required";
export const UPDATE_REQUIRED_STATUS = 426;
/**
 * The header a stream-sync client sends on the legacy writes it still makes.
 * It declares nothing that changes the outcome: a switched account refuses the
 * write whether or not this header is present.
 */
export const STREAM_SYNC_CLIENT_HEADER = "vana-stream-sync-client";

export const UPDATE_REQUIRED_MESSAGE =
  "This account has moved to stream sync. Update the Vana app to keep syncing. The data already on this device is untouched.";

/** What the gate reads: the owner-bound mode, or nothing wired. */
export type LegacyWriteMode = Pick<OwnedAccountStorageMode, "read">;

/**
 * The one decision: whether a legacy write must be refused right now. Only a
 * fresh explicit Off lets it through.
 */
export function legacyWritesRefused(
  mode: LegacyWriteMode | undefined,
): boolean {
  return (mode?.read() ?? "unknown") !== "unswitched";
}

/**
 * The refusal for a legacy write, or `null` when the write may proceed.
 * HTTP entries return this response; the decision is `legacyWritesRefused`.
 */
export function refuseLegacyWrite(
  mode: LegacyWriteMode | undefined,
): Response | null {
  const value = mode?.read() ?? "unknown";
  if (value === "unswitched") return null;
  if (value === "unknown") return accountModeUnknownResponse();
  // Both error shapes the legacy surface uses, so an old client reads the
  // message from whichever field it already knows.
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
