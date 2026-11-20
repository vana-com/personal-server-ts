/**
 * The legacy-write gate: the words a refused legacy write is answered with.
 *
 * It decides nothing. The mode module (`sync/account-mode`) decides, and the
 * legacy-write seal (`storage/legacy-write-seal.ts`) asks it under the
 * module's lock. This file only turns an answer into the 426 or 503 a legacy
 * client reads, and carries that answer through a handler as an error.
 *
 * - switched: 426 `update_required`, from every caller. No request header and
 *   no delegated builder signature exempts a write.
 * - unknown, or no mode wired: a retryable 503 `ACCOUNT_MODE_UNKNOWN`. A
 *   missing answer is never permission.
 *
 * `refuseLegacyWrite` is the early, unlocked refusal a route gives before it
 * reads a body. It is a courtesy: the write that follows must still pass the
 * seal at its durable step.
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

/** What the early refusal reads: the owner-bound mode, or nothing wired. */
export type LegacyWriteMode = Pick<OwnedAccountStorageMode, "read">;

/** Why a legacy write was refused: the account switched, or the mode is unknown. */
export type LegacyWriteVerdict = "switched" | "unknown";

/** The 426 an old client reads. */
export function updateRequiredResponse(): Response {
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

/**
 * A refused legacy write, carried through a handler or a background caller.
 * Thrown by the legacy-write seal; `verdict` says why: `switched` (426, never
 * retry) or `unknown` (503, retry).
 */
export class LegacyWriteRefusedError extends Error {
  constructor(
    readonly response: Response,
    readonly verdict: LegacyWriteVerdict = response.status === 426
      ? "switched"
      : "unknown",
  ) {
    super(
      verdict === "switched"
        ? "legacy write refused: the account has moved to stream sync"
        : "legacy write refused: the account storage mode is unknown",
    );
    this.name = "LegacyWriteRefusedError";
  }
}

/** The error for a module answer that refused a legacy write. */
export function legacyWriteRefusedErrorFor(
  verdict: LegacyWriteVerdict,
): LegacyWriteRefusedError {
  return new LegacyWriteRefusedError(
    verdict === "switched"
      ? updateRequiredResponse()
      : accountModeUnknownResponse(),
    verdict,
  );
}

/**
 * The early, unlocked refusal for a legacy write, or `null` when the mode
 * says unswitched. A translation of the module's answer and nothing more.
 */
export function refuseLegacyWrite(
  mode: LegacyWriteMode | undefined,
): Response | null {
  switch (mode?.read() ?? "unknown") {
    case "unswitched":
      return null;
    case "switched":
      return updateRequiredResponse();
    case "unknown":
      return accountModeUnknownResponse();
  }
}
