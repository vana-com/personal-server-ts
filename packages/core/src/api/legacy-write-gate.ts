/**
 * The one check that refuses a legacy-format write once an account has moved
 * to stream sync.
 *
 * Switch state: the server already holds it locally as `streamSync.write`,
 * which its host sets from the Account setting (`GET /api/v1/me/stream-sync`)
 * before each launch. A host builds one `AccountStorageMode` from that source
 * and passes the same instance here and to the read selector, so the state
 * cannot fall back once seen and cannot differ between the two. That mode is
 * the only switch input: this module takes no flag of its own and keeps no
 * latch of its own.
 *
 * Two checks, one decision. Admission refuses early, before any body is read.
 * The commit fence (`fenceLegacyCommit`) asks again immediately before each
 * durable publication, with no `await` between the question and the call that
 * publishes, so a switch that lands while a request was parked on I/O refuses
 * that request with nothing stored.
 *
 * Unknown: a mode that cannot be established (the host gave no evidence, or
 * the owner does not match) refuses legacy writes with a retryable 503
 * `ACCOUNT_MODE_UNKNOWN`, like reads. A known-unswitched account is never
 * refused.
 *
 * Who is refused: every legacy write for a switched account, from every
 * caller. No request header and no delegated builder signature exempts a
 * write. A client built for stream sync that still makes a legacy write is
 * refused too, so the client must stop making legacy writes on switched
 * accounts. Unswitched accounts are never refused.
 */

import {
  accountModeUnknownResponse,
  type AccountStorageMode,
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

/** What a legacy write may do right now. */
export type LegacyWriteVerdict = "allow" | "switched" | "unknown";

/**
 * The one decision. No mode wired means no gate: `allow`. `requestOwner` is
 * the owner the write is for; a mode bound to another owner answers unknown.
 */
export function legacyWriteVerdict(
  mode: AccountStorageMode | undefined,
  requestOwner?: string,
): LegacyWriteVerdict {
  if (mode === undefined) return "allow";
  switch (mode.read(requestOwner)) {
    case "switched":
      return "switched";
    case "unknown":
      return "unknown";
    case "unswitched":
      return "allow";
  }
}

/** Thrown by `fenceLegacyCommit` to hand a ready refusal back through a handler. */
export class LegacyWriteRefusedError extends Error {
  constructor(readonly response: Response) {
    super("legacy write refused");
  }
}

/**
 * The commit fence. Call it immediately before the call that makes a legacy
 * write durable, after every `await` that precedes it. It re-reads the mode,
 * so a switch seen since admission refuses the write before anything is
 * stored. Throws `LegacyWriteRefusedError`; the caller's surrounding handler
 * turns it into the response and discards anything it staged.
 */
export function fenceLegacyCommit(
  mode: AccountStorageMode | undefined,
  requestOwner?: string,
): void {
  const refusal = refuseLegacyWrite(mode, requestOwner);
  if (refusal) throw new LegacyWriteRefusedError(refusal);
}

/**
 * The refusal for a legacy write, or `null` when the write may proceed.
 * HTTP entries return this response; the decision is `legacyWriteVerdict`.
 */
export function refuseLegacyWrite(
  mode: AccountStorageMode | undefined,
  requestOwner?: string,
): Response | null {
  const verdict = legacyWriteVerdict(mode, requestOwner);
  if (verdict === "allow") return null;
  if (verdict === "unknown") return accountModeUnknownResponse();
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
