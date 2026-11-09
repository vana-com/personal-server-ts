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
 * Two layers, one decision. The storage seal (`storage/legacy-write-seal.ts`)
 * is the invariant: every storage asks it immediately before the final durable
 * step, so no writer can publish a legacy file after the switch, whichever
 * route, worker or replay reached storage. This module's admission
 * (`admitLegacyWrite`) and route commit fence (`fenceLegacyCommit`) are early
 * refusals that answer a clean 426/503 before a body is read or an upload is
 * staged; correctness never depends on them. A route with no mode wired has no
 * early opinion; the seal still decides, and an unwired seal refuses.
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
 * The one decision. No mode wired is `unknown`, never `allow`: a store that was
 * not told what the account chose must not guess "legacy is fine".
 * `requestOwner` is the owner the write is for; a mode bound to another owner
 * answers unknown.
 */
export function legacyWriteVerdict(
  mode: AccountStorageMode | undefined,
  requestOwner?: string,
): LegacyWriteVerdict {
  if (mode === undefined) return "unknown";
  switch (mode.read(requestOwner)) {
    case "switched":
      return "switched";
    case "unknown":
      return "unknown";
    case "unswitched":
      return "allow";
  }
}

/**
 * Hands a ready refusal back through a handler or a background caller. Thrown
 * by the legacy-write seal (`storage/legacy-write-seal.ts`) at the final
 * durable step and by the route-level early refusals. `verdict` says why:
 * `switched` (426, do not retry) or `unknown` (503, retry).
 */
export class LegacyWriteRefusedError extends Error {
  constructor(
    readonly response: Response,
    readonly verdict: "switched" | "unknown" = response.status === 426
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

/**
 * The early, route-level refusal: a clean 426 or 503 before a body is read. A
 * route with no mode wired has no opinion here (`null`); the storage seal still
 * refuses at the final durable step, so nothing relies on this answer.
 */
export function admitLegacyWrite(
  mode: AccountStorageMode | undefined,
  requestOwner?: string,
): Response | null {
  return mode === undefined ? null : refuseLegacyWrite(mode, requestOwner);
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
  const refusal = admitLegacyWrite(mode, requestOwner);
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
