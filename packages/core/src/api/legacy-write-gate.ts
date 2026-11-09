/**
 * The one check that refuses a legacy-format write once an account has moved
 * to stream sync.
 *
 * Switch state: the server already holds it locally as `streamSync.write`,
 * which its host sets from the Account setting (`GET /api/v1/me/stream-sync`)
 * before each launch. A caller passes that state in; this module never reads
 * config or the network. Each host builds one `AccountStorageMode` from its
 * source and derives this gate's switch with `legacyWriteSwitchOf`, so the
 * state it reads cannot fall back once seen and cannot differ from the
 * answer the read selector gets.
 *
 * Who is refused: every legacy write for a switched account, from every
 * caller. No request header and no delegated builder signature exempts a
 * write. A client built for stream sync that still makes a legacy write is
 * refused too, so the client must stop making legacy writes on switched
 * accounts. Unswitched accounts are never refused.
 */

import {
  createAccountStorageMode,
  legacyWriteSwitchOf,
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

/** The switch state a server reads at the moment of the write. */
export type LegacyWriteSwitch = () => boolean;

/**
 * A one-way latch over the switch source, as the write gate's view of an
 * `AccountStorageMode` (see `account-storage-mode.ts`, which owns the latch).
 * Hosts build the mode once and pass that instance to the gate and to the read
 * selector; this wrapper remains for a caller that has only a raw source.
 * Before the source has ever said true, a source that throws reads as not
 * switched, so an unreachable source never blocks an unswitched account's
 * writes (fail open).
 */
export function latchLegacyWriteSwitch(
  source: LegacyWriteSwitch,
): LegacyWriteSwitch {
  return legacyWriteSwitchOf(createAccountStorageMode({ source }));
}

/**
 * The one decision: whether a legacy write must be refused right now.
 * `switchedOn` absent means no gate was wired: nothing is refused.
 */
export function legacyWritesRefused(
  switchedOn: LegacyWriteSwitch | undefined,
): boolean {
  return switchedOn !== undefined && switchedOn() === true;
}

/**
 * The refusal for a legacy write, or `null` when the write may proceed.
 * HTTP entries return this response; the decision is `legacyWritesRefused`.
 */
export function refuseLegacyWrite(
  switchedOn: LegacyWriteSwitch | undefined,
): Response | null {
  if (!legacyWritesRefused(switchedOn)) return null;
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
