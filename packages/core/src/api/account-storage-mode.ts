/**
 * The one answer to "has this account moved to stream sync?".
 *
 * The answer comes from exactly one place: the shared mode module
 * (`sync/account-mode`), which holds a durable per-owner record fed by the
 * Account's answers that hosts forward as evidence. `accountStorageModeOf`
 * turns that module into the `AccountStorageMode` port below, and a host hands
 * the same port to everything that needs the answer: the legacy write gate,
 * the read selector and the MCP engines. Two consumers can never disagree,
 * because there is one record. No consumer derives the mode from config.
 *
 * Three values:
 * - `switched`: the Account has said On for this owner. Permanent: a later Off
 *   at the same generation does not reopen legacy storage.
 * - `unswitched`: the Account said Off and has never said On. No expiry.
 * - `unknown`: no answer yet for this owner (a new owner, or another owner).
 *   Reads stay on the legacy path and never wait; legacy writes pause with a
 *   retryable 503 until the first answer. It is never permission to write.
 *
 * Reader presence is never the mode. Whether a stream reader is wired says what
 * this runtime can do; the mode says what the account has chosen.
 *
 * The owner is never optional. `read` takes the owner the caller acts for, so
 * a call without one does not type-check. Consumers do not hold the raw mode:
 * the host binds it to its own server owner once (`accountStorageModeFor`) and
 * hands consumers the bound view, whose `read()` cannot be asked about another
 * account.
 */

export type AccountStorageModeValue = "switched" | "unswitched" | "unknown";

export interface AccountStorageMode {
  /**
   * The mode right now, for the account `requestOwner`. Required: an empty
   * owner is `unknown`.
   */
  read(requestOwner: string): AccountStorageModeValue;
}

/**
 * A mode bound to the owner of the runtime that holds it. This is what every
 * consumer receives: its `read()` always asks about `owner` and nothing else,
 * so a consumer cannot drop the owner or ask about another account.
 */
export interface OwnedAccountStorageMode {
  readonly owner: string;
  read(): AccountStorageModeValue;
}

/**
 * Bind `mode` to the runtime's own server owner. A missing owner binds to the
 * empty string, which the mode answers `unknown`.
 */
export function accountStorageModeFor(
  mode: AccountStorageMode,
  owner: string | undefined,
): OwnedAccountStorageMode {
  const bound = owner ?? "";
  return { owner: bound, read: () => mode.read(bound) };
}

/** What a read of this account must use. */
export type StorageSelection =
  /** The account is switched: every read is answered from stream data only. */
  | { readonly kind: "streams" }
  /** Off, or no answer yet: reads behave as before the switch. */
  | { readonly kind: "legacy" };

export const ACCOUNT_MODE_UNKNOWN_CODE = "ACCOUNT_MODE_UNKNOWN";
export const ACCOUNT_MODE_UNKNOWN_STATUS = 503;
export const ACCOUNT_MODE_RETRY_AFTER_SECONDS = 5;

/** The retryable 503 a legacy write gets before the owner's first answer. */
export function accountModeUnknownResponse(): Response {
  const message =
    "This server has not heard from the account yet, so legacy writes are paused. Retry shortly.";
  return new Response(
    JSON.stringify({
      error: {
        code: ACCOUNT_MODE_UNKNOWN_STATUS,
        errorCode: ACCOUNT_MODE_UNKNOWN_CODE,
        message,
      },
    }),
    {
      status: ACCOUNT_MODE_UNKNOWN_STATUS,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store",
        "retry-after": String(ACCOUNT_MODE_RETRY_AFTER_SECONDS),
      },
    },
  );
}

/** The slice of the data API deps the selector reads. */
export interface StorageSelectionDeps {
  readonly accountStorageMode?: OwnedAccountStorageMode;
}

/**
 * The one decision a read makes before it touches any store. Only a switched
 * account reads streams; everything else, including an owner with no answer
 * yet, reads as before. Depends only on the account mode.
 */
export function selectAccountStorageMode(
  deps: StorageSelectionDeps,
): StorageSelection {
  return deps.accountStorageMode?.read() === "switched"
    ? { kind: "streams" }
    : { kind: "legacy" };
}
