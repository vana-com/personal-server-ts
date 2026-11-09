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
 * - `switched`: the Account has said On for this owner at least once. One-way
 *   here: a later Off, an unknown answer or an expiry does not reopen legacy
 *   storage.
 * - `unswitched`: the Account recently said an explicit Off for this owner and
 *   has never said On. "Recently" is bounded (see `OFF_TTL_MS`).
 * - `unknown`: anything else, including an owner the module has never heard
 *   about and a caller that names no owner or another owner. Unknown refuses
 *   legacy reads and writes with a retryable 503; it is never permission.
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
  /** The account has a fresh explicit Off: reads behave as before the switch. */
  | { readonly kind: "legacy" }
  /**
   * The mode cannot be established and nothing is latched. Never legacy: the
   * caller answers `response` (503, retryable) and reads nothing.
   */
  | {
      readonly kind: "refuse";
      readonly reason: "mode_unknown";
      readonly retryable: true;
      readonly response: Response;
    };

export const ACCOUNT_MODE_UNKNOWN_CODE = "ACCOUNT_MODE_UNKNOWN";
export const ACCOUNT_MODE_UNKNOWN_STATUS = 503;
export const ACCOUNT_MODE_RETRY_AFTER_SECONDS = 5;

/** The retryable 503 for a request the module cannot place yet. */
export function accountModeUnknownResponse(): Response {
  const message =
    "This server cannot tell yet whether the account has moved to stream sync. Retry shortly.";
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
 * The one decision a read makes before it touches any store. Depends only on
 * the account mode; the presence of a stream reader plays no part.
 */
export function selectAccountStorageMode(
  deps: StorageSelectionDeps,
): StorageSelection {
  // No mode wired is unknown, never "behave as before the switch existed".
  switch (deps.accountStorageMode?.read() ?? "unknown") {
    case "switched":
      return { kind: "streams" };
    case "unswitched":
      return { kind: "legacy" };
    case "unknown":
      return {
        kind: "refuse",
        reason: "mode_unknown",
        retryable: true,
        response: accountModeUnknownResponse(),
      };
  }
}
