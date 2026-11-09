/**
 * The one answer to "has this account moved to stream sync?".
 *
 * A host builds ONE `AccountStorageMode` per runtime from the switch source it
 * already has (the Account setting, held locally as `streamSync.write`) and
 * hands that same instance to everything that needs the answer: the legacy
 * write gate (and its commit fence), the read selector and the MCP engines.
 * Two consumers can then never disagree, because there is one latch and it is
 * the only switch input: no second flag takes part in the decision.
 *
 * Three values:
 * - `switched`: the source has said true at least once. One-way: a later
 *   `false`, or a source that cannot be read, does not reopen legacy storage.
 * - `unswitched`: the source said false and has never said true.
 * - `unknown`: the source cannot be read and has never said true, or the caller
 *   asks about an owner this instance is not bound to. Reads and legacy writes
 *   both refuse with a retryable 503 while the mode is unknown.
 *
 * The source is sampled once when the instance is built, so a `true` the host
 * already holds at startup is latched before the first request. A host that
 * can change the source later (a config update) calls `read()` just before it
 * changes it, so no `true` is lost between samples.
 *
 * Reader presence is never the mode. Whether a stream reader is wired says what
 * this runtime can do; the mode says what the account has chosen.
 *
 * The latch lives inside each instance, never at module scope, so two accounts
 * in one process (two runtimes, two tests) cannot share it. An instance bound
 * to an owner answers `unknown` for any other owner.
 */

export type AccountStorageModeValue = "switched" | "unswitched" | "unknown";

export interface AccountStorageMode {
  /**
   * The mode right now. `requestOwner` is the owner the caller is acting for
   * (for example `deps.serverOwner`). When both it and the bound owner are
   * known and differ, the answer is `unknown`: this instance holds no
   * knowledge of that account.
   */
  read(requestOwner?: string): AccountStorageModeValue;
}

export interface CreateAccountStorageModeInput {
  /** The owner address this instance answers for. Unbound when absent. */
  owner?: string;
  /**
   * The raw switch: true once the account has moved to stream sync. Called on
   * every `read` until it says true; may throw when the Account is unreachable.
   */
  source: () => boolean;
}

function sameOwner(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

export function createAccountStorageMode(
  input: CreateAccountStorageModeInput,
): AccountStorageMode {
  let latched = false;
  const mode: AccountStorageMode = {
    read(requestOwner) {
      if (
        input.owner !== undefined &&
        requestOwner !== undefined &&
        !sameOwner(input.owner, requestOwner)
      ) {
        return "unknown";
      }
      if (latched) return "switched";
      try {
        if (input.source() === true) {
          latched = true;
          return "switched";
        }
        return "unswitched";
      } catch {
        return "unknown";
      }
    },
  };
  // Eager sample: latch a startup `true` before any request arrives.
  mode.read();
  return mode;
}

/** What a read of this account must use. */
export type StorageSelection =
  /** The account is switched: every read is answered from stream data only. */
  | { readonly kind: "streams" }
  /** The account is unswitched, or no mode is wired: reads behave as today. */
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

/** The retryable 503 for a read or legacy write while the mode is unknown. */
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
  readonly accountStorageMode?: AccountStorageMode;
  readonly serverOwner?: string;
}

/**
 * The one decision a read makes before it touches any store. Depends only on
 * the account mode; the presence of a stream reader plays no part.
 */
export function selectAccountStorageMode(
  deps: StorageSelectionDeps,
): StorageSelection {
  if (deps.accountStorageMode === undefined) return { kind: "legacy" };
  switch (deps.accountStorageMode.read(deps.serverOwner)) {
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
