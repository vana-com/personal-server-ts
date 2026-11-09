/**
 * Fail fast when a seal callback calls back into the authority that runs it.
 *
 * A commit callback (`commitLegacy`, `commitStream`, `commitImportSeed`) runs
 * while the authority's lock is held. A call back into the authority from
 * inside it that takes the lock, or waits for the lock, waits for the callback
 * to finish, and the callback waits for that call: a deadlock with no error.
 * This guard makes such a call throw `ReentrantAuthorityCall` at once.
 *
 * The callback is marked with an async-context value (`AsyncLocalStorage`), so
 * the mark follows the callback's own awaits, timers and promises, and does
 * not reach a call that merely runs at the same time. No timeout is involved.
 *
 * Where the guard is off: this module is bundled for browsers, so it never
 * imports `node:async_hooks`. It asks the host for it at run time
 * (`process.getBuiltinModule`, Node 22.3 and later). Where the host gives no
 * `AsyncLocalStorage` (a browser, or an older Node), the guard is OFF and a
 * re-entrant call waits forever as it did before. `callbackGuardAvailable`
 * tells a caller or a test which case it is in.
 *
 * The mark ends when the callback settles. A timer or promise that the callback
 * started and that outlives it is outside the mark.
 */

/** An authority call was made from inside a callback that the authority runs. */
export class ReentrantAuthorityCall extends Error {
  constructor(call: string) {
    super(
      `${call} was called from inside a commit callback of the same authority, ` +
        "which holds the lock that call needs",
    );
    this.name = "ReentrantAuthorityCall";
  }
}

interface Frame {
  active: boolean;
}

/** The part of `AsyncLocalStorage` that the guard uses. */
export interface AsyncLocal {
  run<R>(frame: Frame, fn: () => R): R;
  getStore(): Frame | undefined;
}

export type AsyncLocalConstructor = new () => AsyncLocal;

function detectAsyncLocalStorage(): AsyncLocalConstructor | null {
  try {
    const host = globalThis as {
      process?: { getBuiltinModule?: (id: string) => unknown };
    };
    const loaded = host.process?.getBuiltinModule?.("node:async_hooks") as
      { AsyncLocalStorage?: AsyncLocalConstructor } | undefined;
    return loaded?.AsyncLocalStorage ?? null;
  } catch {
    return null;
  }
}

const detected = detectAsyncLocalStorage();

/** True where a re-entrant call is detected; false where the guard is off. */
export const callbackGuardAvailable = detected !== null;

export interface CallbackGuard {
  /** Run a seal callback with the mark set; the mark ends when it settles. */
  run<T>(callback: () => T | Promise<T>): Promise<T>;
  /** Throw `ReentrantAuthorityCall` when called from inside a callback. */
  assertOutside(call: string): void;
}

/** One guard per authority: a callback of one may call another authority. */
export function createCallbackGuard(
  storage: AsyncLocalConstructor | null = detected,
): CallbackGuard {
  if (storage === null) {
    return {
      run: async (callback) => await callback(),
      assertOutside: () => {},
    };
  }
  const local = new storage();
  return {
    async run(callback) {
      const frame: Frame = { active: true };
      try {
        return await local.run(frame, callback);
      } finally {
        frame.active = false;
      }
    },
    assertOutside(call) {
      if (local.getStore()?.active === true) {
        throw new ReentrantAuthorityCall(call);
      }
    },
  };
}
