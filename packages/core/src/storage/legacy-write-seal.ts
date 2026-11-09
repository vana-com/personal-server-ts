/**
 * The legacy-write seal: the one place that decides whether a legacy version
 * may become durable.
 *
 * Once an account has moved to stream sync, stream data is its only store and
 * no new legacy file may appear. Checking at the HTTP routes is not enough:
 * derivative compute, the download worker, boot recovery and a request that
 * was parked on I/O when the switch landed all reach storage without passing a
 * route. So the check lives where the bytes become durable. Every storage that
 * installs a legacy file or index row (Node index manager, Node file
 * publishing, import operations, the Lite index install) takes a seal and
 * wraps its final durable step in `commit`. A storage that holds no seal does
 * not compile; a seal that nobody has bound to a mode refuses (unknown).
 *
 * `commit(step)` asks the account mode, then runs `step` in the same tick:
 * there is no `await` between the question and the call that publishes. A
 * switch that lands later cannot undo a step that already started, so
 * `drain()` waits for the steps that started before the switch to finish.
 * Hosts call it after they observe the switch and before they delete legacy
 * files.
 *
 * Switched and unknown both refuse. The refusal is a
 * `LegacyWriteRefusedError` carrying the ready 426 or 503 response, so an HTTP
 * caller answers it as is and a background caller (worker, replay) can tell it
 * from a fault. The route-level checks stay as early refusals for a clean
 * answer before a body is read; nothing depends on them.
 *
 * Modeled on the read-side seal (`mcp/legacy-seal.ts`): the wrong action is
 * made impossible at the boundary instead of avoided by each caller.
 */

import type { AccountStorageMode } from "../api/account-storage-mode.js";
import {
  LegacyWriteRefusedError,
  legacyWriteVerdict,
  refuseLegacyWrite,
  type LegacyWriteVerdict,
} from "../api/legacy-write-gate.js";

export interface LegacyWriteSeal {
  /** What a legacy write may do right now. */
  verdict(): LegacyWriteVerdict;
  /** Throws `LegacyWriteRefusedError` unless the seal is open. */
  assertOpen(): void;
  /**
   * The one commit function. Asks the mode, then runs `step` synchronously. If
   * `step` returns a promise, the commit stays in flight until it settles.
   * Throws `LegacyWriteRefusedError` (and runs nothing) unless open.
   */
  commit<T>(step: () => T): T;
  /**
   * Resolves once every commit that started before this call has settled
   * (whether it succeeded or failed). A commit that starts later is refused if
   * the account has switched, so after a switch is observed this is enough to
   * know no legacy write is still landing.
   */
  drain(): Promise<void>;
}

export interface BindableLegacyWriteSeal extends LegacyWriteSeal {
  /**
   * Bind the seal to the account mode it answers for. Until then the seal
   * answers `unknown` and refuses. Binding the same mode again is a no-op;
   * binding a different one throws, because two modes for one store could
   * disagree.
   */
  bind(input: LegacyWriteSealBinding): void;
}

export interface LegacyWriteSealBinding {
  mode: AccountStorageMode;
  /** The owner this store holds data for. Unbound when absent. */
  owner?: string;
}

export function createLegacyWriteSeal(
  initial?: LegacyWriteSealBinding,
): BindableLegacyWriteSeal {
  let binding: LegacyWriteSealBinding | undefined = initial;
  const inFlight = new Set<Promise<unknown>>();

  const verdict = (): LegacyWriteVerdict =>
    // No mode bound is `unknown`, never `allow`.
    binding === undefined
      ? "unknown"
      : legacyWriteVerdict(binding.mode, binding.owner);

  const assertOpen = (): void => {
    const v = verdict();
    if (v === "allow") return;
    // `refuseLegacyWrite` builds the 426/503 response for the same verdict.
    const response = refuseLegacyWrite(binding?.mode, binding?.owner)!;
    throw new LegacyWriteRefusedError(response, v);
  };

  return {
    verdict,
    assertOpen,
    commit<T>(step: () => T): T {
      assertOpen();
      const result = step();
      if (isThenable(result)) {
        const tracked: Promise<unknown> = Promise.resolve(result).then(
          () => undefined,
          () => undefined,
        );
        inFlight.add(tracked);
        void tracked.then(() => inFlight.delete(tracked));
      }
      return result;
    },
    async drain() {
      // Commits that start while draining are not waited for: they are
      // refused once the account has switched.
      while (inFlight.size > 0) await Promise.all([...inFlight]);
    },
    bind(input) {
      if (binding !== undefined && binding.mode !== input.mode) {
        throw new Error("legacy write seal is already bound to another mode");
      }
      binding = input;
    },
  };
}

function isThenable(value: unknown): value is PromiseLike<unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { then?: unknown }).then === "function"
  );
}

export { LegacyWriteRefusedError } from "../api/legacy-write-gate.js";
export type { LegacyWriteVerdict } from "../api/legacy-write-gate.js";
