/**
 * The legacy-write seal: the one place a legacy write is allowed to become
 * durable.
 *
 * Once an account has moved to stream sync, stream data is its only store and
 * no new legacy file, row or remote object may appear. Checking at the HTTP
 * routes is not enough: derivative compute, the download worker, boot
 * recovery and a request parked on I/O when the switch landed all reach
 * storage without passing a route. So the check lives where the bytes become
 * durable, and it is the mode module's own seal (`ModeAuthority.commitLegacy`),
 * not a copy of its answer:
 *
 * - `commit(write)` takes the module's shared lock, re-reads the durable
 *   record inside it and runs `write` only for an unswitched account. The On
 *   latch takes the same lock exclusively, so it waits for every write that
 *   started before it and no write starts after it. There is no gap between
 *   the question and the write for an On to land in.
 * - `remove(work)` is the same lock for a pure removal, admitted in every
 *   mode. A person must always be able to remove data, and the host erases
 *   legacy files after the switch through the same storage. Nothing new may
 *   become durable inside it.
 * - `admit()` is the early, unlocked refusal a route gives before it reads a
 *   body. It is a courtesy: nothing depends on it.
 *
 * A storage cannot skip the seal. Every call that installs a legacy file or
 * index row takes a `LegacyWriteHold`, and the only place a hold exists is
 * inside `commit`. Code that writes without one does not compile.
 *
 * The lock is not re-entrant, and it queues a waiting On ahead of later
 * shared holders. So a write inside `commit` or `remove` must not call
 * `commit` or `remove` again, and must not wait on a lock that another sealed
 * caller holds while it waits for this one: take scope locks before the seal.
 */

import {
  LegacyWriteRefusedError,
  legacyWriteRefusedErrorFor,
  updateRequiredResponse,
  type LegacyWriteVerdict,
} from "../api/legacy-write-gate.js";
import { accountModeUnknownResponse } from "../api/account-storage-mode.js";
import type {
  ModeAuthority,
  ModeDecision,
} from "../sync/account-mode/index.js";

declare const held: unique symbol;

/**
 * Proof that the caller is inside `LegacyWriteSeal.commit`. Required by every
 * call that installs a legacy file or index row. It carries no data.
 */
export interface LegacyWriteHold {
  readonly [held]: true;
}

export interface LegacyWriteSeal {
  /**
   * Run `write` as a legacy write: refused unless the account is unswitched,
   * decided under the module's shared lock. Throws `LegacyWriteRefusedError`
   * (and runs nothing) when refused.
   */
  commit<T>(write: (hold: LegacyWriteHold) => T | Promise<T>): Promise<T>;
  /** Run a pure removal under the same lock, in every mode. */
  remove<T>(work: () => T | Promise<T>): Promise<T>;
  /** The early refusal for a legacy write (no lock), or `null` when open. */
  admit(): Response | null;
  /**
   * What a legacy write would get right now, without taking the lock. For a
   * background worker that wants to stop early; never a permission.
   */
  verdict(): "allow" | LegacyWriteVerdict;
}

export type SealAuthority = Pick<
  ModeAuthority,
  "read" | "commitLegacy" | "commitRemoval"
>;

export interface LegacyWriteSealInput {
  authority: SealAuthority;
  /**
   * The owner this store holds data for. A store with no owner cannot say
   * which account it holds, so its writes get the retryable 503.
   */
  owner: string | undefined;
}

const HOLD = {} as LegacyWriteHold;

export function createLegacyWriteSeal(
  input: LegacyWriteSealInput,
): LegacyWriteSeal {
  const owner = input.owner ?? "";

  return {
    async commit(write) {
      const result = await input.authority.commitLegacy(owner, () =>
        write(HOLD),
      );
      if (!result.ok)
        throw legacyWriteRefusedErrorFor(
          result.decision.status === 426 ? "switched" : "unknown",
        );
      return result.value;
    },
    remove: (work) => input.authority.commitRemoval(work),
    admit() {
      switch (verdictOf(input.authority.read(owner))) {
        case "allow":
          return null;
        case "switched":
          return updateRequiredResponse();
        case "unknown":
          return accountModeUnknownResponse();
      }
    },
    verdict() {
      return verdictOf(input.authority.read(owner));
    },
  };
}

/** Off allows; On is 426; no answer yet is the retryable 503. */
function verdictOf(decision: ModeDecision): "allow" | LegacyWriteVerdict {
  if (decision.kind === "legacy") return "allow";
  if (decision.kind === "streams") return "switched";
  return decision.status === 426 ? "switched" : "unknown";
}

export { LegacyWriteRefusedError };
export type { LegacyWriteVerdict };
