/**
 * The one holder of the per-owner account-mode record, and the lock the legacy
 * write seals share with the On latch.
 *
 * - `read` is synchronous and never waits: before the first answer it is
 *   `unknown` (reads and legacy writes pause), after it `streams` or `legacy`.
 *   It follows the saved record only, so the person's data stays readable
 *   while the Account cannot be reached.
 * - `legacyWriteDecision` is what a legacy write gets. It is `read`, except
 *   that an Off authorizes a write only after a verified answer obtained in
 *   this process, and only while that answer is still the latest evidence.
 *   A saved Off is history, not permission: a restart starts with none, and a
 *   failed read (the host posts `unknown`) takes it away. Either way legacy
 *   writes get a retryable 503 until the next verified, current answer (its
 *   generation not below the record's), and nothing is erased: the record, its
 *   generation and an On stay as they were. A device that kept writing on a
 *   remembered Off could not tell that another device had switched the
 *   Account.
 * - Evidence is numbered per owner when it arrives, before any await. A
 *   verified answer takes effect only if no later evidence was submitted, so a
 *   slow save cannot undo a failed read that finished first. An answer that
 *   arrives and cannot be applied (its save or the record load fails) takes
 *   the earlier permission back, under the lock: the latest evidence says the
 *   record is not what the permission was given for.
 * - This is a local guarantee. It cannot make a switch on another device
 *   atomic with this device's storage: a write between the last verified read
 *   and the next one is detected afterwards, not prevented. Preventing it needs
 *   the registry to refuse legacy-protocol writes.
 * - A load that fails leaves the authority unloaded: `read` stays `unknown`
 *   for every owner, `submitEvidence` saves nothing, and the next
 *   `submitEvidence` retries the load before judging the evidence.
 * - `submitEvidence` takes the lock exclusively, saves the new record, then
 *   publishes it. A save that fails throws and changes nothing in memory.
 * - `commitLegacy` takes the lock shared and reads the record inside it with no
 *   await before the write starts. An On therefore waits for every legacy
 *   write already running, and no legacy write starts after it. This is the
 *   commit fence: a check made before the lock is only an early refusal.
 * - A write run under `commitLegacy` or `commitRemoval` must not call either
 *   again: the inner call would wait behind a queued On that waits for it.
 */

import {
  SWITCHED_REFUSAL,
  UNKNOWN_DECISION,
  applyAnswer,
  normalizeOwner,
  type AccountModeRecord,
  type ModeDecision,
  type ModeRecordStore,
  type RefuseDecision,
} from "./record.js";
import { createRwLock } from "./rw-lock.js";

export type CommitResult<T> =
  { ok: true; value: T } | { ok: false; decision: RefuseDecision };

/** What a host says about one owner after asking the Account. */
export interface ModeEvidenceInput {
  owner: string;
  /**
   * `unknown` (or anything else): the host could not read the Account. It
   * changes no record; it pauses legacy writes for an Off until a verified,
   * current answer, and returns the decision.
   */
  state: "on" | "off" | "unknown";
  /** Absent means 0. */
  generation?: number;
}

export interface ModeAuthority {
  /** Settles once the saved records are loaded. Never rejects; boot may skip it. */
  readonly ready: Promise<void>;
  /** The mode that reads and listings follow: the saved record, nothing else. */
  read(owner: string): ModeDecision;
  /**
   * What a legacy write gets right now, with no lock: for an early refusal or
   * a worker that wants to stop. The commit fence (`commitLegacy`) is the
   * decision; this is never a permission.
   */
  legacyWriteDecision(owner: string): ModeDecision;
  submitEvidence(input: ModeEvidenceInput): Promise<ModeDecision>;
  /** Run `write` as a legacy write: only for an owner whose answer is Off. */
  commitLegacy<T>(
    owner: string,
    write: () => T | Promise<T>,
  ): Promise<CommitResult<T>>;
  /** Run a pure removal under the same lock, in every mode. */
  commitRemoval<T>(work: () => T | Promise<T>): Promise<T>;
  /** Wait for work in flight, then refuse new legacy writes. */
  close(): Promise<void>;
}

export interface ModeAuthorityOptions {
  store: ModeRecordStore;
  now?: () => number;
  /** Called after an answer that leaves the owner On (the import wake-up). */
  onOn?: (owner: string) => void;
  onWarning?: (message: string, detail?: unknown) => void;
}

export function createModeAuthority(
  options: ModeAuthorityOptions,
): ModeAuthority {
  const now = options.now ?? Date.now;
  const warn = options.onWarning ?? (() => {});
  const records = new Map<string, AccountModeRecord>();
  const lock = createRwLock();
  /**
   * Owners whose latest evidence in this process was a verified answer that
   * is current (its generation is not older than the record's). In memory
   * only: a record is history and survives a restart, this is what the host
   * saw since this process started, so a restart starts empty.
   */
  const verified = new Set<string>();
  /**
   * The number of the latest evidence submitted for each owner, taken before
   * the first await. A verified answer ends a pause only while it is still the
   * latest: one asked before a later submission cannot speak for the Account's
   * state after it.
   */
  const latest = new Map<string, number>();
  let submissions = 0;
  let loaded = false;
  let loadFailed = false;
  let closed = false;
  /** One retry in flight, shared so concurrent evidence does not reload twice. */
  let reloadInFlight: Promise<void> | null = null;

  async function attemptLoad(): Promise<void> {
    try {
      const saved = await options.store.load();
      records.clear();
      for (const [owner, record] of saved)
        records.set(normalizeOwner(owner), record);
      loaded = true;
      loadFailed = false;
    } catch (error: unknown) {
      // A failed load is a distinct state, not an empty record set: the
      // records stay unloaded, reads stay unknown, and evidence saves nothing
      // until a later submit retries the load.
      warn("account mode records could not be loaded", error);
      loadFailed = true;
    }
  }

  const ready = attemptLoad();

  async function retryLoadIfFailed(): Promise<void> {
    if (!loadFailed) return;
    if (!reloadInFlight) {
      reloadInFlight = attemptLoad().finally(() => {
        reloadInFlight = null;
      });
    }
    await reloadInFlight;
  }

  function read(owner: string): ModeDecision {
    const record =
      loaded && typeof owner === "string"
        ? records.get(normalizeOwner(owner))
        : undefined;
    if (!record) return UNKNOWN_DECISION;
    return record.answer === "on" ? { kind: "streams" } : { kind: "legacy" };
  }

  function legacyWriteDecision(owner: string): ModeDecision {
    const decision = read(owner);
    return decision.kind === "legacy" &&
      !(typeof owner === "string" && verified.has(normalizeOwner(owner)))
      ? UNKNOWN_DECISION
      : decision;
  }

  return {
    ready,
    read,
    legacyWriteDecision,
    async submitEvidence(input) {
      // Before the first await, so a failed read takes effect at once and not
      // behind an earlier answer that is still waiting on its save.
      const owner = normalizeOwner(input.owner);
      const ticket = (submissions += 1);
      latest.set(owner, ticket);
      const answered = input.state === "on" || input.state === "off";
      if (!answered) verified.delete(owner);
      await ready;
      if (answered) {
        const release = await lock.exclusive();
        // An answer that arrived and was not applied (a failed save, a failed
        // load) is the latest evidence, and it is not an Off. The permission
        // an earlier verified answer gave is taken back under this lock, so no
        // legacy write can start on it, and only an applied answer restores it.
        let applied = false;
        try {
          // Retried under the lock, so the exclusive request is queued before
          // the load starts: an On still waits for legacy writes in flight,
          // and no legacy write starts after it.
          await retryLoadIfFailed();
          if (loadFailed) {
            // Still no records to judge against: save nothing, change nothing.
            return read(owner);
          }
          const prev = records.get(owner);
          const generation = input.generation ?? 0;
          const next = applyAnswer(
            prev,
            input.state as "on" | "off",
            generation,
            now(),
          );
          if (next !== prev) {
            await options.store.save(owner, next);
            records.set(owner, next);
          }
          applied = true;
          // Verified for this process only when nothing was submitted after
          // it and it is not older than the record.
          if (latest.get(owner) === ticket && generation >= next.generation) {
            verified.add(owner);
          }
        } finally {
          if (!applied) verified.delete(owner);
          release();
        }
      } else {
        await retryLoadIfFailed();
        // Nothing to add: the pause was set above, with no lock. A legacy
        // write already running keeps its shared hold, and every write that
        // starts later reads it inside its own hold.
      }
      const decision = legacyWriteDecision(owner);
      if (decision.kind === "streams") {
        try {
          options.onOn?.(owner);
        } catch (error) {
          warn("the On callback failed", error);
        }
      }
      return decision;
    },
    async commitLegacy(owner, write) {
      await ready;
      const release = await lock.shared();
      try {
        // No await between this read and the start of the write.
        const decision = closed ? UNKNOWN_DECISION : legacyWriteDecision(owner);
        if (decision.kind === "legacy") {
          return { ok: true, value: await write() };
        }
        return {
          ok: false,
          decision:
            decision.kind === "streams"
              ? SWITCHED_REFUSAL
              : (decision as RefuseDecision),
        };
      } finally {
        release();
      }
    },
    async commitRemoval(work) {
      const release = await lock.shared();
      try {
        return await work();
      } finally {
        release();
      }
    },
    async close() {
      closed = true;
      (await lock.exclusive())();
    },
  };
}
