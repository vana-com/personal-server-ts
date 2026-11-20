/**
 * The one holder of the per-owner account-mode record, and the lock the legacy
 * write seals share with the On latch.
 *
 * - `read` is synchronous and never waits: before the first answer it is
 *   `unknown` (reads and legacy writes pause), after it `streams` or `legacy`.
 *   It follows the saved record only, so the person's data stays readable
 *   while the Account cannot be reached.
 * - `legacyWriteDecision` is what a legacy write gets. It is `read`, except
 *   while an answer is waiting to be applied (below) or after an answer that
 *   did not take effect (a save that failed, or a generation older than the
 *   record's). The saved Off is the Account's last word, and it authorizes
 *   legacy writes after a restart and while the Account cannot be read: a
 *   failed read (the host posts `unknown`) changes nothing, so a person who
 *   never switched keeps importing when the Account is slow or down. Before
 *   any answer there is no record and no permission: `unknown`, as before.
 *   The remembered Off is not the registry's view of the Account: if the
 *   person switched on another device, this device keeps writing legacy data
 *   until its next fresh answer; only the registry can refuse that write
 *   (see the last point). Nothing here erases or lowers a record: an On stays On, a fresh answer always replaces
 *   the remembered one by the generation rule in `record.ts`.
 * - Answers are numbered per owner when they arrive, before any await. An
 *   answer takes effect only if no later answer was submitted, so a slow save
 *   cannot undo a newer answer that finished first. A failed read is not an
 *   answer and takes no number.
 * - An answer that has arrived and is not applied yet suspends the permission
 *   from its arrival: `legacyWriteDecision` is `unknown` for that owner, and a
 *   `commitLegacy` that has not started waits once for the answers pending
 *   when it was asked for, then judges inside the lock. Evidence that arrives
 *   after that is not waited for (a steady stream could renew the wait
 *   forever): the write gets the retryable `unknown`, never a pass. So no
 *   write starts on a permission that an arrived answer may contradict, and
 *   an Off poll that applies unchanged only delays a write. Only a write
 *   already running keeps its hold; the On waits for it.
 *   When the answer settles, what it does to the permission is one of three
 *   effects (`PermissionEffect`):
 *   - lift: it was applied, is the latest, and is not older than the record.
 *   - withdraw: it failed to apply (a save that threw), is not the latest, or is
 *     older than the record. The owner stays without permission until a later
 *     current answer lifts it; a failed read does not give it back.
 *   - keep: it could not be judged because the records would not load. It is
 *     held (below) and judged when they do; until then it changes nothing, like
 *     a failed read, and the owner has no permission.
 *   This is a change to the in-memory write permission only: the saved record
 *   and what reads follow stay as they were.
 * - This is a local guarantee. It cannot make a switch on another device
 *   atomic with this device's storage: a write between the last answer and the
 *   next one is detected afterwards, not prevented. Preventing it needs the
 *   registry to refuse legacy-protocol writes.
 * - A load that fails leaves the authority unloaded: `read` stays `unknown`
 *   for every owner, `submitEvidence` saves nothing, and the next
 *   `submitEvidence` retries the load before judging the evidence. The answers
 *   that arrive meanwhile are held per owner, in arrival order (`held` below),
 *   and applied when the records load, each as a live answer is; the owner has
 *   no permission until they are all applied. A submission that loads the
 *   records returns only after that, with the decision a write then meets.
 * - `submitEvidence` takes the lock exclusively, saves the new record, then
 *   publishes it. A save that fails throws; the record in memory stays as it
 *   was, and legacy-write permission is withdrawn for that owner (above).
 *   The withdrawal is held in memory only, so a restart restores the saved
 *   Off: the store keeps the record it had (a failed save leaves it unchanged:
 *   the file store replaces by rename, the IndexedDB store by one transaction),
 *   and that Off authorizes legacy writes again while the Account cannot be
 *   read. The next answer the Account gives replaces it, and the registry
 *   refuses legacy-protocol writes once the owner is On.
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

/** What an answer does to its owner's write permission when it settles. */
type PermissionEffect = "lift" | "withdraw" | "keep";

/**
 * The most runs of different answers held per owner. Past it the runs are
 * reduced to the highest On and the owner is not given the permission when
 * they are applied: a backlog that long is a store that has been down through
 * hundreds of switches, and a fresh answer replaces it.
 */
const MAX_HELD_RUNS = 64;

/** The answers of one owner that could not be judged yet, in arrival order. */
interface HeldAnswers {
  /**
   * Consecutive identical answers are one run with a count: each is a save
   * attempt when applied, as on the readable path, but a poll that repeats
   * costs a number, not a backlog.
   */
  runs: Array<{
    state: "on" | "off";
    generation: number;
    count: number;
    /** The ticket of the run's last answer. */
    ticket: number;
  }>;
  /** Runs were dropped (`MAX_HELD_RUNS`): the permission is not given back. */
  lossy: boolean;
}

export type CommitResult<T> =
  { ok: true; value: T } | { ok: false; decision: RefuseDecision };

/** What a host says about one owner after asking the Account. */
export interface ModeEvidenceInput {
  owner: string;
  /**
   * `unknown` (or anything else): the host could not read the Account. It
   * changes nothing, neither the record nor the permission it gives, and
   * returns the decision the remembered answer gives (`unknown` with none).
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
   * Owners whose latest answer did not take effect: it could not be saved, its
   * generation is older than the record's, or it was superseded. The
   * remembered Off must not keep authorizing writes against an answer the
   * Account just gave and this process could not keep. In memory only, so a
   * restart clears it (see `submitEvidence` above); a later answer that
   * applies and is current removes the owner. A failed read, and an answer
   * held because the records would not load, add or remove no one.
   */
  const withdrawn = new Set<string>();
  /**
   * The number of the latest answer submitted for each owner, taken before
   * the first await. An answer lifts a withdrawal only while it is still the
   * latest: one submitted before a later answer cannot speak for the Account's
   * state after it.
   */
  const latest = new Map<string, number>();
  let submissions = 0;
  /**
   * Answers (on or off) that have arrived and not settled, per owner, by
   * their evidence number; and the writes waiting for the answers that were
   * pending when they were asked for. Added before the first await.
   */
  const unsettled = new Map<string, Set<number>>();
  const cohortWaiters = new Map<
    string,
    Array<{ through: number; resolve: () => void }>
  >();
  /**
   * Invariant: for every sequence of answers, failed loads, failed saves and
   * restarts, the permission is never wider than the one the same answers give
   * with the records readable throughout (the oracle: `applyAnswer` and one
   * save attempt per answer, in arrival order), and it is equal when no save
   * fails. A submission returns the decision a legacy write then meets. Every
   * On this process applies, live or after the records load, wakes the import.
   * `authority.test.ts` checks it against a seeded model, failures counted
   * over all saves.
   *
   * One path enforces it. An answer that cannot be judged (the records will
   * not load) is held as it arrived, and when they load `replayHeld` applies
   * it with `judge`, the call a live answer makes: one save attempt, and a
   * failed save withdraws the permission and moves on. So recovery makes the
   * save attempts the readable store makes, in its order, and meets the same
   * failures however the store counts them. A shortcut that applies fewer or
   * other answers (a fold of them) makes other attempts, meets other
   * failures, and can save an answer the readable store lost.
   *
   * Restart: held answers are in memory only. One a restart loses was given
   * while the records would not load, so no process could keep it; the
   * registry refuses legacy writes once the owner is On.
   *
   * The memory per owner is the runs of different answers, at most
   * `MAX_HELD_RUNS`, however many arrive.
   */
  const held = new Map<string, HeldAnswers>();
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
    if (decision.kind !== "legacy") return decision;
    const key = typeof owner === "string" ? normalizeOwner(owner) : null;
    return key !== null &&
      !withdrawn.has(key) &&
      !unsettled.has(key) &&
      !held.has(key)
      ? decision
      : UNKNOWN_DECISION;
  }

  /**
   * Resolves once every answer pending now has settled. Answers that arrive
   * later are not waited for: that wait could be renewed forever.
   */
  function cohortSettled(key: string): Promise<void> {
    const pending = unsettled.get(key);
    if (!pending || pending.size === 0) return Promise.resolve();
    return new Promise((resolve) => {
      const waiters = cohortWaiters.get(key) ?? [];
      // Tickets are issued in order, so the latest one for this owner is at
      // or above every pending answer's.
      waiters.push({ through: latest.get(key) ?? 0, resolve });
      cohortWaiters.set(key, waiters);
    });
  }

  function settle(key: string, ticket: number): void {
    const pending = unsettled.get(key);
    pending?.delete(ticket);
    // Tickets are added in increasing order and a Set keeps insertion order,
    // so the first one is the oldest. No spread: the set is unbounded.
    const oldest = pending?.values().next().value ?? Infinity;
    if (pending?.size === 0) unsettled.delete(key);
    const waiters = cohortWaiters.get(key) ?? [];
    const waiting = waiters.filter((w) => w.through >= oldest);
    if (waiting.length > 0) cohortWaiters.set(key, waiting);
    else cohortWaiters.delete(key);
    for (const w of waiters) if (w.through < oldest) w.resolve();
  }

  /**
   * Judge one live answer against the loaded records, saving it when it
   * applies. Under the lock.
   */
  async function judge(
    owner: string,
    state: "on" | "off",
    generation: number,
    ticket: number,
  ): Promise<PermissionEffect> {
    const next = await applySaved(owner, state, generation);
    // The answer takes effect only when it was applied, no later answer was
    // submitted, and it is not older than the record.
    return latest.get(owner) === ticket && generation >= next.generation
      ? "lift"
      : "withdraw";
  }

  function applyEffect(owner: string, effect: PermissionEffect): void {
    if (effect === "lift") withdrawn.delete(owner);
    else if (effect !== "keep") withdrawn.add(owner);
  }

  function hold(
    owner: string,
    answer: { state: "on" | "off"; generation: number; ticket: number },
  ): void {
    const entry = held.get(owner) ?? { runs: [], lossy: false };
    held.set(owner, entry);
    const last = entry.runs[entry.runs.length - 1];
    if (
      last &&
      last.state === answer.state &&
      last.generation === answer.generation
    ) {
      last.count += 1;
      last.ticket = answer.ticket;
      return;
    }
    entry.runs.push({ ...answer, count: 1 });
    if (entry.runs.length > MAX_HELD_RUNS) {
      let on: (typeof entry.runs)[number] | undefined;
      for (const run of entry.runs) {
        if (run.state === "on" && (!on || run.generation > on.generation)) {
          on = run;
        }
      }
      entry.runs = on ? [{ ...on, count: 1 }] : [];
      entry.lossy = true;
    }
  }

  /** Apply one answer to the loaded record and save it; throws if the save does. */
  async function applySaved(
    owner: string,
    state: "on" | "off",
    generation: number,
  ): Promise<AccountModeRecord> {
    const prev = records.get(owner);
    const next = applyAnswer(prev, state, generation, now());
    if (next !== prev) {
      await options.store.save(owner, next);
      records.set(owner, next);
    }
    return next;
  }

  /**
   * Apply every held answer, now that the records are loaded, in arrival
   * order, each through `judge` as a live answer is. A save that fails
   * withdraws the owner and the next answer is applied, as on the readable
   * path. An owner is released in the step that applies its last effect, with
   * nothing awaited between, so no check sees an owner that is judged but not
   * settled as free. Adds to `woken` each owner an applied answer left On.
   * Under the lock.
   */
  async function replayHeld(woken: Set<string>): Promise<void> {
    for (const [owner, entry] of [...held]) {
      let effect: PermissionEffect = "withdraw";
      for (const run of entry.runs) {
        for (let n = 1; n <= run.count; n += 1) {
          try {
            // Only the last answer's effect counts: an older one is no
            // longer the latest, so it can only withdraw.
            effect = await judge(
              owner,
              run.state,
              run.generation,
              n === run.count ? run.ticket : 0,
            );
            if (records.get(owner)?.answer === "on") woken.add(owner);
          } catch (error: unknown) {
            warn("a held answer could not be saved", error);
            effect = "withdraw";
          }
        }
      }
      applyEffect(owner, entry.lossy ? "withdraw" : effect);
      held.delete(owner);
    }
  }

  return {
    ready,
    read,
    legacyWriteDecision,
    async submitEvidence(input) {
      // Before the first await, so an answer is counted as pending from its
      // arrival. A failed read is not an answer: it takes no number.
      const owner = normalizeOwner(input.owner);
      const answered = input.state === "on" || input.state === "off";
      const ticket = answered ? (submissions += 1) : 0;
      if (answered) {
        latest.set(owner, ticket);
        const pending = unsettled.get(owner) ?? new Set<number>();
        pending.add(ticket);
        unsettled.set(owner, pending);
      }
      // Owners the import must be woken for, after the lock is released.
      const woken = new Set<string>();
      try {
        if (answered) {
          // Settled in the `finally`, under the lock, whatever happens.
          let release: (() => void) | undefined;
          // Withdraw until the answer is judged: a throw anywhere before that
          // (a save that failed) leaves the owner without permission.
          let effect: PermissionEffect = "withdraw";
          try {
            await ready;
            release = await lock.exclusive();
            // Retried under the lock, so the exclusive request is queued
            // before the load starts: an On still waits for legacy writes in
            // flight, and no legacy write starts after it.
            await retryLoadIfFailed();
            const answer = {
              state: input.state as "on" | "off",
              generation: input.generation ?? 0,
              ticket,
            };
            if (loadFailed) {
              // No records to judge against: held, and judged when they load.
              hold(owner, answer);
              effect = "keep";
            } else {
              // Earlier held answers first, then this one, by the same path.
              await replayHeld(woken);
              effect = await judge(
                owner,
                answer.state,
                answer.generation,
                ticket,
              );
            }
          } finally {
            // The release comes last, whatever the bookkeeping does.
            try {
              applyEffect(owner, effect);
              settle(owner, ticket);
            } finally {
              release?.();
            }
          }
        } else {
          await ready;
          await retryLoadIfFailed();
          // A failed read adds no answer, but a load it triggered must still
          // judge the answers held while the records were unreadable.
          if (loaded && !loadFailed && held.size > 0) {
            const release = await lock.exclusive();
            try {
              await replayHeld(woken);
            } finally {
              release();
            }
          }
        }
        // After the answer settled: what a write meets now, never `read`.
        const decision = legacyWriteDecision(owner);
        if (decision.kind === "streams") woken.add(owner);
        return decision;
      } finally {
        for (const woke of woken) {
          try {
            options.onOn?.(woke);
          } catch (error) {
            warn("the On callback failed", error);
          }
        }
      }
    },
    async commitLegacy(owner, write) {
      // An answer that has arrived and is not applied yet may contradict the
      // permission. Wait once, outside the lock (its exclusive request may be
      // queued behind other shared holders), for the answers pending at this
      // call: captured before the first await. Evidence that arrives after
      // that is not waited for: inside the lock, `legacyWriteDecision` is
      // `unknown` while any answer is unsettled, so the write is refused
      // (retryable) and never admitted past it.
      const cohort =
        typeof owner === "string"
          ? cohortSettled(normalizeOwner(owner))
          : Promise.resolve();
      await ready;
      await cohort;
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
