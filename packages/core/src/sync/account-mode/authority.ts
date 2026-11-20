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
 *   that arrive meanwhile are held in arrival order and judged, one by one by
 *   the same rule as a live answer, when the records load (`held` below).
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

/** An answer that arrived while the records would not load. */
interface HeldAnswer {
  state: "on" | "off";
  generation: number;
  ticket: number;
}

/** Different held answers kept per owner before one is dropped (see `held`). */
const MAX_HELD_ANSWERS = 1024;

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
   * Invariant: for every sequence of answers and failed loads, the permission
   * once the records load again equals the permission the same answers give
   * with the records readable throughout, or is stricter.
   *
   * It holds by construction: an answer that arrives while the records will
   * not load is judged against nothing, so it is held here, per owner, in
   * arrival order. When the records load, `replayHeld` folds the held answers
   * through `judge`, the rule the readable path uses, in that order and under
   * the lock, so the record and the permission are what the readable path
   * would have produced. The owner keeps no permission (`legacyWriteDecision`
   * is `unknown`) from the first held answer until the last one's effect has
   * been applied, including while a save is pending. In memory only.
   *
   * Bound: adjacent answers that are equal (state and generation) fold to the
   * last one alone, which is exact (the repeat changes no record, and its
   * effect equals the first's), so a poll that repeats cannot grow the list.
   * Past `MAX_HELD_ANSWERS` different answers the oldest is dropped and the
   * owner is marked `lost`: the record may then differ from the readable
   * path's, so the owner gets no permission back in this process (a restart
   * clears it, as for any withdrawal). Dropping an answer would otherwise be
   * able to allow more than the readable path, so it is always paired with
   * that permanent withdrawal.
   */
  const held = new Map<string, HeldAnswer[]>();
  const lost = new Set<string>();
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
   * Judge one answer against the loaded records, saving it when it applies.
   * The only rule for an answer's effect on the permission: used for a live
   * answer and for each answer held through a failed load. Under the lock.
   */
  async function judge(
    owner: string,
    state: "on" | "off",
    generation: number,
    ticket: number,
  ): Promise<PermissionEffect> {
    const prev = records.get(owner);
    const next = applyAnswer(prev, state, generation, now());
    if (next !== prev) {
      await options.store.save(owner, next);
      records.set(owner, next);
    }
    // The answer takes effect only when it was applied, no later answer was
    // submitted, and it is not older than the record.
    return latest.get(owner) === ticket && generation >= next.generation
      ? "lift"
      : "withdraw";
  }

  function applyEffect(owner: string, effect: PermissionEffect): void {
    // An owner that lost a held answer is never lifted again in this process.
    if (effect === "lift" && !lost.has(owner)) withdrawn.delete(owner);
    else if (effect !== "keep") withdrawn.add(owner);
  }

  function hold(owner: string, answer: HeldAnswer): void {
    const list = held.get(owner) ?? [];
    const last = list[list.length - 1];
    if (
      last &&
      last.state === answer.state &&
      last.generation === answer.generation
    ) {
      list[list.length - 1] = answer;
    } else {
      list.push(answer);
      if (list.length > MAX_HELD_ANSWERS) {
        list.shift();
        lost.add(owner);
      }
    }
    held.set(owner, list);
  }

  /**
   * Judge every held answer in arrival order, now that records are loaded.
   * Under the lock. An owner's entry stays until its last effect is applied,
   * with nothing awaited between that and the removal, so no check sees an
   * owner that is judged but not settled as free.
   */
  async function replayHeld(): Promise<void> {
    for (const [owner, answers] of [...held]) {
      for (const answer of answers) {
        let effect: PermissionEffect = "withdraw";
        try {
          effect = await judge(
            owner,
            answer.state,
            answer.generation,
            answer.ticket,
          );
        } catch (error: unknown) {
          warn("a held answer could not be saved", error);
        }
        applyEffect(owner, effect);
      }
      if (lost.has(owner)) withdrawn.add(owner);
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
      if (answered) {
        // Settled in the `finally`, under the lock, whatever happens.
        let release: (() => void) | undefined;
        // Withdraw until the answer is judged: a throw anywhere before that
        // (a save that failed) leaves the owner without permission.
        let effect: PermissionEffect = "withdraw";
        try {
          await ready;
          release = await lock.exclusive();
          // Retried under the lock, so the exclusive request is queued before
          // the load starts: an On still waits for legacy writes in flight,
          // and no legacy write starts after it.
          await retryLoadIfFailed();
          if (loadFailed) {
            // Still no records to judge against: save nothing, change no
            // record. Hold the answer; it is judged when the records load.
            hold(owner, {
              state: input.state as "on" | "off",
              generation: input.generation ?? 0,
              ticket,
            });
            effect = "keep";
            return read(owner);
          }
          await replayHeld();
          effect = await judge(
            owner,
            input.state as "on" | "off",
            input.generation ?? 0,
            ticket,
          );
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
            await replayHeld();
          } finally {
            release();
          }
        }
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
