/**
 * The stateful half of the shared account-mode module.
 *
 * The policy (`reduceAccountMode`, in `mode-machine.ts`) decides everything
 * about the mode. This file does only what a pure function cannot: it holds
 * the records, takes the one lock that the commit seal and the latch write
 * share, probes for legacy files, and writes the durable store.
 *
 * - One store has one owning runtime. The authority claims the store before it
 *   loads anything. A store another runtime owns is never read as authority
 *   and never written: every answer is 503 ACCOUNT_MODE_STORE_OWNED, and the
 *   next evidence tries the claim again.
 * - Nothing is answered before the stored records are loaded. Until then
 *   every read refuses with a retryable 503.
 * - Every record write is a compare-and-set against the record this authority
 *   last read or wrote, and never lowers an On (see `record-store.ts`). A write
 *   the store rejects, or that does not settle within `saveTimeoutMs`, is a
 *   failed save: the owner is unknown until a later save succeeds.
 * - Evidence takes the lock exclusively; a legacy commit takes it shared and
 *   re-reads the record inside it, with no await between that re-read and the
 *   start of the write. An On latch therefore waits for every legacy write
 *   already in flight, and no legacy write starts after the latch is set. A
 *   check done before the lock was taken is only an early refusal and is never
 *   trusted for a write. The only legacy commit is this async one: its lock
 *   is held until the callback settles, however long that takes.
 *
 * - `close` drains before it lets go. It refuses new work at once, then takes
 *   the write side of the lock, so every admitted legacy callback and evidence
 *   save has finished, and waits for every save still running at the store
 *   (also one the authority already gave up on). Only then does it release the
 *   store, so no write of this runtime can land after the next owner has it.
 *   A callback or save that never settles holds the store until it does or the
 *   process dies: the kernel, not a timer, frees an owner.
 * - A store another runtime owns is asked again, at most once per
 *   `ownerRetryMs` and one ask at a time, whenever an answer is wanted. A claim
 *   that succeeds loads the records afresh before anything is served.
 * - The import-seed publish is not a method of the authority. The code that
 *   creates the authority gets it as a separate capability
 *   (`createModeAuthorityWithImporter`); everyone else holds only the authority.
 *
 * A commit callback must not call back into the authority that runs it, other
 * than `read` and `admit` (which take no lock): the call would wait for the
 * callback, and the callback for the call. Such a call rejects at once with
 * `ReentrantAuthorityCall` (see `reentrancy.ts`; the guard is off where the host
 * has no `AsyncLocalStorage`, such as a browser, and the call then waits).
 */

import {
  OFF_TTL_MS,
  fromDurable,
  normalizeOwner,
  reduceAccountMode,
  toDurable,
  type AccountModeRecord,
  type ModeDecision,
  type ModeEvent,
  type ModeReduction,
  type ModeState,
} from "./mode-machine.js";
import type { DurableModeRecord } from "./mode-machine.js";
import {
  ModeStoreConflictError,
  ModeStoreOwnedError,
  type ModeRecordStore,
  type ModeStoreLease,
} from "./record-store.js";
import { createCallbackGuard } from "./reentrancy.js";
import { createRwLock, type RwLock } from "./rw-lock.js";

export type RefuseDecision = Extract<ModeDecision, { kind: "refuse" }>;

export type CommitResult<T> =
  { ok: true; value: T } | { ok: false; decision: RefuseDecision };

/**
 * The result of a stream seal: the write's value and whether the owner still
 * owes an import (true only for the importer's own seed publish), or the
 * refusal. The write did not run when `ok` is false.
 */
export type StreamCommitResult<T> =
  | { ok: true; value: T; importRequired: boolean }
  | { ok: false; decision: RefuseDecision };

/** What a host says about one owner after asking the Account. */
export interface ModeEvidenceInput {
  /** The owner the answer is about. */
  owner: string;
  /** The owner the caller authenticated as. A mismatch changes no state. */
  authOwner: string;
  state: ModeState;
  /**
   * Milliseconds since the epoch, on the host's clock, when the Account request
   * started. The module uses it once, to learn how old the answer already is
   * on arrival (never negative); expiry is then counted on its own monotonic
   * clock, so a later wall-clock change cannot extend or shorten a stored Off.
   */
  fetchStartedAt: number;
  /** HTTP status of the Account response, or null when there was none. */
  rawStatus: number | null;
  /**
   * The Account generation of the answer; absent means 0. A reset (Dev only)
   * raises it by one. An Off lowers a saved On only at a higher generation than
   * the latch, and an On at a higher one raises the latch.
   */
  generation?: number;
}

export interface AuthorityClock {
  /** Monotonic milliseconds; never goes backward within one boot. */
  mono(): number;
  /** Wall-clock milliseconds since the epoch. Used only to age an answer. */
  wall(): number;
}

export interface ModeAuthorityOptions {
  store: ModeRecordStore;
  /** A new value on every process start. */
  bootId: string;
  /** False when the monotonic clock cannot be compared with a stored one. */
  clockTrusted?: boolean;
  clock?: AuthorityClock;
  /**
   * The bound on each of the authority's own awaits while it holds the lock: a
   * store save, a store re-read and a legacy-file probe. A save or re-read
   * that does not settle in this many ms poisons the authority: it refuses
   * everything with 503 ACCOUNT_MODE_UNKNOWN until it is closed and a new one
   * opens the store, because the stalled call may still land. A probe that does
   * not settle counts as legacy files present. A write callback is never
   * bounded: its lock is held until it settles.
   */
  saveTimeoutMs?: number;
  /**
   * Whether the legacy store holds any data for the owner. Asked once, at the
   * first On for an owner, to set `importPending` in the record saved with that
   * On. A probe that throws counts as true: an import that finds nothing is
   * harmless, a skipped one is not.
   */
  hasLegacyFiles?: (owner: string) => boolean | Promise<boolean>;
  /**
   * How long a runtime that the store refused waits before it asks again
   * (default 1000 ms on the authority's monotonic clock).
   */
  ownerRetryMs?: number;
  onWarning?: (message: string, detail?: unknown) => void;
}

export interface ModeAuthority {
  /** Resolves when the stored records are loaded and the boot event is applied. */
  readonly ready: Promise<void>;
  /**
   * Take one Account answer. Returns the decision for the owner after the
   * answer is applied. A `streams` decision is returned only after the On
   * record is durable.
   */
  submitEvidence(input: ModeEvidenceInput): Promise<ModeDecision>;
  /** Same as `submitEvidence` with the fetch start already on the module's clock. */
  submitEvidenceMono(
    input: Omit<ModeEvidenceInput, "fetchStartedAt"> & {
      fetchStartMono: number;
    },
  ): Promise<ModeDecision>;
  /** The mode right now. Never throws; unknown while records are unloaded. */
  read(owner: string): ModeDecision;
  admit(owner: string, operationId: string): ModeDecision;
  /**
   * The seal for a legacy write. The lock is held until `write` settles, so
   * an On latch waits for it.
   */
  commitLegacy<T>(
    owner: string,
    operationId: string,
    write: () => T | Promise<T>,
  ): Promise<CommitResult<T>>;
  /**
   * The seal for a stream write. `write` runs under the shared side of the
   * lock, like a legacy commit: the decision is taken again inside it, and an
   * On latch, `importDone` or `close` waits until `write` settles. Refused with
   * 503 IMPORT_PENDING while the owner's legacy import is owed, and with 503
   * for an owner that is not On. A refusal never runs `write`.
   */
  commitStream<T>(
    owner: string,
    operationId: string,
    write: () => T | Promise<T>,
  ): Promise<StreamCommitResult<T>>;
  /**
   * Whether the owner's legacy import is still owed. False for an owner with
   * nothing to import and for an account that is not switched. Rejects when
   * the mode is unknown, so a caller never reads "unknown" as "done".
   */
  importPending(owner: string): Promise<boolean>;
  /**
   * The host finished importing the owner's legacy files into streams. The
   * clean record is saved before it is used; until then stream commits stay
   * refused. Changes nothing for an owner with no pending import.
   */
  importDone(owner: string): Promise<ModeDecision>;
  /**
   * Refuse new work, finish the work in flight, then let go of the store. The
   * authority answers 503 from then on. Safe to call twice.
   */
  close(): Promise<void>;
  /** A copy of the in-memory records, for diagnostics and tests. */
  snapshot(): Map<string, AccountModeRecord>;
}

/**
 * The legacy importer's own way to publish a seed into streams. Unlike
 * `commitStream` it is admitted while the import is pending: the import has to
 * publish before it can say it is done. It answers `streams` only for a saved
 * On, and refuses once the authority is closed.
 *
 * It is not on `ModeAuthority`: only the code that creates the authority holds
 * it, and hands it to the importer.
 */
export interface ImportSeedCapability {
  commitImportSeed<T>(
    owner: string,
    operationId: string,
    write: () => T | Promise<T>,
  ): Promise<StreamCommitResult<T>>;
}

const REFUSE_UNKNOWN: RefuseDecision = {
  kind: "refuse",
  code: "ACCOUNT_MODE_UNKNOWN",
  status: 503,
};

const REFUSE_STORE_OWNED: RefuseDecision = {
  kind: "refuse",
  code: "ACCOUNT_MODE_STORE_OWNED",
  status: 503,
};

/**
 * An Off whose fetch started further than this ahead of the module's wall
 * clock is not believed: it would otherwise count as just started and live
 * the full window. A smaller skew is clamped to an age of zero.
 */
export const MAX_FETCH_SKEW_MS = 60_000;

export const DEFAULT_SAVE_TIMEOUT_MS = 30_000;

export const DEFAULT_OWNER_RETRY_MS = 1000;

const isOwnedError = (error: unknown): boolean =>
  error instanceof ModeStoreOwnedError ||
  (error instanceof Error && error.name === "ModeStoreOwnedError");

const isConflictError = (error: unknown): boolean =>
  error instanceof ModeStoreConflictError ||
  (error instanceof Error && error.name === "ModeStoreConflictError");

/** A store call that did not settle within the bound. */
class StoreStalledError extends Error {
  constructor(what: string, ms: number) {
    super(`record store ${what} did not settle in ${ms} ms`);
    this.name = "StoreStalledError";
  }
}

function settleWithin<T>(
  work: Promise<T>,
  ms: number,
  what: string,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new StoreStalledError(what, ms)), ms);
    work.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

export function defaultAuthorityClock(): AuthorityClock {
  return {
    mono: () => performance.now(),
    wall: () => Date.now(),
  };
}

/** The authority, for everyone who is not the legacy importer. */
export function createModeAuthority(
  options: ModeAuthorityOptions,
): ModeAuthority {
  return createModeAuthorityWithImporter(options).authority;
}

/**
 * The authority and, beside it, the importer's capability. Keep the capability
 * in the code that wires the importer; hand the authority to everything else.
 */
export function createModeAuthorityWithImporter(
  options: ModeAuthorityOptions,
): { authority: ModeAuthority; importSeed: ImportSeedCapability } {
  const clock = options.clock ?? defaultAuthorityClock();
  const warn = options.onWarning ?? (() => {});
  const lock: RwLock = createRwLock();
  const callbacks = createCallbackGuard();
  const records = new Map<string, AccountModeRecord>();
  /** What the store held for each owner when this authority last read or wrote it. */
  const stored = new Map<string, DurableModeRecord>();
  /** Owners whose last save failed: re-read the store before the next one. */
  const stale = new Set<string>();
  const saveTimeoutMs = options.saveTimeoutMs ?? DEFAULT_SAVE_TIMEOUT_MS;
  const ownerRetryMs = options.ownerRetryMs ?? DEFAULT_OWNER_RETRY_MS;
  /** Every save running at the store, also one the authority gave up on. */
  const inFlightSaves = new Set<Promise<unknown>>();
  let loaded = false;
  let blocked = false;
  let closed = false;
  let closing: Promise<void> | null = null;
  /** A store call stalled: refuse everything until a new authority opens. */
  let poisoned = false;
  let lease: ModeStoreLease | null = null;
  let starting: Promise<void> | null = null;
  /** The authority's monotonic time at the start of the latest load attempt. */
  let lastAttempt: number | null = null;

  const now = () => ({
    nowMono: clock.mono(),
    nowWall: clock.wall(),
    bootId: options.bootId,
  });

  /** Ask for a decision without changing state. */
  function decide(event: ModeEvent): ModeDecision {
    if (closed || poisoned) return REFUSE_UNKNOWN;
    if (!loaded) {
      askAgain();
      return blocked ? REFUSE_STORE_OWNED : REFUSE_UNKNOWN;
    }
    return reduceAccountMode(
      records.get(normalizeOwner(event.owner)) ?? null,
      event,
      now(),
    ).decision;
  }

  /** Apply an event that changes state. Synchronous: no await inside. */
  function apply(event: ModeEvent): ModeReduction {
    const owner = normalizeOwner(event.owner);
    const result = reduceAccountMode(records.get(owner) ?? null, event, now());
    if (result.record) records.set(owner, result.record);
    return result;
  }

  /**
   * Take the stored row for `owner` into memory. The store is the authority
   * for what is monotone: an On that is stored and not held here is adopted
   * (never lowered), and a record nobody here has seen is adopted. Otherwise
   * the held record stays, and the stored row becomes the base of the next
   * compare-and-set.
   */
  function takeStored(owner: string, row: DurableModeRecord | undefined): void {
    if (row === undefined) {
      stored.delete(owner);
      return;
    }
    stored.set(owner, row);
    const held = records.get(owner);
    if (
      held === undefined ||
      (row.switched && !held.switched) ||
      // A record the store lost is not a fresh Off, whatever is held here.
      (row.historyUnknown === true && !held.switched)
    ) {
      records.set(owner, fromDurable(owner, row));
    }
  }

  /** Re-read one owner's row. False when the store cannot be read. */
  async function refresh(owner: string): Promise<boolean> {
    try {
      const rows = await settleWithin(
        Promise.resolve(options.store.load()),
        saveTimeoutMs,
        "load",
      );
      takeStored(owner, rows.get(owner));
      stale.delete(owner);
      return true;
    } catch (error) {
      warn("account mode record could not be re-read", error);
      if (error instanceof StoreStalledError) poisoned = true;
      return false;
    }
  }

  /**
   * Save the owner's record, then tell the policy how it went. Nothing that
   * depends on the record is answered before this settles. The save is a
   * compare-and-set against the row this authority last saw, and is bounded:
   * one that hangs would hold the lock for good. A save that stalls poisons
   * the authority (it may still land, so nothing else is written behind it),
   * and stays tracked so `close` waits for it.
   */
  async function persistOwner(owner: string): Promise<ModeDecision> {
    if (stale.has(owner)) await refresh(owner);
    if (poisoned) return REFUSE_UNKNOWN;
    const record = records.get(owner);
    if (!record) return REFUSE_UNKNOWN;
    const next = toDurable(record);
    try {
      const work = Promise.resolve(
        options.store.save(owner, next, stored.get(owner) ?? null),
      );
      inFlightSaves.add(work);
      const done = () => inFlightSaves.delete(work);
      work.then(done, done);
      await settleWithin(work, saveTimeoutMs, "save");
    } catch (error) {
      warn("account mode record could not be saved", error);
      const decision = apply({ type: "saveFailed", owner }).decision;
      stale.add(owner);
      if (error instanceof StoreStalledError) poisoned = true;
      // A rejected compare-and-set means the store holds something newer.
      else if (isConflictError(error)) await refresh(owner);
      return decision;
    }
    stored.set(owner, next);
    return apply({ type: "saveComplete", owner }).decision;
  }

  async function load(): Promise<void> {
    if (closed) throw new Error("The account mode authority is closed.");
    lastAttempt = clock.mono();
    const mine = await options.store.claim();
    try {
      // A close that came while the claim was pending gets the store back.
      if (closed) throw new Error("The account mode authority is closed.");
      const rows = await options.store.load();
      if (closed) throw new Error("The account mode authority is closed.");
      records.clear();
      stored.clear();
      stale.clear();
      for (const [owner, row] of rows) {
        const key = normalizeOwner(owner);
        stored.set(key, row);
        records.set(key, fromDurable(key, row));
      }
    } catch (error) {
      await mine.release().catch(() => {});
      throw error;
    }
    lease = mine;
    for (const owner of [...records.keys()]) {
      apply({
        type: "boot",
        owner,
        bootId: options.bootId,
        clockTrusted: options.clockTrusted ?? true,
      });
    }
    blocked = false;
    loaded = true;
  }

  /**
   * Ask for a store another runtime owned, or one that could not be read,
   * again: at most once per `ownerRetryMs`, one ask at a time. The answer that
   * triggered it stays a refusal; a claim that succeeds loads the records
   * afresh, so nothing held before is served.
   */
  function askAgain(): void {
    if (closed || loaded || starting !== null) return;
    if (lastAttempt !== null && clock.mono() - lastAttempt < ownerRetryMs) {
      return;
    }
    start().catch((error) => {
      if (!isOwnedError(error)) {
        warn("account mode records could not be loaded", error);
      }
    });
  }

  function start(): Promise<void> {
    if (loaded) return Promise.resolve();
    // A failed load is retried by the next caller; until one succeeds every
    // read refuses.
    starting ??= load().catch((error) => {
      starting = null;
      // A store another runtime owns refuses everything, and is tried again.
      blocked = isOwnedError(error);
      throw error;
    });
    return starting;
  }

  // Begin loading now: nothing may be served before the records are in. A
  // failure is surfaced to whoever awaits `ready` or submits evidence.
  const ready = start();
  ready.catch((error) =>
    warn("account mode records could not be loaded", error),
  );

  async function legacyFilesMayExist(owner: string): Promise<boolean> {
    if (!options.hasLegacyFiles) return false;
    try {
      return await settleWithin(
        Promise.resolve(options.hasLegacyFiles(owner)),
        saveTimeoutMs,
        "legacy file probe",
      );
    } catch (error) {
      warn("legacy file probe failed; reporting an import is required", error);
      return true;
    }
  }

  /** Null when the records are loaded and owned; otherwise the refusal. */
  async function available(): Promise<RefuseDecision | null> {
    if (closed) return REFUSE_UNKNOWN;
    try {
      await start();
    } catch (error) {
      if (isOwnedError(error)) return REFUSE_STORE_OWNED;
      throw error;
    }
    return closed ? REFUSE_UNKNOWN : null;
  }

  async function submit(
    input: Omit<ModeEvidenceInput, "fetchStartedAt"> & {
      fetchStartMono: number;
    },
  ): Promise<ModeDecision> {
    callbacks.assertOutside("submitEvidence");
    const unavailable = await available();
    if (unavailable) return unavailable;
    const release = await lock.exclusive();
    try {
      // A close that began while this waited has the lock next, and a stalled
      // store refuses everything: stop here.
      if (closed || poisoned) return REFUSE_UNKNOWN;
      const owner = normalizeOwner(input.owner);
      // After a failed save, learn what the store holds before judging this
      // answer against it: a reset that failed to save must not be forgotten
      // by the retry that follows it.
      if (stale.has(owner)) {
        await refresh(owner);
        if (closed || poisoned) return REFUSE_UNKNOWN;
      }
      // The probe is only read at a new On; the policy owns what it means.
      // An owner whose record was lost owes the import without asking.
      const held = records.get(owner);
      const legacyFiles =
        input.state === "on" &&
        held?.switched !== true &&
        held?.historyUnknown !== true
          ? await legacyFilesMayExist(owner)
          : undefined;
      const applied = apply({
        type: "evidence",
        owner: input.owner ?? "",
        authOwner: input.authOwner ?? "",
        state: input.state,
        fetchStartMono: input.fetchStartMono,
        rawStatus: input.rawStatus,
        legacyFiles,
        generation: input.generation,
      });
      return applied.persist ? await persistOwner(owner) : applied.decision;
    } finally {
      release();
    }
  }

  /** Null only when legacy work may proceed. */
  function refusal(decision: ModeDecision): RefuseDecision | null {
    if (decision.kind === "legacy") return null;
    if (decision.kind === "refuse") return decision;
    // A switched account: legacy writes are refused with 426.
    return {
      kind: "refuse",
      code: "LEGACY_REFUSED_SWITCHED",
      status: 426,
    };
  }

  function commitEvent(owner: string, operationId: string): ModeEvent {
    return { type: "commit", owner, operationId, sink: "legacy" };
  }

  /**
   * A stream write's seal: the decision is taken again inside the shared side
   * of the lock, and the write runs under it, so an On latch, an importDone or
   * a close waits for it. A refusal never runs the write.
   */
  async function sealStream<T>(
    sink: "stream" | "importSeed",
    owner: string,
    operationId: string,
    write: () => T | Promise<T>,
  ): Promise<StreamCommitResult<T>> {
    callbacks.assertOutside(
      sink === "stream" ? "commitStream" : "commitImportSeed",
    );
    const event: ModeEvent = { type: "commit", owner, operationId, sink };
    const refuse = (decision: ModeDecision): StreamCommitResult<T> => ({
      ok: false,
      decision: decision.kind === "refuse" ? decision : REFUSE_UNKNOWN,
    });
    const early = decide(event);
    if (early.kind !== "streams") return refuse(early);
    const release = await lock.shared();
    try {
      const decision = decide(event);
      if (decision.kind !== "streams") return refuse(decision);
      return {
        ok: true,
        value: await callbacks.run(write),
        importRequired: decision.importRequired,
      };
    } finally {
      release();
    }
  }

  const importSeed: ImportSeedCapability = {
    commitImportSeed: (owner, operationId, write) =>
      sealStream("importSeed", owner, operationId, write),
  };

  const authority: ModeAuthority = {
    ready,
    snapshot: () => new Map([...records].map(([k, v]) => [k, { ...v }])),

    submitEvidenceMono: submit,
    submitEvidence(input) {
      const wall = clock.wall();
      // A fetch start far ahead of this clock is not believed: as evidence it
      // is unknown, not "just started". (An On does not use the fetch start.)
      const future =
        input.state === "off" &&
        input.fetchStartedAt - wall > MAX_FETCH_SKEW_MS;
      const age = Number.isFinite(input.fetchStartedAt)
        ? Math.max(0, wall - input.fetchStartedAt)
        : Number.NaN;
      return submit({
        owner: input.owner,
        authOwner: input.authOwner,
        state: input.state,
        rawStatus: input.rawStatus,
        generation: input.generation,
        fetchStartMono: future ? Number.NaN : clock.mono() - age,
      });
    },

    read: (owner) => decide({ type: "read", owner }),
    admit: (owner, operationId) =>
      decide({ type: "admit", owner, operationId }),

    async commitLegacy(owner, operationId, write) {
      callbacks.assertOutside("commitLegacy");
      // An early refusal needs no lock: refusing is always safe.
      const early = refusal(decide(commitEvent(owner, operationId)));
      if (early) return { ok: false, decision: early };
      const release = await lock.shared();
      try {
        if (closed || poisoned) {
          return { ok: false, decision: REFUSE_UNKNOWN };
        }
        // Re-read the durable record inside the lock, then check and start the
        // write in the same tick. A writer that bypassed ownership would show
        // up here; an unreadable store leaves the owner unknown.
        if (!(await refresh(normalizeOwner(owner)))) {
          return { ok: false, decision: REFUSE_UNKNOWN };
        }
        const refused = refusal(decide(commitEvent(owner, operationId)));
        if (refused) return { ok: false, decision: refused };
        return { ok: true, value: await callbacks.run(write) };
      } finally {
        release();
      }
    },

    commitStream: (owner, operationId, write) =>
      sealStream("stream", owner, operationId, write),

    async importPending(owner) {
      callbacks.assertOutside("importPending");
      const unavailable = await available();
      if (unavailable)
        throw new Error("account mode unknown: store unavailable");
      const answer = decide({ type: "read", owner });
      if (answer.kind === "streams") return answer.importRequired;
      if (answer.kind === "legacy") return false;
      throw new Error("account mode unknown for this owner");
    },

    async importDone(owner) {
      callbacks.assertOutside("importDone");
      const unavailable = await available();
      if (unavailable) return unavailable;
      const release = await lock.exclusive();
      try {
        if (closed || poisoned) return REFUSE_UNKNOWN;
        const applied = apply({ type: "importDone", owner: owner ?? "" });
        return applied.persist
          ? await persistOwner(normalizeOwner(owner))
          : applied.decision;
      } finally {
        release();
      }
    },

    close() {
      try {
        callbacks.assertOutside("close");
      } catch (error) {
        // Before anything is changed: a refused close leaves the authority open.
        return Promise.reject(error);
      }
      // Refuse new work before anything is awaited.
      closed = true;
      loaded = false;
      blocked = false;
      closing ??= (async () => {
        // A claim or load still in flight gives the store back itself.
        await starting?.catch(() => undefined);
        // The write side: every admitted callback and evidence save is done.
        const release = await lock.exclusive();
        try {
          await Promise.allSettled([...inFlightSaves]);
          records.clear();
          stored.clear();
          stale.clear();
          const held = lease;
          lease = null;
          await held?.release();
        } finally {
          release();
        }
      })();
      return closing;
    },
  };
  return { authority, importSeed };
}

export { OFF_TTL_MS };
