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
 * Do not call `submitEvidence` from inside a commit callback: evidence waits
 * for every in-flight commit, so the call would wait for itself.
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
import { createRwLock, type RwLock } from "./rw-lock.js";

export type RefuseDecision = Extract<ModeDecision, { kind: "refuse" }>;

export type CommitResult<T> =
  { ok: true; value: T } | { ok: false; decision: RefuseDecision };

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
  /** A save that does not settle in this many ms counts as a failed save. */
  saveTimeoutMs?: number;
  /**
   * Whether the legacy store holds any data for the owner. Asked once, at the
   * first On for an owner, to set `importPending` in the record saved with that
   * On. A probe that throws counts as true: an import that finds nothing is
   * harmless, a skipped one is not.
   */
  hasLegacyFiles?: (owner: string) => boolean | Promise<boolean>;
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
   * Whether a stream write may commit for this owner now. Refused with 503
   * IMPORT_PENDING while the owner's legacy import is owed.
   */
  commitStream(owner: string, operationId: string): ModeDecision;
  /**
   * Whether the legacy importer's own publish of a seed into streams may
   * commit for this owner. Unlike `commitStream` it is admitted while the
   * import is pending: the import has to publish before it can say it is done.
   * Only the importer calls it. It answers `streams` only for a saved On.
   */
  commitImportSeed(owner: string, operationId: string): ModeDecision;
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
  /** Let go of the store. The authority answers 503 from then on. */
  close(): Promise<void>;
  /** A copy of the in-memory records, for diagnostics and tests. */
  snapshot(): Map<string, AccountModeRecord>;
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

const isOwnedError = (error: unknown): boolean =>
  error instanceof ModeStoreOwnedError ||
  (error instanceof Error && error.name === "ModeStoreOwnedError");

const isConflictError = (error: unknown): boolean =>
  error instanceof ModeStoreConflictError ||
  (error instanceof Error && error.name === "ModeStoreConflictError");

function settleWithin<T>(work: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`record store save did not settle in ${ms} ms`)),
      ms,
    );
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

export function createModeAuthority(
  options: ModeAuthorityOptions,
): ModeAuthority {
  const clock = options.clock ?? defaultAuthorityClock();
  const warn = options.onWarning ?? (() => {});
  const lock: RwLock = createRwLock();
  const records = new Map<string, AccountModeRecord>();
  /** What the store held for each owner when this authority last read or wrote it. */
  const stored = new Map<string, DurableModeRecord>();
  /** Owners whose last save failed: re-read the store before the next one. */
  const stale = new Set<string>();
  const saveTimeoutMs = options.saveTimeoutMs ?? DEFAULT_SAVE_TIMEOUT_MS;
  let loaded = false;
  let blocked = false;
  let closed = false;
  let lease: ModeStoreLease | null = null;
  let starting: Promise<void> | null = null;

  const now = () => ({
    nowMono: clock.mono(),
    nowWall: clock.wall(),
    bootId: options.bootId,
  });

  /** Ask for a decision without changing state. */
  function decide(event: ModeEvent): ModeDecision {
    if (!loaded) return blocked ? REFUSE_STORE_OWNED : REFUSE_UNKNOWN;
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
    if (held === undefined || (row.switched && !held.switched)) {
      records.set(owner, fromDurable(owner, row));
    }
  }

  /** Re-read one owner's row. False when the store cannot be read. */
  async function refresh(owner: string): Promise<boolean> {
    try {
      takeStored(owner, (await options.store.load()).get(owner));
      stale.delete(owner);
      return true;
    } catch (error) {
      warn("account mode record could not be re-read", error);
      return false;
    }
  }

  /**
   * Save the owner's record, then tell the policy how it went. Nothing that
   * depends on the record is answered before this settles. The save is a
   * compare-and-set against the row this authority last saw, and is bounded:
   * one that hangs would hold the lock for good.
   */
  async function persistOwner(owner: string): Promise<ModeDecision> {
    if (stale.has(owner)) await refresh(owner);
    const record = records.get(owner);
    if (!record) return REFUSE_UNKNOWN;
    const next = toDurable(record);
    try {
      await settleWithin(
        options.store.save(owner, next, stored.get(owner) ?? null),
        saveTimeoutMs,
      );
    } catch (error) {
      warn("account mode record could not be saved", error);
      const decision = apply({ type: "saveFailed", owner }).decision;
      stale.add(owner);
      // A rejected compare-and-set means the store holds something newer.
      if (isConflictError(error)) await refresh(owner);
      return decision;
    }
    stored.set(owner, next);
    return apply({ type: "saveComplete", owner }).decision;
  }

  async function load(): Promise<void> {
    if (closed) throw new Error("The account mode authority is closed.");
    const mine = await options.store.claim();
    try {
      const rows = await options.store.load();
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
      return await options.hasLegacyFiles(owner);
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
    const unavailable = await available();
    if (unavailable) return unavailable;
    const release = await lock.exclusive();
    try {
      const owner = normalizeOwner(input.owner);
      // The probe is only read at a new On; the policy owns what it means.
      const legacyFiles =
        input.state === "on" && records.get(owner)?.switched !== true
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

  return {
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
        fetchStartMono: future ? Number.NaN : clock.mono() - age,
      });
    },

    read: (owner) => decide({ type: "read", owner }),
    admit: (owner, operationId) =>
      decide({ type: "admit", owner, operationId }),

    async commitLegacy(owner, operationId, write) {
      // An early refusal needs no lock: refusing is always safe.
      const early = refusal(decide(commitEvent(owner, operationId)));
      if (early) return { ok: false, decision: early };
      const release = await lock.shared();
      try {
        // Re-read the durable record inside the lock, then check and start the
        // write in the same tick. A writer that bypassed ownership would show
        // up here; an unreadable store leaves the owner unknown.
        if (!(await refresh(normalizeOwner(owner)))) {
          return { ok: false, decision: REFUSE_UNKNOWN };
        }
        const refused = refusal(decide(commitEvent(owner, operationId)));
        if (refused) return { ok: false, decision: refused };
        return { ok: true, value: await write() };
      } finally {
        release();
      }
    },

    commitStream: (owner, operationId) =>
      decide({ type: "commit", owner, operationId, sink: "stream" }),

    commitImportSeed: (owner, operationId) =>
      decide({ type: "commit", owner, operationId, sink: "importSeed" }),

    async importPending(owner) {
      const unavailable = await available();
      if (unavailable)
        throw new Error("account mode unknown: store unavailable");
      const answer = decide({ type: "read", owner });
      if (answer.kind === "streams") return answer.importRequired;
      if (answer.kind === "legacy") return false;
      throw new Error("account mode unknown for this owner");
    },

    async importDone(owner) {
      const unavailable = await available();
      if (unavailable) return unavailable;
      const release = await lock.exclusive();
      try {
        const applied = apply({ type: "importDone", owner: owner ?? "" });
        return applied.persist
          ? await persistOwner(normalizeOwner(owner))
          : applied.decision;
      } finally {
        release();
      }
    },

    async close() {
      closed = true;
      loaded = false;
      blocked = false;
      records.clear();
      stored.clear();
      stale.clear();
      const held = lease;
      lease = null;
      await held?.release();
    },
  };
}

export { OFF_TTL_MS };
