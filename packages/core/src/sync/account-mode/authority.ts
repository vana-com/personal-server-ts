/**
 * The stateful half of the shared account-mode module.
 *
 * The policy (`reduceAccountMode`, in `mode-machine.ts`) decides everything
 * about the mode. This file does only what a pure function cannot: it holds
 * the records, takes the one lock that the commit seal and the latch write
 * share, probes for legacy files, and writes the durable store.
 *
 * - Nothing is answered before the stored records are loaded. Until then
 *   every read refuses with a retryable 503.
 * - Evidence takes the lock exclusively; a legacy commit takes it shared and
 *   re-reads the record inside it, with no await between that re-read and the
 *   start of the write. An On latch therefore waits for every legacy write
 *   already in flight, and no legacy write starts after the latch is set. A
 *   check done before the lock was taken is only an early refusal and is never
 *   trusted for a write.
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
import type { ModeRecordStore } from "./record-store.js";
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
  /**
   * Whether the legacy store holds any data for the owner. Asked once, at the
   * first On for an owner, to set `importRequired`. A probe that throws counts
   * as true: an import that finds nothing is harmless, a skipped one is not.
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
   * The seal for a legacy write whose durable step is synchronous. The check
   * and `write` run in one tick, so no latch can fall between them.
   */
  commitLegacySync<T>(
    owner: string,
    operationId: string,
    write: () => T,
  ): CommitResult<T>;
  /**
   * The seal for a legacy write whose durable step awaits. The lock is held
   * until `write` settles, so an On latch waits for it.
   */
  commitLegacy<T>(
    owner: string,
    operationId: string,
    write: () => T | Promise<T>,
  ): Promise<CommitResult<T>>;
  /** Whether a stream write may commit for this owner now. */
  commitStream(owner: string, operationId: string): ModeDecision;
  /** A copy of the in-memory records, for diagnostics and tests. */
  snapshot(): Map<string, AccountModeRecord>;
}

const REFUSE_UNKNOWN: RefuseDecision = {
  kind: "refuse",
  code: "ACCOUNT_MODE_UNKNOWN",
  status: 503,
};

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
  let loaded = false;
  let starting: Promise<void> | null = null;

  const now = () => ({
    nowMono: clock.mono(),
    nowWall: clock.wall(),
    bootId: options.bootId,
  });

  /** Ask for a decision without changing state. */
  function decide(event: ModeEvent): ModeDecision {
    if (!loaded) return REFUSE_UNKNOWN;
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
   * Save the owner's record, then tell the policy how it went. Nothing that
   * depends on the record is answered before this settles.
   */
  async function persistOwner(owner: string): Promise<ModeDecision> {
    const record = records.get(owner);
    if (!record) return REFUSE_UNKNOWN;
    try {
      await options.store.save(owner, toDurable(record));
    } catch (error) {
      warn("account mode record could not be saved", error);
      return apply({ type: "saveFailed", owner }).decision;
    }
    return apply({ type: "saveComplete", owner }).decision;
  }

  async function load(): Promise<void> {
    const stored = await options.store.load();
    records.clear();
    for (const [owner, record] of stored) {
      const key = normalizeOwner(owner);
      records.set(key, fromDurable(key, record));
    }
    for (const owner of [...records.keys()]) {
      apply({
        type: "boot",
        owner,
        bootId: options.bootId,
        clockTrusted: options.clockTrusted ?? true,
      });
    }
    loaded = true;
  }

  function start(): Promise<void> {
    if (loaded) return Promise.resolve();
    // A failed load is retried by the next caller; until one succeeds every
    // read refuses.
    starting ??= load().catch((error) => {
      starting = null;
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

  async function submit(
    input: Omit<ModeEvidenceInput, "fetchStartedAt"> & {
      fetchStartMono: number;
    },
  ): Promise<ModeDecision> {
    await start();
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

  /**
   * Re-read the owner's durable record. Another runtime on the same store may
   * have latched On since this one last looked. On is adopted (never lowered),
   * so this can only make the answer stricter. A store that cannot be read
   * leaves the owner unknown for this commit.
   */
  async function adoptDurableOn(owner: string): Promise<boolean> {
    const key = normalizeOwner(owner);
    try {
      const stored = (await options.store.load()).get(key);
      if (stored?.switched === true && records.get(key)?.switched !== true) {
        records.set(key, fromDurable(key, stored));
      }
      return true;
    } catch (error) {
      warn("account mode record could not be re-read at commit", error);
      return false;
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
      const age = Number.isFinite(input.fetchStartedAt)
        ? Math.max(0, clock.wall() - input.fetchStartedAt)
        : Number.NaN;
      return submit({
        owner: input.owner,
        authOwner: input.authOwner,
        state: input.state,
        rawStatus: input.rawStatus,
        fetchStartMono: clock.mono() - age,
      });
    },

    read: (owner) => decide({ type: "read", owner }),
    admit: (owner, operationId) =>
      decide({ type: "admit", owner, operationId }),

    commitLegacySync(owner, operationId, write) {
      const refused = refusal(decide(commitEvent(owner, operationId)));
      if (refused) return { ok: false, decision: refused };
      return { ok: true, value: write() };
    },

    async commitLegacy(owner, operationId, write) {
      // An early refusal needs no lock: refusing is always safe.
      const early = refusal(decide(commitEvent(owner, operationId)));
      if (early) return { ok: false, decision: early };
      const release = await lock.shared();
      try {
        // Re-read the durable record inside the lock, then check and start the
        // write in the same tick.
        if (!(await adoptDurableOn(owner))) {
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
  };
}

export { OFF_TTL_MS };
