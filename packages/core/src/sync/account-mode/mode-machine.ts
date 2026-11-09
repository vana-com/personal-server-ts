/**
 * The policy: the one place that decides what an account's mode is.
 *
 * `reduceAccountMode` maps (one owner's record, one event, a sampled clock) to
 * a new record and a decision. It reads no clock, disk or network, so a host
 * in any language can port it and run the same vectors. The authority
 * (`authority.ts`) only does what a pure function cannot: it holds the records,
 * orders the work, probes for legacy files and writes the disk.
 *
 * What the policy guarantees:
 * - Only an authenticated, successful (2xx), explicit On or Off counts. Any
 *   other answer (timeout, non-2xx, unknown state, an Off older than the
 *   window) changes nothing. In particular it never ends a still-fresh Off.
 * - A never-seen owner, a missing owner and a mismatched owner are unknown.
 *   Asking about an owner never creates a record.
 * - Every accepted On or Off is saved before any answer depends on it. While a
 *   save is pending, or after it failed, the owner is unknown.
 * - An On is never lowered by an Off, an outage, expiry or a restart.
 * - An Off lasts `OFF_TTL_MS` from the start of its Account request, on the
 *   monotonic clock of one boot. Equal to the deadline counts as expired. A
 *   restart expires every Off.
 * - The first On is saved with `importPending` set when the owner has legacy
 *   files (the probe the authority passes in), in the same write. Every answer
 *   says `importRequired` while it is set, and a stream commit is refused with
 *   503 IMPORT_PENDING. Only an `importDone` event, saved before use, clears it.
 *   A crash after the On is saved cannot lose the import: the flag is on disk.
 *   The importer's own seed publish (sink `importSeed`) is the one commit
 *   admitted while the flag is set, so the import can finish.
 */

/**
 * How long a stored clean Off authorizes legacy work without a fresh Account
 * answer. The window bounds how long a device can write legacy data that a
 * later import must recover after the Account switched on another device.
 */
export const OFF_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export interface ModeClock {
  /** Monotonic milliseconds within this boot. */
  readonly nowMono: number;
  /** Wall-clock milliseconds; recorded as a time, never used to judge age. */
  readonly nowWall: number;
  /** A new value on every process start. */
  readonly bootId: string;
}

export type ModeState = "on" | "off" | "unknown";

/** The working record for one owner. Owners are lowercased. */
export interface AccountModeRecord {
  readonly owner: string;
  /** Irreversible even while its durable save is pending or failed. */
  readonly switched: boolean;
  readonly switchedAt: number | null;
  /** When a clean Off was last accepted; kept after the Off expires. */
  readonly cleanOffAt: number | null;
  /** Monotonic start of the Account request behind the current Off. */
  readonly offFetchStartMono: number | null;
  readonly bootId: string;
  /** Whether the latest accepted On or Off has reached the disk. */
  readonly persistence: "none" | "pending" | "saved" | "failed";
  /** The host owes an import of its legacy files and has not reported it done. */
  readonly importPending: boolean;
  /**
   * The store could not read this owner's record and set it aside, so nothing
   * is known about the owner's history: it may have been On with an import
   * owed. Absent means false. While set, no Off is accepted.
   */
  readonly historyUnknown?: true;
  /**
   * The Account generation this owner's latch was judged at: 0 for everyone,
   * raised by an On (or a reset) with a higher generation, never lowered.
   * An Off clears an On only when its generation is higher than this.
   */
  readonly generation: number;
}

/** What is kept on disk for one owner (no save state: it is saved by being there). */
export interface DurableModeRecord {
  switched: boolean;
  switchedAt: number | null;
  cleanOffAt: number | null;
  offFetchStartMono: number | null;
  bootId: string | null;
  /** An import is owed; cleared only by importDone. */
  importPending: boolean;
  /**
   * A tombstone: the store set this owner's unreadable record aside, so the
   * owner's history is unknown. Written only by a store's own quarantine path,
   * never by `save`; serialized only when true (absent means false). Not a
   * switched record, and no Off can be minted over it. An On replaces it, with
   * the import owed.
   */
  historyUnknown?: true;
  /**
   * The Account generation of the latch (see `AccountModeRecord.generation`).
   * Absent means 0, so a record written before the field existed reads as 0;
   * serialized only when above 0.
   */
  generation?: number;
}

export type ModeEvent =
  | {
      readonly type: "evidence";
      readonly owner: string;
      /** The owner the caller authenticated as. */
      readonly authOwner: string | null;
      readonly state: ModeState;
      readonly fetchStartMono: number | null;
      readonly rawStatus: number | null;
      /** Whether legacy files exist for the owner. Only read at a new On. */
      readonly legacyFiles?: boolean;
      /**
       * The Account generation of this answer; absent means 0. A reset (Dev
       * only) raises it by one. An Off lowers an On only at a higher one.
       */
      readonly generation?: number;
    }
  | {
      readonly type: "boot";
      readonly owner: string;
      readonly bootId: string;
      readonly clockTrusted: boolean;
    }
  | { readonly type: "read"; readonly owner: string }
  /** The host finished importing its legacy files into streams. */
  | { readonly type: "importDone"; readonly owner: string }
  | {
      readonly type: "admit";
      readonly owner: string;
      readonly operationId: string;
    }
  | {
      readonly type: "commit";
      readonly owner: string;
      readonly operationId: string;
      /**
       * `importSeed` is the legacy importer's own publish into streams. It is
       * admitted while the import is pending; `stream` is not.
       */
      readonly sink: "legacy" | "stream" | "importSeed";
    }
  | { readonly type: "saveComplete" | "saveFailed"; readonly owner: string };

export type ModeDecision =
  | { readonly kind: "streams"; readonly importRequired: boolean }
  | { readonly kind: "legacy" }
  | {
      readonly kind: "refuse";
      /** 503 is retryable; 426 is not. */
      readonly code:
        | "ACCOUNT_MODE_UNKNOWN"
        | "LEGACY_REFUSED_SWITCHED"
        /** Another runtime owns the record store. */
        | "ACCOUNT_MODE_STORE_OWNED"
        /** A stream write before the owed import is done. */
        | "IMPORT_PENDING";
      readonly status: 503 | 426;
    };

export interface ModeReduction {
  readonly record: AccountModeRecord | null;
  readonly decision: ModeDecision;
  /** The record must be saved, then answered with saveComplete or saveFailed. */
  readonly persist: boolean;
}

const UNKNOWN: ModeDecision = {
  kind: "refuse",
  code: "ACCOUNT_MODE_UNKNOWN",
  status: 503,
};

/** Owners are compared lowercased; anything that is not a string has no owner. */
export function normalizeOwner(owner: unknown): string {
  return typeof owner === "string" ? owner.toLowerCase() : "";
}

export function validModeOwner(owner: unknown): owner is string {
  return (
    typeof owner === "string" && owner.length > 0 && owner.trim() === owner
  );
}

export function createModeRecord(
  owner: string,
  bootId: string,
): AccountModeRecord {
  if (!validModeOwner(owner))
    throw new Error("An account mode record needs an owner.");
  return {
    owner,
    switched: false,
    switchedAt: null,
    cleanOffAt: null,
    offFetchStartMono: null,
    bootId,
    persistence: "none",
    importPending: false,
    generation: 0,
  };
}

export function toDurable(record: AccountModeRecord): DurableModeRecord {
  return {
    switched: record.switched,
    switchedAt: record.switchedAt,
    cleanOffAt: record.cleanOffAt,
    offFetchStartMono: record.offFetchStartMono,
    bootId: record.bootId,
    importPending: record.importPending,
    ...(record.historyUnknown === true
      ? { historyUnknown: true as const }
      : {}),
    ...(record.generation > 0 ? { generation: record.generation } : {}),
  };
}

/**
 * The record a store writes for an owner whose stored record it could not read
 * and set aside: history unknown, not On, no Off evidence, no import flag.
 * Only a store's own quarantine path writes it.
 */
export function tombstoneRecord(): DurableModeRecord {
  return {
    switched: false,
    switchedAt: null,
    cleanOffAt: null,
    offFetchStartMono: null,
    bootId: null,
    importPending: false,
    historyUnknown: true,
  };
}

/** A record read from the disk has, by being there, been saved. */
export function fromDurable(
  owner: string,
  record: DurableModeRecord,
): AccountModeRecord {
  return {
    owner,
    switched: record.switched,
    switchedAt: record.switchedAt,
    cleanOffAt: record.cleanOffAt,
    offFetchStartMono: record.offFetchStartMono,
    bootId: record.bootId ?? "",
    persistence: "saved",
    importPending: record.importPending,
    ...(record.historyUnknown === true
      ? { historyUnknown: true as const }
      : {}),
    generation: record.generation ?? 0,
  };
}

function finiteTime(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function succeeded(status: unknown): boolean {
  return (
    typeof status === "number" &&
    Number.isInteger(status) &&
    status >= 200 &&
    status < 300
  );
}

/** Started no later than now, and less than the window ago. */
function insideWindow(fetchStartMono: unknown, nowMono: unknown): boolean {
  return (
    finiteTime(fetchStartMono) &&
    finiteTime(nowMono) &&
    fetchStartMono <= nowMono &&
    nowMono - fetchStartMono < OFF_TTL_MS
  );
}

function freshOff(record: AccountModeRecord, clock: ModeClock): boolean {
  return (
    validModeOwner(clock.bootId) &&
    record.bootId === clock.bootId &&
    finiteTime(record.offFetchStartMono) &&
    // Equal to the deadline is expired.
    insideWindow(record.offFetchStartMono, clock.nowMono)
  );
}

function expireOff(record: AccountModeRecord): AccountModeRecord {
  return record.offFetchStartMono === null
    ? record
    : { ...record, offFetchStartMono: null };
}

const unsaved = (record: AccountModeRecord): boolean =>
  record.persistence === "pending" || record.persistence === "failed";

/** What the record allows right now. Never changes it. */
function decide(
  record: AccountModeRecord,
  event: ModeEvent,
  clock: ModeClock,
): ModeDecision {
  if (!record.switched) {
    if (unsaved(record) || !freshOff(record, clock)) return UNKNOWN;
    return { kind: "legacy" };
  }
  if (record.persistence !== "saved") return UNKNOWN;
  if (event.type === "commit" && event.sink === "legacy") {
    return {
      kind: "refuse",
      code: "LEGACY_REFUSED_SWITCHED",
      status: 426,
    };
  }
  if (
    event.type === "commit" &&
    event.sink === "stream" &&
    record.importPending
  ) {
    return { kind: "refuse", code: "IMPORT_PENDING", status: 503 };
  }
  return { kind: "streams", importRequired: record.importPending };
}

export function reduceAccountMode(
  record: AccountModeRecord | null,
  event: ModeEvent,
  clock: ModeClock,
): ModeReduction {
  const refuseUnchanged = (): ModeReduction => ({
    record,
    decision: UNKNOWN,
    persist: false,
  });
  if (!event) return refuseUnchanged();
  const owner = normalizeOwner(event.owner);
  if (!validModeOwner(owner)) return refuseUnchanged();
  if (record !== null && record.owner !== owner) return refuseUnchanged();
  if (event.type === "evidence") {
    const authOwner = normalizeOwner(event.authOwner);
    if (!validModeOwner(authOwner) || authOwner !== owner) {
      return refuseUnchanged();
    }
  }
  if (
    (event.type === "admit" || event.type === "commit") &&
    !validModeOwner(event.operationId)
  )
    return refuseUnchanged();
  if (
    event.type === "commit" &&
    event.sink !== "legacy" &&
    event.sink !== "stream" &&
    event.sink !== "importSeed"
  )
    return refuseUnchanged();
  if (
    event.type === "boot" &&
    (!validModeOwner(event.bootId) ||
      event.bootId !== clock.bootId ||
      typeof event.clockTrusted !== "boolean")
  )
    return refuseUnchanged();
  // Only an accepted answer creates a record; asking about an owner never does.
  if (record === null && event.type !== "evidence") return refuseUnchanged();

  const settle = (
    next: AccountModeRecord,
    decision: ModeDecision = decide(next, event, clock),
    persist = false,
  ): ModeReduction => ({ record: next, decision, persist });

  switch (event.type) {
    case "evidence": {
      const generation = event.generation ?? 0;
      const usable =
        Number.isSafeInteger(generation) &&
        generation >= 0 &&
        succeeded(event.rawStatus) &&
        (event.state === "on" ||
          (event.state === "off" &&
            insideWindow(event.fetchStartMono, clock.nowMono) &&
            validModeOwner(clock.bootId) &&
            finiteTime(clock.nowWall)));
      if (!usable) {
        // An answer that is not a usable On or Off changes nothing.
        return record === null ? refuseUnchanged() : settle(record);
      }
      let next = record ?? createModeRecord(owner, clock.bootId);
      let persist = false;
      if (event.state === "off" && next.historyUnknown === true) {
        // The owner's record was unreadable, so it may have been On: no Off
        // is accepted until an On answers.
        return settle(next);
      }
      if (
        event.state === "off" &&
        next.switched &&
        generation > next.generation
      ) {
        // The one sanctioned lowering: the Account was reset (Dev only) and
        // says Off at a higher generation than the latch. Any other Off after
        // an On changes nothing. The import flag goes with the latch; stream
        // data is not touched.
        next = {
          ...next,
          switched: false,
          switchedAt: null,
          cleanOffAt: clock.nowWall,
          offFetchStartMono: event.fetchStartMono as number,
          bootId: clock.bootId,
          persistence: "pending",
          importPending: false,
          generation,
        };
        return settle(next, undefined, true);
      }
      if (event.state === "on") {
        if (!next.switched) {
          // An On older than a reset this owner already saw is stale.
          if (generation < next.generation) return settle(next);
          // From a tombstone the import is owed whatever the probe says: the
          // lost record may have held a pending import, and the import is
          // idempotent.
          const owed =
            next.historyUnknown === true || event.legacyFiles === true;
          const { historyUnknown: _cleared, ...rest } = next;
          next = {
            ...rest,
            switched: true,
            switchedAt: finiteTime(clock.nowWall) ? clock.nowWall : null,
            offFetchStartMono: null,
            persistence: "pending",
            importPending: owed,
            generation,
          };
          persist = true;
        } else if (generation > next.generation) {
          // The Account says On at a higher generation: learn it.
          next = { ...next, generation, persistence: "pending" };
          persist = true;
        } else persist = unsaved(next);
      } else if (!next.switched) {
        // An older response cannot extend a newer accepted Off's lifetime.
        const newer =
          next.bootId !== clock.bootId ||
          next.offFetchStartMono === null ||
          (event.fetchStartMono as number) >= next.offFetchStartMono;
        if (newer) {
          next = {
            ...next,
            cleanOffAt: clock.nowWall,
            offFetchStartMono: event.fetchStartMono as number,
            bootId: clock.bootId,
            persistence: "pending",
          };
          persist = true;
        } else persist = unsaved(next);
      }
      return settle(next, undefined, persist);
    }
    case "boot": {
      const base = record as AccountModeRecord;
      const next =
        !event.clockTrusted || base.bootId !== event.bootId
          ? expireOff(base)
          : base;
      return settle({ ...next, bootId: event.bootId });
    }
    case "saveComplete": {
      const base = record as AccountModeRecord;
      return settle({ ...base, persistence: "saved" });
    }
    case "importDone": {
      const base = record as AccountModeRecord;
      // Only a saved On can owe an import. Unsaved, nothing is closed or
      // opened here: the owner stays unknown until a save lands.
      if (!base.switched || base.persistence === "none") return settle(base);
      if (base.persistence !== "saved") {
        // A failed importDone save is asked again; a failed On save is not
        // cleared, because the host was never told to import.
        return base.importPending
          ? settle(base)
          : settle(base, undefined, true);
      }
      if (!base.importPending) return settle(base);
      return settle(
        { ...base, importPending: false, persistence: "pending" },
        undefined,
        true,
      );
    }
    case "saveFailed":
      return settle({
        ...(record as AccountModeRecord),
        persistence: "failed",
      });
    case "read":
    case "admit":
    case "commit":
      return settle(record as AccountModeRecord);
    default:
      return refuseUnchanged();
  }
}
