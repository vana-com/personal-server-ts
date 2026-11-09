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
 * - `importRequired` is set once, when an On is first saved, from the legacy
 *   files probe the authority passes in. It is delivered with that save.
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
  /** An import is owed and has not been reported yet. */
  readonly importPending: boolean;
}

/** What is kept on disk for one owner (no save state: it is saved by being there). */
export interface DurableModeRecord {
  switched: boolean;
  switchedAt: number | null;
  cleanOffAt: number | null;
  offFetchStartMono: number | null;
  bootId: string | null;
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
    }
  | {
      readonly type: "boot";
      readonly owner: string;
      readonly bootId: string;
      readonly clockTrusted: boolean;
    }
  | { readonly type: "read"; readonly owner: string }
  | {
      readonly type: "admit";
      readonly owner: string;
      readonly operationId: string;
    }
  | {
      readonly type: "commit";
      readonly owner: string;
      readonly operationId: string;
      readonly sink: "legacy" | "stream";
    }
  | { readonly type: "saveComplete" | "saveFailed"; readonly owner: string };

export type ModeDecision =
  | { readonly kind: "streams"; readonly importRequired: boolean }
  | { readonly kind: "legacy" }
  | {
      readonly kind: "refuse";
      /** 503 is retryable; 426 is not. */
      readonly code: "ACCOUNT_MODE_UNKNOWN" | "LEGACY_REFUSED_SWITCHED";
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
  };
}

export function toDurable(record: AccountModeRecord): DurableModeRecord {
  return {
    switched: record.switched,
    switchedAt: record.switchedAt,
    cleanOffAt: record.cleanOffAt,
    offFetchStartMono: record.offFetchStartMono,
    bootId: record.bootId,
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
    importPending: false,
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
  return { kind: "streams", importRequired: false };
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
    event.sink !== "stream"
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
      const usable =
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
      if (event.state === "on") {
        if (!next.switched) {
          next = {
            ...next,
            switched: true,
            switchedAt: finiteTime(clock.nowWall) ? clock.nowWall : null,
            offFetchStartMono: null,
            persistence: "pending",
            importPending: event.legacyFiles === true,
          };
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
      const next = { ...base, persistence: "saved" as const };
      if (next.switched && next.importPending) {
        // The import request goes out once, with the first durable On.
        return settle(
          { ...next, importPending: false },
          { kind: "streams", importRequired: true },
        );
      }
      return settle(next);
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
