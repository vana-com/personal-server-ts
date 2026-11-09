/**
 * The seam between the stateful authority and the pure per-owner reducer
 * (`mode-machine.ts`).
 *
 * The authority keeps all owners in one map plus the set of owners whose On
 * save has not settled. The pure reducer works on one owner's record and
 * carries the save state inside the record. This file converts between the two
 * and adds three rules the authority needs from the pure reducer:
 *
 * - Owners are lowercased here. The pure reducer treats owners as opaque.
 * - An answer that is not a successful explicit On or Off (a timeout, a
 *   non-2xx status, an unknown state, an Off older than the TTL) is a plain
 *   read. It never ends a still-fresh Off: an unreachable Account must not
 *   block a person who has not switched. The pure reducer ends the Off on such
 *   an answer; the authority does not forward it.
 * - `importRequired` is never taken from the pure reducer. The authority sets
 *   it once, at the first durable On, from a probe of the legacy files.
 * - Every accepted Off is saved before it is used, as an On is. While the save
 *   is pending or has failed, every answer for that owner is unknown. A failed
 *   save leaves the owner unknown until a later Off is saved.
 *
 * Nothing here reads a clock, a store or the network.
 */

import {
  OFF_TTL_MS,
  reduceAccountMode,
  type AccountModeRecord,
  type ModeClock as PureClock,
  type ModeDecision as PureDecision,
  type ModeEvent as PureEvent,
} from "./mode-machine.js";

export { OFF_TTL_MS };

export type ModeState = "on" | "off" | "unknown";

/** What is kept on disk for one owner. */
export interface OwnerModeRecord {
  switched: boolean;
  switchedAt: number | null;
  cleanOffAt: number | null;
  offFetchStartMono: number | null;
  bootId: string | null;
}

export type ModeEvent =
  | {
      op: "evidence";
      owner: string;
      authOwner: string;
      state: ModeState;
      fetchStartMono: number;
      rawStatus: number | null;
    }
  | { op: "boot"; bootId: string; clockTrusted: boolean }
  | { op: "read"; owner: string }
  | { op: "admit"; owner: string; operationId: string }
  | {
      op: "commit";
      owner: string;
      operationId: string;
      sink: "legacy" | "stream";
    }
  | { op: "saveComplete"; owner: string }
  | { op: "saveFailed"; owner: string };

export type ModeDecision =
  | { kind: "streams"; importRequired: boolean }
  | { kind: "legacy" }
  | {
      kind: "refuse";
      code: "ACCOUNT_MODE_UNKNOWN" | "LEGACY_REFUSED_SWITCHED";
      status: 503 | 426;
    };

/** The durable store: one record per owner, outside the data database. */
export interface ModeRecordStore {
  load(): Promise<Map<string, OwnerModeRecord>>;
  save(owner: string, record: OwnerModeRecord): Promise<void>;
}

/** The instant the reducer judges by. */
export interface ReduceClock {
  /** Monotonic milliseconds within this boot. */
  nowMono: number;
  /** Wall-clock milliseconds; stored only as a record of when. */
  nowWall: number;
  /** A new value on every process start. */
  bootId: string;
}

export interface ReduceResult {
  records: Map<string, OwnerModeRecord>;
  pendingSave: Set<string>;
  decision: ModeDecision | null;
  persist: string[];
}

const UNKNOWN: ModeDecision = {
  kind: "refuse",
  code: "ACCOUNT_MODE_UNKNOWN",
  status: 503,
};

const normalize = (owner: unknown): string =>
  typeof owner === "string" ? owner.toLowerCase() : "";

function toPure(
  owner: string,
  record: OwnerModeRecord | undefined,
  pending: ReadonlySet<string>,
): AccountModeRecord | null {
  if (!record) return null;
  return {
    owner,
    switched: record.switched,
    switchedAt: record.switchedAt,
    cleanOffAt: record.cleanOffAt,
    offFetchStartMono: record.offFetchStartMono,
    bootId: record.bootId ?? "",
    persistence: !record.switched
      ? "none"
      : pending.has(owner)
        ? "pending"
        : "saved",
    importPending: false,
  };
}

function fromPure(record: AccountModeRecord): OwnerModeRecord {
  return {
    switched: record.switched,
    switchedAt: record.switchedAt,
    cleanOffAt: record.cleanOffAt,
    offFetchStartMono: record.offFetchStartMono,
    bootId: record.bootId,
  };
}

function fromPureDecision(decision: PureDecision): ModeDecision {
  if (decision.kind === "refuse") {
    return { kind: "refuse", code: decision.code, status: decision.status };
  }
  if (decision.kind === "streams") {
    return { kind: "streams", importRequired: false };
  }
  return { kind: "legacy" };
}

const succeeded = (status: number | null): boolean =>
  typeof status === "number" &&
  Number.isInteger(status) &&
  status >= 200 &&
  status < 300;

function offIsInsideWindow(fetchStartMono: number, nowMono: number): boolean {
  return (
    Number.isFinite(fetchStartMono) &&
    fetchStartMono <= nowMono &&
    nowMono - fetchStartMono < OFF_TTL_MS
  );
}

export function reduce(
  recordsIn: ReadonlyMap<string, OwnerModeRecord>,
  pendingIn: ReadonlySet<string>,
  event: ModeEvent,
  clock: ReduceClock,
): ReduceResult {
  const records = new Map(recordsIn);
  const pendingSave = new Set(pendingIn);
  const persist: string[] = [];
  const done = (decision: ModeDecision | null): ReduceResult => ({
    records,
    pendingSave,
    decision,
    persist,
  });
  const pureClock: PureClock = clock;

  if (event.op === "boot") {
    // A new process starts a new monotonic epoch: no stored Off survives it.
    for (const [owner, record] of recordsIn) {
      const result = reduceAccountMode(
        toPure(owner, record, pendingIn),
        {
          type: "boot",
          owner,
          bootId: event.bootId,
          clockTrusted: event.clockTrusted,
        },
        pureClock,
      );
      if (result.record) records.set(owner, fromPure(result.record));
    }
    return done(null);
  }

  const owner = normalize(event.owner);
  const before = recordsIn.get(owner);
  const pure = toPure(owner, before, pendingIn);

  /** Run one pure event; keep the new record only when it changes state. */
  const run = (pureEvent: PureEvent, keepNewRecord: boolean) => {
    const result = reduceAccountMode(pure, pureEvent, pureClock);
    if (result.record && (keepNewRecord || pure !== null)) {
      records.set(owner, fromPure(result.record));
    }
    return result;
  };

  switch (event.op) {
    case "read":
    case "admit":
    case "commit": {
      const pureEvent: PureEvent =
        event.op === "read"
          ? { type: "read", owner }
          : event.op === "admit"
            ? { type: "admit", owner, operationId: event.operationId }
            : {
                type: "commit",
                owner,
                operationId: event.operationId,
                sink: event.sink,
              };
      const decision = fromPureDecision(run(pureEvent, false).decision);
      return done(pendingIn.has(owner) ? UNKNOWN : decision);
    }
    case "saveComplete":
    case "saveFailed": {
      if (event.op === "saveComplete") pendingSave.delete(owner);
      else pendingSave.add(owner);
      const result = run({ type: event.op, owner }, false);
      return done(
        event.op === "saveFailed" ? UNKNOWN : fromPureDecision(result.decision),
      );
    }
    case "evidence": {
      const authOwner = normalize(event.authOwner);
      const ownersAgree = owner !== "" && owner === authOwner;
      const good = succeeded(event.rawStatus);
      const forwardable =
        good &&
        (event.state === "on" ||
          (event.state === "off" &&
            offIsInsideWindow(event.fetchStartMono, clock.nowMono)));
      if (ownersAgree && !forwardable) {
        // Not a usable answer: it changes nothing and gets the current mode.
        const current = fromPureDecision(
          run({ type: "read", owner }, false).decision,
        );
        return done(pendingIn.has(owner) ? UNKNOWN : current);
      }
      const result = run(
        {
          type: "evidence",
          owner,
          authOwner,
          state: event.state,
          fetchStartMono: event.fetchStartMono,
          rawStatus: event.rawStatus,
        },
        true,
      );
      const after = result.record;
      const newOn =
        event.state === "on" &&
        after?.switched === true &&
        before?.switched !== true;
      const newOff =
        event.state === "off" &&
        after?.switched === false &&
        (after.offFetchStartMono !== (before?.offFetchStartMono ?? null) ||
          after.cleanOffAt !== (before?.cleanOffAt ?? null));
      if (ownersAgree && (newOn || newOff || pendingIn.has(owner))) {
        // A new On or Off, or one whose save failed: it must reach the disk
        // before any answer that depends on it is served.
        if (forwardable) {
          pendingSave.add(owner);
          persist.push(owner);
          return done(null);
        }
      }
      return done(
        pendingIn.has(owner) ? UNKNOWN : fromPureDecision(result.decision),
      );
    }
  }
}
