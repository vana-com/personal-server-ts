/**
 * Pure, owner-bound policy. No clock, network or storage reads occur here.
 * Hosts supply authenticated evidence and a sampled clock; a decision is not a
 * reusable capability. Call again with the latest record at the actual sink.
 */
export const OFF_TTL_MS = 7 * 24 * 60 * 60 * 1000;

export interface ModeClock {
  readonly nowMono: number;
  readonly nowWall: number;
  readonly bootId: string;
}

export interface AccountModeRecord {
  readonly owner: string;
  /** Irreversible even while its durable save is pending or failed. */
  readonly switched: boolean;
  readonly switchedAt: number | null;
  /** Historical clean Off, retained after expiry/unknown for migration. */
  readonly cleanOffAt: number | null;
  readonly offFetchStartMono: number | null;
  readonly bootId: string;
  readonly persistence: "none" | "pending" | "saved" | "failed";
  /** Delivery of an import request, not proof that an import has completed. */
  readonly importPending: boolean;
}

export type ModeEvent =
  | { readonly type: "evidence"; readonly owner: string; readonly authOwner: string | null;
      readonly state: "on" | "off" | "unknown"; readonly fetchStartMono: number | null;
      readonly rawStatus: number | null }
  | { readonly type: "boot"; readonly owner: string; readonly bootId: string; readonly clockTrusted: boolean }
  | { readonly type: "read"; readonly owner: string }
  | { readonly type: "admit"; readonly owner: string; readonly operationId: string }
  | { readonly type: "commit"; readonly owner: string; readonly operationId: string; readonly sink: "legacy" | "stream" }
  | { readonly type: "saveComplete" | "saveFailed"; readonly owner: string };

export type ModeDecision =
  | { readonly kind: "streams" | "legacy"; readonly importRequired: boolean }
  | { readonly kind: "refuse"; readonly code: "ACCOUNT_MODE_UNKNOWN"; readonly status: 503;
      readonly retryable: true; readonly importRequired: boolean }
  | { readonly kind: "refuse"; readonly code: "LEGACY_REFUSED_SWITCHED"; readonly status: 426;
      readonly retryable: false; readonly importRequired: boolean };

export interface ModeReduction {
  readonly record: AccountModeRecord | null;
  readonly decision: ModeDecision;
}

/** Owners are opaque canonical IDs. Normalize addresses at the adapter boundary. */
export function validModeOwner(owner: unknown): owner is string {
  return typeof owner === "string" && owner.length > 0 && owner.trim() === owner;
}

export function createModeRecord(owner: string, bootId: string): AccountModeRecord {
  if (!validModeOwner(owner)) throw new Error("An account mode record needs an owner.");
  return { owner, switched: false, switchedAt: null, cleanOffAt: null,
    offFetchStartMono: null, bootId, persistence: "none", importPending: false };
}

function unknownDecision(): ModeDecision {
  return { kind: "refuse", code: "ACCOUNT_MODE_UNKNOWN", status: 503,
    retryable: true, importRequired: false };
}

function finiteTime(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function freshOff(record: AccountModeRecord, clock: ModeClock): boolean {
  return validModeOwner(clock.bootId) && record.bootId === clock.bootId &&
    finiteTime(clock.nowMono) && finiteTime(record.offFetchStartMono) &&
    clock.nowMono >= record.offFetchStartMono &&
    clock.nowMono - record.offFetchStartMono < OFF_TTL_MS;
}

function expireOff(record: AccountModeRecord): AccountModeRecord {
  return record.offFetchStartMono === null ? record : { ...record, offFetchStartMono: null };
}

/**
 * saveComplete may be emitted only after this owner's On record is durably saved.
 * A storage adapter must serialize saves/acks per owner: an unrelated/old write
 * completion is not an On saveComplete. Unknown evidence invalidates current Off
 * without erasing the historical clean Off used to request migration.
 */
export function reduceAccountMode(
  record: AccountModeRecord | null,
  event: ModeEvent,
  clock: ModeClock,
): ModeReduction {
  const refuseUnchanged = (): ModeReduction => ({ record, decision: unknownDecision() });
  if (!event || !validModeOwner(event.owner) ||
      (record !== null && record.owner !== event.owner)) return refuseUnchanged();
  if (event.type === "evidence" &&
      (!validModeOwner(event.authOwner) || event.authOwner !== event.owner)) return refuseUnchanged();
  if ((event.type === "admit" || event.type === "commit") &&
      !validModeOwner(event.operationId)) return refuseUnchanged();
  if (event.type === "commit" && event.sink !== "legacy" && event.sink !== "stream") return refuseUnchanged();
  if (event.type === "boot" &&
      (!validModeOwner(event.bootId) || event.bootId !== clock.bootId ||
       typeof event.clockTrusted !== "boolean")) return refuseUnchanged();

  let next = record ?? createModeRecord(event.owner, clock.bootId);
  switch (event.type) {
    case "evidence": {
      const successful = typeof event.rawStatus === "number" &&
        Number.isInteger(event.rawStatus) && event.rawStatus >= 200 && event.rawStatus < 300;
      if (successful && event.state === "on") {
        if (!next.switched) next = { ...next, switched: true,
          switchedAt: finiteTime(clock.nowWall) ? clock.nowWall : null,
          persistence: "pending", importPending: next.cleanOffAt !== null,
          offFetchStartMono: null };
      } else if (!next.switched) {
        if (successful && event.state === "off" &&
            finiteTime(event.fetchStartMono) && finiteTime(clock.nowMono) &&
            finiteTime(clock.nowWall) && validModeOwner(clock.bootId) &&
            event.fetchStartMono <= clock.nowMono &&
            clock.nowMono - event.fetchStartMono < OFF_TTL_MS) {
          // An old response cannot extend a newer accepted Off's lifetime.
          if (next.bootId !== clock.bootId || next.offFetchStartMono === null ||
              event.fetchStartMono >= next.offFetchStartMono) {
            next = { ...next, cleanOffAt: clock.nowWall,
              offFetchStartMono: event.fetchStartMono, bootId: clock.bootId };
          }
        } else next = expireOff(next);
      }
      break;
    }
    case "boot":
      if (!event.clockTrusted || next.bootId !== event.bootId) next = expireOff(next);
      next = { ...next, bootId: event.bootId };
      break;
    case "saveComplete":
      if (next.switched) next = { ...next, persistence: "saved" };
      break;
    case "saveFailed":
      if (next.switched) next = { ...next, persistence: "failed" };
      break;
    case "read":
    case "admit":
    case "commit":
      break;
    default:
      return refuseUnchanged();
  }

  if (!next.switched) {
    if (!freshOff(next, clock)) return { record: expireOff(next), decision: unknownDecision() };
    return { record: next, decision: { kind: "legacy", importRequired: false } };
  }
  if (next.persistence !== "saved") return { record: next, decision: unknownDecision() };

  // Evidence, boot, save completion and admission never consume migration delivery.
  const importRequired = next.importPending && (event.type === "read" || event.type === "commit");
  if (importRequired) next = { ...next, importPending: false };
  if (event.type === "commit" && event.sink === "legacy") {
    return { record: next, decision: { kind: "refuse", code: "LEGACY_REFUSED_SWITCHED",
      status: 426, retryable: false, importRequired } };
  }
  return { record: next, decision: { kind: "streams", importRequired } };
}
