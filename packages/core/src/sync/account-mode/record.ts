/**
 * The per-owner account-mode record and the rule that updates it.
 *
 * The Account says On or Off for a person. The server keeps the last answer per
 * owner, with no expiry:
 * - On latches. A later Off at the same generation is ignored.
 * - A higher generation (a Dev reset) replaces the record, On or Off.
 * - A lower generation is stale and ignored.
 * - After the first answer an owner is never unknown again.
 */

export type ModeAnswer = "on" | "off";

export interface AccountModeRecord {
  readonly answer: ModeAnswer;
  /** 0 for everyone; raised by one only by a Dev reset. */
  readonly generation: number;
  /** Epoch milliseconds when this answer was saved. Informational. */
  readonly receivedAt: number;
}

/** What a legacy gate or a read sees for one owner. */
export type ModeDecision =
  | { kind: "streams" }
  | { kind: "legacy" }
  /** No answer yet (503, retryable), or a legacy write on a switched account (426). */
  | RefuseDecision;

export type RefuseDecision =
  | { kind: "refuse"; code: "ACCOUNT_MODE_UNKNOWN"; status: 503 }
  | { kind: "refuse"; code: "LEGACY_REFUSED_SWITCHED"; status: 426 };

export const UNKNOWN_DECISION: RefuseDecision = {
  kind: "refuse",
  code: "ACCOUNT_MODE_UNKNOWN",
  status: 503,
};
export const SWITCHED_REFUSAL: RefuseDecision = {
  kind: "refuse",
  code: "LEGACY_REFUSED_SWITCHED",
  status: 426,
};

/** Owners are compared case-insensitively (addresses). */
export function normalizeOwner(owner: string): string {
  return owner.trim().toLowerCase();
}

/** The record after one answer. Returns `prev` itself when nothing changes. */
export function applyAnswer(
  prev: AccountModeRecord | undefined,
  answer: ModeAnswer,
  generation: number,
  now: number,
): AccountModeRecord {
  if (!prev || generation > prev.generation) {
    return { answer, generation, receivedAt: now };
  }
  if (generation < prev.generation) return prev;
  if (prev.answer === "off" && answer === "on") {
    return { answer, generation, receivedAt: now };
  }
  return prev;
}

/** Where records live between runs. A host supplies one (file, IndexedDB). */
export interface ModeRecordStore {
  load(): Promise<ReadonlyMap<string, AccountModeRecord>>;
  save(owner: string, record: AccountModeRecord): Promise<void>;
}

export function createMemoryModeRecordStore(
  initial: Iterable<[string, AccountModeRecord]> = [],
): ModeRecordStore & { readonly saved: Map<string, AccountModeRecord> } {
  const saved = new Map(initial);
  return {
    saved,
    load: async () => new Map(saved),
    save: async (owner, record) => {
      saved.set(owner, record);
    },
  };
}

/** A parsed record, or null when the value is not one. */
export function parseRecord(value: unknown): AccountModeRecord | null {
  if (typeof value !== "object" || value === null) return null;
  const v = value as Record<string, unknown>;
  if (v.answer !== "on" && v.answer !== "off") return null;
  if (!Number.isSafeInteger(v.generation) || (v.generation as number) < 0) {
    return null;
  }
  const receivedAt = typeof v.receivedAt === "number" ? v.receivedAt : 0;
  return { answer: v.answer, generation: v.generation as number, receivedAt };
}
