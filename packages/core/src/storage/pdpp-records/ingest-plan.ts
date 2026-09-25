import {
  encodeRecordKey,
  keyMatchesData,
  RecordKeyError,
} from "./record-key.js";
import type {
  IngestOutcome,
  IngestResult,
  PdppRecordEnvelopeInput,
  StreamSemantics,
} from "./types.js";

/** The stored state of a key that decides an envelope's outcome. */
export interface CurrentContent {
  deleted: boolean;
  data: Record<string, unknown> | null;
}

/**
 * What one envelope should do to the store. Both backends call this so they
 * cannot disagree about outcomes; each only performs the write.
 *
 * Content is `deleted` plus the canonical JSON of `data`. `emitted_at` is
 * version metadata, not content: re-emitting equal content is `unchanged`
 * and keeps the stored `emitted_at`, so a full refresh of unchanged data
 * writes no history and wakes no `changes_since` reader.
 */
export type IngestPlan =
  | { outcome: IngestOutcome; write?: undefined }
  | {
      outcome: { index: number; outcome: "accepted" };
      write: { recordKey: string; data: Record<string, unknown> | null };
    };

export function planIngest(
  index: number,
  envelope: PdppRecordEnvelopeInput,
  semantics: StreamSemantics,
  primaryKey: string[],
  current: (recordKey: string) => CurrentContent | undefined,
): IngestPlan {
  const reject = (reason: string): IngestPlan => ({
    outcome: { index, outcome: "rejected", reason },
  });
  const unchanged = (flag?: "append_only_conflict"): IngestPlan => ({
    outcome: { index, outcome: "unchanged", ...(flag && { flag }) },
  });

  if (typeof envelope.emitted_at !== "string" || !envelope.emitted_at) {
    return reject("emitted_at must be a non-empty string");
  }
  if (
    envelope.op !== undefined &&
    envelope.op !== "upsert" &&
    envelope.op !== "delete"
  ) {
    return reject("op must be 'upsert' or 'delete'");
  }

  let recordKey: string;
  try {
    recordKey = encodeRecordKey(envelope.key);
  } catch (err) {
    if (err instanceof RecordKeyError) return reject(err.message);
    throw err;
  }
  const existing = current(recordKey);

  if (envelope.op === "delete") {
    if (semantics === "append_only") {
      return reject("append_only streams do not support delete directives");
    }
    if (!existing || existing.deleted) return unchanged();
    return {
      outcome: { index, outcome: "accepted" },
      write: { recordKey, data: null },
    };
  }

  const data = envelope.data;
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    return reject("data must be a JSON object for upsert");
  }
  try {
    if (!keyMatchesData(envelope.key, data, primaryKey)) {
      return reject(
        "envelope key does not match data's declared primary_key fields",
      );
    }
  } catch (err) {
    if (err instanceof RecordKeyError) return reject(err.message);
    throw err;
  }

  if (existing && !existing.deleted) {
    if (canonicalJson(existing.data) === canonicalJson(data)) {
      return unchanged();
    }
    // Core: append_only records are immutable and duplicate keys are
    // idempotent, so the first write stands. The flag lets the producer
    // count a source that changed a record it declared immutable.
    if (semantics === "append_only") return unchanged("append_only_conflict");
  }
  return {
    outcome: { index, outcome: "accepted" },
    write: { recordKey, data },
  };
}

/** JSON with object keys sorted at every depth. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value as Record<string, unknown>)
        .sort()
        .map((key) => [key, sortKeys((value as Record<string, unknown>)[key])]),
    );
  }
  return value;
}

/** The per-index outcomes plus the counts callers already read. */
export function summarizeIngest(results: IngestOutcome[]): IngestResult {
  let accepted = 0;
  let unchanged = 0;
  const rejected: IngestResult["rejected"] = [];
  for (const result of results) {
    if (result.outcome === "accepted") accepted += 1;
    else if (result.outcome === "unchanged") unchanged += 1;
    else rejected.push({ index: result.index, reason: result.reason });
  }
  return { accepted, unchanged, rejected, results };
}
