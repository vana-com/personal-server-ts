/** Versioned, neutral connector evidence. Hosts collect facts; core owns policy. */
import {
  canonicalJson,
  type JsonValue,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { RunIntakeError } from "./intake.js";

export type RawEndScope =
  | { readonly kind: "run" }
  | { readonly kind: "stream"; readonly stream: string };
export interface RawEndError {
  readonly kind: "error" | "skip_result" | "detail_gap";
  readonly scope: RawEndScope;
  readonly code: string;
  readonly recoveryHint?: {
    readonly retryable?: boolean;
    readonly action?: string;
    readonly retryAfterMs?: number;
  };
}
export interface RawRecordEvidence {
  readonly liveKeys: readonly JsonValue[];
  readonly deletedKeys: readonly JsonValue[];
  readonly everDeletedKeys: readonly JsonValue[];
  readonly upsertEvents: number;
  readonly deleteEvents: number;
}
export interface RawEndV1 {
  readonly wireDialect: "connector-end-evidence/1";
  readonly lastBatch: number;
  readonly selectedStreams: readonly string[];
  readonly covered?: readonly string[];
  readonly finish:
    | { readonly kind: "completed" }
    | {
        readonly kind: "certified_failed_done";
        readonly failedStreams: readonly string[];
      }
    | {
        readonly kind: "failed_done_upsert_only";
        readonly failedStreams?: readonly string[];
      };
  readonly errors: readonly RawEndError[];
  readonly records: Readonly<Record<string, RawRecordEvidence>>;
  readonly checkpoints: Readonly<Record<string, JsonValue>>;
  readonly preflightExcludedStreams: readonly string[];
  readonly detailCoverage: Readonly<Record<string, JsonValue>>;
  readonly invalidDetailCoverageStreams: readonly string[];
  readonly wholeStreamEvidence: readonly {
    readonly stream: string;
    readonly report: JsonValue;
  }[];
}

export function rawEndInvalid(why: string): never {
  throw new RunIntakeError("invalid_request", `raw end: ${why}`);
}
function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function count(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
function json(value: unknown): value is JsonValue {
  return (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value)) ||
    (Array.isArray(value) && value.every(json)) ||
    (object(value) && Object.values(value).every(json))
  );
}
/** Canonical tuple equality, shared with durable intake (never host stringify). */
export function rawKeySet(value: unknown): Set<string> {
  if (!Array.isArray(value)) return rawEndInvalid("key list required");
  const keys = new Set<string>();
  for (const key of value) {
    if (!Array.isArray(key) || key.length === 0 || !json(key))
      rawEndInvalid("primary-key tuple required");
    const canonical = canonicalJson(key as JsonValue);
    if (keys.has(canonical)) rawEndInvalid("duplicate key");
    keys.add(canonical);
  }
  return keys;
}

/** Parse untrusted wire input. Scope-less legacy errors become run-scoped once. */
export function validateRawEnd(body: unknown): RawEndV1 {
  if (!object(body) || body.wireDialect !== "connector-end-evidence/1")
    rawEndInvalid("unknown wire dialect");
  if (!(body.lastBatch === -1 || count(body.lastBatch)))
    rawEndInvalid("unsafe lastBatch");
  const names = (value: unknown, selected?: readonly string[]): string[] => {
    if (
      !Array.isArray(value) ||
      value.some(
        (s) =>
          typeof s !== "string" ||
          s.length === 0 ||
          (selected && !selected.includes(s)),
      ) ||
      new Set(value).size !== value.length
    )
      return rawEndInvalid("duplicate, empty or unselected stream");
    return value as string[];
  };
  const selected = names(body.selectedStreams);
  if (body.covered !== undefined) names(body.covered, selected);
  names(body.preflightExcludedStreams, selected);
  names(body.invalidDetailCoverageStreams, selected);
  const map = (value: unknown): Record<string, unknown> => {
    if (!object(value)) return rawEndInvalid("stream map required");
    names(Object.keys(value), selected);
    return value;
  };
  for (const value of [body.checkpoints, body.detailCoverage]) {
    if (!Object.values(map(value)).every(json))
      rawEndInvalid("JSON value required");
  }
  const finish = body.finish;
  if (
    !object(finish) ||
    !["completed", "certified_failed_done", "failed_done_upsert_only"].some(
      (kind) => kind === finish.kind,
    )
  )
    rawEndInvalid("unknown finish");
  if (
    finish.kind === "certified_failed_done" ||
    finish.failedStreams !== undefined
  )
    names(finish.failedStreams, selected);
  for (const evidence of Object.values(map(body.records))) {
    if (
      !object(evidence) ||
      !count(evidence.upsertEvents) ||
      !count(evidence.deleteEvents)
    )
      rawEndInvalid("unsafe event counts");
    const live = rawKeySet(evidence.liveKeys);
    const deleted = rawKeySet(evidence.deletedKeys);
    const ever = rawKeySet(evidence.everDeletedKeys);
    if (
      [...live].some((k) => deleted.has(k)) ||
      [...deleted].some((k) => !ever.has(k)) ||
      [...ever].some((k) => !live.has(k) && !deleted.has(k)) ||
      live.size > evidence.upsertEvents ||
      ever.size > evidence.deleteEvents ||
      (ever.size === 0 && evidence.deleteEvents !== 0) ||
      (live.size + deleted.size === 0 &&
        (evidence.upsertEvents !== 0 || evidence.deleteEvents !== 0))
    )
      rawEndInvalid("inconsistent record evidence");
  }
  if (!Array.isArray(body.wholeStreamEvidence))
    rawEndInvalid("whole stream evidence list required");
  const proofs: string[] = [];
  for (const proof of body.wholeStreamEvidence) {
    if (
      !object(proof) ||
      typeof proof.stream !== "string" ||
      !json(proof.report)
    )
      rawEndInvalid("bad whole stream evidence");
    proofs.push(proof.stream);
  }
  names(proofs, selected);
  if (!Array.isArray(body.errors)) rawEndInvalid("errors list required");
  const errors = body.errors.map((error: unknown) => {
    if (
      !object(error) ||
      !["error", "skip_result", "detail_gap"].some(
        (kind) => kind === error.kind,
      ) ||
      typeof error.code !== "string" ||
      !error.code
    )
      rawEndInvalid("bad error");
    const scope = error.scope ?? { kind: "run" };
    if (!object(scope) || (scope.kind !== "run" && scope.kind !== "stream"))
      rawEndInvalid("bad error scope");
    if (scope.kind === "stream") names([scope.stream], selected);
    if (error.recoveryHint !== undefined) {
      const h = error.recoveryHint;
      if (
        !object(h) ||
        (h.retryable !== undefined && typeof h.retryable !== "boolean") ||
        (h.action !== undefined && typeof h.action !== "string") ||
        (h.retryAfterMs !== undefined && !count(h.retryAfterMs))
      )
        rawEndInvalid("bad recovery hint");
    }
    return { ...error, scope };
  });
  return { ...body, errors } as unknown as RawEndV1;
}
