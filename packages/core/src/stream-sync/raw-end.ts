/** Versioned, neutral connector evidence. Hosts collect facts; core owns policy. */
import type { JsonValue } from "@opendatalabs/personal-server-ts-stream-sync";
import { RunIntakeError } from "./intake.js";

export type RawEndScope =
  | { readonly kind: "run" }
  | { readonly kind: "stream"; readonly stream: string };
export interface RawEndError {
  readonly kind:
    "error" | "skip_result" | "detail_gap" | "detail_gap_recovered";
  readonly scope: RawEndScope;
  readonly code?: string;
  /** Native SKIP/DETAIL_GAP reason, preserved when the event has no code. */
  readonly reason?: string;
  readonly retryable?: boolean;
  readonly status?: string;
  readonly message?: string;
  readonly diagnostics?: JsonValue;
  /** Original detail/reference payload, including gap identity and locator. */
  readonly raw?: JsonValue;
  readonly recoveryHint?:
    | string
    | {
        readonly retryable?: boolean;
        readonly action?: string;
        readonly retryAfterMs?: number;
      };
}
export interface RawEndV1 {
  readonly wireDialect: "connector-end-evidence/1";
  readonly lastBatch: number;
  readonly selectedStreams: readonly string[];
  readonly covered?: readonly string[];
  /** The connector's actual DONE, never a host-certified finish verdict.
   * Missing, cancelled and protocol-invalid DONE use the abort path.
   */
  readonly done: {
    readonly status: "succeeded" | "failed";
    /** Emitted RECORD frames, including deletes and repeated keys. */
    readonly recordsEmitted?: number;
    readonly error?: {
      readonly code?: string;
      readonly retryable?: boolean;
      readonly message?: string;
      readonly diagnostics?: JsonValue;
    };
  };
  readonly errors: readonly RawEndError[];
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
  if ("finish" in body || "failedStreams" in body)
    rawEndInvalid("host finish verdicts are not raw DONE evidence");
  const done = body.done;
  if (
    !object(done) ||
    (done.status !== "succeeded" && done.status !== "failed")
  )
    rawEndInvalid("valid DONE required; otherwise abort");
  if (done.recordsEmitted !== undefined && !count(done.recordsEmitted))
    rawEndInvalid("unsafe DONE record count");
  if (done.error !== undefined) {
    const e = done.error;
    if (
      done.status === "succeeded" ||
      !object(e) ||
      (e.code !== undefined &&
        (typeof e.code !== "string" || !e.code.trim())) ||
      (e.retryable !== undefined && typeof e.retryable !== "boolean") ||
      (e.message !== undefined && typeof e.message !== "string") ||
      (e.diagnostics !== undefined && !json(e.diagnostics))
    )
      rawEndInvalid("invalid DONE error");
  }
  if ("records" in body)
    rawEndInvalid("record evidence is derived from durable batches");
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
      !["error", "skip_result", "detail_gap", "detail_gap_recovered"].some(
        (kind) => kind === error.kind,
      ) ||
      (error.code !== undefined &&
        (typeof error.code !== "string" || !error.code)) ||
      (error.reason !== undefined && typeof error.reason !== "string") ||
      (error.retryable !== undefined && typeof error.retryable !== "boolean") ||
      (error.status !== undefined && typeof error.status !== "string") ||
      (error.message !== undefined && typeof error.message !== "string") ||
      (error.diagnostics !== undefined && !json(error.diagnostics)) ||
      (error.raw !== undefined && !json(error.raw))
    )
      rawEndInvalid("bad error");
    const scope = error.scope ?? { kind: "run" };
    if (!object(scope) || (scope.kind !== "run" && scope.kind !== "stream"))
      rawEndInvalid("bad error scope");
    if (scope.kind === "stream") names([scope.stream], selected);
    if (error.recoveryHint !== undefined) {
      const h = error.recoveryHint;
      if (
        typeof h !== "string" &&
        (!object(h) ||
          (h.retryable !== undefined && typeof h.retryable !== "boolean") ||
          (h.action !== undefined && typeof h.action !== "string") ||
          (h.retryAfterMs !== undefined && !count(h.retryAfterMs)))
      )
        rawEndInvalid("bad recovery hint");
    }
    return { ...error, scope };
  });
  return { ...body, errors } as unknown as RawEndV1;
}
