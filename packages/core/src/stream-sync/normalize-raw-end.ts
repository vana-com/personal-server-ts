import { type JsonValue } from "@opendatalabs/personal-server-ts-stream-sync";
import type { EndRequest, StreamObservation } from "./intake.js";
import type { RunFinishStream } from "./run-finish-plan.js";
import {
  rawEndInvalid,
  rawKeySet,
  validateRawEnd,
  type RawEndError,
  type RawRecordEvidence,
} from "./raw-end.js";

export interface RawEndBegin {
  readonly selectedStreams: readonly string[];
  readonly streams: Readonly<
    Record<string, RunFinishStream & { readonly fullRead?: boolean }>
  >;
}
export interface NormalizedRawEnd extends EndRequest {
  readonly streams: Readonly<
    Record<string, StreamObservation & { readonly sourceAnswered?: boolean }>
  >;
}
export const EMPTY_RAW_RECORDS: RawRecordEvidence = {
  liveKeys: [],
  deletedKeys: [],
  everDeletedKeys: [],
  upsertEvents: 0,
  deleteEvents: 0,
};
function sameKeys(a: readonly JsonValue[], b: readonly JsonValue[]): boolean {
  const left = rawKeySet(a),
    right = rawKeySet(b);
  return left.size === right.size && [...left].every((key) => right.has(key));
}
/** V1 machine-code fallback. Human messages are never policy inputs. */
const RETRYABLE_CODES_V1 = new Set([
  "timeout",
  "rate_limited",
  "temporarily_unavailable",
]);
function retryable(error: RawEndError): boolean {
  const hint = error.recoveryHint;
  if (hint?.retryable !== undefined) return hint.retryable;
  if (error.kind === "detail_gap") return true;
  return (
    hint?.action === "retry_by_runtime" || RETRYABLE_CODES_V1.has(error.code)
  );
}

/** Whole-inventory proof: an explicit tuple inventory matching durable final keys.
 * Counts corroborate that inventory; count-only reports never prove replacement.
 * Other declaration strategies cannot authorize whole-inventory replacement.
 */
function wholeProof(report: JsonValue, evidence: RawRecordEvidence): boolean {
  if (report === null || typeof report !== "object" || Array.isArray(report))
    return false;
  const {
    keys,
    considered,
    covered,
    gap_keys: gaps,
  } = report as { readonly [key: string]: JsonValue };
  if (
    !Array.isArray(keys) ||
    !Number.isSafeInteger(considered) ||
    considered !== covered ||
    considered !== keys.length ||
    (gaps !== undefined && (!Array.isArray(gaps) || gaps.length !== 0))
  )
    return false;
  try {
    return sameKeys(keys, [...evidence.liveKeys, ...evidence.deletedKeys]);
  } catch {
    return false;
  }
}

function validDetailReport(report: JsonValue | undefined): boolean {
  if (report === undefined) return true;
  if (report === null || typeof report !== "object" || Array.isArray(report))
    return false;
  const r = report as { readonly [key: string]: JsonValue };
  return (
    typeof r.considered === "number" &&
    Number.isSafeInteger(r.considered) &&
    r.considered >= 0 &&
    typeof r.covered === "number" &&
    Number.isSafeInteger(r.covered) &&
    r.covered >= 0 &&
    r.covered <= r.considered &&
    ["required_keys", "hydrated_keys", "gap_keys"].every(
      (field) => r[field] === undefined || Array.isArray(r[field]),
    )
  );
}

/** Validate, bind to START selection, and reconcile against durably captured batches. */
export function normalizeRawEnd(
  body: unknown,
  begin: RawEndBegin,
  durable: Readonly<Record<string, RawRecordEvidence>>,
): NormalizedRawEnd {
  const raw = validateRawEnd(body);
  if (
    new Set(begin.selectedStreams).size !== begin.selectedStreams.length ||
    raw.selectedStreams.length !== begin.selectedStreams.length ||
    raw.selectedStreams.some(
      (s) =>
        !begin.selectedStreams.includes(s) ||
        !Object.prototype.hasOwnProperty.call(begin.streams, s),
    )
  )
    rawEndInvalid("selection differs from begin");
  for (const stream of Object.keys(durable))
    if (!raw.selectedStreams.includes(stream))
      rawEndInvalid("unselected durable records");
  const streams: Record<
    string,
    StreamObservation & { sourceAnswered?: boolean }
  > = Object.create(null);
  const proven: string[] = [];
  // Collection-failure SKIPs are complete evidence, not a capped diagnostic
  // sample. Every one must be attributable to the selected set. A run-scoped
  // failure withdraws certification; unknown streams were already rejected.
  const failureSkips = raw.errors.filter(
    (e) => e.kind === "skip_result" && e.code === "stream_collection_failed",
  );
  const certified =
    raw.done.status === "failed" &&
    raw.done.error?.code === "stream_collection_failed" &&
    failureSkips.length > 0 &&
    failureSkips.every((e) => e.scope.kind === "stream");
  const failed = certified
    ? [
        ...new Set(
          failureSkips.flatMap((e) =>
            e.scope.kind === "stream" ? [e.scope.stream] : [],
          ),
        ),
      ]
    : [];
  const finish =
    raw.done.status === "succeeded"
      ? "completed"
      : certified
        ? "certified_failed_done"
        : "failed_done_upsert_only";
  for (const stream of raw.selectedStreams) {
    const supplied = raw.records[stream] ?? EMPTY_RAW_RECORDS;
    const captured = durable[stream] ?? EMPTY_RAW_RECORDS;
    if (
      supplied.upsertEvents !== captured.upsertEvents ||
      supplied.deleteEvents !== captured.deleteEvents ||
      !sameKeys(supplied.liveKeys, captured.liveKeys) ||
      !sameKeys(supplied.deletedKeys, captured.deletedKeys) ||
      !sameKeys(supplied.everDeletedKeys, captured.everDeletedKeys)
    )
      rawEndInvalid(`records contradict durable batches for ${stream}`);
    const errors = raw.errors.filter(
      (e) => e.scope.kind === "run" || e.scope.stream === stream,
    );
    const skips = errors.filter((e) => e.kind !== "detail_gap");
    const gaps = errors.filter((e) => e.kind === "detail_gap");
    const proof = raw.wholeStreamEvidence.find((p) => p.stream === stream);
    const declaration = begin.streams[stream]!;
    const validProof =
      proof !== undefined &&
      declaration.mode === "full_refresh" &&
      declaration.fullRead === true &&
      declaration.coverageStrategy === "full_inventory" &&
      wholeProof(proof.report, captured);
    const observation: StreamObservation & { sourceAnswered?: boolean } = {
      liveRecord: captured.liveKeys.length > 0,
      explicitDelete: captured.everDeletedKeys.length > 0,
      retryableSkip: skips.some(retryable),
      otherSkip: skips.some((e) => !retryable(e)),
      preflightExclusion: raw.preflightExcludedStreams.includes(stream),
      detailGap:
        gaps.length === 0
          ? "none"
          : gaps.some((e) => !retryable(e))
            ? "fatal"
            : "retryable",
      invalidDetailCoverage:
        !validDetailReport(raw.detailCoverage[stream]) ||
        raw.invalidDetailCoverageStreams.includes(stream) ||
        (proof !== undefined && !validProof),
      failedInDone: failed.includes(stream),
      ...(raw.detailCoverage[stream] === undefined
        ? {}
        : { detailCoverage: raw.detailCoverage[stream] }),
      ...(raw.covered === undefined
        ? {}
        : { sourceAnswered: raw.covered.includes(stream) }),
    };
    streams[stream] = observation;
    if (
      validProof &&
      !observation.retryableSkip &&
      !observation.otherSkip &&
      !observation.preflightExclusion &&
      observation.detailGap === "none" &&
      !observation.invalidDetailCoverage &&
      !observation.failedInDone &&
      observation.sourceAnswered !== false &&
      finish !== "failed_done_upsert_only"
    )
      proven.push(stream);
  }
  return {
    finish,
    streams,
    checkpoints: raw.checkpoints,
    lastBatch: raw.lastBatch,
    provenFullStreams: proven.sort(),
  };
}
