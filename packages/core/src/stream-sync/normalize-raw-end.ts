import {
  canonicalJson,
  type JsonValue,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { EndRequest, StreamObservation } from "./intake.js";
import type { RunFinishStream } from "./run-finish-plan.js";
import { rawEndInvalid, validateRawEnd, type RawEndError } from "./raw-end.js";

/** Core-owned final keys and delete history captured by durable intake. */
export interface DurableRecordEvidence {
  readonly liveKeys: readonly JsonValue[];
  readonly deletedKeys: readonly JsonValue[];
  readonly everDeletedKeys: readonly JsonValue[];
  readonly upsertEvents: number;
  readonly deleteEvents: number;
}
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
export const EMPTY_RAW_RECORDS: DurableRecordEvidence = {
  liveKeys: [],
  deletedKeys: [],
  everDeletedKeys: [],
  upsertEvents: 0,
  deleteEvents: 0,
};
/** V1 machine-code fallback. Human messages are never policy inputs. */
const RETRYABLE_CODES_V1 = new Set([
  "timeout",
  "rate_limited",
  "temporarily_unavailable",
]);
function machineCode(error: RawEndError): string | undefined {
  return error.code ?? error.reason;
}
function isGap(error: RawEndError): boolean {
  return error.kind === "detail_gap" || error.kind === "detail_gap_recovered";
}
function retryable(error: RawEndError): boolean {
  const hint = error.recoveryHint;
  const structured = typeof hint === "object" ? hint : undefined;
  // Preserve the native gap field; never fabricate a recoveryHint for it.
  if (error.retryable === false || structured?.retryable === false)
    return false;
  if (error.retryable === true || structured?.retryable === true) return true;
  if (isGap(error)) return true;
  return (
    hint === "retry_by_runtime" ||
    structured?.action === "retry_by_runtime" ||
    RETRYABLE_CODES_V1.has(machineCode(error) ?? "")
  );
}

/** The connector claims complete enumeration; core counts its durable final keys.
 * Only an explicit report under a full-read/full-inventory declaration can prove
 * replacement. Equal counts alone outside that claim never authorize it.
 */
function wholeProof(
  report: JsonValue,
  evidence: DurableRecordEvidence,
): boolean {
  if (report === null || typeof report !== "object" || Array.isArray(report))
    return false;
  const {
    considered,
    covered,
    gap_keys: gaps,
  } = report as {
    readonly [key: string]: JsonValue;
  };
  return (
    !("keys" in report) &&
    Number.isSafeInteger(considered) &&
    considered === covered &&
    considered === evidence.liveKeys.length + evidence.deletedKeys.length &&
    (gaps === undefined || (Array.isArray(gaps) && gaps.length === 0)) &&
    validDetailReport(report) &&
    !reportHasGap(report)
  );
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

/** A report can expose a gap even if the connector omitted its gap event. */
function reportHasGap(report: JsonValue | undefined): boolean {
  if (report === undefined || !validDetailReport(report)) return false;
  const r = report as { readonly [key: string]: JsonValue };
  const hydrated = Array.isArray(r.hydrated_keys) ? r.hydrated_keys : [];
  return (
    r.considered !== r.covered ||
    (Array.isArray(r.gap_keys) && r.gap_keys.length > 0) ||
    (Array.isArray(r.required_keys) &&
      r.required_keys.some(
        (key) => !hydrated.some((h) => canonicalJson(key) === canonicalJson(h)),
      ))
  );
}

/** Validate, bind to START selection, and derive record facts from durably captured batches. */
export function normalizeRawEnd(
  body: unknown,
  begin: RawEndBegin,
  durable: Readonly<Record<string, DurableRecordEvidence>>,
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
  // Protocol RECORD totals include deletes and repeated upserts before folding.
  if (raw.done.recordsEmitted !== undefined) {
    const emitted = Object.values(durable).reduce(
      (total, evidence) =>
        total + evidence.upsertEvents + evidence.deleteEvents,
      0,
    );
    if (!Number.isSafeInteger(emitted) || raw.done.recordsEmitted !== emitted)
      rawEndInvalid("DONE record count contradicts durable batches");
  }
  const streams: Record<
    string,
    StreamObservation & { sourceAnswered?: boolean }
  > = Object.create(null);
  const proven: string[] = [];
  // Collection-failure SKIPs are complete evidence, not a capped diagnostic
  // sample. Every one must be attributable to the selected set. A run-scoped
  // failure withdraws certification; unknown streams were already rejected.
  const failureSkips = raw.errors.filter(
    (e) =>
      e.kind === "skip_result" && machineCode(e) === "stream_collection_failed",
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
    const captured = Object.hasOwn(durable, stream)
      ? durable[stream]!
      : EMPTY_RAW_RECORDS;
    const detailCoverage = Object.hasOwn(raw.detailCoverage, stream)
      ? raw.detailCoverage[stream]
      : undefined;
    const errors = raw.errors.filter(
      (e) => e.scope.kind === "run" || e.scope.stream === stream,
    );
    const skips = errors.filter((e) => !isGap(e));
    const gaps = errors.filter(isGap);
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
          ? reportHasGap(detailCoverage)
            ? "retryable"
            : "none"
          : gaps.some((e) => !retryable(e))
            ? "fatal"
            : "retryable",
      invalidDetailCoverage:
        !validDetailReport(detailCoverage) ||
        raw.invalidDetailCoverageStreams.includes(stream) ||
        (proof !== undefined && !validProof),
      failedInDone: failed.includes(stream),
      ...(detailCoverage === undefined ? {} : { detailCoverage }),
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
