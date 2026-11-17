import type { JsonValue } from "@opendatalabs/personal-server-ts-stream-sync";
import type {
  EndRequest,
  RunFinish,
  StreamObservation,
} from "../stream-sync/intake.js";

/** What a host saw of a stream that emitted nothing. */
export const SILENT_STREAM: StreamObservation = {
  liveRecord: false,
  explicitDelete: false,
  retryableSkip: false,
  otherSkip: false,
  preflightExclusion: false,
  detailGap: "none",
  invalidDetailCoverage: false,
  failedInDone: false,
};

/**
 * An end body built from what the test's connector did. Each named stream gets
 * the observation of its kind; a stream in no list is silent.
 */
export function endRequest(options: {
  readonly lastBatch: number;
  /** Every stream the run selected. Defaults to the streams named below. */
  readonly streams?: readonly string[];
  /** Streams that emitted a live record. */
  readonly live?: readonly string[];
  /** Streams that emitted an explicit delete. */
  readonly deleted?: readonly string[];
  /** Streams the connector skipped and cannot retry. */
  readonly skipped?: readonly string[];
  /** A run-wide skip the runtime can retry. */
  readonly retry?: boolean;
  readonly finish?: RunFinish;
  readonly checkpoints?: Readonly<Record<string, JsonValue>>;
  readonly provenFullStreams?: readonly string[];
  /** Per-stream observation fields that override the kinds above. */
  readonly observe?: Readonly<Record<string, Partial<StreamObservation>>>;
}): EndRequest {
  const named = new Set([
    ...(options.streams ?? []),
    ...(options.live ?? []),
    ...(options.deleted ?? []),
    ...(options.skipped ?? []),
    ...Object.keys(options.observe ?? {}),
  ]);
  const streams: Record<string, StreamObservation> = {};
  for (const name of named)
    streams[name] = {
      ...SILENT_STREAM,
      liveRecord: options.live?.includes(name) ?? false,
      explicitDelete: options.deleted?.includes(name) ?? false,
      otherSkip: options.skipped?.includes(name) ?? false,
      retryableSkip: options.retry === true,
      ...options.observe?.[name],
    };
  return {
    finish: options.finish ?? "completed",
    streams,
    checkpoints: options.checkpoints ?? {},
    lastBatch: options.lastBatch,
    ...(options.provenFullStreams === undefined
      ? {}
      : { provenFullStreams: options.provenFullStreams }),
  };
}
