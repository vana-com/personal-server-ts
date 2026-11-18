/** Shared run-intake contract for Node, Lite and native hosts.
 * P03/P04 own persistence and lifecycle; hosts compose the database facade.
 */
import type {
  ControlState,
  JsonValue,
  KeyFieldType,
} from "@opendatalabs/personal-server-ts-stream-sync";

import type { EndOutcome, EndResult } from "./host-contract.js";

/**
 * The run-intake refusals and the HTTP status each carries. Hosts that run a
 * writer of their own read this list from the
 * generated host contract, never from a copy.
 */
export const RUN_INTAKE_ERROR_STATUS = {
  invalid_request: 400,
  owner_mismatch: 409,
  lease_lost: 409,
  connection_busy: 409,
  /** The connection is stopped: deleted, and an explicit connect is required. */
  connection_stopped: 409,
  /**
   * A delete of this connection is not finished on this device and the last
   * resume failed. The device keeps retrying; no run may write until it lands.
   */
  delete_pending: 409,
  gone: 410,
  run_conflict: 409,
  unknown_artifact: 422,
  batch_gap: 409,
  restricted_scope_unsupported: 422,
  control_basis_mismatch: 409,
  control_basis_unavailable: 503,
  /**
   * The registry's control row for this connector is under another key, so this
   * owner key cannot publish a run. Refused before anything is written locally.
   */
  control_foreign: 409,
} as const;

export type RunIntakeErrorName = keyof typeof RUN_INTAKE_ERROR_STATUS;

export class RunIntakeError extends Error {
  readonly status: number;
  constructor(
    readonly code: RunIntakeErrorName,
    message: string = code,
    readonly nextBatch?: number,
    /** `delete_pending` only: the error name of the last failed resume. */
    readonly lastError?: string,
  ) {
    super(message);
    this.name = "RunIntakeError";
    this.status = RUN_INTAKE_ERROR_STATUS[code];
  }
}

export type CoverageStrategy =
  | "checkpoint_window"
  | "full_inventory"
  | "parent_detail_accounting"
  | "snapshot_import_receipt"
  | "singleton_presence";

/** One stream of a verified connector artifact. */
export interface IntakeStreamDeclaration {
  readonly name: string;
  readonly semantics: "mutable_state" | "append_only";
  readonly primaryKey: readonly string[];
  /** `false` = every run reads the whole stream (§3.0). Default `true`. */
  readonly incremental?: boolean;
  readonly consentTimeField?: string;
  /** Collection profile §3.5. Missing declarations never authorize deletion. */
  readonly coverageStrategy?: CoverageStrategy;
  /**
   * The type the stream's schema declares for each primary-key field, in key
   * order; `null` where it declares none (or several). Lets a delete made
   * before typed keys were kept name its typed key (see `keyFromRecordKey`).
   */
  readonly keyTypes?: readonly (KeyFieldType | null)[];
  /**
   * The streams whose STATE this stream's cursor depends on: the manifest's
   * `state_stream` then its `parent_streams`. Run end holds a parent's cursor
   * when a child is blocked, and drops a child's cursor when a parent has none.
   */
  readonly stateParents?: readonly string[];
}

export interface IntakeDeclarations {
  /**
   * The connector key of the verified artifact. A run's `connector` must
   * equal it: the artifact fixes which connector a producer may publish as.
   */
  readonly connector: string;
  /** The connector version; it becomes the head profile version. */
  readonly version: string;
  readonly streams: readonly IntakeStreamDeclaration[];
}

/**
 * Resolve an artifact digest to its declarations. Host code fills the table
 * after it verified the artifact; an unknown digest answers `null`.
 */
export type ResolveArtifact = (
  digest: string,
) => IntakeDeclarations | null | Promise<IntakeDeclarations | null>;

export interface BeginRequest {
  /** Explicit selection for raw-end V1; absence preserves legacy admission. */
  readonly selectedStreams?: readonly string[];
  readonly connector: string;
  readonly artifactDigest: string;
  readonly owner: { readonly address: string; readonly leaseId: string | null };
  /** True when the run asks for a full collection (a profile mode, not an action). */
  readonly wantFull?: boolean;
  /**
   * True only for an explicit connect action by the owner. The only thing that
   * starts a connection the device saw deleted (§2.4 `stopped`).
   */
  readonly connect?: boolean;
  /** Control-row version observed by a retry caller; 0 means authoritative absence. */
  readonly expectedControlVersion?: number;
  readonly observedAt?: number;
  /**
   * The scope the producer will put in START, per stream. Used only to
   * refuse `fields` and `resources` (R17).
   */
  readonly streams?: readonly {
    readonly name: string;
    readonly fields?: unknown;
    readonly resources?: unknown;
    readonly time_range?: unknown;
  }[];
}

export interface BeginResponse {
  readonly runId: string;
  readonly status: "collecting" | "will_discard" | "ended";
  /** Original local end acknowledgement. Remote publication is confirmed separately. */
  readonly receipt?: EndResponse;
  readonly discardReason: "registry_unreachable" | null;
  readonly stuck: boolean;
  readonly binding: { readonly keyCheck: string };
  /**
   * The control basis this `begin` admitted against, classified for
   * the owner's key: what a caller that must know the connection's state
   * before it collects (a save that reports the control version it observed)
   * would otherwise read again. An explicit full collection can use its local
   * applied basis: the publication commit validates that lifetime and log
   * position atomically. Retry and reconnect admission read the registry.
   * Absent from an answer that replays an earlier
   * `begin` or an ended run, and `undefined` when the registry did not answer
   * (the run begins offline). A replay therefore reads the same as an
   * unreachable registry: a caller that needs the state after a replay reads
   * the registry itself; the row is not stored with the run.
   */
  readonly control?: ControlState;
  readonly start: {
    readonly collection_mode: "full_refresh" | "incremental";
    readonly state: JsonValue | null;
  };
  readonly streams: readonly {
    readonly name: string;
    readonly semantics: string;
    readonly primaryKey: readonly string[];
    readonly incremental: boolean;
    readonly consentTimeField?: string;
    /** Collection profile §3.5. Missing declarations never authorize deletion. */
    readonly coverageStrategy?: CoverageStrategy;
    readonly stateParents?: readonly string[];
    readonly mode: "full_refresh" | "incremental";
  }[];
}

export interface BatchRequest {
  readonly batch: number;
  readonly records: readonly {
    readonly stream: string;
    readonly op?: string;
    readonly key?: string | string[];
    readonly data: unknown;
  }[];
}

export interface BatchResponse {
  readonly applied: boolean;
  readonly accepted: number;
  /** Compatibility count: explicit deletes are accepted, so this is always zero. */
  readonly deletesSkipped: number;
  /**
   * Publish while collecting only: upserts not admitted because a newer delete
   * is remembered for their key.
   */
  readonly tombstoned?: number;
  /**
   * Publish while collecting only: this batch carried upserts of a stream whose
   * connector is below the version floor or head key. They were staged, not
   * admitted; run end refuses the stream with `updateRequired`.
   */
  readonly updateRequired?: boolean;
}

/**
 * How a run's connector finished, as the host saw it. `completed`: DONE
 * succeeded. `certified_failed_done`: DONE failed and named the streams that
 * failed, so the others can count. `failed_done_upsert_only`: DONE failed
 * without that certification, so only records count.
 */
export type RunFinish =
  "completed" | "certified_failed_done" | "failed_done_upsert_only";

/**
 * What the host saw of one selected stream. Facts only: run end decides from
 * them whether the stream is covered and whether its cursor may move. A
 * run-wide skip (one that names no stream) is reported on every stream.
 */
export interface StreamObservation {
  /** The stream's records, folded by key in order, leave a live record. */
  readonly liveRecord: boolean;
  /** The stream emitted at least one explicit delete. */
  readonly explicitDelete: boolean;
  /** A SKIP_RESULT for this stream (or the run) the runtime can retry. */
  readonly retryableSkip: boolean;
  /** A SKIP_RESULT for this stream (or the run) the runtime cannot retry. */
  readonly otherSkip: boolean;
  /** The host refused the stream's data before sending it. */
  readonly preflightExclusion: boolean;
  /**
   * A DETAIL_GAP for this stream. `retryable` when any gap did not say
   * `retryable: false`; `fatal` when every gap did.
   */
  readonly detailGap: "none" | "retryable" | "fatal";
  /** A DETAIL_COVERAGE report for this stream that the host could not accept. */
  readonly invalidDetailCoverage: boolean;
  /** A failed DONE named this stream as failed. */
  readonly failedInDone: boolean;
  /** The connector's last DETAIL_COVERAGE report for this stream, as sent. */
  readonly detailCoverage?: JsonValue;
}

export interface EndRequest {
  readonly finish: RunFinish;
  /** Every stream the run selected, and only those. */
  readonly streams: Readonly<Record<string, StreamObservation>>;
  /** The connector's STATE per stream, as emitted. */
  readonly checkpoints: Readonly<Record<string, JsonValue>>;
  readonly lastBatch: number;
  /** H: streams the producer proved it read whole. P05 applies the per-stream replacement proof. */
  readonly provenFullStreams?: readonly string[];
}

export interface EndResponse {
  readonly result: EndResult;
  readonly stuck: boolean;
  /** At least one stream was refused because this app needs an update. */
  readonly updateRequired: boolean;
  /** What the run's observations made it. `failed` ended it with nothing kept. */
  readonly outcome: EndOutcome;
  /** The streams whose records this run kept (deletes are kept for every stream). */
  readonly coveredStreams: readonly string[];
  /** The covered streams this run may replace whole. */
  readonly provenFullStreams: readonly string[];
  /**
   * The run confirmed no selected stream: every stream was skipped, or silent
   * where a silent stream cannot count.
   */
  readonly unconfirmed: boolean;
}

/**
 * Whether a run's work is saved. `published`: a publication this database
 * confirmed covered the work. `pending`: accepted, not yet confirmed.
 * `superseded`: refused, discarded, replaced, or its connection was deleted
 * or restarted since. `unknown`: nothing durable says (runs from before this
 * record existed, runs still collecting, runs with no accepted stream).
 */
export type RunPublicationState =
  "published" | "pending" | "superseded" | "unknown";

export interface RunStreamPublication {
  readonly name: string;
  readonly state: RunPublicationState;
  readonly reason?: string;
  /** The publication that covered this stream. Kept after supersession. */
  readonly publication?: {
    readonly generation: number;
    readonly version: number;
    readonly dataHash: string;
    /** Local change sequence of this database. Not a time. */
    readonly watermark: number;
  };
}

/**
 * The last locally confirmed publication state of an ended run; it is not a
 * fresh read of remote storage. `published` means every accepted stream has a
 * confirmed publication, not that every original record is still in the head.
 */
export interface RunPublicationStatus {
  readonly runId: string;
  readonly state: RunPublicationState;
  readonly reason?: string;
  readonly streams: readonly RunStreamPublication[];
}

export interface RunIntake {
  begin(runId: string, req: BeginRequest): Promise<BeginResponse>;
  batch(runId: string, req: BatchRequest): Promise<BatchResponse>;
  end(runId: string, req: EndRequest): Promise<EndResponse>;
  abort(runId: string, reason: "failed" | "cancelled"): Promise<void>;
  /**
   * Whether an ended run is saved, from durable local state. An unknown run
   * answers `gone`. With `binding`, another owner answers `owner_mismatch` and
   * another connector `run_conflict`, as `begin` does.
   */
  publicationStatus(
    runId: string,
    binding?: { readonly owner?: string; readonly connector?: string },
  ): Promise<RunPublicationStatus>;
}

/** Adapt an already-composed database intake without constructing another writer. */
export function createStreamSyncIntake(options: {
  readonly intake: RunIntake;
}): RunIntake {
  return options.intake;
}
