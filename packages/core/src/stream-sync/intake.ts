/** Shared run-intake contract for Node, Lite and native hosts.
 * P03/P04 own persistence and lifecycle; hosts compose the database facade.
 */
import type { JsonValue } from "@opendatalabs/personal-server-ts-stream-sync";

/** What `end` can answer (V2 §2.3). */
export type EndResult =
  "queued" | "checkpoint_only" | "no_checkpoint" | "discarded" | "aborted";

export type RunIntakeErrorName =
  | "invalid_request"
  | "owner_mismatch"
  | "lease_lost"
  | "connection_busy"
  | "connection_stopped"
  | "gone"
  | "run_conflict"
  | "unknown_artifact"
  | "batch_gap"
  | "restricted_scope_unsupported";

const STATUS: Record<RunIntakeErrorName, number> = {
  invalid_request: 400,
  owner_mismatch: 409,
  lease_lost: 409,
  connection_busy: 409,
  connection_stopped: 409,
  gone: 410,
  run_conflict: 409,
  unknown_artifact: 422,
  batch_gap: 409,
  restricted_scope_unsupported: 422,
};

export class RunIntakeError extends Error {
  readonly status: number;
  constructor(
    readonly code: RunIntakeErrorName,
    message: string = code,
    readonly nextBatch?: number,
  ) {
    super(message);
    this.name = "RunIntakeError";
    this.status = STATUS[code];
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
  readonly status: "collecting" | "will_discard";
  readonly discardReason: "registry_unreachable" | null;
  readonly stuck: boolean;
  readonly binding: { readonly keyCheck: string };
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
}

export interface EndRequest {
  readonly outcome:
    "succeeded" | "partial" | "retry_pending" | "failed" | "cancelled";
  readonly coveredStreams: readonly string[];
  readonly checkpointCandidate?: Readonly<Record<string, JsonValue>> | null;
  readonly lastBatch: number;
  /** H: streams the producer proved it read whole. P05 applies the per-stream replacement proof. */
  readonly provenFullStreams?: readonly string[];
}

export interface EndResponse {
  readonly result: EndResult;
  readonly stuck: boolean;
  /** At least one stream was refused because this app needs an update. */
  readonly updateRequired: boolean;
}

export interface RunIntake {
  begin(runId: string, req: BeginRequest): Promise<BeginResponse>;
  batch(runId: string, req: BatchRequest): Promise<BatchResponse>;
  end(runId: string, req: EndRequest): Promise<EndResponse>;
  abort(runId: string, reason: "failed" | "cancelled"): Promise<void>;
}

/** Adapt an already-composed database intake without constructing another writer. */
export function createStreamSyncIntake(options: {
  readonly intake: RunIntake;
}): RunIntake {
  return options.intake;
}
