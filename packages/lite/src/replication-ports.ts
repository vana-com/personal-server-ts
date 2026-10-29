/**
 * The ports a phone (or other PS-Lite) host implements for record replication
 * (host contract, docs/replication/host-contract.md §4). PS-Lite owns what to
 * replicate and when a step is due; the host owns storage, network I/O and
 * the app lifecycle that triggers steps.
 *
 * - Persistence: `LiteReplicaPersistence`, the canonical native transaction
 *   plus fragment-sized byte storage (§4.3).
 * - Transport: `LiteReplicaObjectTransfers`, storage object I/O done natively
 *   (unity-surfaces `apps/mobile-shell/lib/replication/native_replica_transport.dart`),
 *   plus core's `ReplicaRosterPort` (§4.2).
 * - Trigger/status: `LiteReplicationRuntime` (`replication-runtime.ts`).
 *
 * In-memory reference implementations live in `test-support/replication.ts`.
 */
import type { ReplicaRosterPort } from "@opendatalabs/personal-server-ts-core/replication/roster";
import type { ReplicationStepper } from "@opendatalabs/personal-server-ts-core/replication/host-driver";
import type { ReplicaEnvironment } from "@opendatalabs/personal-server-ts-core/replication/writer-identity";
import type { ReplicaSql } from "@opendatalabs/personal-server-ts-core/replication/effects";
import type {
  LiteCanonicalPersistence,
  LiteCanonicalTransaction,
} from "./canonical-persistence.js";

/** Passed by the host at PS start (§4.1). Absent means off. */
export interface ReplicationBootConfig {
  /** The host's opt-in record says "on" (§5). */
  enabled: boolean;
  owner: `0x${string}`;
  environment: ReplicaEnvironment;
  chainId: number;
  limits: ReplicationLimits;
}

export interface ReplicationLimits {
  /** Fragment size target. Lite: 1 MiB, the native record limit. */
  fragmentBytes: number;
  /** Work, memory and time per step (§6). */
  step: { units: number; bytes: number; deadlineMs: number };
}

/** The phone's step bound (§6): 20 units, 8 MiB, 30 s; 1 MiB fragments. */
export const LITE_REPLICATION_LIMITS: ReplicationLimits = {
  fragmentBytes: 1024 * 1024,
  step: { units: 20, bytes: 8 * 1024 * 1024, deadlineMs: 30_000 },
};

/** The most a Lite fragment may be: one native record. */
export const LITE_MAX_FRAGMENT_BYTES = 1024 * 1024;

/**
 * Why a boot configuration cannot run, or `undefined` when it can. PS refuses
 * an invalid value rather than clamping it.
 */
export function replicationBootConfigProblem(
  config: ReplicationBootConfig,
): "invalid_owner" | "invalid_environment" | "invalid_limits" | undefined {
  if (!/^0x[0-9a-fA-F]{40}$/.test(config.owner)) return "invalid_owner";
  if (config.environment !== "dev" && config.environment !== "prod")
    return "invalid_environment";
  const { fragmentBytes, step } = config.limits;
  const positive = (value: number) => Number.isSafeInteger(value) && value > 0;
  if (
    !positive(config.chainId) ||
    !positive(fragmentBytes) ||
    fragmentBytes > LITE_MAX_FRAGMENT_BYTES ||
    !positive(step.units) ||
    !positive(step.bytes) ||
    !positive(step.deadlineMs)
  )
    return "invalid_limits";
  return undefined;
}

/**
 * Length and SHA-256 of replica bytes as the native side computes them.
 * `sha256` is 64 lowercase hex characters with no `sha256:` prefix, the native
 * bridge's format.
 */
export interface LiteReplicaBytesInfo {
  length: number;
  sha256: string;
}

/**
 * Fragment-sized byte storage beside the canonical rows (§4.3). Canonical
 * values stop at 256 KiB and blob methods take record blob claims, so
 * fragments and manifests use this instead.
 */
export interface LiteReplicaBytes {
  /**
   * Stage bytes from frames of at most 128 KiB. The native side computes
   * length and SHA-256 itself; the returned id is invisible to readers until
   * a transaction attaches it.
   */
  stageBytes(chunks: AsyncIterable<Uint8Array>): Promise<string>;
  /** Attached bytes only, in frames of at most 128 KiB. Missing ids throw. */
  readBytes(id: string): AsyncIterable<Uint8Array>;
}

export interface LiteReplicaTransaction extends LiteCanonicalTransaction {
  /**
   * Publish staged bytes under their id in THIS transaction, after checking
   * the native length and SHA-256 against `expected`. Rollback publishes
   * nothing. Attaching the same bytes again is a no-op.
   */
  attachBytes(stagingId: string, expected: LiteReplicaBytesInfo): Promise<void>;
  /** Drop attached bytes when this transaction commits. Absent ids are a no-op. */
  releaseBytes(id: string): Promise<void>;
  /**
   * Replication's relational state in THIS transaction (§4.3): the phase
   * engine's `pdpp_transport_*` and `pdpp_replica_*` tables, in the same
   * native SQLite database as the canonical rows. PS sends only its own
   * fixed statements; parameters never carry more than one canonical value.
   */
  readonly sql: LiteReplicaSql;
}

/** `ReplicaSql` answered asynchronously over the bridge. */
export interface LiteReplicaSql extends ReplicaSql {
  get(
    sql: string,
    params: readonly LiteReplicaSqlValue[],
  ): Promise<Record<string, unknown> | undefined>;
  all(
    sql: string,
    params: readonly LiteReplicaSqlValue[],
  ): Promise<Record<string, unknown>[]>;
  run(
    sql: string,
    params: readonly LiteReplicaSqlValue[],
  ): Promise<{ changes: number }>;
  exec(sql: string): Promise<void>;
}
type LiteReplicaSqlValue = Parameters<ReplicaSql["get"]>[1][number];

/** The canonical native transaction, widened to replica bytes. */
export interface LiteReplicaPersistence
  extends Omit<LiteCanonicalPersistence, "transaction">, LiteReplicaBytes {
  transaction<T>(run: (tx: LiteReplicaTransaction) => Promise<T>): Promise<T>;
}

/** Failure codes of a native transfer (`NativeReplicaException.code`). */
export type LiteReplicaTransferFailure =
  | "invalid-request"
  | "invalid-url"
  | "blocked-host"
  | "too-large"
  | "timeout"
  | "cancelled"
  | "busy"
  | "http-status"
  | "not-found"
  | "too-many-redirects"
  | "length-mismatch"
  | "digest-mismatch"
  | "unavailable"
  | "quota"
  | "storage-full";

/** A native transfer failed. `busy` means the host's fixed capacity is full. */
export class LiteReplicaTransferError extends Error {
  constructor(
    readonly code: LiteReplicaTransferFailure,
    message: string = code,
  ) {
    super(message);
    this.name = "LiteReplicaTransferError";
  }
}

export interface LiteReplicaTransferCall {
  /**
   * Aborting cancels the transfer (the bridge's `replica.cancel`): the host
   * closes its socket, discards what it staged and fails with `cancelled`.
   */
  signal: AbortSignal;
  /** Deadline for the whole transfer, capacity wait included. */
  deadlineMs: number;
}

/**
 * Storage object I/O the phone host runs natively, with fixed capacity: a
 * transfer that does not fit fails `busy` rather than queueing without bound,
 * so the coordinator defers it. The bridge operations are `replica.download`,
 * `replica.probe`, `replica.upload` and `replica.cancel`. Adapters do not
 * retry; the coordinator settles each failure.
 */
export interface LiteReplicaObjectTransfers {
  /**
   * Stream `url` into a new byte stage of at most `maxBytes`. With
   * `expected`, a different length or digest fails and the stage is
   * discarded. 404 and 410 fail `not-found`, which is definitive absence.
   * The stage is invisible until a transaction attaches it.
   */
  download(
    request: { url: string; maxBytes: number; expected?: LiteReplicaBytesInfo },
    call: LiteReplicaTransferCall,
  ): Promise<LiteReplicaBytesInfo & { stagingId: string }>;
  /** False only on 404 or 410. Reads no body. */
  probe(
    request: { url: string },
    call: LiteReplicaTransferCall,
  ): Promise<boolean>;
  /**
   * Stream attached bytes `bytesId` to `url`. Redirects are refused; a
   * non-2xx answer fails `http-status`.
   */
  upload(
    request: {
      url: string;
      method: "PUT" | "POST";
      headers: Record<string, string>;
      bytesId: string;
    },
    call: LiteReplicaTransferCall,
  ): Promise<{ status: number }>;
}

/** The network side the host supplies (§4.2). */
export interface LiteReplicaNetwork {
  transfers: LiteReplicaObjectTransfers;
  roster: ReplicaRosterPort;
}

/**
 * The replication phase engine over the ports above: one finite step of
 * prepare, publish, discover, download, import and reconcile. PS supplies it,
 * not the host. PS-Lite has none yet; until it does the runtime reports
 * `blocked: "no_engine"` and never steps.
 */
export type LiteReplicationEngine = ReplicationStepper;

/** What made the host ask for a step now (§4.4). */
export type LiteReplicationTrigger =
  "foreground" | "local_write" | "network" | "sync_now";
