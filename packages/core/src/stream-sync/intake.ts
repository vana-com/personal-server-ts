import { ConnectionStoppedError } from "../localdb/delete.js";
/**
 * Run intake: the entry point every app uses to feed whole-file stream sync
 * (run-intake contract v2, §2, as reduced by rulings R17-R19 and R23).
 *
 *   begin  -> batches (ordered) -> end      or      abort
 *
 * One adapter, two transports. The full server mounts it as HTTP routes
 * (`packages/server/src/routes/stream-sync-runs.ts`); PS-Lite and the
 * OwnerDataClient hosts call it in process. Both call the same four methods
 * and get the same `RunIntakeError` names.
 *
 * The writer issues the START (mode and state) and binds the run to the
 * owner, the key check and the write lease. The adapter never lets a
 * producer name a primary key: the stream shapes come from a declaration
 * table that host code filled after it verified the artifact (§6).
 *
 * There is no account derivation (R23): every run publishes under the
 * identity-less name. A run is `will_discard` only while the registry is
 * unreachable; stream sync drops it, the legacy copy is unaffected.
 */

import {
  MissingKeyFieldError,
  isPlainObject,
  primaryKeyValues,
  streamScope,
  IDENTITYLESS_NS,
  type HeadProfile,
  type JsonObject,
  type JsonValue,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { RunGoneError, type StreamSyncWriter } from "./writer.js";

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

/** One stream of a verified connector artifact. */
export interface IntakeStreamDeclaration {
  readonly name: string;
  readonly semantics: "mutable_state" | "append_only";
  readonly primaryKey: readonly string[];
  /** `false` = every run reads the whole stream (§3.0). Default `true`. */
  readonly incremental?: boolean;
  readonly consentTimeField?: string;
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
    readonly mode: "full_refresh" | "incremental";
  }[];
}

export interface BatchRequest {
  readonly batch: number;
  readonly records: readonly {
    readonly stream: string;
    readonly op?: string;
    readonly data: unknown;
  }[];
}

export interface BatchResponse {
  readonly applied: boolean;
  readonly accepted: number;
  readonly deletesSkipped: number;
}

export interface EndRequest {
  readonly outcome:
    "succeeded" | "partial" | "retry_pending" | "failed" | "cancelled";
  readonly coveredStreams: readonly string[];
  readonly checkpointCandidate?: Readonly<Record<string, JsonValue>> | null;
  readonly lastBatch: number;
  /** H: streams the producer proved it read whole. PS-2 reads it; today it is ignored. */
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

export interface StreamSyncIntakeOptions {
  readonly writer: StreamSyncWriter;
  readonly resolveArtifact: ResolveArtifact;
  /**
   * The write lease now held by the host (`null` = none). A run bound to a
   * lease that is no longer held answers `lease_lost` (M5).
   */
  readonly currentLease?: () => string | null;
  /** True while a connection delete or method change is in flight (M5). */
  readonly deleting?: (connector: string) => boolean | Promise<boolean>;
  /**
   * The owner and key check now in force. Defaults to the writer's. A host
   * whose owner can change under a running run supplies it.
   */
  readonly currentBinding?: () => Promise<{ owner: string; keyCheck: string }>;
}

const RUN_ID = /^[A-Za-z0-9._-]{1,128}$/;
const OWNER = /^0x[0-9a-fA-F]{40}$/;
const ENDED_MEMORY = 1024;

interface Run {
  readonly connector: string;
  readonly request: string;
  readonly response: BeginResponse;
  readonly decl: Map<string, IntakeStreamDeclaration>;
  readonly version: string;
  readonly binding: { owner: string; keyCheck: string; leaseId: string | null };
  /** The run reached the writer; a dropped one never did. */
  inWriter: boolean;
  willDiscard: boolean;
  lastBatch: number;
  deletesSkipped: number;
  /** A stream with at least one record: its candidate cursor is not safe. */
  hadRecords: boolean;
}

function invalid(message: string): RunIntakeError {
  return new RunIntakeError("invalid_request", message);
}

function canonical(value: unknown): string {
  return JSON.stringify(value, (_k, v: unknown) =>
    isPlainObject(v)
      ? Object.fromEntries(
          Object.entries(v as JsonObject).sort(([a], [b]) => (a < b ? -1 : 1)),
        )
      : v,
  );
}

/** Validate a name the way a scope will carry it. */
function checkName(connector: string, stream: string): void {
  try {
    streamScope(connector, IDENTITYLESS_NS, stream);
  } catch (error) {
    throw invalid((error as Error).message);
  }
  if (connector.includes("|") || stream.includes("|")) {
    throw invalid("names may not contain '|'");
  }
}

/**
 * R24: START never carries a cursor for a stream whose issued mode is
 * `full_refresh`. A producer runtime reads "a cursor is present" as
 * "read incrementally", so the rule lives here, once, not in each producer.
 * The writer keeps the stored checkpoint; only what is sent is filtered.
 */
function withoutFullCursors(
  state: JsonValue | null,
  modes: ReadonlyMap<string, "full_refresh" | "incremental">,
): JsonValue | null {
  if (state === null || !isPlainObject(state as JsonObject)) return state;
  const kept = Object.fromEntries(
    Object.entries(state as JsonObject).filter(
      ([stream]) => modes.get(stream) !== "full_refresh",
    ),
  );
  return Object.keys(kept).length > 0 ? kept : null;
}

export class StreamSyncIntake implements RunIntake {
  private readonly runs = new Map<string, Run>();
  private readonly ended = new Set<string>();

  constructor(private readonly options: StreamSyncIntakeOptions) {}

  // --------------------------------------------------------------- begin

  async begin(runId: string, req: BeginRequest): Promise<BeginResponse> {
    const { writer } = this.options;
    if (!RUN_ID.test(runId)) throw invalid("bad runId");
    if (!isPlainObject(req as unknown as JsonObject)) {
      throw invalid("the body is not an object");
    }
    const { connector, artifactDigest, owner } = req;
    if (typeof connector !== "string" || connector === "") {
      throw invalid("connector is required");
    }
    checkName(connector, "s");
    if (typeof artifactDigest !== "string" || artifactDigest === "") {
      throw invalid("artifactDigest is required");
    }
    if (
      !owner ||
      typeof owner.address !== "string" ||
      !OWNER.test(owner.address) ||
      !(owner.leaseId === null || typeof owner.leaseId === "string")
    ) {
      throw invalid("owner.address and owner.leaseId are required");
    }
    if (req.wantFull !== undefined && typeof req.wantFull !== "boolean") {
      throw invalid("wantFull must be a boolean");
    }
    if (req.connect !== undefined && typeof req.connect !== "boolean") {
      throw invalid("connect must be a boolean");
    }
    if (
      req.observedAt !== undefined &&
      !(typeof req.observedAt === "number" && Number.isFinite(req.observedAt))
    ) {
      throw invalid("observedAt must be a number");
    }

    // Replay of a begin that is still running.
    const same = this.runs.get(runId);
    if (same) {
      if (same.request !== canonical(req)) {
        throw new RunIntakeError("run_conflict");
      }
      return same.response;
    }
    if (this.ended.has(runId)) throw new RunIntakeError("gone");

    const now = await this.binding();
    if (owner.address.toLowerCase() !== now.owner.toLowerCase()) {
      throw new RunIntakeError("owner_mismatch");
    }
    if (owner.leaseId !== null) this.checkLease(owner.leaseId);
    if (await this.options.deleting?.(connector)) {
      throw new RunIntakeError("connection_busy");
    }

    const declarations = await this.options.resolveArtifact(artifactDigest);
    if (!declarations) throw new RunIntakeError("unknown_artifact");
    // The artifact binds the connector (owner decision B): a producer cannot
    // publish under a name its verified artifact does not carry.
    if (declarations.connector !== connector) {
      throw invalid("connector does not match the artifact");
    }
    const decl = new Map(declarations.streams.map((d) => [d.name, d]));
    for (const d of declarations.streams) checkName(connector, d.name);
    for (const entry of req.streams ?? []) {
      if (!decl.has(entry.name)) {
        throw invalid(`stream ${String(entry.name)} is not declared`);
      }
      // R17: a field- or resource-limited run would replace whole items with
      // partial ones on every run.
      if (
        (entry.fields !== undefined && entry.fields !== null) ||
        (entry.resources !== undefined && entry.resources !== null)
      ) {
        throw new RunIntakeError(
          "restricted_scope_unsupported",
          `stream ${entry.name} limits fields or resources`,
        );
      }
    }

    let willDiscard = false;
    if (!writer.hasControls()) {
      try {
        await writer.refreshControls();
      } catch {
        willDiscard = true;
      }
    }

    const wantFull = req.wantFull === true;
    const connect = req.connect === true;
    let collection: "full_refresh" | "incremental";
    let state: JsonValue | null;
    let keyCheck: string;
    // The offline path skips the writer's gate, so it applies the same refusal.
    if (willDiscard && !connect && (await writer.isStopped(connector))) {
      throw new RunIntakeError("connection_stopped");
    }
    if (willDiscard) {
      const issued = await writer.issueStart(connector, wantFull);
      collection = issued.start.collectionMode;
      state = issued.start.state;
      keyCheck = issued.start.keyCheck;
    } else {
      try {
        const issued = await writer.beginRun({
          runId,
          connector,
          userConnect: connect,
          ...(req.observedAt !== undefined
            ? { observedAt: req.observedAt }
            : {}),
          identity: "none",
          issue: { wantFull },
          leaseId: owner.leaseId,
        });
        collection = issued.collectionMode;
        state = issued.state;
        keyCheck = issued.keyCheck;
      } catch (error) {
        if (error instanceof RunGoneError) throw new RunIntakeError("gone");
        if (error instanceof ConnectionStoppedError) {
          throw new RunIntakeError("connection_stopped");
        }
        throw error;
      }
    }
    const runFull = collection === "full_refresh";
    const modes = new Map(
      declarations.streams.map((d) => [
        d.name,
        runFull || d.incremental === false
          ? ("full_refresh" as const)
          : ("incremental" as const),
      ]),
    );
    const response: BeginResponse = {
      runId,
      status: willDiscard ? "will_discard" : "collecting",
      discardReason: willDiscard ? "registry_unreachable" : null,
      stuck: await writer.stuck(connector),
      binding: { keyCheck },
      start: {
        collection_mode: collection,
        state: withoutFullCursors(state, modes),
      },
      streams: declarations.streams.map((d) => ({
        name: d.name,
        semantics: d.semantics,
        primaryKey: d.primaryKey,
        incremental: d.incremental !== false,
        ...(d.consentTimeField ? { consentTimeField: d.consentTimeField } : {}),
        mode: modes.get(d.name)!,
      })),
    };
    this.runs.set(runId, {
      connector,
      request: canonical(req),
      response,
      decl,
      version: declarations.version,
      binding: { owner: now.owner, keyCheck, leaseId: owner.leaseId },
      inWriter: !willDiscard,
      willDiscard,
      lastBatch: -1,
      deletesSkipped: 0,
      hadRecords: false,
    });
    return response;
  }

  // --------------------------------------------------------------- batch

  async batch(runId: string, req: BatchRequest): Promise<BatchResponse> {
    const run = await this.live(runId);
    if (
      !isPlainObject(req as unknown as JsonObject) ||
      !Number.isInteger(req.batch) ||
      req.batch < 0 ||
      !Array.isArray(req.records)
    ) {
      throw invalid("batch and records are required");
    }
    if (req.batch <= run.lastBatch) {
      return { applied: false, accepted: 0, deletesSkipped: 0 };
    }
    if (req.batch > run.lastBatch + 1) {
      throw new RunIntakeError("batch_gap", "batch_gap", run.lastBatch + 1);
    }

    // Check the whole batch before any line is spooled, so a refused batch
    // leaves no trace and the producer may resend it.
    const checked: { stream: string; delete: boolean; data: JsonObject }[] = [];
    for (const record of req.records) {
      if (!isPlainObject(record as unknown as JsonObject)) {
        throw invalid("a record is not an object");
      }
      const decl = run.decl.get(record.stream);
      if (!decl)
        throw invalid(`stream ${String(record.stream)} is not declared`);
      if (
        record.op !== undefined &&
        record.op !== "upsert" &&
        record.op !== "delete"
      ) {
        throw invalid("op must be upsert or delete");
      }
      if (!isPlainObject(record.data as JsonObject)) {
        throw invalid("data must be an object");
      }
      const data = record.data as JsonObject;
      if (record.op === "delete") {
        checked.push({ stream: record.stream, delete: true, data });
        continue;
      }
      try {
        primaryKeyValues(data, decl.primaryKey);
      } catch (error) {
        if (error instanceof MissingKeyFieldError) {
          throw invalid(`a record of ${record.stream} lacks its primary key`);
        }
        throw error;
      }
      checked.push({ stream: record.stream, delete: false, data });
    }

    const response = {
      applied: true,
      accepted: 0,
      deletesSkipped: 0,
    };
    for (const record of checked) {
      // R17: a delete is skipped and counted, never stored.
      if (record.delete) {
        response.deletesSkipped += 1;
        run.deletesSkipped += 1;
        continue;
      }
      if (run.willDiscard) continue;
      const decl = run.decl.get(record.stream)!;
      const profile: HeadProfile = { key: null, version: run.version };
      await this.options.writer.append(runId, record.stream, record.data, {
        primaryKey: decl.primaryKey,
        profile,
        incremental: decl.incremental !== false,
      });
      run.hadRecords = true;
      response.accepted += 1;
    }
    run.lastBatch = req.batch;
    return response;
  }

  // ----------------------------------------------------------------- end

  async end(runId: string, req: EndRequest): Promise<EndResponse> {
    const { writer } = this.options;
    const run = await this.live(runId);
    if (
      !isPlainObject(req as unknown as JsonObject) ||
      !Number.isInteger(req.lastBatch) ||
      !Array.isArray(req.coveredStreams)
    ) {
      throw invalid("outcome, coveredStreams and lastBatch are required");
    }
    if (req.lastBatch !== run.lastBatch) {
      throw new RunIntakeError("batch_gap", "batch_gap", run.lastBatch + 1);
    }
    const covered = [...new Set(req.coveredStreams)];
    for (const name of covered) {
      if (!run.decl.has(name)) throw invalid(`stream ${name} is not declared`);
    }
    const candidate = req.checkpointCandidate ?? null;
    if (candidate !== null && !isPlainObject(candidate as JsonObject)) {
      throw invalid("checkpointCandidate must be an object");
    }
    const keys = Object.keys(candidate ?? {});

    switch (req.outcome) {
      case "failed":
      case "cancelled":
        await this.finishWithout(runId, run, req.outcome);
        return {
          result: "aborted",
          stuck: await writer.stuck(run.connector),
          updateRequired: false,
        };
      case "retry_pending":
        for (const key of keys) {
          if (!run.decl.has(key))
            throw invalid(`stream ${key} is not declared`);
        }
        break;
      case "succeeded":
      case "partial": {
        const set = new Set(covered);
        for (const key of keys) {
          if (!set.has(key)) {
            throw invalid(`checkpoint stream ${key} is not covered`);
          }
        }
        break;
      }
      default:
        throw invalid("unknown outcome");
    }

    if (run.willDiscard) {
      // Never reached the writer: count it for the stuck check and forget it.
      await writer.noteDropped(run.connector);
      this.forget(runId);
      return {
        result: "discarded",
        stuck: await writer.stuck(run.connector),
        updateRequired: false,
      };
    }

    if (req.outcome === "retry_pending") {
      const status = await writer.saveCheckpointOnly(
        runId,
        (candidate ?? {}) as Record<string, JsonValue>,
      );
      this.forget(runId);
      const kind = status.outcome?.kind;
      return {
        result:
          kind === "checkpointed"
            ? "checkpoint_only"
            : kind === "no_checkpoint"
              ? "no_checkpoint"
              : "discarded",
        stuck: await writer.stuck(run.connector),
        updateRequired: false,
      };
    }

    if (covered.length === 0 && keys.length === 0 && !run.hadRecords) {
      // Nothing to publish and nothing to remember.
      await this.finishWithout(runId, run, "cancelled");
      return {
        result: "no_checkpoint",
        stuck: await writer.stuck(run.connector),
        updateRequired: false,
      };
    }
    for (const name of covered) {
      const decl = run.decl.get(name)!;
      await writer.declareStream(runId, name, {
        primaryKey: decl.primaryKey,
        profile: { key: null, version: run.version },
        incremental: decl.incremental !== false,
      });
    }
    const status = await writer.finishRun(runId, {
      checkpointCandidate: keys.length > 0 ? (candidate as JsonValue) : null,
      coveredStreams: covered,
    });
    this.forget(runId);
    return {
      result: status.phase === "ready" ? "queued" : "discarded",
      stuck: await writer.stuck(run.connector),
      updateRequired: false,
    };
  }

  // --------------------------------------------------------------- abort

  async abort(runId: string, reason: "failed" | "cancelled"): Promise<void> {
    const run = await this.live(runId);
    await this.finishWithout(runId, run, reason);
  }

  // ------------------------------------------------------------- helpers

  private async binding(): Promise<{ owner: string; keyCheck: string }> {
    return (
      this.options.currentBinding ?? (() => this.options.writer.binding())
    )();
  }

  private checkLease(leaseId: string): void {
    const held = this.options.currentLease;
    if (held && held() !== leaseId) throw new RunIntakeError("lease_lost");
  }

  /** The running run, after the M5 checks; `gone` for any other id. */
  private async live(runId: string): Promise<Run> {
    const run = this.runs.get(runId);
    if (!run) throw new RunIntakeError("gone");
    const now = await this.binding();
    if (
      now.owner.toLowerCase() !== run.binding.owner.toLowerCase() ||
      now.keyCheck !== run.binding.keyCheck
    ) {
      throw new RunIntakeError("owner_mismatch");
    }
    if (run.binding.leaseId !== null) this.checkLease(run.binding.leaseId);
    return run;
  }

  /** End a run that publishes nothing. */
  private async finishWithout(
    runId: string,
    run: Run,
    reason: "failed" | "cancelled",
  ): Promise<void> {
    if (run.inWriter) {
      try {
        await this.options.writer.abortRun(runId, reason);
      } catch (error) {
        if (!(error instanceof RunGoneError)) throw error;
      }
    } else if (reason !== "cancelled") {
      await this.options.writer.noteDropped(run.connector);
    }
    this.forget(runId);
  }

  private forget(runId: string): void {
    this.runs.delete(runId);
    this.ended.add(runId);
    if (this.ended.size > ENDED_MEMORY) {
      this.ended.delete(this.ended.values().next().value as string);
    }
  }
}

export function createStreamSyncIntake(
  options: StreamSyncIntakeOptions,
): StreamSyncIntake;
export function createStreamSyncIntake(options: {
  readonly intake: RunIntake;
}): RunIntake;
export function createStreamSyncIntake(
  options: StreamSyncIntakeOptions | { readonly intake: RunIntake },
): RunIntake {
  return "intake" in options ? options.intake : new StreamSyncIntake(options);
}
