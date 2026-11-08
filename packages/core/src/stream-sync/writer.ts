/**
 * Stream-sync writer: run intake, the publish driver (§2.7), the checkpoint
 * re-check (§2.4), `needsFull`, the record limit (§2.2) and the Desktop seed
 * with receipts (§2.9).
 *
 * Every rule comes from `@opendatalabs/personal-server-ts-stream-sync`
 * (`decide`, `chooseBase`, `planBuckets`, `BucketReducer`,
 * `checkpointDecision`, `afterCommit`, ...). This module only sequences I/O
 * around them and keeps the outbox durable.
 *
 * Durable layout under the files port:
 *
 *   state.json                         needsFull, checkpoints, seed targets, receipts
 *   runs/<runId>/entry.json            the outbox entry and per-stream host data
 *   runs/<runId>/spool/s<i>.log        intake log of stream i (durable)
 *   runs/<runId>/spool/s<i>/<shard>    shards of that log (derived, never synced)
 *   runs/<runId>/seed/s<i>.log         seed log of stream i (durable)
 *   runs/<runId>/seed/s<i>/<shard>     shards of that log (derived, never synced)
 *   runs/<runId>/excluded.ndjson       record_too_large: stream, key digest, bytes
 *   runs/<runId>/request-s<i>.json     persisted signed request of stream i
 *   runs/<runId>/head-s<i>.bin         persisted head ciphertext of stream i
 *   results/<runId>.json               the final outcome of a finished run
 *
 * A run that was still collecting when the process stopped is discarded at
 * the next start: its spool may miss records, and publishing it would be
 * publishing a partial run under the run's checkpoint.
 */

import {
  IDENTITYLESS_NS,
  PART_LIMIT_BYTES,
  DEFAULT_PART_TARGET_BYTES,
  SEED_OBSERVED_AT,
  SEED_RUN_ID,
  afterCommit,
  basePartsFor,
  checkpointDecision,
  chooseBase,
  classifyControl,
  controlHashes,
  controlScope,
  createOutboxEntry,
  decide,
  decodePart,
  deriveKeyCheck,
  digestHead,
  encodeHead,
  encodeLine,
  encodePart,
  inPrefix,
  isNoop,
  isPlainObject,
  lineSize,
  parseScope,
  partBlobName,
  pkHash,
  pkHashBits,
  planBuckets,
  shardOf,
  startState,
  streamRunResult,
  streamScope,
  verifyHead,
  BucketReducer,
  type BucketResult,
  type CheckpointDecision,
  type ControlHashes,
  classifyStreamRow,
  type ControlState,
  type Decision,
  type DecidePhase,
  type Head,
  type HeadPart,
  type HeadProfile,
  type JsonObject,
  type JsonValue,
  type NeedsFull,
  type OutboxEntry,
  type OutboxProblem,
  type OutboxStream,
  type StartSnapshot,
  canonicalBytes32,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { publicationMetadataHash } from "../publication/publish.js";
import {
  NO_FLOOR,
  compareConnectorVersions,
  planStreamStep,
  stampBefore,
  type ExecutedStep,
  type PlanHead,
  type PlanRun,
  type StreamFloor,
} from "./publish-plan.js";
import { streamSyncHashes } from "./crypto.js";
import type { StreamSyncHome } from "./home.js";
import {
  AmbiguousRegistryReplyError,
  RegistryRefusedError,
  type SignedRegistryPost,
  type StreamSyncBlobs,
  type StreamSyncFaultPoint,
  type StreamSyncKeyPorts,
  type StreamSyncRegistry,
  type StreamSyncSeedSource,
  type StreamSyncSigner,
} from "./ports.js";
import {
  SpoolWriter,
  deriveShards,
  spoolLogPath,
  compactShard,
  countShard,
  emptyShardBytes,
  lineStamp,
  readSpool,
  shardPath,
} from "./spool.js";

import {
  pinnedWriterSnapshot,
  overlayPlanKey,
  type WriterOverlayLog,
} from "./writer-overlay.js";
import type {
  StreamSyncOverlaySnapshot,
  StreamSyncOverlayRun,
  StreamSyncOverlayStream,
  StreamSyncImportedCoverage,
  StreamSyncPublishReceipt,
} from "../stream-sync-read/ports.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
/** Conflicts handled within one publish pass before the stream waits for the next pass. */
const CONFLICTS_PER_PASS = 8;
/** m1: the furthest a producer clock may run ahead of this process. */
const SKEW_MS = 5 * 60 * 1000;

/** Problems a host shows on top of the package's outbox problems. */
export type StreamSyncHostProblem =
  | OutboxProblem
  | "base_unreadable"
  | "unsupported_format"
  | "ambiguous_reply"
  | "registry_refused"
  /** An older run than the newest commit on the stream; it never commits (commit order). */
  | "out_of_order"
  /** An earlier run of the stream did not commit in this pass; commits stay in order. */
  | "earlier_run_pending";

export interface StreamSyncCheckpoint {
  readonly ns: string;
  readonly generation: number;
  readonly value: JsonValue | null;
}

export type SeedReceipt = "merged" | "skipped";

interface WriterState {
  version: 1;
  needsFull: NeedsFull;
  checkpoints: Record<string, StreamSyncCheckpoint>;
  /**
   * Per connector, how many times its checkpoint was invalidated: a control
   * change seen, or a deliberate clear. It only grows and outlives the
   * checkpoint, so a save can tell that an invalidation came after the run's
   * control read, even when no checkpoint was stored. A state file without it
   * reads as 0.
   */
  invalidations?: Record<string, number>;
  /**
   * Per connector and namespace, the newest control state known: the whole
   * state. Each entry only moves forward and another namespace never touches
   * it. Every decision uses this, never a raw read.
   */
  observedControl?: Record<string, Record<string, ControlState>>;
  seedTargets: Record<string, string>;
  /** `<installId>|<connector>|<ns>|<stream>` → receipt. */
  receipts: Record<string, SeedReceipt>;
  /** The last three finished-run verdicts per connector, newest last. */
  recent?: Record<string, ("good" | "bad")[]>;
  /**
   * Per stream (`floorKey`), the highest connector version that registered on
   * it and the newest commit: the version floor and the commit order of the
   * publish plan. Only moves forward. A state file without it reads as none.
   */
  streamFloors?: Record<
    string,
    { version: string; committed: [observedAt: number, runId: string] }
  >;
}

interface HostStream {
  /** Persisted in the same atomic entry write as committed/noop. */
  receipt?: StreamSyncPublishReceipt;
  /** The plan step this stream executed (committed/noop): what the head became. */
  executed?: ExecutedStep;
  /** The plan step of a persisted request, for a resend; with its version floor. */
  planned?: ExecutedStep & { floor: string };
  index: number;
  primaryKey: string[];
  profile: HeadProfile;
  /** Run spool bytes per shard; set when the run finishes. */
  shardBytes: number[] | null;
  /** Seed spool bytes per shard; set when the seed is spooled. */
  seedShardBytes: number[] | null;
  /** A seed stream added at publish (§2.9), with no run records. */
  seedOnly: boolean;
  /** Declared `incremental: false`: every run of it is a full read (§3.0). */
  fullStream: boolean;
  /** The seed is merged into this stream's publish. */
  seedApplies: boolean;
  recordTooLarge: number;
  problem: StreamSyncHostProblem | null;
  detail: string | null;
}

type Phase = "collecting" | "ready" | "done";

export type RunOutcome =
  | {
      readonly kind: "checkpointed";
      readonly generation: number;
    }
  | {
      readonly kind: "no_checkpoint";
      readonly generation: number;
      readonly reason: Extract<CheckpointDecision, { kind: "skip" }>["reason"];
    }
  | {
      readonly kind: "discarded";
      readonly recollect: boolean;
      readonly clearCheckpoints: boolean;
      readonly restartFull: boolean;
      readonly why: string;
    }
  | { readonly kind: "failed"; readonly why: string }
  | { readonly kind: "aborted"; readonly reason: AbortReason };

/** Why a run ended without publishing; `discarded` is a run intake dropped. */
export type AbortReason = "failed" | "cancelled";

interface HostEntry {
  version: 1;
  phase: Phase;
  entry: OutboxEntry;
  /** The checkpoint the run started from, `null` for a full run. */
  checkpointUsed: { ns: string; generation: number } | null;
  /** Target generation, once admission decided `publish`. */
  target: number | null;
  streams: Record<string, HostStream>;
  outcome: RunOutcome | null;
  /** Intake crossed the durable ready barrier (absent on older entries). */
  ready?: boolean;
  /** Verified read binding, never inferred while taking a snapshot. */
  generation?: number | null;
  /** Immutable intake identity; persisted before exposure, including on upgrade. */
  overlayRevision?: string;
  /** Seed streams this run must hold receipts for before its checkpoint. */
  seedStreams: string[];
  /** M5: who the run writes for; checked again before it publishes. */
  binding?: { owner: string; keyCheck: string; leaseId: string | null };
}

/** The START the writer issued to a run (V2 §2.1). */
export interface IssuedStart {
  readonly collectionMode: "full_refresh" | "incremental";
  readonly state: JsonValue | null;
  readonly keyCheck: string;
}

export interface StreamSyncRunStart {
  readonly runId: string;
  readonly connector: string;
  /** True only for a run started by an explicit connect action (M9). */
  readonly userConnect: boolean;
  /** Run start in ms; the `o` of every line. Defaults to the clock. */
  readonly observedAt?: number;
  /** Every run is identity-less (R23); kept so existing callers compile. */
  readonly identity?: "none";
  /** The checkpoint the run resumes from; omit for a full run. */
  readonly checkpointUsed?: {
    readonly ns: string;
    readonly generation: number;
  } | null;
  /**
   * Issue the START from the saved state (V2 §2.1, R16): the run is full when
   * the caller asks, a `needsFull` entry forces it, or no checkpoint exists.
   * The returned state is the stored value (`null` when forced or without a
   * checkpoint); the intake adapter strips cursors of full_refresh streams
   * before it sends START (R24). Replaces `checkpointUsed`.
   */
  readonly issue?: { readonly wantFull: boolean };
  /** The write lease the run is bound to; `null` on hosts with no lease. */
  readonly leaseId?: string | null;
}

/** A run id that finished, or whose entry this process no longer drives. */
export class RunGoneError extends Error {
  constructor(readonly runId: string) {
    super(`run ${runId} is gone`);
  }
}

export interface StreamSyncStreamStatus {
  readonly state: OutboxStream["state"];
  readonly generation?: number;
  readonly complete?: boolean;
  readonly problem: StreamSyncHostProblem | null;
  readonly detail: string | null;
  readonly recordTooLarge: number;
}

export interface StreamSyncRunStatus {
  readonly runId: string;
  readonly connector: string;
  readonly ns: string | null;
  readonly phase: Phase;
  readonly target: number | null;
  readonly outcome: RunOutcome | null;
  readonly streams: Readonly<Record<string, StreamSyncStreamStatus>>;
}

export interface StreamSyncPublishReport {
  readonly runs: readonly StreamSyncRunStatus[];
}

export interface StreamSyncWriterOptions {
  readonly ownerAddress: `0x${string}`;
  readonly registry: StreamSyncRegistry;
  readonly blobs: StreamSyncBlobs;
  /** The one storage home of this owner and network (see `bindStreamSyncHome`). */
  readonly home: StreamSyncHome;
  readonly keys: StreamSyncKeyPorts;
  readonly signer: StreamSyncSigner;
  /** Desktop only: this install's retained rows (§2.9). */
  readonly seed?: StreamSyncSeedSource;
  /** Writer target per part (§2.2, at most 4 MiB). */
  readonly partTargetBytes?: number;
  /** Budget for one reduce pass and one shard compaction, in line bytes. */
  readonly reduceBudgetBytes?: number;
  readonly now?: () => number;
  /** Receives cleanup failures; the payload holds a run id and a message, never row data. */
  readonly logger?: { warn(obj: Record<string, unknown>, msg?: string): void };
  /** Test hook: throw at a named point to model a crash. */
  readonly fault?: (
    point: StreamSyncFaultPoint,
    context: { runId: string; stream?: string },
  ) => void;
  /** Called when a discarded `userConnect` run asks for a fresh full run (§2.4). */
  readonly onRestartFull?: (connector: string) => void;
}

export { compareConnectorVersions } from "./publish-plan.js";

/** The `streamFloors` key of a stream. */
function floorKey(connector: string, ns: string, stream: string): string {
  return JSON.stringify([connector, ns, stream]);
}

function floorOf(
  state: WriterState,
  connector: string,
  ns: string,
  stream: string,
): StreamFloor {
  const held = state.streamFloors?.[floorKey(connector, ns, stream)];
  if (!held) return NO_FLOOR;
  return {
    version: held.version,
    committed: { observedAt: held.committed[0], runId: held.committed[1] },
  };
}

function planHeadOf(head: Head): PlanHead {
  return {
    generation: head.generation,
    primaryKey: head.primaryKey,
    profile: head.profile,
    complete: head.complete,
  };
}

function coverageKey(
  binding: { owner: string; keyCheck: string },
  connector: string,
  ns: string,
  stream: string,
  generation: number,
): string {
  return JSON.stringify([
    binding.owner.toLowerCase(),
    binding.keyCheck,
    connector,
    ns,
    stream,
    generation,
  ]);
}

function json(value: unknown): Uint8Array {
  return encoder.encode(JSON.stringify(value));
}

function emptyState(): WriterState {
  return {
    version: 1,
    needsFull: [],
    checkpoints: {},
    seedTargets: {},
    receipts: {},
  };
}

class PendingStream extends Error {
  constructor(
    readonly problem: StreamSyncHostProblem,
    detail: string,
  ) {
    super(detail);
  }
}

class Discard extends Error {
  constructor(
    readonly decision: Extract<Decision, { kind: "discard" }>,
    readonly why: string,
  ) {
    super(why);
  }
}

interface ActiveRun {
  readonly spool: SpoolWriter;
  readonly shardBytes: Map<string, number[]>;
  recordTooLarge: Map<string, number>;
  /** Records appended per stream (R19: a retry-pending cursor needs none). */
  readonly records: Map<string, number>;
  excluded: string[];
}

export class StreamSyncWriter {
  private readonly hashes = streamSyncHashes;
  private readonly targetBytes: number;
  private readonly reduceBudget: number;
  private readonly now: () => number;
  private keyCheck: string | null = null;
  private control: ControlHashes | null = null;
  /** §2.4 `controls`: the last listing completed in this app session. */
  private controls: Map<string, Record<string, ControlState>> | null = null;
  private readonly active = new Map<string, ActiveRun>();
  private intakeQueue: Promise<unknown> = Promise.resolve();
  private publishQueue: Promise<unknown> = Promise.resolve();
  private stateQueue: Promise<unknown> = Promise.resolve();
  private recovery: Promise<void> | null = null;
  private lifecycleQueue: Promise<unknown> = Promise.resolve();
  /**
   * Runs whose removal failed. They stay on disk, already covered and hidden
   * from snapshots, and each later lifecycle step retries them. Nothing in the
   * writer is poisoned for good: cleanup is garbage collection, so a failure
   * to remove a run never turns off reads of other runs.
   */
  private readonly removalRetry = new Set<string>();
  private readonly pins = new Map<string, number>();
  /**
   * Latest durable-import coverage per (owner, keyCheck, connector, ns, stream,
   * generation), kept even when no receipt matches it yet: the reader can
   * acknowledge before the writer stores its receipt, and a no-op run gets a
   * receipt for a head the reader already imported. Memory only. It belongs to
   * this reader/store lifetime, so startup must reconcile it again.
   */
  private readonly coverage = new Map<string, StreamSyncImportedCoverage>();

  constructor(private readonly options: StreamSyncWriterOptions) {
    if (
      options.home.ownerAddress.toLowerCase() !==
      options.ownerAddress.toLowerCase()
    ) {
      throw new Error("Stream-sync home belongs to a different owner");
    }
    this.targetBytes = options.partTargetBytes ?? DEFAULT_PART_TARGET_BYTES;
    this.reduceBudget = options.reduceBudgetBytes ?? PART_LIMIT_BYTES;
    this.now = options.now ?? (() => Date.now());
  }

  // ---------------------------------------------------------------- state

  private async readState(): Promise<WriterState> {
    const bytes = await this.options.home.files.read("state.json");
    if (!bytes) return emptyState();
    return JSON.parse(decoder.decode(bytes)) as WriterState;
  }

  private async writeState(state: WriterState): Promise<void> {
    await this.options.home.files.write("state.json", json(state));
  }

  /**
   * Read-modify-write of `state.json` under one short lock (V2 §3.8). The
   * intake and publish queues both write it; `change` does no network I/O.
   */
  private withState<T>(
    change: (state: WriterState) => T | Promise<T>,
  ): Promise<T> {
    const run = async () => {
      const state = await this.readState();
      const result = await change(state);
      await this.writeState(state);
      return result;
    };
    const next = this.stateQueue.then(run, run);
    this.stateQueue = next.catch(() => undefined);
    return next;
  }

  private async readEntry(runId: string): Promise<HostEntry | null> {
    const bytes = await this.options.home.files.read(
      `runs/${runId}/entry.json`,
    );
    return bytes ? (JSON.parse(decoder.decode(bytes)) as HostEntry) : null;
  }

  private lifecycle<T>(work: () => Promise<T>): Promise<T> {
    const next = this.lifecycleQueue.then(work, work);
    this.lifecycleQueue = next.catch(() => undefined);
    return next;
  }

  private writeEntry(host: HostEntry): Promise<void> {
    return this.lifecycle(() =>
      this.options.home.files.write(
        `runs/${host.entry.runId}/entry.json`,
        json(host),
      ),
    );
  }

  private fault(point: StreamSyncFaultPoint, runId: string, stream?: string) {
    this.options.fault?.(point, { runId, ...(stream ? { stream } : {}) });
  }

  private async keys(): Promise<{ keyCheck: string; control: ControlHashes }> {
    if (this.keyCheck === null || this.control === null) {
      this.keyCheck = await deriveKeyCheck((m) =>
        this.options.keys.namespaceHmac(m),
      );
      this.control = await controlHashes(this.hashes.keccak256, this.keyCheck);
    }
    return { keyCheck: this.keyCheck, control: this.control };
  }

  /** Run intake work in order: begin, declare, finish, abort (V2 §3.8). */
  private intake<T>(work: () => Promise<T>): Promise<T> {
    const next = this.intakeQueue.then(work, work);
    this.intakeQueue = next.catch(() => undefined);
    return next;
  }

  /** Run publish work in order. It never blocks intake. */
  private publish<T>(work: () => Promise<T>): Promise<T> {
    const next = this.publishQueue.then(work, work);
    this.publishQueue = next.catch(() => undefined);
    return next;
  }

  // ------------------------------------------------------------ controls

  /**
   * §2.4: list every control row of the owner and keep the states as this
   * app session's `controls`. Runs that start after this use it as `start`.
   */
  refreshControls(): Promise<void> {
    return this.intake(async () => {
      const { control } = await this.keys();
      const rows = await this.options.registry.listControlRows();
      const listed: { connector: string; ns: string; state: ControlState }[] =
        [];
      for (const row of rows) {
        const parsed = parseScope(row.scope);
        if (parsed?.kind !== "control") continue;
        listed.push({
          connector: parsed.connector,
          ns: parsed.ns,
          state: classifyControl(row.read, control),
        });
      }
      // A listing is a control read too: record it like every other, and
      // keep the newest known state of each row, not the raw listing.
      const newest = await this.withState((state) =>
        listed.map((row) =>
          recordControl(state, row.connector, row.ns, row.state),
        ),
      );
      const next = new Map<string, Record<string, ControlState>>();
      listed.forEach((row, i) => {
        const states = next.get(row.connector) ?? {};
        states[row.ns] = newest[i]!;
        next.set(row.connector, states);
      });
      this.controls = next;
    });
  }

  private startSnapshot(connector: string): StartSnapshot {
    if (this.controls === null) return null;
    return { ...(this.controls.get(connector) ?? {}) };
  }

  // -------------------------------------------------------------- intake

  /**
   * What a run of `connector` may use: the saved checkpoint, unless a
   * `needsFull` entry forces a full run (§2.4).
   */
  async runPlan(connector: string): Promise<{
    mustBeFull: boolean;
    checkpoint: StreamSyncCheckpoint | null;
  }> {
    const state = await this.readState();
    const mustBeFull = state.needsFull.some((k) => k.connector === connector);
    return {
      mustBeFull,
      checkpoint: mustBeFull ? null : (state.checkpoints[connector] ?? null),
    };
  }

  /**
   * §2.9 seed state of `connector` on this install: whether the seed target
   * is known (set by the first identified run of the connector) and the
   * receipt of each stream for that target. Empty without a seed source.
   */
  async seedStatus(connector: string): Promise<{
    targetKnown: boolean;
    receipts: Readonly<Record<string, SeedReceipt>>;
  }> {
    const seed = this.options.seed;
    const state = await this.readState();
    const target = state.seedTargets[connector];
    const receipts: Record<string, SeedReceipt> = {};
    if (seed && target !== undefined) {
      const prefix = `${seed.installId}|${connector}|${target}|`;
      for (const [key, receipt] of Object.entries(state.receipts)) {
        if (key.startsWith(prefix))
          receipts[key.slice(prefix.length)] = receipt;
      }
    }
    return { targetKnown: target !== undefined, receipts };
  }

  /** The owner and key check a run is bound to (V2 §2.1, M5). */
  async binding(): Promise<{ owner: string; keyCheck: string }> {
    const { keyCheck } = await this.keys();
    return { owner: this.options.ownerAddress, keyCheck };
  }

  /** Whether `controls` was listed in this app session (§2.4). */
  hasControls(): boolean {
    return this.controls !== null;
  }

  /**
   * The START a run of `connector` would be issued now (V2 §2.1, R16). Full
   * when asked, forced by `needsFull`, or without a checkpoint. `state` is
   * the stored value unless a `needsFull` entry cleared it.
   */
  async issueStart(
    connector: string,
    wantFull: boolean,
  ): Promise<{
    start: IssuedStart;
    checkpoint: StreamSyncCheckpoint | null;
    full: boolean;
  }> {
    const plan = await this.runPlan(connector);
    const full = wantFull || plan.mustBeFull || plan.checkpoint === null;
    const { keyCheck } = await this.keys();
    return {
      start: {
        collectionMode: full ? "full_refresh" : "incremental",
        state: plan.checkpoint?.value ?? null,
        keyCheck,
      },
      checkpoint: plan.checkpoint,
      full,
    };
  }

  /**
   * Start a run. With `issue` the writer issues the START (returned) and
   * records mode and checkpoint in the entry. A finished run id, or one whose
   * entry this process does not drive (a restart), answers `RunGoneError`.
   */
  beginRun(input: StreamSyncRunStart): Promise<IssuedStart> {
    return this.intake(async () => {
      if (!RUN_ID.test(input.runId))
        throw new Error(`bad runId ${input.runId}`);
      if (await this.options.home.files.read(`results/${input.runId}.json`)) {
        throw new RunGoneError(input.runId);
      }
      if (await this.readEntry(input.runId)) {
        if (!this.active.has(input.runId)) throw new RunGoneError(input.runId);
        throw new Error(`run ${input.runId} already exists`);
      }
      const state = await this.readState();
      let checkpointUsed = input.checkpointUsed ?? null;
      let full = checkpointUsed === null;
      let issued: IssuedStart | null = null;
      if (input.issue) {
        const plan = await this.issueStart(
          input.connector,
          input.issue.wantFull,
        );
        issued = plan.start;
        full = plan.full;
        checkpointUsed = plan.checkpoint
          ? {
              ns: plan.checkpoint.ns,
              generation: plan.checkpoint.generation,
            }
          : null;
      }
      const { keyCheck } = await this.keys();
      const now = this.now();
      const entry = createOutboxEntry({
        runId: input.runId,
        connector: input.connector,
        start: this.startSnapshot(input.connector),
        userConnect: input.userConnect,
        full,
        // m1: a producer clock cannot place lines more than 5 min ahead.
        observedAt: Math.min(input.observedAt ?? now, now + SKEW_MS),
        spoolRef: `runs/${input.runId}/spool`,
        checkpointCandidate: null,
        needsFull: state.needsFull,
      });
      const host: HostEntry = {
        version: 1,
        phase: "collecting",
        entry,
        checkpointUsed: checkpointUsed
          ? { ns: checkpointUsed.ns, generation: checkpointUsed.generation }
          : null,
        target: null,
        generation: verifiedGeneration(state, input.connector),
        overlayRevision: globalThis.crypto.randomUUID(),
        streams: {},
        outcome: null,
        seedStreams: [],
        binding: {
          owner: this.options.ownerAddress,
          keyCheck,
          leaseId: input.leaseId ?? null,
        },
      };
      // Active before the entry exists, so a recovery pass on the publish
      // queue never mistakes this run for one a dead process left behind.
      this.active.set(input.runId, {
        spool: new SpoolWriter(this.options.home.files),
        shardBytes: new Map(),
        recordTooLarge: new Map(),
        records: new Map(),
        excluded: [],
      });
      try {
        await this.writeEntry(host);
      } catch (error) {
        this.active.delete(input.runId);
        throw error;
      }
      return (
        issued ?? {
          collectionMode: full ? "full_refresh" : "incremental",
          state: null,
          keyCheck,
        }
      );
    });
  }

  declareStream(
    runId: string,
    stream: string,
    shape: {
      readonly primaryKey: readonly string[];
      readonly profile: HeadProfile;
      /** `false` = every run reads the whole stream (§3.0). */
      readonly incremental?: boolean;
    },
  ): Promise<void> {
    return this.intake(async () => {
      const host = await this.collecting(runId);
      if (host.streams[stream]) return;
      host.streams[stream] = this.newStream(nextIndex(host), shape);
      host.entry = {
        ...host.entry,
        streams: { ...host.entry.streams, [stream]: { state: "planned" } },
      };
      await this.writeEntry(host);
    });
  }

  private newStream(
    index: number,
    shape: {
      readonly primaryKey: readonly string[];
      readonly profile: HeadProfile;
      readonly incremental?: boolean;
    },
  ): HostStream {
    if (shape.primaryKey.length === 0) {
      throw new Error("a stream needs a primary key");
    }
    return {
      index,
      primaryKey: [...shape.primaryKey],
      profile: { key: shape.profile.key, version: shape.profile.version },
      shardBytes: null,
      seedShardBytes: null,
      seedOnly: false,
      fullStream: shape.incremental === false,
      seedApplies: false,
      recordTooLarge: 0,
      problem: null,
      detail: null,
    };
  }

  private async collecting(runId: string): Promise<HostEntry> {
    const host = await this.readEntry(runId);
    if (!host || host.phase !== "collecting" || !this.active.has(runId)) {
      throw new Error(`run ${runId} is not collecting in this process`);
    }
    return host;
  }

  /**
   * Add one record. A record whose canonical line is over 8 MiB is not
   * spooled; the stream counts it as `record_too_large` and keeps its key
   * digest and size locally (§2.2).
   */
  async append(
    runId: string,
    stream: string,
    record: Record<string, unknown>,
    shape?: {
      readonly primaryKey: readonly string[];
      readonly profile: HeadProfile;
      readonly incremental?: boolean;
    },
  ): Promise<"spooled" | "too_large"> {
    const run = this.active.get(runId);
    if (!run) throw new Error(`run ${runId} is not collecting in this process`);
    let info = this.streamCache.get(`${runId}\u0000${stream}`);
    if (!info) {
      if (shape) await this.declareStream(runId, stream, shape);
      const host = await this.collecting(runId);
      const declared = host.streams[stream];
      if (!declared) throw new Error(`stream ${stream} is not declared`);
      info = {
        index: declared.index,
        primaryKey: declared.primaryKey,
        observedAt: host.entry.observedAt,
      };
      this.streamCache.set(`${runId}\u0000${stream}`, info);
    }
    if (!isPlainObject(record))
      throw new Error("a record must be a JSON object");
    const value = record as JsonObject;
    const hash = await pkHash(this.hashes.sha256, value, info.primaryKey);
    const text = encodeLine({ o: info.observedAt, r: runId, v: value });
    const size = lineSize(text);
    if (!size.fits) {
      run.recordTooLarge.set(stream, (run.recordTooLarge.get(stream) ?? 0) + 1);
      run.excluded.push(
        JSON.stringify({ stream, pkHash: hash, bytes: size.bytes }),
      );
      return "too_large";
    }
    const shard = shardOf(hash);
    let bytes = run.shardBytes.get(stream);
    if (!bytes) {
      bytes = emptyShardBytes();
      run.shardBytes.set(stream, bytes);
    }
    bytes[shard]! += size.bytes + 1;
    run.records.set(stream, (run.records.get(stream) ?? 0) + 1);
    await run.spool.add(
      spoolLogPath(`runs/${runId}/spool/s${info.index}`),
      hash,
      text,
      size.bytes,
    );
    return "spooled";
  }

  /** Spool directories whose shards were derived by this process, with bytes. */
  private readonly derived = new Map<string, number[]>();

  private readonly streamCache = new Map<
    string,
    { index: number; primaryKey: string[]; observedAt: number }
  >();

  /**
   * End intake. The run becomes publishable.
   *
   * `coveredStreams` limits the run to the streams its connector fully
   * covered (§3.5): the others are dropped with their spool lines, never
   * published empty. Omit it to publish every declared stream.
   *
   * Every run (R23) publishes under the identity-less name.
   */
  finishRun(
    runId: string,
    input: {
      readonly checkpointCandidate: JsonValue | null;
      readonly coveredStreams?: readonly string[];
    },
  ): Promise<StreamSyncRunStatus> {
    return this.intake(async () => {
      const host = await this.collecting(runId);
      const run = this.active.get(runId)!;
      // The run stays active until its `ready` write is durable, so a
      // recovery pass on the publish queue cannot take it for an abandoned
      // run. It is forgotten on any failure and once it is `ready`.
      try {
        await run.spool.flush();
        if (input.coveredStreams) this.keepCovered(host, input.coveredStreams);
        if (run.excluded.length > 0) {
          await this.options.home.files.appendMany([
            {
              path: `runs/${runId}/excluded.ndjson`,
              bytes: encoder.encode(run.excluded.map((l) => `${l}\n`).join("")),
            },
          ]);
        }
        const connector = host.entry.connector;
        const ns = IDENTITYLESS_NS;
        for (const [name, stream] of Object.entries(host.streams)) {
          stream.shardBytes = run.shardBytes.get(name) ?? emptyShardBytes();
          stream.recordTooLarge = run.recordTooLarge.get(name) ?? 0;
        }
        if (this.options.seed) {
          await this.withState((state) => {
            state.seedTargets[connector] ??= ns;
          });
        }
        // Intake appends are not durable one by one. The run becomes `ready`
        // only after one sync of its intake logs (§2.6).
        await this.options.home.files.sync(`runs/${runId}`);
        host.entry = {
          ...host.entry,
          ns,
          checkpointCandidate: input.checkpointCandidate,
        };
        host.generation ??= verifiedGeneration(
          await this.readState(),
          connector,
        );
        host.overlayRevision ??= globalThis.crypto.randomUUID();
        host.phase = "ready";
        host.ready = true;
        await this.writeEntry(host);
      } finally {
        this.forget(runId);
      }
      return this.statusOf(host);
    });
  }

  private forget(runId: string): void {
    this.active.delete(runId);
    for (const key of [...this.streamCache.keys()]) {
      if (key.startsWith(`${runId}\u0000`)) this.streamCache.delete(key);
    }
  }

  /** Drop every declared stream outside `covered` from the run (§3.5). */
  private keepCovered(host: HostEntry, covered: readonly string[]): void {
    const keep = new Set(covered);
    const streams = { ...host.entry.streams };
    for (const name of Object.keys(host.streams)) {
      if (keep.has(name)) continue;
      delete host.streams[name];
      delete streams[name];
    }
    host.entry = { ...host.entry, streams };
  }

  /**
   * End a run that must publish nothing (V2 §3.7): `failed` or `cancelled`.
   * Idempotent for a run this process
   * already ended; a run it never drove answers `RunGoneError`.
   */
  abortRun(runId: string, reason: AbortReason): Promise<void> {
    return this.intake(async () => {
      const run = this.active.get(runId);
      const host = await this.readEntry(runId);
      if (!run || !host || host.phase !== "collecting") {
        throw new RunGoneError(runId);
      }
      // Buffered lines are dropped, not written to be removed again.
      run.spool.clear();
      try {
        await this.finish(host, { kind: "aborted", reason });
      } finally {
        this.forget(runId);
      }
    });
  }

  /**
   * End a `retry_pending` run (V2 §3.6, R19): save its cursors, publish
   * nothing. A cursor of a stream that emitted records in this run is
   * dropped, because those records are not published and the next run
   * must read them again. Same admission as a publish: a stale namespace or
   * generation saves nothing.
   */
  saveCheckpointOnly(
    runId: string,
    candidate: Readonly<Record<string, JsonValue>>,
  ): Promise<StreamSyncRunStatus> {
    return this.intake(async () => {
      const host = await this.collecting(runId);
      const run = this.active.get(runId)!;
      const kept: Record<string, JsonValue> = {};
      for (const [stream, cursor] of Object.entries(candidate)) {
        if ((run.records.get(stream) ?? 0) === 0) kept[stream] = cursor;
      }
      run.spool.clear();
      // Active until the run has ended, so recovery cannot end it first.
      try {
        this.keepCovered(host, []);
        const ns = IDENTITYLESS_NS;
        host.entry = {
          ...host.entry,
          ns,
          checkpointCandidate: Object.keys(kept).length > 0 ? kept : null,
        };
        try {
          host.target = await this.admit(host, "first");
        } catch (error) {
          if (error instanceof Discard) {
            await this.discard(host, error);
            return this.statusOf(host);
          }
          if (
            error instanceof PendingStream ||
            error instanceof RegistryRefusedError
          ) {
            await this.finish(host, {
              kind: "no_checkpoint",
              generation: 0,
              reason: "control_changed",
            });
            return this.statusOf(host);
          }
          throw error;
        }
        await this.checkpoint(host);
        return this.statusOf(host);
      } finally {
        this.forget(runId);
      }
    });
  }

  /**
   * M4: three finished runs in a row of one connector that published
   * nothing (failed, discarded or dropped by intake). A cancel is not a
   * failure.
   */
  async stuck(connector: string): Promise<boolean> {
    const recent = (await this.readState()).recent?.[connector] ?? [];
    return recent.length >= 3 && recent.every((v) => v === "bad");
  }

  /** Count a run intake dropped before the writer saw it (`will_discard`). */
  noteDropped(connector: string): Promise<void> {
    return this.note(connector, "bad");
  }

  private note(connector: string, verdict: "good" | "bad"): Promise<void> {
    return this.withState((state) => {
      const recent = (state.recent ??= {});
      recent[connector] = [...(recent[connector] ?? []), verdict].slice(-3);
    });
  }

  private async compact(dir: string, shardBytes: number[]): Promise<void> {
    for (let shard = 0; shard < shardBytes.length; shard += 1) {
      if (shardBytes[shard]! <= this.targetBytes / 4) continue;
      const after = await compactShard(
        this.options.home.files,
        shardPath(dir, shard),
        shard,
        this.reduceBudget,
      );
      if (after !== null) shardBytes[shard] = after;
    }
  }

  // ------------------------------------------------------------- publish

  /** One sync-loop step: refresh `controls`, then publish every ready run. */
  async cycle(): Promise<StreamSyncPublishReport> {
    await this.refreshControls();
    return this.publishPending();
  }

  publishPending(): Promise<StreamSyncPublishReport> {
    return this.publish(async () => {
      await this.recover();
      const runs: StreamSyncRunStatus[] = [];
      const hosts: HostEntry[] = [];
      for (const runId of await this.runIds()) {
        const host = await this.readEntry(runId);
        if (host && host.phase === "ready") hosts.push(host);
      }
      hosts.sort(
        (a, b) =>
          a.entry.observedAt - b.entry.observedAt ||
          (a.entry.runId < b.entry.runId ? -1 : 1),
      );
      // Commit order: a stream an earlier run did not resolve in this pass
      // holds back every later run of that stream until the next pass.
      const held = new Set<string>();
      for (const host of hosts) {
        await this.publishEntry(host, held);
        runs.push(this.statusOf(host));
        if (host.phase === "done" || host.entry.ns === null) continue;
        for (const [name, outbox] of Object.entries(host.entry.streams)) {
          if (
            outbox.state === "committed" ||
            outbox.state === "noop" ||
            outbox.state === "discarded"
          )
            continue;
          const problem = host.streams[name]?.problem;
          if (
            problem === "connector_update_required" ||
            problem === "out_of_order"
          )
            continue;
          held.add(floorKey(host.entry.connector, host.entry.ns, name));
        }
      }
      return { runs };
    });
  }

  private async runIds(): Promise<string[]> {
    const ids = new Set<string>();
    for (const path of await this.options.home.files.list("runs")) {
      const match = /^runs\/([^/]+)\/entry\.json$/.exec(path);
      if (match) ids.add(match[1]!);
    }
    return [...ids].sort();
  }

  /** Discard runs left collecting by an earlier process. */
  private recover(): Promise<void> {
    this.recovery ??= (async () => {
      for (const runId of await this.runIds()) {
        if (this.active.has(runId)) continue;
        const host = await this.readEntry(runId);
        if (host?.phase === "collecting") {
          await this.finish(host, {
            kind: "failed",
            why: "the process stopped before the run finished collecting",
          });
        } else if (host?.phase === "done") {
          await this.reclaim(host);
        }
      }
    })().catch((error) => {
      this.recovery = null;
      throw error;
    });
    return this.recovery;
  }

  /**
   * The only way the writer reads a control row. The read is recorded in the
   * connector's control watermark and the watermark's state is returned
   * (`recordControl`): a lagging read yields the newer state already known,
   * so no decision can use a raw read. The network read is outside the state
   * lock; the recording is one short mutation.
   */
  private async readControl(
    connector: string,
    ns: string,
  ): Promise<ControlState> {
    const { control } = await this.keys();
    const current = classifyControl(
      await this.options.registry.read(controlScope(connector, ns)),
      control,
    );
    return this.withState((state) =>
      recordControl(state, connector, ns, current),
    );
  }

  /**
   * §2.4 admission for one decision point: read control, `decide`, follow
   * `reread` once and `create`/`reconnect` with an `after_write` re-read.
   * Returns the target generation, or throws `Discard`/`PendingStream`.
   */
  private async admit(host: HostEntry, phase: DecidePhase): Promise<number> {
    const { entry } = host;
    const ns = entry.ns!;
    const scope = controlScope(entry.connector, ns);
    const start = startState(entry.start, ns);
    let current = await this.readControl(entry.connector, ns);
    let decision = decide({
      start,
      current,
      userConnect: entry.userConnect,
      full: entry.full,
      phase,
    });
    if (decision.kind === "reread") {
      current = await this.readControl(entry.connector, ns);
      decision = decide({
        start,
        current,
        userConnect: entry.userConnect,
        full: entry.full,
        phase: "reread",
      });
    }
    if (decision.kind === "create" || decision.kind === "reconnect") {
      await this.writeControl(scope, decision.target);
      this.fault("after_control_write", entry.runId);
      current = await this.readControl(entry.connector, ns);
      decision = decide({
        start,
        current,
        userConnect: entry.userConnect,
        full: entry.full,
        phase: "after_write",
      });
    }
    switch (decision.kind) {
      case "publish":
        if (host.generation != null && host.generation !== decision.target) {
          throw new PendingStream(
            "registry_inconsistent",
            "admission differs from the run generation",
          );
        }
        host.generation = decision.target;
        await this.writeEntry(host);
        return decision.target;
      case "discard":
        throw new Discard(decision, `control reads ${describe(current)}`);
      case "keep_pending":
        throw new PendingStream(
          decision.reason,
          `control reads ${describe(current)}`,
        );
      default:
        throw new PendingStream(
          "registry_inconsistent",
          `unexpected decision ${decision.kind}`,
        );
    }
  }

  private async writeControl(scope: string, version: number): Promise<void> {
    const { control } = await this.keys();
    const request = await this.sign(
      scope,
      control.activeData,
      control.activeMetadata,
      version,
    );
    // A create or reconnect reply (2xx or replay) is followed by a re-read;
    // a 409 means someone else moved the row, which the re-read shows too.
    try {
      await this.options.registry.post(request);
    } catch (error) {
      if (!(error instanceof AmbiguousRegistryReplyError)) throw error;
    }
  }

  private async sign(
    scope: string,
    dataHash: `0x${string}`,
    metadataHash: `0x${string}`,
    version: number,
  ): Promise<SignedRegistryPost> {
    const signature = await this.options.signer.signAddData({
      ownerAddress: this.options.ownerAddress,
      scope,
      dataHash,
      metadataHash,
      expectedVersion: BigInt(version),
    });
    return {
      ownerAddress: this.options.ownerAddress,
      scope,
      dataHash,
      metadataHash,
      expectedVersion: String(version),
      signature,
    };
  }

  private async publishEntry(
    host: HostEntry,
    held: ReadonlySet<string> = new Set(),
  ): Promise<void> {
    try {
      // M5: a run publishes only for the owner and key it began with.
      const bound = host.binding;
      if (bound) {
        const now = await this.binding();
        if (bound.owner !== now.owner || bound.keyCheck !== now.keyCheck) {
          await this.finish(host, {
            kind: "failed",
            why: "owner_mismatch: the owner or key changed since the run began",
          });
          return;
        }
      }
      const target = await this.admit(host, "first");
      if (host.target !== null && host.target !== target) {
        throw new PendingStream(
          "registry_inconsistent",
          `admitted at ${target}, run is bound to ${host.target}`,
        );
      }
      host.target = target;
      await this.prepareSeed(host);
      await this.writeEntry(host);
    } catch (error) {
      if (error instanceof Discard) return this.discard(host, error);
      if (error instanceof RegistryRefusedError) {
        error = new PendingStream("registry_refused", error.message);
      }
      if (error instanceof PendingStream) {
        for (const stream of Object.values(host.streams)) {
          stream.problem = error.problem;
          stream.detail = error.message;
        }
        await this.writeEntry(host);
        return;
      }
      throw error;
    }

    for (const name of Object.keys(host.streams).sort()) {
      const state = host.entry.streams[name]!.state;
      if (state === "committed" || state === "noop") continue;
      if (held.has(floorKey(host.entry.connector, host.entry.ns!, name))) {
        host.streams[name]!.problem = "earlier_run_pending";
        host.streams[name]!.detail =
          "an earlier run of this stream is not committed yet";
        await this.writeEntry(host);
        continue;
      }
      try {
        await this.publishStream(host, name);
        host.streams[name]!.problem = null;
        host.streams[name]!.detail = null;
      } catch (error) {
        if (error instanceof Discard) return this.discard(host, error);
        if (error instanceof PendingStream) {
          host.streams[name]!.problem = error.problem;
          host.streams[name]!.detail = error.message;
          await this.writeEntry(host);
          continue;
        }
        if (error instanceof AmbiguousRegistryReplyError) {
          host.streams[name]!.problem = "ambiguous_reply";
          host.streams[name]!.detail = error.message;
          await this.writeEntry(host);
          continue;
        }
        if (error instanceof RegistryRefusedError) {
          // A refused request is never resent; the next pass signs anew.
          this.setStream(host, name, { state: "planned" });
          host.streams[name]!.problem = "registry_refused";
          host.streams[name]!.detail = error.message;
          await this.writeEntry(host);
          continue;
        }
        throw error;
      }
    }

    const states = Object.values(host.entry.streams).map((s) => s.state);
    if (!states.every((s) => s === "committed" || s === "noop")) return;
    await this.checkpoint(host);
  }

  /** §2.9: decide the seed for this run once the target generation is known. */
  private async prepareSeed(host: HostEntry): Promise<void> {
    const seed = this.options.seed;
    if (!seed) return;
    const { entry } = host;
    const state = await this.readState();
    if (state.seedTargets[entry.connector] !== entry.ns) return;
    const seedStreams = await seed.streams(entry.connector);
    const receiptKey = (stream: string) =>
      `${seed.installId}|${entry.connector}|${entry.ns}|${stream}`;
    if (host.target !== 1) {
      const open = seedStreams.filter(
        (s) => state.receipts[receiptKey(s.stream)] === undefined,
      );
      if (open.length > 0) {
        await this.withState((fresh) => {
          for (const s of open) {
            fresh.receipts[receiptKey(s.stream)] ??= "skipped";
          }
        });
      }
      return;
    }
    for (const s of seedStreams) {
      if (state.receipts[receiptKey(s.stream)] !== undefined) continue;
      let stream = host.streams[s.stream];
      if (!stream) {
        stream = this.newStream(nextIndex(host), s);
        stream.shardBytes = emptyShardBytes();
        stream.seedOnly = true;
        host.streams[s.stream] = stream;
        host.entry = {
          ...host.entry,
          streams: { ...host.entry.streams, [s.stream]: { state: "planned" } },
        };
      }
      stream.seedApplies = true;
      if (!host.seedStreams.includes(s.stream)) host.seedStreams.push(s.stream);
    }
  }

  private async spoolSeed(host: HostEntry, name: string): Promise<void> {
    const seed = this.options.seed!;
    const stream = host.streams[name]!;
    if (stream.seedShardBytes !== null) return;
    const dir = `runs/${host.entry.runId}/seed/s${stream.index}`;
    await this.options.home.files.remove(dir);
    await this.options.home.files.remove(spoolLogPath(dir));
    this.derived.delete(dir);
    const writer = new SpoolWriter(this.options.home.files);
    const bytes = emptyShardBytes();
    for await (const record of seed.records(host.entry.connector, name)) {
      if (!isPlainObject(record)) continue;
      const value = record as JsonObject;
      const hash = await pkHash(this.hashes.sha256, value, stream.primaryKey);
      const text = encodeLine({
        o: SEED_OBSERVED_AT,
        r: SEED_RUN_ID,
        v: value,
      });
      const size = lineSize(text);
      if (!size.fits) {
        stream.recordTooLarge += 1;
        continue;
      }
      const shard = shardOf(hash);
      bytes[shard]! += size.bytes + 1;
      await writer.add(spoolLogPath(dir), hash, text, size.bytes);
    }
    await writer.flush();
    await this.options.home.files.sync(spoolLogPath(dir));
    stream.seedShardBytes = bytes;
    await this.writeEntry(host);
  }

  /**
   * Shard counts of a spool whose shards are ready to read. The shards are
   * derived from the durable intake log and compacted once per process; a
   * run found after a restart derives them again, because the files were
   * never synced and may be missing or short. `counted` is the intake count
   * per shard, which the log still holds.
   */
  private async readyShards(
    dir: string,
    counted: readonly number[],
  ): Promise<number[]> {
    const known = this.derived.get(dir);
    if (known) return known;
    await deriveShards(this.options.home.files, dir);
    const bytes = [...counted];
    await this.compact(dir, bytes);
    this.derived.set(dir, bytes);
    return bytes;
  }

  private async publishStream(host: HostEntry, name: string): Promise<void> {
    for (let attempt = 0; attempt < CONFLICTS_PER_PASS; attempt += 1) {
      const outbox = host.entry.streams[name]!;
      if (outbox.state === "request_persisted") {
        if (await this.resend(host, name)) return;
        continue;
      }
      if (await this.planAndPost(host, name)) return;
    }
    throw new PendingStream(
      "registry_inconsistent",
      `${CONFLICTS_PER_PASS} version conflicts in one pass; retrying next cycle`,
    );
  }

  private setStream(host: HostEntry, name: string, next: OutboxStream): void {
    host.entry = {
      ...host.entry,
      streams: { ...host.entry.streams, [name]: next },
    };
  }

  /** Resend the persisted request byte for byte. True when committed. */
  private async resend(host: HostEntry, name: string): Promise<boolean> {
    const runId = host.entry.runId;
    const outbox = host.entry.streams[name]!;
    const request = JSON.parse(
      decoder.decode((await this.options.home.files.read(outbox.requestRef!))!),
    ) as SignedRegistryPost;
    const cipher = await this.options.home.files.read(outbox.headCipherRef!);
    const head = parseHeadKey(request);
    if (cipher) await this.options.blobs.put(head, cipher);
    const result = await this.options.registry.post(request);
    this.fault("after_post_reply", runId, name);
    if (result.kind === "committed") {
      const stream = host.streams[name]!;
      await this.committed(
        host,
        name,
        outbox.generation!,
        outbox.complete!,
        "committed",
        Number(request.expectedVersion),
        request.dataHash,
        stream.planned ?? {
          // A request persisted before plan steps were recorded.
          kind: "publish",
          head: {
            generation: outbox.generation!,
            primaryKey: stream.primaryKey,
            profile: stream.profile,
            complete: outbox.complete!,
          },
          replacesBase: false,
          floor: stream.profile.version,
        },
      );
      return true;
    }
    this.setStream(host, name, { state: "planned" });
    await this.writeEntry(host);
    return false;
  }

  /** §2.7 from "read control" to the POST. True when committed or no-op. */
  private async planAndPost(host: HostEntry, name: string): Promise<boolean> {
    const { entry } = host;
    const runId = entry.runId;
    const ns = entry.ns!;
    const stream = host.streams[name]!;
    const target = await this.admit(host, "first");
    if (target !== host.target) {
      throw new PendingStream(
        "registry_inconsistent",
        `admitted at ${target}, run is bound to ${host.target}`,
      );
    }
    const scope = streamScope(entry.connector, ns, name);
    const { keyCheck } = await this.keys();

    const row = await this.options.registry.read(scope);
    const rowKind = classifyStreamRow(row, this.control!);
    let head: Head | null = null;
    if (rowKind === "present" && row.found) {
      head = await this.loadHead(scope, row.dataHash, {
        connector: entry.connector,
        ns,
        stream: name,
        keyCheck,
      });
    }
    const choice = chooseBase(rowKind, head, target);
    if (choice.kind === "stale_generation") {
      // F1: the stream holds a newer generation than this run's target.
      try {
        await this.admit(host, "stale_base");
      } catch (error) {
        if (error instanceof Discard) {
          throw new Discard(error.decision, `stale_generation: ${error.why}`);
        }
        if (error instanceof PendingStream) {
          throw new PendingStream(
            error.problem,
            `stale_generation: ${error.message}`,
          );
        }
        throw error;
      }
      throw new PendingStream(
        "registry_inconsistent",
        "stale_generation: control still admits the target",
      );
    }
    // The publish plan decides this step (publish-plan.ts); this method only
    // executes it: the parts, the head upload and the POST.
    const decision = planStreamStep(
      {
        head: head && planHeadOf(head),
        floor: floorOf(await this.readState(), entry.connector, ns, name),
      },
      this.planRun(host, name, await this.readState()),
    );
    if (decision.kind === "refused") {
      throw new PendingStream(
        decision.reason,
        decision.reason === "out_of_order"
          ? "a newer run already committed on this stream"
          : `base primary key ${JSON.stringify(head?.primaryKey ?? [])} needs a newer connector`,
      );
    }
    if (decision.kind === "deferred") {
      throw new PendingStream(
        "registry_inconsistent",
        `publish plan deferred the stream: ${decision.reason}`,
      );
    }
    const base =
      choice.kind === "base" &&
      (decision.kind === "noop" || !decision.replacesBase)
        ? choice.head
        : null;
    if (stream.seedApplies) await this.spoolSeed(host, name);
    const next = decision.head;
    const complete = next.complete;

    const built = await this.buildParts(host, name, scope, target, base);
    // A step whose parts, completeness, key and profile all equal the base's
    // changes nothing a reader sees: record a no-op of the same head.
    if (
      isNoop(base, built.parts, complete, {
        primaryKey: next.primaryKey,
        profile: next.profile,
      })
    ) {
      if (!row.found) throw new Error("no-op requires a registered base");
      await this.committed(
        host,
        name,
        target,
        complete,
        "noop",
        row.version,
        row.dataHash,
        {
          kind: "noop",
          head: planHeadOf(base!),
          replacesBase: false,
          floor: decision.floor,
        },
      );
      return true;
    }
    const step: ExecutedStep & { floor: string } = {
      kind: "publish",
      head: next,
      replacesBase: decision.kind === "publish" && decision.replacesBase,
      floor: decision.floor,
    };
    const clear = encodeHead({
      complete,
      connector: entry.connector,
      format: 1,
      generation: target,
      keyCheck,
      ns,
      observedAt: entry.observedAt,
      parts: built.parts,
      primaryKey: next.primaryKey,
      profile: next.profile,
      recordCount: built.parts.reduce((n, p) => n + p.count, 0),
      stream: name,
    });
    const digest = await digestHead(this.hashes.keccak256, clear);
    const cipher = await this.options.keys.encrypt(scope, clear);
    await this.options.blobs.put(`${scope}/${digest.blobName}`, cipher);
    this.fault("after_head_upload", runId, name);

    const version = row.found ? row.version + 1 : 1;
    const request = await this.sign(
      scope,
      digest.dataHash,
      publicationMetadataHash(
        scope,
        new Date(entry.observedAt).toISOString(),
        clear.length,
      ),
      version,
    );
    const requestRef = `runs/${runId}/request-s${stream.index}.json`;
    const headCipherRef = `runs/${runId}/head-s${stream.index}.bin`;
    await this.options.home.files.write(headCipherRef, cipher);
    await this.options.home.files.write(requestRef, json(request));
    stream.planned = step;
    this.setStream(host, name, {
      state: "request_persisted",
      requestRef,
      headCipherRef,
      generation: target,
      complete,
    });
    await this.writeEntry(host);
    this.fault("after_request_persisted", runId, name);

    const result = await this.options.registry.post(request);
    this.fault("after_post_reply", runId, name);
    if (result.kind === "committed") {
      await this.committed(
        host,
        name,
        target,
        complete,
        "committed",
        version,
        request.dataHash,
        step,
      );
      return true;
    }
    this.setStream(host, name, { state: "planned" });
    await this.writeEntry(host);
    return false;
  }

  /** What the publish plan reads of one run's stream. */
  private planRun(host: HostEntry, name: string, state: WriterState): PlanRun {
    const { entry } = host;
    const stream = host.streams[name]!;
    const seed = this.options.seed;
    const seedOpen =
      seed !== undefined &&
      entry.ns !== null &&
      host.target === null &&
      state.seedTargets[entry.connector] === entry.ns &&
      state.receipts[
        `${seed.installId}|${entry.connector}|${entry.ns}|${name}`
      ] === undefined;
    const outbox = entry.streams[name];
    const executed: ExecutedStep | undefined =
      stream.executed ??
      ((outbox?.state === "committed" || outbox?.state === "noop") &&
      outbox.generation !== undefined
        ? {
            // An entry from before plan steps were recorded.
            kind: outbox.state === "noop" ? "noop" : "publish",
            head: {
              generation: outbox.generation,
              primaryKey: stream.primaryKey,
              profile: stream.profile,
              complete: outbox.complete ?? false,
            },
            replacesBase: false,
          }
        : undefined);
    return {
      runId: entry.runId,
      observedAt: entry.observedAt,
      generation: host.target ?? host.generation ?? null,
      primaryKey: stream.primaryKey,
      profile: stream.profile,
      full: entry.full || stream.fullStream,
      foreignCheckpoint:
        host.checkpointUsed !== null && host.checkpointUsed.ns !== entry.ns,
      empty: (stream.shardBytes ?? []).every((bytes) => bytes === 0),
      seed: stream.seedApplies ? "merged" : seedOpen ? "unresolved" : "none",
      ...(executed ? { executed } : {}),
      // The request is signed and persisted; the registry's answer is not.
      ...(!executed && outbox?.state === "request_persisted"
        ? { inFlight: true }
        : {}),
    };
  }

  /** Record a commit or no-op: `needsFull` and seed receipt, then the outbox. */
  private async committed(
    host: HostEntry,
    name: string,
    generation: number,
    complete: boolean,
    kind: "committed" | "noop",
    registryVersion: number,
    dataHash: string,
    step: ExecutedStep & { floor: string },
  ): Promise<void> {
    const { entry } = host;
    const stream = host.streams[name]!;
    await this.withState((state) => {
      // The version floor and the commit order only move forward.
      const key = floorKey(entry.connector, entry.ns!, name);
      const prev = floorOf(state, entry.connector, entry.ns!, name);
      const stamp = { observedAt: entry.observedAt, runId: entry.runId };
      const version =
        prev.version === null ||
        compareConnectorVersions(step.floor, prev.version) === "higher"
          ? step.floor
          : prev.version;
      const committed =
        prev.committed && stampBefore(stamp, prev.committed)
          ? prev.committed
          : stamp;
      (state.streamFloors ??= {})[key] = {
        version,
        committed: [committed.observedAt, committed.runId],
      };
      // §3.0: a stream declared `incremental: false` is read whole every run.
      const effect = afterCommit(state.needsFull, {
        connector: entry.connector,
        ns: entry.ns!,
        stream: name,
        complete,
        runFull: entry.full || stream.fullStream,
      });
      state.needsFull = effect.needsFull;
      if (effect.clearCheckpoint) {
        invalidateCheckpoint(state, entry.connector, true);
      }
      if (stream.seedApplies && this.options.seed) {
        state.receipts[
          `${this.options.seed.installId}|${entry.connector}|${entry.ns}|${name}`
        ] = "merged";
      }
    });
    stream.receipt = {
      registryVersion,
      dataHash: canonicalBytes32(dataHash),
      generation,
    };
    stream.executed = {
      kind: step.kind,
      head: step.head,
      replacesBase: step.replacesBase,
    };
    delete stream.planned;
    this.setStream(host, name, {
      state: kind,
      generation,
      complete,
      ...(stream.recordTooLarge > 0
        ? { recordTooLarge: stream.recordTooLarge }
        : {}),
    });
    await this.writeEntry(host);
    this.fault("after_commit_recorded", entry.runId, name);
  }

  private async checkpoint(host: HostEntry): Promise<void> {
    const { entry } = host;
    const ns = entry.ns!;
    // Snapshot before the control read: an invalidation that lands after it
    // makes that read stale, and the save below refuses to use it.
    const epoch =
      (await this.readState()).invalidations?.[entry.connector] ?? 0;
    const control = await this.readControl(entry.connector, ns);
    const seed = this.options.seed;
    const streams = Object.fromEntries(
      Object.entries(entry.streams).map(([k, v]) => [k, streamRunResult(v)]),
    );
    const decision = await this.withState((state) => {
      if ((state.invalidations?.[entry.connector] ?? 0) !== epoch) {
        // The records are already published; the next run reads them again.
        return { kind: "stale" as const };
      }
      const seedReceiptsPending = host.seedStreams.some(
        (s) =>
          seed !== undefined &&
          state.receipts[`${seed.installId}|${entry.connector}|${ns}|${s}`] ===
            undefined,
      );
      // Decide on the watermark as of this mutation, not on the read alone.
      const latest = state.observedControl?.[entry.connector]?.[ns] ?? control;
      const decided = checkpointDecision({
        target: host.target!,
        streams,
        control: latest,
        seedReceiptsPending,
      });
      const held = state.checkpoints[entry.connector];
      if (
        decided.kind === "save" &&
        held?.ns === ns &&
        held.generation > decided.generation
      ) {
        // Never replace a newer generation's checkpoint with an older one.
        return { kind: "stale" as const };
      }
      if (decided.kind === "save") {
        // §3.6: this run's cursors join the saved ones of the same namespace
        // and generation, so a stream the run did not cover keeps its own.
        const prev = state.checkpoints[entry.connector];
        const same = prev?.ns === ns && prev.generation === decided.generation;
        state.checkpoints[entry.connector] = {
          ns,
          generation: decided.generation,
          value: mergeCursors(
            same ? prev.value : null,
            entry.checkpointCandidate,
          ),
        };
      }
      return decided;
    });
    if (decision.kind === "stale") {
      await this.finish(host, {
        kind: "no_checkpoint",
        generation: host.target!,
        reason: "control_changed",
      });
      return;
    }
    if (decision.kind === "save") {
      this.fault("after_checkpoint_saved", entry.runId);
      await this.finish(host, {
        kind: "checkpointed",
        generation: decision.generation,
      });
      return;
    }
    await this.finish(host, {
      kind: "no_checkpoint",
      generation: host.target!,
      reason: decision.reason,
    });
  }

  private async discard(host: HostEntry, error: Discard): Promise<void> {
    const { entry } = host;
    const { decision } = error;
    if (decision.clearCheckpoints) {
      await this.withState((state) => {
        invalidateCheckpoint(
          state,
          entry.connector,
          state.checkpoints[entry.connector]?.ns === entry.ns,
        );
      });
    }
    for (const [name, stream] of Object.entries(entry.streams)) {
      if (stream.state !== "committed" && stream.state !== "noop") {
        this.setStream(host, name, { state: "discarded" });
      }
    }
    await this.finish(host, {
      kind: "discarded",
      recollect: decision.recollect,
      clearCheckpoints: decision.clearCheckpoints,
      restartFull: decision.restartFull,
      why: error.why,
    });
    if (decision.restartFull) this.options.onRestartFull?.(entry.connector);
  }

  private async finish(host: HostEntry, outcome: RunOutcome): Promise<void> {
    // Older ready entries have no explicit ready marker.
    host.ready ??= host.phase === "ready";
    host.outcome = outcome;
    host.phase = "done";
    const runId = host.entry.runId;
    await this.writeEntry(host);
    await this.options.home.files.write(
      `results/${runId}.json`,
      json(this.statusOf(host)),
    );
    await this.reclaim(host);
    if (!(outcome.kind === "aborted" && outcome.reason === "cancelled")) {
      const bad =
        outcome.kind === "failed" ||
        outcome.kind === "discarded" ||
        outcome.kind === "aborted";
      await this.note(host.entry.connector, bad ? "bad" : "good");
    }
    for (const dir of [...this.derived.keys()]) {
      if (dir.startsWith(`runs/${runId}/`)) this.derived.delete(dir);
    }
  }

  /**
   * A stream is covered only when its own receipt satisfies the latest
   * coverage for the same binding, connector, namespace, stream and generation.
   * Never treat a missing pre-upgrade receipt as proof of read coverage.
   */
  private isCovered(host: HostEntry, name: string): boolean {
    const receipt = host.streams[name]?.receipt;
    if (
      !receipt ||
      !host.binding ||
      host.entry.ns === null ||
      host.generation == null
    )
      return false;
    const coverage = this.coverage.get(
      coverageKey(
        host.binding,
        host.entry.connector,
        host.entry.ns,
        name,
        host.generation,
      ),
    );
    if (!coverage) return false;
    if (coverage.registryVersion !== receipt.registryVersion)
      return coverage.registryVersion > receipt.registryVersion;
    try {
      return coverage.dataHash === canonicalBytes32(receipt.dataHash);
    } catch {
      return false; // an unreadable stored hash never proves coverage
    }
  }

  private retainedStreams(host: HostEntry): string[] {
    if (host.ready === false || host.outcome?.kind === "aborted") return [];
    // A stream only the seed fills stays until its receipt is covered: it
    // publishes a head later runs of the stream meet, so the reader's plan
    // needs its step. It holds no intake rows and exposes no seed rows.
    return Object.keys(host.streams).filter(
      (name) =>
        host.entry.streams[name]?.state !== "discarded" &&
        !this.isCovered(host, name),
    );
  }

  private reclaim(host: HostEntry): Promise<void> {
    return this.lifecycle(() => this.reclaimLocked(host));
  }

  private async reclaimLocked(host: HostEntry): Promise<void> {
    if (host.phase !== "done" || this.inconsistentReceipt(host)) return;
    if (
      (this.pins.get(host.entry.runId) ?? 0) > 0 ||
      this.retainedStreams(host).length > 0
    )
      return;
    const runId = host.entry.runId;
    try {
      await this.options.home.files.remove(`runs/${runId}`);
      this.removalRetry.delete(runId);
    } catch (error) {
      this.removalRetry.add(runId);
      this.reportCleanup(runId, error);
    }
  }

  private reportCleanup(runId: string, error: unknown): void {
    this.options.logger?.warn(
      {
        runId,
        error: error instanceof Error ? error.message : String(error),
      },
      "stream-sync run cleanup failed; it will be retried",
    );
  }

  /** Retry removals that failed earlier. Call inside the lifecycle queue. */
  private async retryRemovals(): Promise<void> {
    for (const runId of [...this.removalRetry]) {
      this.removalRetry.delete(runId);
      try {
        const host = await this.readEntry(runId);
        if (host) await this.reclaimLocked(host);
      } catch (error) {
        this.removalRetry.add(runId);
        this.reportCleanup(runId, error);
      }
    }
  }

  /** Called only by the home-bound overlay adapter. Does no network I/O. */
  async snapshotOverlay(connector: string): Promise<StreamSyncOverlaySnapshot> {
    await this.recover();
    const bound = await this.binding();
    return this.lifecycle(async () => {
      await this.retryRemovals();
      const runs: StreamSyncOverlayRun[] = [];
      const logs = new Map<
        StreamSyncOverlayRun,
        ReadonlyMap<string, WriterOverlayLog>
      >();
      const state = await this.readState();
      const plans = new Map<string, { floor: StreamFloor; runs: PlanRun[] }>();
      for (const runId of await this.runIds()) {
        const host = await this.readEntry(runId);
        if (
          !host ||
          host.entry.connector !== connector ||
          host.phase === "collecting" ||
          host.ready === false ||
          host.outcome?.kind === "aborted" ||
          host.entry.ns === null ||
          !host.binding ||
          host.binding.owner.toLowerCase() !== bound.owner.toLowerCase() ||
          host.binding.keyCheck !== bound.keyCheck
        )
          continue;
        const generation = host.generation ?? null;
        // Never expose or reclaim an inconsistent run, including a discarded receipt.
        if (this.inconsistentReceipt(host)) continue;
        if (!host.overlayRevision) {
          host.overlayRevision = globalThis.crypto.randomUUID();
          await this.options.home.files.write(
            `runs/${runId}/entry.json`,
            json(host),
          );
        }
        const streams: StreamSyncOverlayStream[] = [];
        const runLogs = new Map<string, WriterOverlayLog>();
        for (const name of this.retainedStreams(host)) {
          const stream = host.streams[name]!;
          if (stream.shardBytes === null)
            throw new Error("ready stream has no intake byte counts");
          const descriptor = {
            name,
            primaryKey: Object.freeze([...stream.primaryKey]),
            profile: Object.freeze({ ...stream.profile }),
            complete:
              (host.entry.full || stream.fullStream) &&
              (!host.checkpointUsed ||
                host.checkpointUsed.ns === host.entry.ns),
            state: stream.receipt
              ? ("published" as const)
              : stream.problem
                ? ("failed" as const)
                : ("pending" as const),
            ...(stream.receipt
              ? { receipt: Object.freeze({ ...stream.receipt }) }
              : {}),
          };
          streams.push(
            Object.freeze({
              ...descriptor,
              contentRevision: JSON.stringify([
                host.overlayRevision,
                runId,
                host.entry.ns,
                generation,
                host.entry.observedAt,
                descriptor,
              ]),
            }),
          );
          const planKey = overlayPlanKey(host.entry.ns, name);
          const plan = plans.get(planKey) ?? {
            floor: floorOf(state, connector, host.entry.ns, name),
            runs: [],
          };
          plan.runs.push(Object.freeze(this.planRun(host, name, state)));
          plans.set(planKey, plan);
          // A seed-only stream has no intake log: its rows are never read.
          if (stream.seedOnly) continue;
          runLogs.set(name, {
            path: spoolLogPath(`runs/${runId}/spool/s${stream.index}`),
            bytes: stream.shardBytes.reduce((sum, n) => sum + n, 0),
            primaryKey: descriptor.primaryKey,
          });
        }
        if (streams.length === 0) continue;
        const run: StreamSyncOverlayRun = Object.freeze({
          runId,
          connector,
          ns: host.entry.ns,
          generation,
          observedAt: host.entry.observedAt,
          state: streams.every((s) => s.state === "published")
            ? "published"
            : streams.some((s) => s.state === "failed")
              ? "failed"
              : "pending",
          streams: Object.freeze(streams),
        });
        runs.push(run);
        logs.set(run, runLogs);
      }
      for (const run of runs)
        this.pins.set(run.runId, (this.pins.get(run.runId) ?? 0) + 1);
      return pinnedWriterSnapshot(
        this.options.home.files,
        Object.freeze(runs),
        logs,
        () => {
          void this.lifecycle(async () => {
            for (const run of runs) {
              const count = this.pins.get(run.runId)! - 1;
              if (count === 0) this.pins.delete(run.runId);
              else this.pins.set(run.runId, count);
            }
            for (const run of runs) {
              try {
                const host = await this.readEntry(run.runId);
                if (host?.phase === "done") await this.reclaimLocked(host);
              } catch (error) {
                // Unreadable metadata fails the read of that run, not the writer.
                this.removalRetry.add(run.runId);
                this.reportCleanup(run.runId, error);
              }
            }
            await this.retryRemovals();
          });
        },
        plans,
      );
    });
  }

  private inconsistentReceipt(host: HostEntry): boolean {
    return Object.values(host.streams).some(
      (stream) =>
        stream.receipt &&
        (host.generation == null ||
          stream.receipt.generation !== host.generation),
    );
  }

  /** The caller has committed these bytes to its durable read store. */
  async acknowledgeOverlay(offered: StreamSyncImportedCoverage): Promise<void> {
    // Reject a malformed digest before it can be stored or reclaim anything.
    const coverage = {
      ...offered,
      dataHash: canonicalBytes32(offered.dataHash),
    };
    await this.recover();
    const binding = await this.binding();
    await this.lifecycle(async () => {
      await this.retryRemovals();
      const key = coverageKey(
        binding,
        coverage.connector,
        coverage.ns,
        coverage.stream,
        coverage.generation,
      );
      const known = this.coverage.get(key);
      if (!known || coverage.registryVersion >= known.registryVersion)
        this.coverage.set(key, Object.freeze({ ...coverage }));
      for (const runId of await this.runIds()) {
        const host = await this.readEntry(runId);
        if (
          !host ||
          host.entry.connector !== coverage.connector ||
          host.entry.ns === null ||
          host.entry.ns !== coverage.ns ||
          host.generation == null ||
          host.generation !== coverage.generation ||
          this.inconsistentReceipt(host) ||
          !host.binding ||
          host.binding.owner.toLowerCase() !== binding.owner.toLowerCase() ||
          host.binding.keyCheck !== binding.keyCheck
        )
          continue;
        await this.reclaimLocked(host);
      }
    });
  }

  // --------------------------------------------------------------- merge

  private async loadHead(
    scope: string,
    dataHash: string,
    expected: {
      connector: string;
      ns: string;
      stream: string;
      keyCheck: string;
    },
  ): Promise<Head> {
    const name = `h-${dataHash.toLowerCase().replace(/^0x/, "")}`;
    const cipher = await this.options.blobs.get(`${scope}/${name}`);
    if (!cipher)
      throw new PendingStream("base_unreadable", `head ${name} is missing`);
    let clear: Uint8Array;
    try {
      clear = await this.options.keys.decrypt(scope, cipher);
    } catch {
      throw new PendingStream("key_mismatch", `head ${name} does not decrypt`);
    }
    const verified = await verifyHead(this.hashes.keccak256, clear, {
      dataHash,
      ...expected,
    });
    switch (verified.kind) {
      case "ok":
        return verified.head;
      case "key_mismatch":
        throw new PendingStream(
          "key_mismatch",
          `head ${name} has another keyCheck`,
        );
      case "unsupported_format":
        throw new PendingStream(
          "unsupported_format",
          `head ${name} format ${String(verified.format)}`,
        );
      default:
        throw new PendingStream(
          "base_unreadable",
          `head ${name}: ${verified.kind}`,
        );
    }
  }

  /**
   * §2.6: plan buckets with the package planner, reduce each with the
   * package reducer (base lines first, then seed lines, then run lines),
   * encode and upload the parts. Buckets under one shard are reduced in
   * groups that share one pass over the shard file.
   */
  private async buildParts(
    host: HostEntry,
    name: string,
    scope: string,
    target: number,
    base: Head | null,
  ): Promise<{ parts: HeadPart[] }> {
    const stream = host.streams[name]!;
    const runDir = `runs/${host.entry.runId}/spool/s${stream.index}`;
    const seedDir = `runs/${host.entry.runId}/seed/s${stream.index}`;
    const runBytes = await this.readyShards(
      runDir,
      stream.shardBytes ?? emptyShardBytes(),
    );
    const seedBytes = stream.seedShardBytes
      ? await this.readyShards(seedDir, stream.seedShardBytes)
      : emptyShardBytes();
    const shardBytes = runBytes.map((b, i) => b + seedBytes[i]!);
    const baseParts = base?.parts ?? [];

    let plan = planBuckets({
      targetBytes: this.targetBytes,
      baseParts,
      shardBytes,
    });
    if (plan.kind === "needs_counts") {
      const counts: Record<number, number[]> = {};
      for (const shard of plan.shards) {
        counts[shard] = await countShard(this.options.home.files, [
          shardPath(runDir, shard),
          shardPath(seedDir, shard),
        ]);
      }
      plan = planBuckets({
        targetBytes: this.targetBytes,
        baseParts,
        shardBytes,
        prefix16Bytes: counts,
      });
      if (plan.kind !== "plan")
        throw new Error("planner asked for counts twice");
    }

    const groups: string[][] = [];
    let group: string[] = [];
    let groupShard = -1;
    let groupBytes = 0;
    for (const bucket of plan.buckets) {
      const deep = bucket.prefix.length > 8;
      const shard = deep ? parseInt(bucket.prefix.slice(0, 8), 2) : -1;
      if (
        group.length > 0 &&
        (!deep ||
          shard !== groupShard ||
          groupBytes + bucket.estimate > this.reduceBudget)
      ) {
        groups.push(group);
        group = [];
        groupBytes = 0;
      }
      group.push(bucket.prefix);
      groupShard = shard;
      groupBytes += bucket.estimate;
      if (!deep) {
        groups.push(group);
        group = [];
        groupBytes = 0;
      }
    }
    if (group.length > 0) groups.push(group);

    const baseByHash = new Set(baseParts.map((p) => `${p.prefix}:${p.hash}`));
    const parts: HeadPart[] = [];
    while (groups.length > 0) {
      const prefixes = groups.shift()!;
      const results = await this.reduceGroup(
        prefixes,
        stream.primaryKey,
        scope,
        target,
        baseParts,
        [runDir, seedDir],
      );
      for (const result of results) {
        if (result.kind === "split") {
          groups.unshift([`${result.prefix}0`, `${result.prefix}1`]);
          continue;
        }
        if (result.kind === "bucket_too_large") {
          throw new PendingStream(
            "bucket_too_large",
            `bucket ${result.prefix} holds ${result.bytes} bytes of winners`,
          );
        }
        const encoded = await encodePart(this.hashes.sha256, result);
        if (!encoded) continue;
        if (!baseByHash.has(`${encoded.entry.prefix}:${encoded.entry.hash}`)) {
          const cipher = await this.options.keys.encrypt(scope, encoded.data);
          await this.options.blobs.put(
            `${scope}/${partBlobName(target, encoded.entry.hash)}`,
            cipher,
          );
        }
        parts.push(encoded.entry);
      }
    }
    this.fault("after_parts_upload", host.entry.runId, name);
    parts.sort((a, b) =>
      a.prefix < b.prefix ? -1 : a.prefix > b.prefix ? 1 : 0,
    );
    return { parts };
  }

  private async reduceGroup(
    prefixes: readonly string[],
    primaryKey: readonly string[],
    scope: string,
    target: number,
    baseParts: readonly HeadPart[],
    dirs: readonly string[],
  ): Promise<BucketResult[]> {
    const reducers = new Map(prefixes.map((p) => [p, new BucketReducer(p)]));
    const single = prefixes.length === 1 ? reducers.get(prefixes[0]!)! : null;
    const route = (hash: string): BucketReducer | null => {
      if (single) return inPrefix(hash, single.prefix) ? single : null;
      const bits = pkHashBits(hash, 16);
      for (const p of prefixes) {
        if (bits.startsWith(p)) return reducers.get(p)!;
      }
      return null;
    };

    const parts = new Map<string, HeadPart>();
    for (const p of prefixes) {
      for (const part of basePartsFor(p, baseParts)) parts.set(part.hash, part);
    }
    for (const part of parts.values()) {
      const key = `${scope}/${partBlobName(target, part.hash)}`;
      const cipher = await this.options.blobs.get(key);
      if (!cipher)
        throw new PendingStream("base_unreadable", `part ${key} is missing`);
      const clear = await this.options.keys.decrypt(scope, cipher);
      const lines = await decodePart(
        this.hashes.sha256,
        clear,
        part,
        primaryKey,
      );
      for (const { line, text } of lines) {
        const hash = await pkHash(this.hashes.sha256, line.v, primaryKey);
        route(hash)?.add(hash, line, text);
      }
    }

    const shards = new Set<number>();
    for (const p of prefixes) {
      if (p.length >= 8) shards.add(parseInt(p.slice(0, 8), 2));
      else {
        const span = 1 << (8 - p.length);
        const from = p === "" ? 0 : parseInt(p, 2) * span;
        for (let s = from; s < from + span; s += 1) shards.add(s);
      }
    }
    // Seed lines before run lines: on equal stamps the later line wins.
    for (const dir of [...dirs].reverse()) {
      for (const shard of [...shards].sort((a, b) => a - b)) {
        for await (const line of readSpool(
          this.options.home.files,
          shardPath(dir, shard),
        )) {
          route(line.pkHash)?.add(line.pkHash, lineStamp(line.text), line.text);
        }
      }
    }
    return prefixes.map((p) => reducers.get(p)!.finish());
  }

  // -------------------------------------------------------------- status

  private statusOf(host: HostEntry): StreamSyncRunStatus {
    const streams: Record<string, StreamSyncStreamStatus> = {};
    for (const [name, outbox] of Object.entries(host.entry.streams)) {
      const info = host.streams[name];
      streams[name] = {
        state: outbox.state,
        ...(outbox.generation !== undefined
          ? { generation: outbox.generation }
          : {}),
        ...(outbox.complete !== undefined ? { complete: outbox.complete } : {}),
        problem: info?.problem ?? null,
        detail: info?.detail ?? null,
        recordTooLarge: info?.recordTooLarge ?? 0,
      };
    }
    return {
      runId: host.entry.runId,
      connector: host.entry.connector,
      ns: host.entry.ns,
      phase: host.phase,
      target: host.target,
      outcome: host.outcome,
      streams,
    };
  }

  /** Every run still in the outbox, and the results of finished runs. */
  async status(): Promise<{
    pending: StreamSyncRunStatus[];
    finished: StreamSyncRunStatus[];
    needsFull: NeedsFull;
    checkpoints: Record<string, StreamSyncCheckpoint>;
    receipts: Record<string, SeedReceipt>;
  }> {
    const pending: StreamSyncRunStatus[] = [];
    for (const runId of await this.runIds()) {
      const host = await this.readEntry(runId);
      if (host && host.phase !== "done") pending.push(this.statusOf(host));
    }
    const finished: StreamSyncRunStatus[] = [];
    for (const path of await this.options.home.files.list("results")) {
      const bytes = await this.options.home.files.read(path);
      if (bytes)
        finished.push(JSON.parse(decoder.decode(bytes)) as StreamSyncRunStatus);
    }
    const state = await this.readState();
    return {
      pending,
      finished,
      needsFull: state.needsFull,
      checkpoints: state.checkpoints,
      receipts: state.receipts,
    };
  }
}

function mergeCursors(
  prev: JsonValue | null,
  candidate: JsonValue | null,
): JsonValue | null {
  if (candidate === null) return prev;
  if (isPlainObject(prev) && isPlainObject(candidate)) {
    return { ...(prev as JsonObject), ...(candidate as JsonObject) };
  }
  return candidate;
}

function nextIndex(host: HostEntry): number {
  return Object.values(host.streams).reduce(
    (n, v) => Math.max(n, v.index + 1),
    0,
  );
}

function parseHeadKey(request: SignedRegistryPost): string {
  return `${request.scope}/h-${request.dataHash.slice(2).toLowerCase()}`;
}

/** Control rows are ordered by registry version; an absent row ranks 0. */
function controlRank(state: ControlState): number {
  switch (state.kind) {
    case "absent":
      return 0;
    case "active":
      return state.generation;
    case "deleted":
    case "foreign":
      return state.version;
  }
}

/**
 * Apply one control read to the state and return the newest control state
 * known. Ordering rule: within a (connector, namespace) a read ranks by row
 * version and the watermark only moves forward; another namespace never
 * changes it. A read older than the watermark is a
 * late response: it changes nothing and the stored newer state is returned,
 * so it can neither clear a checkpoint, overwrite a newer observation nor
 * authorize a decision. A newer read is an invalidation: it advances the
 * count whether or not a checkpoint is stored.
 * A read that shows a stored checkpoint's generation is gone (a higher row,
 * or the same row no longer active) also clears that checkpoint (§2.4).
 */
function recordControl(
  state: WriterState,
  connector: string,
  ns: string,
  current: ControlState,
): ControlState {
  const marks = ((state.observedControl ??= {})[connector] ??= {});
  const rank = controlRank(current);
  const prev = marks[ns];
  if (prev !== undefined && rank < controlRank(prev)) return prev;
  const moved = prev !== undefined && rank > controlRank(prev);
  marks[ns] = current;
  const checkpoint = state.checkpoints[connector];
  // A read ranked below the checkpoint's generation is a lagging response.
  const stale =
    checkpoint !== undefined &&
    checkpoint.ns === ns &&
    (rank > checkpoint.generation ||
      (rank === checkpoint.generation && current.kind !== "active"));
  if (stale || moved) invalidateCheckpoint(state, connector, stale);
  return current;
}

/**
 * The one place a checkpoint is invalidated: advance the connector's
 * invalidation count in the same state mutation as the clear, so a save that
 * read control earlier cannot restore what was cleared. The count advances
 * even when `clear` is false or the slot is already empty.
 */
function invalidateCheckpoint(
  state: WriterState,
  connector: string,
  clear: boolean,
): void {
  if (clear) delete state.checkpoints[connector];
  const epochs = (state.invalidations ??= {});
  epochs[connector] = (epochs[connector] ?? 0) + 1;
}

function describe(state: ControlState): string {
  switch (state.kind) {
    case "absent":
      return "absent";
    case "active":
      return `active(${state.generation})`;
    case "deleted":
      return `deleted(${state.version})`;
    case "foreign":
      return `foreign(${state.version})`;
  }
}

/** A persisted watermark is verified provenance; an arbitrary checkpoint is not. */
function verifiedGeneration(
  state: WriterState,
  connector: string,
): number | null {
  const control = state.observedControl?.[connector]?.[IDENTITYLESS_NS];
  return control?.kind === "active" ? control.generation : null;
}

export { createWriterOverlaySource } from "./writer-overlay.js";
