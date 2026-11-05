import { assemble } from "./assemble.js";
import { HostContractError, PartIntegrityError } from "./errors.js";
import { sha256Hex, type Sha256 } from "./hash.js";
import {
  buildHead,
  decodeHead,
  encodeHead,
  type Head,
  type Version,
} from "./head.js";
import type { StreamRef } from "./naming.js";
import { overlay } from "./overlay.js";
import { DEFAULT_PART_SIZE_BYTES, split, type SplitWarning } from "./parts.js";
import { stampRun, type Run, type StampedRecord } from "./records.js";

/**
 * The publish decision. Nothing here performs I/O: `planPublish` and
 * `onConflict` are pure, and `publishStream` drives them through ports that
 * the host implements.
 *
 * State table (the driver follows it row by row):
 *
 *   idle            run completed                  -> planning        base = latest synced copy, version V
 *   planning        plan ok                        -> uploading-parts parts are content-addressed, immutable
 *   uploading-parts all parts stored               -> writing-head    the head object is stored only after every part
 *   uploading-parts crash                          -> idle            orphan parts are harmless, nothing registered
 *   writing-head    head object stored             -> registering     the head is named by its own hash
 *   registering     registry accepts V -> V+1      -> done            only now is the run registered
 *   registering     registry rejects (moved)       -> refetch
 *   refetch         new latest copy W              -> planning        overlay the SAME run's records onto W
 *   any             connection tombstoned          -> stopped         no upload until a live head is registered
 *
 * HOST RULES
 *
 * 1. Order. Store every part of a plan, then the head object, then register
 *    the head. A head that reaches readers before one of its parts would break
 *    the guarantee that a head always names stored parts.
 * 2. Heads are content-addressed. The head object is stored under a name
 *    derived from the hash of its bytes, exactly like a part, and the registry
 *    compare-and-set registers that hash. A head is never written under a fixed
 *    name that a later write could replace.
 * 3. A completed run stays PENDING until its head is registered.
 *    `publishStream` reports `registered` only after the compare-and-set
 *    succeeds. Until then the host must keep the run's records (and its
 *    observation time) durably, and must not advance the connector cursor. The
 *    outcome's `runDisposition` says what to do: `complete` (drop the run,
 *    advance the cursor), `keep-pending` (keep both; try again later), or
 *    `discard` (the connection was deleted: drop the run and clear the
 *    cursor). A thrown error also means "not registered": keep the run.
 * 4. No retry limit drops a run. When attempts run out the outcome is
 *    `pending` and the run stays pending. Use `backoffDelayMs` to space the
 *    later attempts.
 */

export interface PublishContext extends StreamRef {
  /** The stream declaration's ordered primary-key fields. */
  readonly primaryKey: readonly string[];
  /** The declaration's source ordering field, when it has one. */
  readonly orderField?: string;
  readonly sha256: Sha256;
  /** Part size limit in bytes; defaults to 4 MiB. */
  readonly partSizeBytes?: number;
}

export interface LatestCopy {
  /** Registry version of the copy; `null` when the stream has no head yet. */
  readonly version: Version | null;
  readonly records: readonly StampedRecord[];
}

export interface PublishInput extends PublishContext {
  /** The latest synced copy, `[]` when there is none. */
  readonly latestCopy: readonly StampedRecord[];
  /** The version `latestCopy` was read at. The registration expects exactly this. */
  readonly baseVersion: Version | null;
  readonly run: Run;
}

export interface PlannedPart {
  readonly hash: string;
  readonly bytes: Uint8Array;
}

export interface PublishPlan {
  /** Store every one of these first. */
  readonly parts: readonly PlannedPart[];
  /** Then store this head object under `headHash`... */
  readonly head: Head;
  readonly headBytes: Uint8Array;
  readonly headHash: string;
  /** ...then register `headHash` if the registry still holds this version. */
  readonly expectedBase: Version | null;
  readonly warnings: readonly SplitWarning[];
}

/** Overlay the run onto the latest copy and lay out parts and head. Pure. */
export async function planPublish(input: PublishInput): Promise<PublishPlan> {
  const merged = overlay(
    input.latestCopy,
    stampRun(input.run),
    input.primaryKey,
    {
      orderField: input.orderField,
    },
  );
  const { parts, warnings } = await split(
    merged,
    input.sha256,
    input.partSizeBytes ?? DEFAULT_PART_SIZE_BYTES,
  );
  const head = buildHead({
    stream: input.stream,
    connectionId: input.connectionId,
    parts,
    recordCount: merged.length,
    baseVersion: input.baseVersion,
  });
  const headBytes = encodeHead(head);
  return {
    parts: parts.map(({ hash, bytes }) => ({ hash, bytes })),
    head,
    headBytes,
    headHash: await sha256Hex(input.sha256, headBytes),
    expectedBase: input.baseVersion,
    warnings,
  };
}

/**
 * The registry rejected the registration because the version moved. Plan again
 * from the NEW latest copy with the SAME run. The device's own stale copy is
 * never an input, so another device's rows cannot be lost, and because the
 * overlay keeps the newer record per key, this run cannot put an older value
 * over a newer one.
 */
export function onConflict(
  newLatest: LatestCopy,
  sameRun: Run,
  context: PublishContext,
): Promise<PublishPlan> {
  return planPublish({
    ...context,
    latestCopy: newLatest.records,
    baseVersion: newLatest.version,
    run: sameRun,
  });
}

/**
 * Reconnect plan: an empty live head over the tombstone, with the tombstone's
 * version as its base. Registering it makes the reconnect a registry fact that
 * every device sees.
 */
export async function planReconnect(
  context: Pick<PublishContext, "connectionId" | "stream" | "sha256">,
  tombstoneVersion: Version,
): Promise<PublishPlan> {
  const head = buildHead({
    stream: context.stream,
    connectionId: context.connectionId,
    parts: [],
    recordCount: 0,
    baseVersion: tombstoneVersion,
  });
  const headBytes = encodeHead(head);
  return {
    parts: [],
    head,
    headBytes,
    headHash: await sha256Hex(context.sha256, headBytes),
    expectedBase: tombstoneVersion,
    warnings: [],
  };
}

/**
 * Delay before attempt number `failures + 1`, doubling from `baseMs` up to
 * `maxMs`. Pure and jitter-free: the host adds randomness if it wants any.
 */
export function backoffDelayMs(
  failures: number,
  options: { baseMs?: number; maxMs?: number } = {},
): number {
  const { baseMs = 1_000, maxMs = 300_000 } = options;
  if (!Number.isFinite(failures) || failures <= 0) return 0;
  return Math.min(maxMs, baseMs * 2 ** Math.min(failures - 1, 30));
}

// ---------------------------------------------------------------------------
// Driver and ports

/** What the registry holds for one stream right now. */
export type LatestHeadResult =
  | { readonly kind: "none" }
  | {
      readonly kind: "head";
      readonly version: Version;
      readonly headHash: string;
    }
  | { readonly kind: "tombstone"; readonly version: Version };

export type CommitIntent = "publish" | "reconnect";

export interface CommitRequest {
  /** Hash of the head object, already stored under its own name. */
  readonly headHash: string;
  readonly expectedBase: Version | null;
  /**
   * `publish` is refused over a tombstone. Only `reconnect` may register a
   * live head over one, and only from the tombstone's own version.
   */
  readonly intent: CommitIntent;
}

export type CommitResult =
  | { readonly kind: "committed"; readonly version: Version }
  /** The registry no longer holds `expectedBase`. */
  | { readonly kind: "version-moved" }
  /** A publish found the connection or stream tombstoned. */
  | { readonly kind: "tombstoned" }
  /** A reconnect found no tombstone to register over. */
  | { readonly kind: "not-tombstoned" }
  /** A reconnect arrived before the delete's blob cleanup was final. */
  | { readonly kind: "cleanup-pending" };

/** What a host supplies. All I/O of a publish goes through these. */
export interface PublishPorts {
  /** The host's local knowledge: has this connection been tombstoned? */
  isTombstoned(connectionId: string): Promise<boolean>;
  readLatest(ref: StreamRef): Promise<LatestHeadResult>;
  /** Bytes of a stored head object, or `null`/throw when it is not stored. */
  fetchHead(
    ref: StreamRef,
    headHash: string,
  ): Promise<Uint8Array | null | undefined>;
  /** Bytes of a stored part, or `null`/throw when it is not stored. */
  fetchPart(
    ref: StreamRef,
    hash: string,
  ): Promise<Uint8Array | null | undefined>;
  /** Store a part under its content hash. Idempotent. */
  putPart(ref: StreamRef, hash: string, bytes: Uint8Array): Promise<void>;
  /** Store a head object under the hash of its bytes. Idempotent. */
  putHead(ref: StreamRef, headHash: string, bytes: Uint8Array): Promise<void>;
  /**
   * Register a head with a compare-and-set on the version. Called only after
   * the head and all its parts are stored.
   */
  commitHead(ref: StreamRef, request: CommitRequest): Promise<CommitResult>;
}

export type LatestState =
  | { readonly kind: "none"; readonly copy: LatestCopy }
  | { readonly kind: "live"; readonly copy: LatestCopy }
  | { readonly kind: "tombstone"; readonly version: Version };

/**
 * Read the registry's current state of a stream, fail closed. The head object
 * must hash to the registry's hash, and every part must verify; any mismatch
 * throws `PartIntegrityError` and no partial copy is returned.
 */
export async function readLatestState(
  ports: Pick<PublishPorts, "readLatest" | "fetchHead" | "fetchPart">,
  ref: StreamRef,
  sha256: Sha256,
): Promise<LatestState> {
  const latest = await ports.readLatest(ref);
  if (latest.kind === "none")
    return { kind: "none", copy: { version: null, records: [] } };
  if (latest.kind === "tombstone") return latest;
  let headBytes: Uint8Array | null | undefined;
  try {
    headBytes = await ports.fetchHead(ref, latest.headHash);
  } catch (cause) {
    throw new PartIntegrityError(
      "missing",
      `head ${latest.headHash} could not be fetched`,
      latest.headHash,
      { cause },
    );
  }
  if (headBytes === null || headBytes === undefined) {
    throw new PartIntegrityError(
      "missing",
      `head ${latest.headHash} is not available`,
      latest.headHash,
    );
  }
  const actual = await sha256Hex(sha256, headBytes);
  if (actual !== latest.headHash) {
    throw new PartIntegrityError(
      "hash",
      `head ${latest.headHash} hashes to ${actual}`,
      latest.headHash,
    );
  }
  const records = await assemble(
    decodeHead(headBytes),
    (hash) => ports.fetchPart(ref, hash),
    sha256,
    ref,
  );
  return { kind: "live", copy: { version: latest.version, records } };
}

export interface PublishStreamArgs extends PublishContext {
  readonly run: Run;
  /**
   * The device's latest synced copy. It may be stale; a stale base costs one
   * rejected registration and a rebase. When omitted the driver reads the
   * latest copy first.
   */
  readonly localBase?: LatestCopy;
  /** Plans tried in this call before reporting `pending`; default 5. */
  readonly maxAttempts?: number;
}

export type PublishOutcome =
  /** The head is registered. The run is done: drop it and advance the cursor. */
  | {
      readonly status: "registered";
      readonly runDisposition: "complete";
      readonly version: Version;
      readonly attempts: number;
      readonly plan: PublishPlan;
    }
  /** Not registered. The run stays pending; try again later. */
  | {
      readonly status: "pending";
      readonly runDisposition: "keep-pending";
      readonly reason: "conflict-retries-exhausted";
      readonly attempts: number;
    }
  /** The connection is tombstoned. Drop the run, clear the cursor, stop. */
  | {
      readonly status: "stopped";
      readonly runDisposition: "discard";
      readonly reason: "tombstoned";
      readonly attempts: number;
    };

export const DEFAULT_MAX_ATTEMPTS = 5;

export async function publishStream(
  ports: PublishPorts,
  args: PublishStreamArgs,
): Promise<PublishOutcome> {
  const ref: StreamRef = {
    connectionId: args.connectionId,
    stream: args.stream,
  };
  const maxAttempts = args.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  const stopped = (attempts: number): PublishOutcome => ({
    status: "stopped",
    runDisposition: "discard",
    reason: "tombstoned",
    attempts,
  });

  let base: LatestCopy | "tombstoned";
  if (args.localBase !== undefined) {
    base = args.localBase;
  } else {
    const state = await readLatestState(ports, ref, args.sha256);
    base = state.kind === "tombstone" ? "tombstoned" : state.copy;
  }

  let attempts = 0;
  let first = true;
  while (base !== "tombstoned" && attempts < maxAttempts) {
    attempts += 1;
    if (await ports.isTombstoned(ref.connectionId)) return stopped(attempts);
    const plan = first
      ? await planPublish({
          ...args,
          latestCopy: base.records,
          baseVersion: base.version,
        })
      : await onConflict(base, args.run, args);
    first = false;

    for (const part of plan.parts)
      await ports.putPart(ref, part.hash, part.bytes);
    await ports.putHead(ref, plan.headHash, plan.headBytes);
    const result = await ports.commitHead(ref, {
      headHash: plan.headHash,
      expectedBase: plan.expectedBase,
      intent: "publish",
    });
    switch (result.kind) {
      case "committed":
        return {
          status: "registered",
          runDisposition: "complete",
          version: result.version,
          attempts,
          plan,
        };
      case "tombstoned":
        return stopped(attempts);
      case "version-moved": {
        if (attempts >= maxAttempts) break;
        const state = await readLatestState(ports, ref, args.sha256);
        base = state.kind === "tombstone" ? "tombstoned" : state.copy;
        break;
      }
      default:
        throw new HostContractError(
          `registry answered ${result.kind} to a publish`,
        );
    }
  }
  if (base === "tombstoned") return stopped(attempts);
  return {
    status: "pending",
    runDisposition: "keep-pending",
    reason: "conflict-retries-exhausted",
    attempts,
  };
}

export type ReconnectOutcome =
  | { readonly status: "reconnected"; readonly version: Version }
  /** The stream has a live head or no head: nothing to register over. */
  | { readonly status: "not-tombstoned"; readonly latest: "none" | "live" }
  /** The delete's blob cleanup is not final yet; retry after it is. */
  | { readonly status: "blocked"; readonly reason: "cleanup-pending" }
  /** Another device registered first; read again and decide. */
  | { readonly status: "version-moved" };

/**
 * Reconnect after a delete: register an empty live head over the tombstone
 * with a compare-and-set on the tombstone's version. Every device that sees
 * that live head resumes (see `ReferenceDevice.syncDownload`).
 *
 * The host must not allow this until the delete's blob cleanup is final.
 * Parts are named by content, and a reconnect re-collects the same account, so
 * the same rows give the same part names; a cleanup that ran after the
 * reconnect would delete parts the new head lists. The registry answers
 * `cleanup-pending` until cleanup is final. This is the chosen fix (the
 * alternative, a per-connection salt in the part hash input, would change the
 * part format and break "the hash of the exact bytes").
 */
export async function reconnectStream(
  ports: PublishPorts,
  context: Pick<PublishContext, "connectionId" | "stream" | "sha256">,
): Promise<ReconnectOutcome> {
  const ref: StreamRef = {
    connectionId: context.connectionId,
    stream: context.stream,
  };
  const latest = await ports.readLatest(ref);
  if (latest.kind !== "tombstone") {
    return {
      status: "not-tombstoned",
      latest: latest.kind === "none" ? "none" : "live",
    };
  }
  const plan = await planReconnect(context, latest.version);
  await ports.putHead(ref, plan.headHash, plan.headBytes);
  const result = await ports.commitHead(ref, {
    headHash: plan.headHash,
    expectedBase: plan.expectedBase,
    intent: "reconnect",
  });
  switch (result.kind) {
    case "committed":
      return { status: "reconnected", version: result.version };
    case "cleanup-pending":
      return { status: "blocked", reason: "cleanup-pending" };
    case "version-moved":
      return { status: "version-moved" };
    case "not-tombstoned":
      return { status: "not-tombstoned", latest: "live" };
    default:
      throw new HostContractError(
        `registry answered ${result.kind} to a reconnect`,
      );
  }
}
