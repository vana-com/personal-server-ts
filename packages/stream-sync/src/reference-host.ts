import { filesOfConnection } from "./connection-files.js";
import { HostContractError } from "./errors.js";
import { sha256Hex, type Sha256 } from "./hash.js";
import { decodeHead, type Version } from "./head.js";
import {
  placeholderNaming,
  type StorageNaming,
  type StreamRef,
} from "./naming.js";
import {
  publishStream,
  readLatestState,
  type CommitRequest,
  type CommitResult,
  type LatestCopy,
  type LatestHeadResult,
  type PublishContext,
  type PublishOutcome,
  type PublishPorts,
} from "./publish.js";
import type { Run, StampedRecord } from "./records.js";

/**
 * A reference in-memory host: a content-addressed object store plus a registry
 * with an integer version per stream, shared by any number of simulated
 * devices. It pins the contract hosts must meet and runs the race tests.
 *
 * - `putPart` and `putHead` refuse bytes whose SHA-256 is not the claimed hash,
 *   and objects are immutable: the same name always holds the same bytes.
 * - The registry accepts a head only when the expected base is the current
 *   version (`null` means "no head yet"). A new head's version is the previous
 *   one plus one. A head is never registered before the head object and every
 *   part it lists are stored (`HostContractError`).
 * - A delete writes a tombstone version into each stream's chain and queues
 *   blob cleanup. A `publish` is refused over a tombstone. Only a `reconnect`
 *   may register a live (empty) head over it, from the tombstone's version,
 *   and only after cleanup is final (`cleanup-pending` otherwise).
 * - Objects are never garbage collected except by connection cleanup, so a
 *   reader holding an older head can always finish reading it.
 */

export interface HostHooks {
  beforePutPart?(hash: string): Promise<void> | void;
  afterPutPart?(hash: string): Promise<void> | void;
  /** Runs after head and parts are stored, before the registry sees the head. */
  beforeCommit?(request: CommitRequest): Promise<void> | void;
  afterCommit?(result: CommitResult): Promise<void> | void;
}

export type HostEvent =
  | { readonly op: "put-part"; readonly device: string; readonly hash: string }
  | { readonly op: "put-head"; readonly device: string; readonly hash: string }
  | {
      readonly op: "commit-head";
      readonly device: string;
      readonly intent: CommitRequest["intent"];
      readonly result: CommitResult["kind"];
    };

interface RegistryEntry {
  version: number;
  state: "live" | "tombstone";
  headHash: string | null;
}

export class ReferenceStore {
  readonly events: HostEvent[] = [];
  private readonly objects = new Map<string, Uint8Array>();
  private readonly registry = new Map<string, RegistryEntry>();
  private readonly deleted = new Set<string>();
  private readonly cleanupQueue = new Map<string, string[]>();

  constructor(
    readonly sha256: Sha256,
    private readonly naming: StorageNaming = placeholderNaming,
  ) {}

  /** Every object and registry name currently held. */
  names(): string[] {
    return [...this.registry.keys(), ...this.objects.keys()].sort();
  }

  /**
   * Delete a connection: tombstone every stream it has, and queue blob
   * cleanup for the heads and parts that exist now. Returns the queued names.
   * Cleanup runs later (`runCleanup`), as it does in a real deployment.
   */
  deleteConnection(connectionId: string): string[] {
    this.deleted.add(connectionId);
    const owned = filesOfConnection(this.names(), connectionId, this.naming);
    for (const name of owned) {
      const parsed = this.naming.parse(name);
      if (parsed?.kind === "stream") {
        const entry = this.registry.get(name)!;
        this.registry.set(name, {
          version: entry.version + 1,
          state: "tombstone",
          headHash: null,
        });
      }
    }
    const blobs = owned.filter((name) => this.objects.has(name));
    this.cleanupQueue.set(connectionId, blobs);
    return blobs;
  }

  /** Run the queued blob cleanup; afterwards a reconnect is allowed. */
  runCleanup(connectionId: string): string[] {
    const queued = this.cleanupQueue.get(connectionId) ?? [];
    for (const name of queued) this.objects.delete(name);
    this.cleanupQueue.delete(connectionId);
    return queued;
  }

  cleanupFinal(connectionId: string): boolean {
    return !this.cleanupQueue.has(connectionId);
  }

  currentVersion(ref: StreamRef): Version | null {
    const entry = this.registry.get(this.naming.streamName(ref));
    return entry === undefined ? null : String(entry.version);
  }

  /** What a reader sees now: one registry snapshot. */
  snapshot(ref: StreamRef): LatestHeadResult {
    const entry = this.registry.get(this.naming.streamName(ref));
    if (entry === undefined) return { kind: "none" };
    if (entry.state === "tombstone")
      return { kind: "tombstone", version: String(entry.version) };
    return {
      kind: "head",
      version: String(entry.version),
      headHash: entry.headHash!,
    };
  }

  readPart(ref: StreamRef, hash: string): Uint8Array | undefined {
    return this.objects.get(this.naming.partName(ref, hash));
  }

  readHead(ref: StreamRef, hash: string): Uint8Array | undefined {
    return this.objects.get(this.naming.headName(ref, hash));
  }

  /** A full reader: registry, then the head object, then each listed part, verified. */
  async readStream(ref: StreamRef): Promise<LatestCopy | null> {
    const state = await readLatestState(
      this.portsFor("reader"),
      ref,
      this.sha256,
    );
    return state.kind === "live" ? state.copy : null;
  }

  /** The ports one simulated device uses. */
  portsFor(device: string, hooks: HostHooks = {}): PublishPorts {
    return {
      isTombstoned: async (connectionId) => this.deleted.has(connectionId),
      readLatest: async (ref) => this.snapshot(ref),
      fetchHead: async (ref, hash) => this.readHead(ref, hash),
      fetchPart: async (ref, hash) => this.readPart(ref, hash),
      putPart: async (ref, hash, bytes) => {
        await hooks.beforePutPart?.(hash);
        await this.store(this.naming.partName(ref, hash), hash, bytes);
        this.events.push({ op: "put-part", device, hash });
        await hooks.afterPutPart?.(hash);
      },
      putHead: async (ref, hash, bytes) => {
        decodeHead(bytes);
        await this.store(this.naming.headName(ref, hash), hash, bytes);
        this.events.push({ op: "put-head", device, hash });
      },
      commitHead: async (ref, request) => {
        await hooks.beforeCommit?.(request);
        const result = await this.commit(ref, request);
        this.events.push({
          op: "commit-head",
          device,
          intent: request.intent,
          result: result.kind,
        });
        await hooks.afterCommit?.(result);
        return result;
      },
    };
  }

  private async store(
    name: string,
    hash: string,
    bytes: Uint8Array,
  ): Promise<void> {
    if ((await sha256Hex(this.sha256, bytes)) !== hash) {
      throw new HostContractError(`bytes do not hash to ${hash}`);
    }
    if (!this.objects.has(name)) this.objects.set(name, bytes.slice());
  }

  private async commit(
    ref: StreamRef,
    request: CommitRequest,
  ): Promise<CommitResult> {
    const key = this.naming.streamName(ref);
    const entry = this.registry.get(key);
    const headBytes = this.readHead(ref, request.headHash);
    if (headBytes === undefined) {
      throw new HostContractError(
        `head ${request.headHash} registered before it was stored`,
      );
    }
    const head = decodeHead(headBytes);
    if (head.connectionId !== ref.connectionId || head.stream !== ref.stream) {
      throw new HostContractError(
        "head does not belong to the stream it is registered for",
      );
    }
    for (const part of head.parts) {
      if (!this.objects.has(this.naming.partName(ref, part.hash))) {
        throw new HostContractError(
          `head registered before its part ${part.hash} was stored`,
        );
      }
    }

    if (request.intent === "publish") {
      if (this.deleted.has(ref.connectionId) || entry?.state === "tombstone") {
        return { kind: "tombstoned" };
      }
      if (this.version(entry) !== request.expectedBase)
        return { kind: "version-moved" };
      return this.register(key, entry, request.headHash);
    }

    if (entry?.state !== "tombstone") return { kind: "not-tombstoned" };
    if (!this.cleanupFinal(ref.connectionId))
      return { kind: "cleanup-pending" };
    if (this.version(entry) !== request.expectedBase)
      return { kind: "version-moved" };
    if (head.parts.length !== 0) {
      throw new HostContractError("a reconnect head must be empty");
    }
    this.deleted.delete(ref.connectionId);
    return this.register(key, entry, request.headHash);
  }

  private version(entry: RegistryEntry | undefined): Version | null {
    return entry === undefined ? null : String(entry.version);
  }

  private register(
    key: string,
    entry: RegistryEntry | undefined,
    headHash: string,
  ): CommitResult {
    const version = (entry?.version ?? 0) + 1;
    this.registry.set(key, { version, state: "live", headHash });
    return { kind: "committed", version: String(version) };
  }
}

// ---------------------------------------------------------------------------
// A simulated device: what a host must keep durable, and when it may advance.

/** The durable state of one device for one stream. It survives a crash. */
export interface DeviceDisk {
  /** The connector cursor. Advanced only when a run's head is registered. */
  cursor: string | null;
  /** A completed run that is not registered yet. */
  pending: { run: Run; cursorAfter: string } | null;
  /** Latest synced copy as last downloaded. */
  localBase: LatestCopy | null;
  /** The device saw a tombstone and waits for a live head. */
  stopped: boolean;
}

export function newDeviceDisk(): DeviceDisk {
  return { cursor: null, pending: null, localBase: null, stopped: false };
}

export class ReferenceDevice {
  constructor(
    readonly name: string,
    private readonly store: ReferenceStore,
    private readonly context: PublishContext,
    readonly disk: DeviceDisk = newDeviceDisk(),
    private readonly hooks: HostHooks = {},
  ) {}

  private get ref(): StreamRef {
    return {
      connectionId: this.context.connectionId,
      stream: this.context.stream,
    };
  }

  /**
   * A collection run completed. Persist it as pending. The cursor does NOT
   * advance here: an incremental connector would never re-emit these rows if
   * the device lost them before they were registered.
   */
  completeRun(run: Run, cursorAfter: string): void {
    if (this.disk.stopped)
      throw new HostContractError("a stopped device must not collect");
    if (this.disk.pending !== null)
      throw new HostContractError("a run is still pending");
    this.disk.pending = { run, cursorAfter };
  }

  /** Try to register the pending run. Applies the outcome's `runDisposition`. */
  async publishPending(maxAttempts?: number): Promise<PublishOutcome | "idle"> {
    const pending = this.disk.pending;
    if (pending === null || this.disk.stopped) return "idle";
    const outcome = await publishStream(
      this.store.portsFor(this.name, this.hooks),
      {
        ...this.context,
        run: pending.run,
        ...(this.disk.localBase ? { localBase: this.disk.localBase } : {}),
        ...(maxAttempts === undefined ? {} : { maxAttempts }),
      },
    );
    switch (outcome.runDisposition) {
      case "complete":
        this.disk.cursor = pending.cursorAfter;
        this.disk.pending = null;
        this.disk.localBase = {
          version: outcome.version,
          records: await this.readBack(outcome.version),
        };
        break;
      case "discard":
        this.honourTombstone();
        break;
      case "keep-pending":
        break;
    }
    return outcome;
  }

  /**
   * Download the registry state. A tombstone stops the device and drops its
   * pending run and cursor. A live head after a stop resumes it, with the
   * cursor cleared so the next run starts from a fresh collection.
   */
  async syncDownload(): Promise<"live" | "tombstoned" | "none"> {
    const state = await readLatestState(
      this.store.portsFor(this.name),
      this.ref,
      this.store.sha256,
    );
    if (state.kind === "tombstone") {
      this.honourTombstone();
      return "tombstoned";
    }
    if (state.kind === "none") return "none";
    if (this.disk.stopped) {
      this.disk.stopped = false;
      this.disk.cursor = null;
    }
    this.disk.localBase = state.copy;
    return "live";
  }

  private honourTombstone(): void {
    this.disk.stopped = true;
    this.disk.pending = null;
    this.disk.cursor = null;
    this.disk.localBase = null;
  }

  private async readBack(version: Version): Promise<readonly StampedRecord[]> {
    const copy = await this.store.readStream(this.ref);
    if (copy === null || copy.version !== version)
      return this.disk.localBase?.records ?? [];
    return copy.records;
  }
}
