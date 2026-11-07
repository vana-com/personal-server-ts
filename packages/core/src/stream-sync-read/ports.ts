/**
 * Host ports for the stream-sync read side (design revision 4.1, §2.9 import,
 * §2.10 reads). The pure rules come from
 * `@opendatalabs/personal-server-ts-stream-sync`; this module names the I/O a
 * host provides: durable files for the registry mirror and imported views,
 * encrypted blob reads, the owner key, and the local outbox overlay.
 */

import type {
  HashPorts,
  HeadProfile,
  Line,
} from "@opendatalabs/personal-server-ts-stream-sync";

/**
 * Durable files. Paths are `/`-separated and relative to the adapter's root.
 * The full server uses the filesystem, PS-Lite uses memory or browser storage.
 */
export interface StreamSyncReadFiles {
  /** Atomically replace a file. Durable when the promise resolves. */
  write(path: string, bytes: Uint8Array): Promise<void>;
  /** The whole file, or `null` when it does not exist. */
  read(path: string): Promise<Uint8Array | null>;
  /** The file in chunks of bounded size; nothing when it does not exist. */
  readChunks(path: string): AsyncIterable<Uint8Array>;
  /** Paths of the files under `prefix/`, recursively. */
  list(prefix: string): Promise<string[]>;
  /** Remove a file, or every file under `prefix/`. */
  remove(prefix: string): Promise<void>;
}

/** Encrypted blob storage keyed `<physical scope>/<blob name>`. */
export interface StreamSyncBlobReader {
  /** `null` when the blob does not exist. */
  get(key: string): Promise<Uint8Array | null>;
}

/** Owner-key operations. The master key never enters the read side. */
export interface StreamSyncReadKeys {
  readonly hashes: HashPorts;
  /** §2.1 keyCheck of this owner key. */
  readonly keyCheck: string;
  /** Per-object decryption with the per-scope key of `scope`. */
  decrypt(scope: string, cipher: Uint8Array): Promise<Uint8Array>;
}

/**
 * A local outbox entry that has not committed (§2.9): its rows are a
 * read-time overlay over the imported view of `(connector, ns, stream)`,
 * merged by the package merge rule. An entry never blocks import.
 */
export interface StreamSyncOverlayEntry {
  readonly runId: string;
  /** `null` while the run's identity is unknown: such rows are not attributable to a connection and are not overlaid. */
  readonly ns: string | null;
  readonly state: "pending" | "failed";
  /** Shown for failed entries. */
  readonly error?: string;
  readonly streams: readonly string[];
  /** Lines of one stream, in spool order. */
  lines(stream: string): AsyncIterable<Line>;
}

export interface StreamSyncOverlaySource {
  entries(connector: string): Promise<readonly StreamSyncOverlayEntry[]>;
}

// Own-writes overlay (pinned snapshots, publish receipts, reader acknowledgment).
// Replaces StreamSyncOverlaySource once the read service is switched over.

/** Durable proof that the writer published this stream version (writer.ts committed/noop). */
export interface StreamSyncPublishReceipt {
  readonly registryVersion: number;
  readonly dataHash: string;       // lowercase hex, as registered
  readonly generation: number;
}

export interface StreamSyncOverlayStream {
  readonly name: string;
  readonly primaryKey: readonly string[];
  /** The writer's head profile: projector key and connector version. */
  readonly profile: HeadProfile;
  /** True only when the run's full/fullStream provenance says so (writer.ts:1460-1466). */
  readonly complete: boolean;
  /** Changes whenever the stream's overlay rows could change; used in cursors. */
  readonly contentRevision: string;
  /** Present once the stream is committed/noop and is waiting for the reader to import it. */
  readonly receipt?: StreamSyncPublishReceipt;
}

export interface StreamSyncOverlayRun {
  readonly runId: string;
  readonly connector: string;
  /** null = not attributable; never overlaid. */
  readonly ns: string | null;
  /** Generation the run is bound to; null when it was never admitted to one. */
  readonly generation: number | null;
  readonly state: "pending" | "failed" | "published";
  readonly error?: string;
  /** Run stamp used by compareStamp (not a registry time). */
  readonly observedAt: string;
  readonly streams: readonly StreamSyncOverlayStream[];
}

/** One read's pinned view of the overlay. Logs it names cannot be removed until release(). */
export interface StreamSyncOverlaySnapshot {
  readonly entries: readonly StreamSyncOverlayRun[];
  /** Lines of one stream of one entry, in spool order, from the pinned log. Throws on a missing or corrupt nonempty log. */
  lines(entry: StreamSyncOverlayRun, stream: string): AsyncIterable<Line>;
  /** Idempotent. */
  release(): void;
}

/** What the reader has durably installed (after ViewStore commit). */
export interface StreamSyncImportedCoverage {
  readonly connector: string;
  readonly ns: string;
  readonly stream: string;
  readonly generation: number;
  readonly registryVersion: number;
  readonly dataHash: string;
}

export interface StreamSyncOverlaySnapshotSource {
  /** Pinned snapshot of all overlay entries of `connector`. Acquire BEFORE leasing imported views. */
  snapshot(connector: string): Promise<StreamSyncOverlaySnapshot>;
  /**
   * Called after a durable ViewStore commit, and for every durable current view at startup.
   * Idempotent. The source retires a published stream only when coverage matches its receipt
   * (same version and dataHash, or a later version in the same generation) and no snapshot pins it.
   * A reader whose files are not durable never calls this.
   */
  acknowledge(coverage: StreamSyncImportedCoverage): Promise<void>;
}

/** Minimal logger shape; the server passes pino, PS-Lite its own. */
export interface StreamSyncReadLogger {
  info(obj: Record<string, unknown>, msg?: string): void;
  warn(obj: Record<string, unknown>, msg?: string): void;
  error(obj: Record<string, unknown>, msg?: string): void;
}
