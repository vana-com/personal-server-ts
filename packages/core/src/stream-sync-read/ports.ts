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
//
// Binding: one source instance belongs to one immutable owner/network/key
// home. Hosts build the reader and the source from that same home; an owner,
// network or key change builds a new pair. Only that reader calls
// `acknowledge`, and only when its files are durable.

/** Durable proof that the writer published this stream version (writer.ts committed/noop). */
export interface StreamSyncPublishReceipt {
  readonly registryVersion: number;
  /** Lowercase hex, as registered. */
  readonly dataHash: string;
  /** Always equal to the owning run's non-null `generation`; a mismatch is an integrity error. */
  readonly generation: number;
}

export interface StreamSyncOverlayStream {
  readonly name: string;
  readonly primaryKey: readonly string[];
  /** The writer's head profile: projector key and connector version. */
  readonly profile: HeadProfile;
  /** True only when the run's full/fullStream provenance says so (writer.ts:1460-1466). */
  readonly complete: boolean;
  /**
   * Identifies this stream's immutable rows and every descriptor field that
   * affects a read (profile, primaryKey, complete, state, receipt). Never
   * reused for different content, including across restart.
   */
  readonly contentRevision: string;
  /**
   * Per-stream publication state. `published` iff `receipt` is present.
   * Terminally discarded streams are never listed (see snapshot membership).
   */
  readonly state: "pending" | "failed" | "published";
  /** Present once the stream is committed/noop and waits for the reader to import it. */
  readonly receipt?: StreamSyncPublishReceipt;
}

export interface StreamSyncOverlayRun {
  readonly runId: string;
  readonly connector: string;
  /** null = not attributable; never overlaid. Never normalized to "". */
  readonly ns: string | null;
  /**
   * The run's verified read-generation binding, from verified active-control
   * provenance at start/ready or from successful admission. null only when
   * genuinely unbound; never inferred from whichever control is active later.
   */
  readonly generation: number | null;
  /** Diagnostic aggregate only. Visibility and retirement use the per-stream fields. */
  readonly state: "pending" | "failed" | "published";
  readonly error?: string;
  /** Run stamp in epoch milliseconds: the same value as Line.o for its rows. */
  readonly observedAt: number;
  /**
   * Positive membership: only streams that are overlay candidates. The source
   * omits terminally discarded streams, uncovered and seed-only streams, and
   * whole runs that are collecting, aborted, checkpoint-only, owner/key
   * mismatched or inconsistent (receipt/run generation mismatch). Omitting a
   * discarded stream never removes another stream's receipt.
   */
  readonly streams: readonly StreamSyncOverlayStream[];
}

/**
 * One read's pinned, immutable view of the overlay: metadata and bytes are
 * frozen, and logs it names are not removed until release().
 */
export interface StreamSyncOverlaySnapshot {
  readonly runs: readonly StreamSyncOverlayRun[];
  /**
   * Lines of one stream of one run of THIS snapshot, in spool order. Rejects a
   * run or stream not in this snapshot; throws on a missing or corrupt
   * nonempty log.
   */
  lines(run: StreamSyncOverlayRun, stream: string): AsyncIterable<Line>;
  /** Idempotent. */
  release(): void;
}

/** What the reader has durably installed (after its ViewStore commit). */
export interface StreamSyncImportedCoverage {
  readonly connector: string;
  readonly ns: string;
  readonly stream: string;
  readonly generation: number;
  readonly registryVersion: number;
  readonly dataHash: string;
}

export interface StreamSyncOverlaySnapshotSource {
  /**
   * Pinned snapshot of every overlay run of `connector`. Acquire it BEFORE
   * leasing imported views, once per read, shared by all input streams.
   * A cursor replays only the exact members (run, stream, contentRevision,
   * base version) it recorded, or the read answers cursor_stale.
   */
  snapshot(connector: string): Promise<StreamSyncOverlaySnapshot>;
  /**
   * Called after a durable ViewStore commit and for every durable current
   * view at startup. Idempotent. A published stream retires only when
   *   run.connector === c.connector && run.ns !== null && run.ns === c.ns &&
   *   stream.name === c.stream && run.generation !== null &&
   *   run.generation === receipt.generation && c.generation === receipt.generation &&
   *   (c.registryVersion > receipt.registryVersion ||
   *    (c.registryVersion === receipt.registryVersion && c.dataHash === receipt.dataHash))
   * and no snapshot pins it. A different generation never covers a receipt.
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
