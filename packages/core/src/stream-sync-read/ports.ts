/**
 * Host ports for the stream-sync read side (design revision 4.1, §2.9 import,
 * §2.10 reads). The pure rules come from
 * `@opendatalabs/personal-server-ts-stream-sync`; this module names the I/O a
 * host provides: durable files for the registry mirror and imported views,
 * encrypted blob reads, the owner key, and the local outbox overlay.
 */

import type {
  HashPorts,
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

/** Minimal logger shape; the server passes pino, PS-Lite its own. */
export interface StreamSyncReadLogger {
  info(obj: Record<string, unknown>, msg?: string): void;
  warn(obj: Record<string, unknown>, msg?: string): void;
  error(obj: Record<string, unknown>, msg?: string): void;
}
