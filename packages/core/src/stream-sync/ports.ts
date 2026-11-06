/**
 * Host ports for whole-file stream sync (design revision 4.1, §2.3, §2.8).
 *
 * The pure rules live in `@opendatalabs/personal-server-ts-stream-sync`.
 * This module names the I/O a host provides to the publish driver: the
 * registry, blob storage, durable files for the spool and outbox, and the
 * AddData signer. Every adapter is injected, so the full server (Node files)
 * and PS-Lite (IndexedDB) run the same driver.
 */

import type { ControlRead } from "@opendatalabs/personal-server-ts-stream-sync";

/** The body of an exclusive `POST /v1/data`, persisted byte-for-byte. */
export interface SignedRegistryPost {
  readonly ownerAddress: string;
  readonly scope: string;
  readonly dataHash: `0x${string}`;
  readonly metadataHash: `0x${string}`;
  readonly expectedVersion: string;
  readonly signature: `0x${string}`;
}

export type RegistryPostResult =
  /** 2xx: written, or the identical row was already there (`replayed`). */
  | { readonly kind: "committed" }
  /** 409: another row holds this version or a higher one. */
  | { readonly kind: "conflict"; readonly latestVersion: string | null };

/** Neither committed nor refused: resend the persisted request unchanged. */
export class AmbiguousRegistryReplyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AmbiguousRegistryReplyError";
  }
}

/** The registry refused the request for good (4xx other than 409). */
export class RegistryRefusedError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "RegistryRefusedError";
  }
}

export interface StreamSyncRegistry {
  /** Authoritative read: `GET /v1/data/:id?includeDeleted=true`. */
  read(scope: string): Promise<ControlRead>;
  /** `POST /v1/data` with `exclusive: true`. Throws `AmbiguousRegistryReplyError`. */
  post(request: SignedRegistryPost): Promise<RegistryPostResult>;
  /**
   * Every control scope row of the owner (`pdpp.<c>~<ns>`), deleted or not.
   * Used for the per-session control listing (§2.4 `controls`).
   */
  listControlRows(): Promise<
    readonly { readonly scope: string; readonly read: ControlRead }[]
  >;
}

/** Encrypted blob storage, keyed `<physical scope>/<blob name>`. */
export interface StreamSyncBlobs {
  put(key: string, bytes: Uint8Array): Promise<void>;
  /** `null` when the blob does not exist. */
  get(key: string): Promise<Uint8Array | null>;
}

/**
 * Durable files for the spool, the outbox and local state. Paths are
 * `/`-separated and relative to the adapter's root.
 */
export interface StreamSyncFiles {
  /** Atomically replace a file. Durable when the promise resolves. */
  write(path: string, bytes: Uint8Array): Promise<void>;
  /** The whole file, or `null` when it does not exist. */
  read(path: string): Promise<Uint8Array | null>;
  /** Append to a file, creating it. Durable when the promise resolves. */
  append(path: string, bytes: Uint8Array): Promise<void>;
  /** The file in chunks of bounded size; nothing when it does not exist. */
  readChunks(path: string): AsyncIterable<Uint8Array>;
  /** Size in bytes; 0 when the file does not exist. */
  size(path: string): Promise<number>;
  /** Paths of the files under `prefix/`, recursively. */
  list(prefix: string): Promise<string[]>;
  /** Remove a file or every file under `prefix/`. */
  remove(prefix: string): Promise<void>;
}

/** Owner-key operations. `masterKey` never enters the driver. */
export interface StreamSyncKeyPorts {
  /** HMAC-SHA256 keyed with `K_ns` (§2.1). */
  namespaceHmac(message: Uint8Array): Promise<Uint8Array>;
  /** Per-object encryption with the per-scope key of `scope`. */
  encrypt(scope: string, clear: Uint8Array): Promise<Uint8Array>;
  decrypt(scope: string, cipher: Uint8Array): Promise<Uint8Array>;
}

export interface StreamSyncSigner {
  signAddData(message: {
    ownerAddress: `0x${string}`;
    scope: string;
    dataHash: `0x${string}`;
    metadataHash: `0x${string}`;
    expectedVersion: bigint;
  }): Promise<`0x${string}`>;
}

/**
 * Desktop seed source (§2.9): this install's retained snapshot rows of a
 * connector, from Desktop runs of the same connector on the same install.
 */
export interface StreamSyncSeedSource {
  /** Stable id of this install, used in receipts. */
  readonly installId: string;
  /** Retained streams of the connector with their primary key and profile. */
  streams(connector: string): Promise<
    readonly {
      readonly stream: string;
      readonly primaryKey: readonly string[];
      readonly profile: {
        readonly key: string | null;
        readonly version: string;
      };
    }[]
  >;
  /** The retained records of one stream. */
  records(
    connector: string,
    stream: string,
  ): AsyncIterable<Record<string, unknown>>;
}

/**
 * Named points where a test can stop the driver to model a crash. A fault
 * throws; the driver instance is then abandoned and a new one resumes from
 * the files.
 */
export type StreamSyncFaultPoint =
  | "after_control_write"
  | "after_parts_upload"
  | "after_head_upload"
  | "after_request_persisted"
  | "after_post_reply"
  | "after_commit_recorded"
  | "after_checkpoint_saved";
