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
import type { SendGovernor } from "./storage-retry.js";

/** The network a gateway deployment names: `vana:<chainId>:<origin>`. */
export function streamSyncNetwork(gateway: {
  readonly chainId: number;
  readonly url: string;
}): string {
  return `vana:${gateway.chainId}:${new URL(gateway.url).origin}`;
}

/** Receipt contract retained for PS-3 seed staging, independent of the retired writer. */
export type SeedReceipt = "merged";

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

/**
 * A condition on another row of the owner, checked by the gateway in the same
 * transaction as the write: the row's head version is `expectedVersion` and,
 * with `notDeleted`, it is not a tombstone. The gateway checks it, so a delete
 * cannot land between the client's check and the write.
 */
export interface RegistryRequirement {
  readonly scope: string;
  readonly expectedVersion: string;
  readonly notDeleted: boolean;
  /**
   * The row's head data hash. A version alone does not tell a refresh of the
   * same version from the row the caller saw; the hash does.
   */
  readonly expectedDataHash?: `0x${string}`;
}

/** The first condition that failed. Nothing was written. */
export interface RegistryRequirementFailure {
  readonly scope: string;
  /** Why it failed, when the gateway says. */
  readonly reason?:
    "absent" | "deleted" | "version-mismatch" | "data-hash-mismatch";
  /** Head version the gateway holds for the row; `null` when it has none. */
  readonly latestVersion: string | null;
  readonly deleted: boolean;
}

/** A single write that carries conditions on other rows. */
export interface ConditionalRegistryPost extends SignedRegistryPost {
  readonly requires: readonly RegistryRequirement[];
}

export type ConditionalPostResult =
  | RegistryPostResult
  | {
      readonly kind: "precondition_failed";
      readonly failure: RegistryRequirementFailure;
    };

/** One signed row of a batch; the owner and the conditions are the batch's. */
export type SignedBatchRow = Omit<SignedRegistryPost, "ownerAddress"> & {
  /**
   * The data hash of the row this one replaces, as the snapshot saw it. The
   * gateway refuses the row when the head's hash differs. Absent for a first
   * version.
   */
  readonly expectedHeadDataHash?: `0x${string}`;
};

/**
 * Several writes of one owner in one request, with conditions on other rows.
 * The conditions are the batch's: if one fails nothing is written. Each row
 * then lands or loses on its own, and a row that lost does not affect its
 * siblings. The conditions are judged on every request, a replay included.
 * `rows` may be empty when `requires` is not: nothing is written and the
 * answer says whether every condition holds.
 */
export interface SignedRegistryBatch {
  readonly ownerAddress: string;
  readonly rows: readonly SignedBatchRow[];
  readonly requires: readonly RegistryRequirement[];
}

export type RegistryBatchRow =
  /** 201: written. */
  | { readonly kind: "committed" }
  /**
   * 409: the gateway holds this version or a later one. The winner's version
   * and data hash come with it; a row whose hash is the winner's is already
   * published (a resend).
   */
  | {
      readonly kind: "conflict";
      readonly latestVersion: string | null;
      readonly latestDataHash: string | null;
    };

export type RegistryBatchResult =
  /** The gateway has no batch route (404 or 405). Nothing was written. */
  | { readonly kind: "unsupported" }
  /**
   * A condition failed. Nothing was written, for any row. `failure` is `null`
   * when the gateway did not say which condition or why: the caller reads the
   * row to find out.
   */
  | {
      readonly kind: "precondition_failed";
      readonly failure: RegistryRequirementFailure | null;
    }
  /** 2xx: one result per request row, in request order. */
  | { readonly kind: "rows"; readonly rows: readonly RegistryBatchRow[] };

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
   * `POST /v1/data` with `requires`. A gateway that does not know `requires`
   * ignores it and writes anyway, and the answer does not say so, so a caller
   * may use this only against a gateway known to enforce it.
   */
  postConditional?(
    request: ConditionalRegistryPost,
  ): Promise<ConditionalPostResult>;
  /**
   * `POST /v1/data/batch`: every row and every condition in one request.
   * Absent on a registry without a batch route. `unsupported` when the
   * gateway answers 404 or 405; the adapter remembers that, so later calls
   * send nothing. Throws `AmbiguousRegistryReplyError`: resend the same
   * request; a row that already landed answers as a conflict with its own hash
   * (or as committed).
   */
  postBatch?(request: SignedRegistryBatch): Promise<RegistryBatchResult>;
  /**
   * Every control scope row of the owner (`pdpp.<c>~<ns>`), deleted or not.
   * Used for the per-session control listing (§2.4 `controls`).
   */
  listControlRows(): Promise<
    readonly { readonly scope: string; readonly read: ControlRead }[]
  >;
  /**
   * Every stream scope row of `connector` in any namespace, deleted or not,
   * whichever device or connector version wrote it. A connection delete
   * finds the streams to erase here, not in local state.
   */
  listStreamRows(
    connector: string,
  ): Promise<readonly { readonly scope: string; readonly read: ControlRead }[]>;
  /**
   * The control row of one connection and every stream row in its namespace,
   * deleted or not, in one pass over the owner's rows. A publish takes its
   * snapshot's starting point from it instead of reading each row. The rows
   * are a hint: the commit still re-checks the control row and posts with
   * compare-and-set. A registry that cannot list in one pass leaves this out,
   * and publish reads each row itself.
   */
  listConnectionRows?(
    connector: string,
    ns: string,
  ): Promise<readonly { readonly scope: string; readonly read: ControlRead }[]>;
  /**
   * One request: a marker of the owner's newest registry change, whatever the
   * number of rows (the gateway's change feed, newest first, one row). A
   * different marker means a row was written, tombstoned or revived since the
   * last read. An EQUAL marker does not prove that nothing changed: it
   * fingerprints one row, so a change that leaves that row alone (another row
   * stamped in the same millisecond) is invisible. `null`: the owner has no
   * rows. `undefined`: this gateway sends no change time, so the caller cannot
   * tell. Throws when the read fails. A hint to start a pull early, never an
   * authority: the unconditional timer cycle is what guarantees completeness,
   * and a pull still reads the rows it applies.
   */
  probeChange?(): Promise<string | null | undefined>;
}

/** Encrypted blob storage, keyed `<physical scope>/<blob name>`. */
export interface StreamSyncBlobs {
  /**
   * The store's send governor: the memory budget a transfer reserves from
   * before it encodes a part, and a window that reports what the gate did
   * during one publish. It is required, because nothing else bounds the parts
   * a stream holds in memory while their PUTs are pending. An in-memory test
   * store gets one too (`createMemoryStreamSyncBlobs`).
   */
  readonly governor: Pick<SendGovernor, "reserve" | "window">;
  /**
   * `beforeAttempt` runs immediately before each request that sends the bytes,
   * after every wait for a turn or a retry delay; a throw stops the upload and
   * reaches the caller. A request already sent cannot be recalled.
   */
  put(
    key: string,
    bytes: Uint8Array,
    beforeAttempt?: () => void,
  ): Promise<void>;
  /** `null` when the blob does not exist. */
  get(key: string): Promise<Uint8Array | null>;
  /**
   * Whether the blob exists. The Vana adapter uses HEAD and reads no body; the
   * SDK fallback downloads the blob. Only a definitive
   * "not found" answers `false`; any other failure throws, never reads as
   * present or absent.
   */
  exists(key: string): Promise<boolean>;
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
  /**
   * Append to files, creating them. The bytes are visible to later reads at
   * once but are durable only after `sync` of a prefix that covers the path:
   * spool intake appends many times and syncs once (§2.6).
   */
  appendMany(
    entries: readonly { readonly path: string; readonly bytes: Uint8Array }[],
  ): Promise<void>;
  /**
   * Make every earlier append under `prefix/` durable, and the files'
   * directory entries with them. A host may release resources it holds for
   * those files (open handles).
   */
  sync(prefix: string): Promise<void>;
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
  /** Per-object encryption with the per-scope key of `scope` (heads). */
  encrypt(scope: string, clear: Uint8Array): Promise<Uint8Array>;
  /** Format-2 part encryption: the age STREAM AEAD over 64 KiB chunks. */
  encryptPart(scope: string, clear: Uint8Array): Promise<Uint8Array>;
  /** Opens a head, a format-1 part (OpenPGP) or a format-2 part (STREAM). */
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
      /**
       * Identity of the staged upload this stream comes from. It changes when
       * the host stages a new upload for the stream, so a delete can skip the
       * upload it saw and still merge a later one.
       */
      readonly upload: string;
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
