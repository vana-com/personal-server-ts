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
  /** First create only. An identical signed replay still succeeds. */
  readonly expectedHeadAbsent?: boolean;
};

/**
 * Several writes of one owner in one request: one all-or-nothing transaction.
 * Every row is stored, or nothing is written. The conditions are judged on the
 * state the request commits, so a condition may name a row the request writes;
 * they are judged on every request, a replay included. `rows` may be empty
 * when `requires` is not: nothing is written and the answer says whether every
 * condition holds.
 */
export interface SignedRegistryBatch {
  readonly ownerAddress: string;
  readonly rows: readonly SignedBatchRow[];
  readonly requires: readonly RegistryRequirement[];
}

/**
 * What the gateway says one batch request may hold (its `Batch-Policy`
 * response header). `rows` and `requires` are item counts, and both can be full
 * in one request; `bytes` is the size of that full request of the largest
 * legal items, so a request within the counts is within `bytes`. The gateway
 * derives them from its backend's limits.
 */
export interface RegistryBatchPolicy {
  readonly rows: number;
  readonly requires: number;
  readonly bytes: number;
  /**
   * Only when the gateway sends it. A batch that writes stream rows of a
   * connection fences that connection's log row, which the batch does not
   * write; the gateway locks one entry per row and one per distinct such log
   * row. A batch with at least one of them holds at most `lockedScopes` rows
   * plus distinct fenced log rows. Without a fence `rows` is the only limit.
   */
  readonly lockedScopes?: number;
}

/** One row of a refused batch (409 `conflict`): nothing of the request was written. */
export type RegistryBatchRow =
  /** 201: the version was already stored (a replay); it stays stored. */
  | { readonly kind: "committed" }
  /**
   * 409: this row lost, so the request was refused. The gateway holds this
   * version or a later one; the winner's version and data hash come with it. A
   * row whose hash is the winner's is already published (a resend).
   */
  | {
      readonly kind: "conflict";
      readonly latestVersion: string | null;
      readonly latestDataHash: string | null;
    }
  /** 424: not written, because another row lost. */
  | { readonly kind: "not_written" };

export type RegistryBatchResult =
  /** 200: every row is stored (written now, or a replay). */
  | { readonly kind: "committed" }
  /** 409 `conflict`: a row lost; nothing was written. One entry per request row, in order. */
  | { readonly kind: "refused"; readonly rows: readonly RegistryBatchRow[] }
  /**
   * A condition failed. Nothing was written, for any row. `failure` is `null`
   * when the gateway did not say which condition or why: the caller reads the
   * row to find out.
   */
  | {
      readonly kind: "precondition_failed";
      readonly failure: RegistryRequirementFailure | null;
    };

/** Neither committed nor refused: resend the persisted request unchanged. */
export class AmbiguousRegistryReplyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AmbiguousRegistryReplyError";
  }
}

/** The gateway asked the client to pause; this is not a feed reset. */
export class RegistryOverloadError extends Error {
  constructor(readonly retryAfterMs: number) {
    super("registry overloaded");
  }
}

/**
 * The registry could not be reached or did not answer: a network failure, a
 * timeout or a 5xx. Nothing says the request was refused or that the data is
 * wrong, so a caller may go on offline. It is the only registry error a caller
 * may treat that way.
 */
export class RegistryUnavailableError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "RegistryUnavailableError";
  }
}

/**
 * An apply met an unavailable registry before its first local write, and no
 * earlier apply of the connection is left half done: it could not learn
 * anything new, and the local data is as complete as the last full apply left
 * it. That is the only unavailability a caller may treat as "offline". Apply
 * has no rollback: an unavailable error after its first write is thrown as the
 * plain `RegistryUnavailableError`, the writes already committed (a purge, a
 * reset, a stream replaced or tombstoned) stay, and `connections.apply_partial`
 * keeps later applies from reading as "before the first write".
 */
export class RegistryUnavailableBeforeWriteError extends RegistryUnavailableError {
  constructor(cause: RegistryUnavailableError) {
    super(cause.message, { cause });
    this.name = "RegistryUnavailableBeforeWriteError";
  }
}

/** The registry refused the request for good (4xx other than 409). */
/**
 * The gateway has no change route: it predates the change push. The caller
 * keeps its timed probe and asks again after a bounded wait, since a gateway
 * that is upgraded gains the route. The client does not remember the answer.
 */
export class ChangeFeedAbsentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ChangeFeedAbsentError";
  }
}

declare const changeCursorBrand: unique symbol;

/**
 * A position in the gateway's change feed. The gateway mints it and only the
 * gateway reads inside it: it carries the database epoch beside the owner's
 * sequence, so a position from a replaced database cannot be mistaken for one
 * in range. A client keeps it exactly as received, compares it with `===`, and
 * sends it back.
 *
 * The type is a branded `symbol`, though the value at run time is the wire
 * string. TypeScript refuses `<`, `>`, `+`, `-`, `BigInt(...)`, and a template
 * literal on a symbol, and a `string` or `number` would allow them. Only
 * {@link changeCursorFromWire} makes one and {@link changeCursorToWire} sends
 * one; no other code has a reason to look at the characters.
 */
export type ChangeCursor = symbol & { readonly [changeCursorBrand]: true };

/** The one place a cursor is made: the string the gateway answered with. */
export function changeCursorFromWire(wire: string): ChangeCursor {
  return wire as unknown as ChangeCursor;
}

/** The one place a cursor is read: the request parameter that returns it. */
export function changeCursorToWire(cursor: ChangeCursor): string {
  return cursor as unknown as string;
}

/** The answer to one held change request. */
export interface RegistryChangeAnswer {
  /**
   * Where the owner's registry is now, in the gateway's database. The next
   * request sends it back as `after`. Compared for equality only: it is not a
   * count of what changed, and a different database's cursor has no order
   * against this one.
   */
  readonly cursor: ChangeCursor;
  /** `cursor` differs from the `after` the request carried (or it carried none). */
  readonly changed: boolean;
  /**
   * What changed after the request's `since`, read in one snapshot at
   * `cursor`. Present on, and only on, a changed answer to a request that sent
   * `since` (a gateway that cannot read the delta answers `reset`). A changed
   * answer to such a request without a readable delta fails the request. A
   * `since` or `after` from another database epoch is answered with a reset
   * delta by the gateway, so the client has no epoch of its own to compare.
   */
  readonly delta?: RegistryChangeDelta;
}

/**
 * The registry rows that changed in `(since, cursor]`, as of one snapshot at
 * `cursor`. The gateway numbers changes in commit order, per owner, with no
 * gap, so a reader that has applied everything up to `since` and applies these
 * rows holds the registry as of `cursor`.
 *
 * `reset`: the gateway cannot say (the cursor is below the records it keeps,
 * above its counter, from another database epoch, or more than one listing
 * page behind): list everything.
 * `gone`: ids of rows the gateway removed (only a failed registration's
 * rollback does), which no scope names. `serversChanged`: the owner's server
 * registrations changed.
 */
export type RegistryChangeDelta =
  | {
      readonly since: ChangeCursor;
      readonly cursor: ChangeCursor;
      readonly reset: true;
    }
  | {
      readonly since: ChangeCursor;
      readonly cursor: ChangeCursor;
      readonly reset: false;
      readonly rows: readonly {
        readonly scope: string;
        readonly read: ControlRead;
      }[];
      readonly gone: readonly string[];
      readonly serversChanged: boolean;
    };

/**
 * What applying a change delta did. `cycle`: the delta holds something only a
 * full cycle handles (a new or reconnected lifetime, an unsupported row or a
 * deleted log row of a live connection, a row of a connection this device
 * does not hold, a removed row, a server change, a reset, a partial apply
 * standing on any connection), or the apply did not reach the delta's
 * position, or the publisher still has eligible work; nothing is settled and
 * the caller runs a cycle. `applied`: the device has applied through the
 * delta's `cursor`, run the publisher, and checked its local eligibility queries
 * for remaining work. A reached version or aggregate receipt is insufficient.
 */
export type DeltaApplyResult =
  | {
      readonly outcome: "applied";
      /** Connections whose log moved (a row of this device's own commit does not). */
      readonly connections: number;
      /** Connections the delta's control tombstones deleted here. */
      readonly deleted: number;
      /** Segment and snapshot GETs, and the time spent in them. */
      readonly blobGets: number;
      readonly blobMs: number;
      /** The whole apply, blob GETs included. */
      readonly applyMs: number;
    }
  | { readonly outcome: "cycle"; readonly reason: string };

export class RegistryRefusedError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "RegistryRefusedError";
  }
}

/**
 * The gateway serves no batch contract: `POST /v1/data/batch` answered 404 or
 * 405, or the route advertises no `Batch-Policy`. Stream sync needs it: a
 * connection delete and a log publish each commit in one batch, and there is
 * no per-row path to fall back to. `answer` says what the gateway answered.
 */
export class RegistryBatchRouteMissingError extends Error {
  constructor(readonly answer: string) {
    super(
      `the data gateway serves no batch contract at POST /v1/data/batch (${answer}); stream sync needs a gateway that serves it`,
    );
    this.name = "RegistryBatchRouteMissingError";
  }
}

export interface StreamSyncRegistry {
  /** Authoritative read: `GET /v1/data/:id?includeDeleted=true`. */
  read(scope: string, signal?: AbortSignal): Promise<ControlRead>;
  /** `POST /v1/data` with `exclusive: true`. Throws `AmbiguousRegistryReplyError`. */
  post(
    request: SignedRegistryPost,
    signal?: AbortSignal,
  ): Promise<RegistryPostResult>;
  /**
   * `POST /v1/data` with `requires`. A gateway that does not know `requires`
   * ignores it and writes anyway, and the answer does not say so, so a caller
   * may use this only against a gateway known to enforce it.
   */
  postConditional?(
    request: ConditionalRegistryPost,
  ): Promise<ConditionalPostResult>;
  /**
   * `POST /v1/data/batch`: every row and every condition in one all-or-nothing
   * request. Throws `RegistryBatchRouteMissingError` when the gateway has no
   * batch route. Throws `AmbiguousRegistryReplyError`: resend the same
   * request; a row that already landed answers as committed (a replay).
   */
  postBatch?(
    request: SignedRegistryBatch,
    signal?: AbortSignal,
  ): Promise<RegistryBatchResult>;
  /**
   * The policy the gateway advertised on its last batch answer or policy
   * read, or `undefined` when it has advertised none yet.
   */
  batchPolicy?(): RegistryBatchPolicy | undefined;
  /**
   * The gateway's batch policy: the one already known, else asked once per
   * process (`OPTIONS /v1/data/batch`; concurrent callers share the request).
   * `undefined`: the gateway answered and advertises none (no batch route, or
   * a route without the header). Throws `AmbiguousRegistryReplyError` when
   * the request got no answer; the next call asks again.
   */
  readBatchPolicy?(
    signal?: AbortSignal,
  ): Promise<RegistryBatchPolicy | undefined>;
  /**
   * Every control scope row of the owner (`pdpp.<c>~<ns>`), deleted or not.
   * Used for the per-session control listing (§2.4 `controls`).
   *
   * Each listed row is as fresh as a read of it begun after the call: a
   * listing is never a copy taken before it. (A row may move after, as after
   * any read.) A connection delete takes its pins from it.
   */
  listControlRows(
    signal?: AbortSignal,
  ): Promise<readonly { readonly scope: string; readonly read: ControlRead }[]>;
  /**
   * Every stream scope row of `connector` in any namespace, deleted or not,
   * whichever device or connector version wrote it. A connection delete
   * finds the streams to erase here, not in local state.
   */
  listStreamRows(
    connector: string,
  ): Promise<readonly { readonly scope: string; readonly read: ControlRead }[]>;
  /**
   * Every row of the owner, control and stream, deleted or not, in one
   * listing. A sync cycle takes it once and reads each connection's control
   * and log rows from it, so the cycle's listings do not depend on when its
   * applies run. The rows are a hint taken before the applies: an apply that
   * holds a newer log position than the listing reads the row again.
   */
  listOwnerRows(): Promise<
    readonly { readonly scope: string; readonly read: ControlRead }[]
  >;
  /**
   * One request: a marker of the owner's newest registry change, whatever the
   * number of rows (the gateway's change feed, newest first, one row). A
   * different marker means a row was written, tombstoned or revived since the
   * last read. An EQUAL marker does not prove that nothing changed: it
   * fingerprints one row, so a change that leaves that row alone (another row
   * stamped in the same millisecond) is invisible. `null`: the owner has no
   * rows. `undefined`: this gateway sends no change time, so the caller cannot
   * tell. Throws when the read fails. A hint to start a pull early, never an
   * authority: the timer's cycle (or the push's position, see
   * `waitForChange`) is what guarantees completeness, and a pull still reads
   * the rows it applies. `signal` ends a read that
   * stalls: a probe is optional work, so no caller may wait on it unbounded.
   */
  probeChange?(signal?: AbortSignal): Promise<string | null | undefined>;
  /**
   * One held request: answers when the owner's registry cursor differs from
   * `after` (a cursor from an earlier answer; none asks for the current one),
   * or after about `waitMs` with `changed: false`. The answer's cursor is a
   * position: it changes whenever anything a client can see changed, and when
   * the gateway's database was replaced. A caller that gets `changed` pulls
   * with its ordinary reads, or applies the answer's delta when it holds
   * everything up to its `since`, and one that gets nothing (a lost answer, a
   * dropped connection) is repaired by the next pull. A caller may skip pulls
   * while the same position stands (see `ChangePush`). Throws
   * `ChangeFeedAbsentError` when the gateway has no such route, and any other
   * error on a failed read, or on an answer without a cursor. `signal` ends the
   * request. `since`: the position up to which the caller holds the registry; a
   * changed answer may then carry the rows changed after it
   * (`RegistryChangeAnswer.delta`).
   */
  waitForChange?(
    after: ChangeCursor | undefined,
    waitMs: number,
    signal: AbortSignal,
    since: ChangeCursor | undefined,
  ): Promise<RegistryChangeAnswer>;
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
  readonly governor: Pick<SendGovernor, "reserve" | "window" | "limitBytes">;
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
