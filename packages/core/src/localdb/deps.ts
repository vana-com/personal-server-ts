import type { SqlDriver } from "./driver.js";
import type { connectionQueue } from "./queue.js";
import type {
  StreamSyncBlobs,
  StreamSyncKeyPorts,
  StreamSyncRegistry,
  StreamSyncSigner,
} from "../stream-sync/ports.js";
import type { StreamCryptoPort } from "../stream-sync/crypto-port.js";

/** The queue every multi-batch operation of one database runs through (B.1). */
export type ConnectionQueue = ReturnType<typeof connectionQueue>;

/**
 * What every PS-2 module needs. One `LocalSyncDeps` belongs to one open
 * database (one owner, one network). Modules take it, never build it.
 * Spec: B.1, C.0-C.4.
 */
export interface LocalSyncDeps {
  readonly db: SqlDriver;
  readonly queue: ConnectionQueue;
  readonly ownerAddress: `0x${string}`;
  readonly registry: StreamSyncRegistry;
  readonly blobs: StreamSyncBlobs;
  readonly keys: StreamSyncKeyPorts;
  readonly signer: StreamSyncSigner;
  readonly logger: {
    info(obj: Record<string, unknown>, msg?: string): void;
    warn(obj: Record<string, unknown>, msg?: string): void;
  };
  readonly now: () => number;
  /** A fresh random id for one operation (`op` in the TEMP tables). */
  readonly newOp: () => string;
  /**
   * SHA-256 of a part, from the host. Default: noble (pure JS). A host with a
   * native one passes it here and to `createStreamSyncKeyPorts`; part hashes and
   * blobs are the same bytes either way.
   */
  readonly streamCrypto?: StreamCryptoPort;
  /** Part target in bytes; default 4 MiB (C.2). */
  readonly partTargetBytes?: number;
  /**
   * The host's wake for publish. Called after rows of a run or an import
   * commit, so a publish starts soon after them and not at the next poll.
   * Fire and forget: the poll is the recovery sweep, so a missed call only
   * costs latency, and a throw here never fails the commit.
   */
  readonly recordsCommitted?: () => void;
  /**
   * Publish while collecting, default off. A run that begins with it on has each
   * batch admitted into `records` as it arrives (same fences as run end), so
   * the publisher relays rows during the run; run end keeps only omission
   * deletes, explicit deletes and the checkpoint. A run keeps the mode it began
   * in (`runs.admitting`), and every later step reads that persisted mode, not
   * this flag: a run that was admitting stays so if the flag goes off. Off:
   * batches stay staged until run end, exactly as before.
   */
  readonly publishWhileCollecting?: boolean;
  /**
   * Default off. On: a stream with no complete head is readable by its owner
   * from its first applied part, in an explicit partial state, and fills in
   * as parts apply (`stream_partial`). Off: a stream is readable only when
   * its head is complete, as before.
   */
  readonly progressiveFirstLoad?: boolean;
  /**
   * Default on. A first load of a log that does not fit one commit's memory
   * budget loads key by key (`log-keyed.ts`). Off: it applies segment by
   * segment in position order, as it does for every other pass. A test that
   * wants the segment-by-segment result to compare against turns it off. A
   * device that holds the rows of a key-ordered load that stopped, and has the
   * flag off, drops those rows and loads again (`rebaselineKeyedLoad`).
   */
  readonly keyedFirstLoad?: boolean;
  /**
   * Default off. A key-ordered first load stages every row of the log in
   * scratch tables before it writes `records`. Off: they are ordinary tables,
   * so each page is journaled and later copied into the database file, and the
   * store holds them until they are dropped. On: they are TEMP tables, which a
   * store whose temp tables spill to a file (SQLite's default) never journals.
   * A host turns it on only when that holds: a store that keeps temp tables in
   * memory would hold the whole log there. Nothing reads the stage after the
   * load stops (a retry stages again), so it needs no durability.
   */
  readonly stageInTempStore?: boolean;
  /**
   * Publish and apply through the stream-sync log (one segment and one
   * registry commit per batch, across streams) instead of per-stream heads.
   * Default off. The flag lets this device START a log on a connection that has
   * none. A connection that has a log (its row is in the registry) is read and
   * written through it by every device of this build, whatever its flag; a
   * device whose build cannot read the log's format refuses to write that
   * connection and reports `update_required` (`UpdateRequiredError`).
   */
  readonly logProtocol?: boolean;
}

/** The one call every commit of local rows makes (run end, import). */
export function announceRecordsCommitted(deps: LocalSyncDeps): void {
  try {
    deps.recordsCommitted?.();
  } catch (error) {
    deps.logger.warn(
      { error: String(error) },
      "stream sync: the publish wake threw; the poll will publish",
    );
  }
}

/** One `connections` row, as the modules pass it around. */
export interface ConnectionRow {
  readonly connectionId: string;
  readonly connector: string;
  readonly ns: string;
  readonly generation: number;
  readonly controlState: "absent" | "active" | "deleted" | "foreign";
  readonly controlVersion: number;
}
