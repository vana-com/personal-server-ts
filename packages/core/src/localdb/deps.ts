import type { SqlDriver } from "./driver.js";
import type { connectionQueue } from "./queue.js";
import type {
  StreamSyncBlobs,
  StreamSyncKeyPorts,
  StreamSyncRegistry,
  StreamSyncSigner,
} from "../stream-sync/ports.js";

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
  /** Part target in bytes; default 4 MiB (C.2). */
  readonly partTargetBytes?: number;
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
