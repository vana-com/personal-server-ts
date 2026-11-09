import type { ResolveArtifact, RunIntake } from "../stream-sync/intake.js";
import type { BlobStore } from "./blobs.js";
import type { CycleReport } from "./cycle.js";
import type { ConnectionDeleter } from "./delete.js";
import type { LocalSyncDeps } from "./deps.js";
import type { LocalListing } from "./listing.js";
import type { OlderVersions } from "./older-versions.js";
import type { RecordQuery } from "./query.js";
import type { LocalResolver } from "./resolve.js";

/**
 * The one facade a host holds for a switched owner's stream sync on the
 * database: it replaces `StreamSyncWriter` + `StreamSyncReadService` in
 * `server/src/bootstrap.ts` and `lite/src/sync.ts`. Hosts build it from deps
 * and wire its parts to the existing routes; nothing else reaches the modules.
 */
export interface LocalSync {
  readonly intake: RunIntake;
  readonly deleter: ConnectionDeleter;
  readonly resolver: LocalResolver;
  readonly listing: LocalListing;
  readonly query: RecordQuery;
  readonly olderVersions: OlderVersions;
  readonly blobs: BlobStore;
  /** `/sync/trigger` and the timer: C.4 order, apply then publish. */
  cycle(): Promise<CycleReport>;
  /** `/sync/file/:id`: apply and publish that connection, then read. */
  syncConnection(
    connectionId: string,
  ): Promise<CycleReport["connections"][number]>;
  close(): Promise<void>;
}

export function createLocalSync(
  deps: LocalSyncDeps,
  options: {
    readonly resolveArtifact: ResolveArtifact;
    readonly declaredStreams: (connector: string) => readonly string[];
    readonly retainedManifests?: () => readonly string[];
    readonly eraseLegacy?: (connector: string) => Promise<void>;
    readonly olderVersionReads: () => boolean;
    readonly deleting?: (connector: string) => boolean | Promise<boolean>;
    readonly currentLease?: () => string | null;
  },
): LocalSync {
  void deps;
  void options;
  throw new Error("PS-2: not built");
}
