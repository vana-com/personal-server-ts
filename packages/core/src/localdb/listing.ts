import type { StreamSyncReadStatus } from "../stream-sync-read/service.js";
import type { LocalSyncDeps } from "./deps.js";
import type { OlderVersionCounts } from "./older-versions.js";

/** One listed scope of `GET /v1/data` (D.2). */
export interface ListedScope {
  readonly scope: string;
  readonly connector: string;
  readonly ns: string;
  readonly records: number | null;
  readonly updatedAt: number | null;
}

/**
 * D.2 listing and D.4 status, from `connections` + `stream_state`. The
 * listing is filtered by `canRead` FIRST (grant filter); a scope whose check
 * throws is skipped and logged; the owner's local-only scopes are included; an
 * alias is listed only if its body can be built; the cache key changes on any
 * control-row change. `status()` is `StreamSyncReadStatus` plus the D.3 counts.
 */
export interface LocalListing {
  listScopes(input: {
    readonly canRead: (scope: string) => boolean | Promise<boolean>;
  }): Promise<readonly ListedScope[]>;
  status(): Promise<
    StreamSyncReadStatus & { readonly olderVersionReads: OlderVersionCounts }
  >;
  /** Changes whenever any control row or stream head changes. */
  cacheKey(): Promise<string>;
}

export function createLocalListing(
  deps: LocalSyncDeps,
  counts: () => OlderVersionCounts,
): LocalListing {
  void deps;
  void counts;
  throw new Error("PS-2: not built");
}
