import type {
  ReadDecision,
  ResolveInput,
} from "../stream-sync-read/service.js";
import type { LocalSyncDeps } from "./deps.js";
import type { OlderVersions } from "./older-versions.js";
import type { RecordQuery } from "./query.js";

/**
 * D.1 / D.0: the read decision over the database. Same `ResolveInput` and
 * `ReadDecision` as today's `StreamSyncReadService.resolve`, so
 * `StreamSyncReadPort` in `api/index.ts` is satisfied unchanged. Carries the
 * #590 latest-complete-head rules, #573 eligibility table, #569 refusals,
 * #596 body-read refusals and the head-bound x402 `served` value. A read of a
 * stream whose registry version is newer joins the running `apply` (B.1).
 * `legacy-projection/bindings.ts` stays only as the legacy-read shim; this module names no connector id.
 */
export interface LocalResolver {
  resolve(input: ResolveInput): Promise<ReadDecision>;
}

export function createLocalResolver(
  deps: LocalSyncDeps,
  parts: { readonly query: RecordQuery; readonly olderVersions: OlderVersions },
): LocalResolver {
  void deps;
  void parts;
  throw new Error("PS-2: not built");
}
