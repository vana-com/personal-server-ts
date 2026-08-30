/*
 * UNREACHABLE as committed — nothing calls this module.
 *
 * `resolveSearches` has no caller and no test. `searchResults` is the only
 * route from its output into a run, and neither query service ever populates
 * it: `query-service.ts` builds the tool host without the field, and PS-Lite
 * throws for `search` outright. So `runner-entry.ts`'s `search` always falls
 * through to its honest denial, and this file is dead at runtime.
 *
 * It is kept deliberately, as the apply-base for
 * `docs/query-layer-experiments/19.15-search-deferred-roundtrip.patch`, which
 * patches this exact file as one of seven. Design §19.15 records that patch as
 * verified by execution: reverting with `git checkout d3c89d3 -- <seven
 * paths>` leaves `git diff d3c89d3` at 0 bytes, and re-applying restores all
 * seven files to matching SHA-256 digests. Deleting this file — or rewriting
 * that hunk into a new-file diff so the patch could carry the file itself —
 * would stop the patch applying against `d3c89d3` and falsify that measured
 * claim. The dead code is the cheaper price, so it is labelled, not removed.
 *
 * The same reasoning keeps `./mcp/search` in `packages/core/package.json`:
 * this file's type-only import is its only consumer, and it exists so this
 * file can be patched back to life.
 *
 * This banner sits above the module doc rather than inside it so the patch's
 * first hunk keeps the contiguous context it matches on.
 */

/**
 * Host-side lexical search for the query layer.
 *
 * `vana.search` is a **host-authority** operation: it reads an index that spans
 * scopes, so it must never live inside the sandbox. The confined runtime asks;
 * this answers, on the host, over the repo's existing MiniSearch index.
 *
 * Reuse, not a second index. Plan §5 names building a parallel index as
 * "PR #231's mistake", so this wraps `packages/core/src/mcp/search` rather than
 * indexing anything itself.
 *
 * Results are filtered to the grant before they leave the host, so a hit in an
 * ungranted scope is not merely unreadable — the script never learns it exists.
 */

import type {
  SearchIndex,
  SearchHit,
} from "@opendatalabs/personal-server-ts-core/mcp/search";
import type { ScriptHit } from "@opendatalabs/personal-server-ts-core/query/tools";

export interface SearchBridgeOptions {
  index: SearchIndex;
  grantedScopes: readonly string[];
  defaultLimit?: number;
}

function toScriptHit(hit: SearchHit): ScriptHit {
  const out: ScriptHit = {
    id: hit.id,
    scope: hit.scope,
    score: hit.score,
  };
  if (hit.title !== undefined) out.title = hit.title;
  if (hit.preview !== undefined) out.preview = hit.preview;
  if (hit.blockRef !== undefined) out.blockRef = hit.blockRef;
  return out;
}

/**
 * Resolve the queries a run may issue, on the host, before the sandbox starts.
 *
 * The confined runtime cannot call back out mid-run without a per-call IPC
 * round trip, which phase 4b measured at ~11s for a 227k-row scan and rejected.
 * Search is O(1)–O(few) per question, so the host resolves it up front and
 * passes the results in.
 */
export function resolveSearches(
  queries: readonly string[],
  options: SearchBridgeOptions,
): Record<string, ScriptHit[]> {
  const granted = new Set(options.grantedScopes);
  const out: Record<string, ScriptHit[]> = {};
  for (const query of queries) {
    const hits = options.index.search({
      query,
      scopes: options.grantedScopes,
      ...(options.defaultLimit === undefined
        ? {}
        : { limit: options.defaultLimit }),
    });
    // Defence in depth: the index is asked for granted scopes only, and the
    // result is filtered again on the way out.
    out[query] = hits.filter((h) => granted.has(h.scope)).map(toScriptHit);
  }
  return out;
}
