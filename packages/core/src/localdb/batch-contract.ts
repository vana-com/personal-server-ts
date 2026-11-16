/**
 * The request-shape rules of the registry's `POST /v1/data/batch`, written
 * once so a test registry can refuse what the real gateway refuses.
 *
 * A request that breaks one of them gets HTTP 400 from the gateway. That is a
 * defect in the caller, not a limit to work around, so a registry used in a
 * test must answer it the same way. A fake that accepts what the gateway
 * refuses lets the defect reach a real gateway, where the caller's fallback
 * hides it: a delete batch the gateway refused with 400 fell back to one
 * request per row, and nothing failed.
 *
 * Rules (the gateway checks the same, in this order):
 * - at most `rows` rows and `requires` conditions;
 * - a condition names a data point the request does not write, because a
 *   condition is judged before the writes and on a row the request also
 *   writes it would be a second compare-and-set on the same row, which the
 *   row's own `expectedVersion` and `expectedHeadDataHash` already are;
 * - a condition scope is not repeated.
 */
import type { SignedRegistryBatch } from "../stream-sync/ports.js";
import {
  GATEWAY_MAX_BATCH_REQUIRES,
  GATEWAY_MAX_BATCH_ROWS,
} from "./batch-commit.js";

/** The reason the gateway answers 400, or null when it accepts the shape. */
export function gatewayBatchRefusal(
  request: SignedRegistryBatch,
  bounds: { readonly rows: number; readonly requires: number } = {
    rows: GATEWAY_MAX_BATCH_ROWS,
    requires: GATEWAY_MAX_BATCH_REQUIRES,
  },
): string | null {
  if (request.rows.length > bounds.rows)
    return `rows: at most ${bounds.rows} rows (got ${request.rows.length})`;
  if (request.requires.length > bounds.requires)
    return `requires: at most ${bounds.requires} entries (got ${request.requires.length})`;
  const written = new Set(request.rows.map((row) => row.scope));
  const seen = new Set<string>();
  for (const [i, need] of request.requires.entries()) {
    if (written.has(need.scope))
      return `requires[${i}].scope: must be a different data point than the one written`;
    if (seen.has(need.scope)) return `requires[${i}].scope: repeated`;
    seen.add(need.scope);
  }
  return null;
}
