/**
 * The request-shape rules of the registry's `POST /v1/data/batch`, written
 * once so a test registry can refuse what the real gateway refuses.
 *
 * A request that breaks one of them gets HTTP 400 from the gateway. That is a
 * defect in the caller, not a limit to work around, so a registry used in a
 * test must answer it the same way. A fake that accepts what the gateway
 * refuses lets the defect reach a real gateway.
 *
 * Rules (the gateway checks the same, in this order):
 * - at most `rows` rows and `requires` conditions (its advertised policy);
 * - a row scope is not repeated: a request writes each row once;
 * - a condition scope is not repeated. (A condition may name a row the
 *   request writes: conditions are judged on the state the request commits.)
 */
import type {
  RegistryBatchPolicy,
  SignedRegistryBatch,
} from "../stream-sync/ports.js";

/** The reason the gateway answers 400, or null when it accepts the shape. */
export function gatewayBatchRefusal(
  request: SignedRegistryBatch,
  policy: Pick<RegistryBatchPolicy, "rows" | "requires">,
): string | null {
  if (request.rows.length > policy.rows)
    return `rows: at most ${policy.rows} rows (got ${request.rows.length})`;
  if (request.requires.length > policy.requires)
    return `requires: at most ${policy.requires} entries (got ${request.requires.length})`;
  const written = new Set<string>();
  for (const [i, row] of request.rows.entries()) {
    if (written.has(row.scope)) return `rows[${i}].scope: repeated`;
    written.add(row.scope);
  }
  const seen = new Set<string>();
  for (const [i, need] of request.requires.entries()) {
    if (seen.has(need.scope)) return `requires[${i}].scope: repeated`;
    seen.add(need.scope);
  }
  return null;
}
