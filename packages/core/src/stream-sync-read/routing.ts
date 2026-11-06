/**
 * Physical stream-sync names (`pdpp.<c>~<ns>`, `pdpp.<c>~<ns>.<s>`) are
 * internal registry and storage names, never SDK scopes. The vana-sdk
 * `ScopeSchema` and `scopeToPathSegments` reject `~`, so every code path that
 * reaches them routes these names away first with this predicate, as
 * `isReplicaScope` is routed.
 */

import { parseScope } from "@opendatalabs/personal-server-ts-stream-sync";

/**
 * True for a physical stream-sync name, and for any other name with `~`: no
 * SDK scope can hold one, so it must not reach the SDK either.
 */
export function isPhysicalScope(name: string): boolean {
  return name.includes("~") || parseScope(name) !== null;
}
