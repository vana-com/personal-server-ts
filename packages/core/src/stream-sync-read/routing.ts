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

/**
 * A logical stream-sync read name: `pdpp.<c>.<s>`. `c` is the connector key
 * and may hold any character but `.` and `~` (a hyphen, for one); the SDK scope
 * rule (lowercase category) does not apply to it.
 */
const LOGICAL_STREAM_SCOPE = /^pdpp\.([^.~]+)\.([^~]+)$/;

export function logicalStreamScopeParts(
  name: string,
): { connector: string; stream: string } | null {
  const match = LOGICAL_STREAM_SCOPE.exec(name);
  return match ? { connector: match[1]!, stream: match[2]! } : null;
}

/**
 * The logical read name a data route serves for `name`, or `null` when `name`
 * is not a stream-sync stream name.
 *
 * Accepts the logical name itself and the identity-less physical stream scope
 * `pdpp.<c>~.<s>` (R23: every name is identity-less), which maps to the
 * logical name. A physical scope with a namespace, and a control scope, stay
 * internal names (ruling Q7) and answer `null`.
 */
export function streamReadScope(name: string): string | null {
  // A route parameter never carries a path separator, whitespace or a control
  // character, whatever the name rule allows.
  if (/[\\/\s\u0000-\u001f\u007f]/.test(name)) return null;
  const parsed = parseScope(name);
  if (parsed) {
    if (parsed.kind !== "stream" || parsed.ns !== "") return null;
    const logical = `pdpp.${parsed.connector}.${parsed.stream}`;
    return LOGICAL_STREAM_SCOPE.test(logical) ? logical : null;
  }
  return LOGICAL_STREAM_SCOPE.test(name) ? name : null;
}
