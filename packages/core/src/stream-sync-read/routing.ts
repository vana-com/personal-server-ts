/**
 * Physical stream-sync names (`pdpp.<c>~<ns>`, `pdpp.<c>~<ns>.<s>`) are
 * internal registry and storage names, never SDK scopes. The vana-sdk
 * `ScopeSchema` and `scopeToPathSegments` reject `~`, so every code path that
 * reaches them routes these names away first with this predicate, as
 * `isReplicaScope` is routed.
 */

import {
  logicalStreamScope,
  parseLogicalStreamScope,
  parseScope,
} from "@opendatalabs/personal-server-ts-stream-sync";

export {
  isPhysicalScope,
  parseLogicalStreamScope as logicalStreamScopeParts,
} from "@opendatalabs/personal-server-ts-stream-sync";

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
    try {
      return logicalStreamScope(parsed.connector, parsed.stream);
    } catch {
      return null;
    }
  }
  return parseLogicalStreamScope(name) ? name : null;
}
