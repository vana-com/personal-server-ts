/**
 * Ruling Q7: physical stream-sync names (`pdpp.<c>~<ns>`, `pdpp.<c>~<ns>.<s>`)
 * are internal registry and storage names, never SDK scopes. The vana-sdk
 * `ScopeSchema` and `scopeToPathSegments` reject `~`, so every code path that
 * reaches them routes physical names away first with this predicate.
 */

import { parseScope } from "@opendatalabs/personal-server-ts-stream-sync";

/**
 * True for a physical stream-sync name, and for any other name with `~`
 * (no SDK scope can hold one, so it must not reach the SDK either).
 */
export function isPhysicalScope(name: string): boolean {
  return parseScope(name) !== null || name.includes("~");
}

/** A physical stream-sync name reached a path that takes SDK scopes only. */
export class PhysicalScopeError extends Error {
  constructor(readonly scope: string) {
    super(`${JSON.stringify(scope)} is a stream-sync name, not a data scope`);
    this.name = "PhysicalScopeError";
  }
}
