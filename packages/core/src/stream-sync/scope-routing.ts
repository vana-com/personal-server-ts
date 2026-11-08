/**
 * Ruling Q7: physical stream-sync names (`pdpp.<c>~<ns>`, `pdpp.<c>~<ns>.<s>`)
 * are internal registry and storage names, never SDK scopes. The vana-sdk
 * `ScopeSchema` and `scopeToPathSegments` reject `~`, so every code path that
 * reaches them routes physical names away first with this predicate.
 */

export { isPhysicalScope } from "@opendatalabs/personal-server-ts-stream-sync";

/** A physical stream-sync name reached a path that takes SDK scopes only. */
export class PhysicalScopeError extends Error {
  constructor(readonly scope: string) {
    super(`${JSON.stringify(scope)} is a stream-sync name, not a data scope`);
    this.name = "PhysicalScopeError";
  }
}
