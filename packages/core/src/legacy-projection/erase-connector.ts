/**
 * This device's legacy scope files of one connector, for a connection delete.
 *
 * A legacy scope (data set) belongs to a connector through the legacy bindings
 * table: each binding names its PDPP source, whose last path segment is the
 * connector key. The table is the only mapping; no connector id is written
 * here. A scope with no binding is not attributed, so it is not erased.
 */

import { LEGACY_SCOPE_BINDINGS, legacyBindingsForProfile } from "./index.js";
import type { DataStoragePort } from "../ports/index.js";

/** The legacy scopes bound to `connector`, in table order. */
export function legacyScopesOfConnector(connector: string): string[] {
  const scopes = new Set(legacyBindingsForProfile(connector).keys());
  for (const [scope, binding] of LEGACY_SCOPE_BINDINGS) {
    if (binding.pdppSource.endsWith(`/${connector}`)) scopes.add(scope);
  }
  return [...scopes];
}

/** The streams of `connector` that its legacy `scope` reads (the binding's fields). */
export function legacyStreamsOfScope(
  connector: string,
  scope: string,
): string[] {
  const binding =
    legacyBindingsForProfile(connector).get(scope) ??
    LEGACY_SCOPE_BINDINGS.get(scope);
  return binding ? Object.keys(binding.fieldsRead) : [];
}

/**
 * Removes this device's local copies of the connector's legacy scope files.
 * `deleteScope` is local only and idempotent: a scope with no files is a
 * no-op.
 */
export async function eraseLegacyScopesOf(
  connector: string,
  storage: Pick<DataStoragePort, "deleteScope">,
): Promise<void> {
  for (const scope of legacyScopesOfConnector(connector)) {
    await storage.deleteScope(scope);
  }
}
