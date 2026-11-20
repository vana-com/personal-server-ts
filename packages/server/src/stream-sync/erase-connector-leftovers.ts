/**
 * What a connection delete erases of one connector from this device, beyond
 * its stream-sync state: the legacy scope files the connector's bindings name
 * and the `pdpp_records` rows of its live connections. The writer runs this
 * last in its purge, so nothing of the connector is left behind.
 *
 * A PDPP source is named by its id, whose last path segment is the connector
 * key (the rule the declaration registry uses). `listConnections` already hides
 * deleted connections, and `deleteConnection` is idempotent.
 */

import { eraseLegacyScopesOf } from "@opendatalabs/personal-server-ts-core/legacy-projection";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";

export interface PdppRecordsForErase {
  /** The PDPP source ids this server knows. */
  readonly sourceIds: Iterable<string>;
  readonly store: {
    listConnections(sourceId: string): readonly { readonly instance: string }[];
    deleteConnection(instance: string): unknown;
  };
}

function connectorKeyOf(sourceId: string): string | null {
  try {
    const segments = new URL(sourceId).pathname
      .split("/")
      .filter((segment) => segment.length > 0);
    return segments[segments.length - 1] ?? null;
  } catch {
    return null;
  }
}

export async function eraseConnectorLeftovers(
  connector: string,
  deps: {
    readonly storage: Pick<DataStoragePort, "deleteScope">;
    readonly pdpp?: PdppRecordsForErase;
  },
): Promise<void> {
  await eraseLegacyScopesOf(connector, deps.storage);
  if (!deps.pdpp) return;
  for (const sourceId of deps.pdpp.sourceIds) {
    if (connectorKeyOf(sourceId) !== connector) continue;
    for (const binding of deps.pdpp.store.listConnections(sourceId)) {
      deps.pdpp.store.deleteConnection(binding.instance);
    }
  }
}
