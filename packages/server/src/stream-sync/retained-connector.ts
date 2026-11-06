/**
 * The connector key a retained declaration publishes as on the run intake
 * (owner decision A: the signed pin id, which Desktop configures as the
 * source's method id). One method names the key. A source with no method
 * publishes as its own id. A source with several methods is ambiguous, so it
 * resolves to nothing and a run for it stays legacy-only.
 */

import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";

export interface RetainedMethods {
  readonly configuredMethods: readonly {
    readonly sourceId: string;
    readonly methodId: string;
  }[];
  readonly connectionMethods: ReadonlyMap<string, readonly string[]>;
}

export function retainedConnectorKey(
  methods: RetainedMethods | undefined,
): (snapshot: DeclarationSnapshot) => string | null {
  return (snapshot) => {
    const ids = new Set<string>(
      methods?.connectionMethods.get(snapshot.source_id) ?? [],
    );
    for (const method of methods?.configuredMethods ?? []) {
      if (method.sourceId === snapshot.source_id) ids.add(method.methodId);
    }
    if (ids.size === 0) return snapshot.source_id;
    return ids.size === 1 ? [...ids][0]! : null;
  };
}
