import { createLocalSync } from "@opendatalabs/personal-server-ts-core/localdb";
import {
  LEGACY_SCOPE_BINDINGS,
  legacyAliasScopes,
} from "@opendatalabs/personal-server-ts-core/legacy-projection";
import { legacyConnectorKey } from "@opendatalabs/personal-server-ts-core/storage/canonical-legacy-projection";
import type { ImportProjectionPort } from "@opendatalabs/personal-server-ts-core/localdb";

/** The one host composition site supplies the frozen catalogue to database
 * listing, read-back and legacy access. It owns no projection algorithms. */
export const aliasScopes = () => LEGACY_SCOPE_BINDINGS.keys();
export const importProjection: ImportProjectionPort = {
  bindings: new Map(
    [...LEGACY_SCOPE_BINDINGS].map(([name, binding]) => [
      name,
      {
        connector: legacyConnectorKey(binding.pdppSource),
        streams: binding.pdppStreams,
      },
    ]),
  ),
};

export function createServerLocalSync(
  deps: Parameters<typeof createLocalSync>[0],
  options: Omit<
    Parameters<typeof createLocalSync>[1],
    "aliasScopes" | "aliasTargets"
  >,
) {
  return createLocalSync(deps, {
    ...options,
    aliasScopes,
    aliasTargets: legacyAliasScopes,
  });
}
