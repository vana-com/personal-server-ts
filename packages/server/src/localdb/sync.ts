import { createLocalSync } from "@opendatalabs/personal-server-ts-core/localdb";
import {
  LEGACY_SCOPE_BINDINGS,
  legacyAliasScopes,
} from "@opendatalabs/personal-server-ts-core/legacy-projection";
export const aliasScopes = () => LEGACY_SCOPE_BINDINGS.keys();

/** Server composition supplies aliases explicitly; core has no default catalogue. */
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
