import { createLocalSync } from "@opendatalabs/personal-server-ts-core/localdb";
import { legacyAliasScopes } from "@opendatalabs/personal-server-ts-core/legacy-projection";
export { legacyAliasScopes as aliasScopes } from "@opendatalabs/personal-server-ts-core/legacy-projection";

/** Server composition supplies aliases explicitly; core has no default catalogue. */
export function createServerLocalSync(
  deps: Parameters<typeof createLocalSync>[0],
  options: Omit<Parameters<typeof createLocalSync>[1], "aliasScopes">,
) {
  return createLocalSync(deps, { ...options, aliasScopes: legacyAliasScopes });
}
