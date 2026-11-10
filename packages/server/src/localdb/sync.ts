import {
  createLocalSync,
  type AliasScopes,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { readTargets } from "@opendatalabs/personal-server-ts-core/stream-sync-read";
import { projectPdppRecordsToLegacyPayload } from "@opendatalabs/personal-server-ts-core/legacy-projection";

/** Legacy alias knowledge belongs to the host, outside the database path. */
export const aliasScopes: AliasScopes = (scope) =>
  readTargets(scope).flatMap((target) => {
    if (!target.binding) return [];
    return [
      {
        connector: target.connector,
        streams: target.streams,
        servedStream: target.binding.window?.parentStream,
        windowed: Boolean(target.binding.window),
        project: (records, now) =>
          projectPdppRecordsToLegacyPayload(scope, [...records], {
            fetchedStreams: [...target.streams],
            profileKey: target.connector,
            orderByPrimaryKey: true,
            now,
          }),
      },
    ];
  });

/** Server composition supplies aliases explicitly; core has no default catalogue. */
export function createServerLocalSync(
  deps: Parameters<typeof createLocalSync>[0],
  options: Omit<Parameters<typeof createLocalSync>[1], "aliasScopes">,
) {
  return createLocalSync(deps, { ...options, aliasScopes });
}
