import { GITHUB_BROWSER_BINDINGS } from "@opendatalabs/personal-server-ts-core/legacy-projection";

// What marks a stored `github.<stream>` file as the browser connector's. Its
// streams are singleton snapshots whose own collection is a nested array
// (`events.events`, `repositories.repositories`, `contributions.days`), while
// the GitHub API connector stores one flat row per record. The stored file
// carries no connector id, so this shape is the source identity.
const snapshotMarkersByStream: Record<
  string,
  { arrays?: string[]; strings?: string[] }
> = {
  profile: { strings: ["username", "profileUrl"] },
  repositories: { arrays: ["repositories"] },
  starred: { arrays: ["starred"] },
  events: { arrays: ["events"] },
  contributions: { arrays: ["days"] },
  history: { arrays: ["pullRequests", "issues"] },
};

/**
 * True when `records` is one github-browser snapshot for `scope`. Cheap and
 * deliberately narrower than the projection: a snapshot missing a required
 * field still counts, so the projection reports it instead of the API
 * bindings reading it as an empty inventory.
 */
export function isGithubBrowserSnapshotFile(
  scope: string,
  records: readonly Record<string, unknown>[],
): boolean {
  const markers = GITHUB_BROWSER_BINDINGS.has(scope)
    ? snapshotMarkersByStream[scope.slice("github.".length)]
    : undefined;
  if (!markers || records.length !== 1) {
    return false;
  }
  const row = records[0];
  return (
    (markers.arrays ?? []).every((key) => Array.isArray(row[key])) &&
    (markers.strings ?? []).every((key) => typeof row[key] === "string")
  );
}
