import type {
  LegacyScopeBinding,
  PdppRecord,
  ProjectionResult,
} from "./types.js";

/**
 * github-browser emits one legacy-shaped snapshot per stream. Its top-level
 * id is a PDPP runtime key, not part of the public legacy payload.
 * The field lists are checked against the signed 0.2.1 collection profile.
 */
const browserSource = "https://registry.pdpp.dev/connectors/github-browser";
const artifactDigest =
  "sha256:f3c345b4aaac1a42887dc0e9fa021f591c618e642a1814ca8b0dfe9adc743dd8";
const fieldsByStream: Record<string, string[]> = {
  profile: [
    "username",
    "fullName",
    "bio",
    "company",
    "location",
    "website",
    "avatarUrl",
    "followers",
    "following",
    "repositoryCount",
    "profileUrl",
    "pinnedRepositories",
    "organizations",
    "achievements",
    "contributionsLastYear",
  ],
  repositories: ["repositories"],
  starred: ["starred"],
  events: ["events", "fetchedAt", "windowDescription"],
  contributions: [
    "totalContributionsLastYear",
    "yearTotals",
    "days",
    "monthlyTotals",
    "topDay",
    "fetchedAt",
  ],
  history: ["pullRequests", "issues", "fetchedAt", "windowDescription"],
};
const requiredByStream: Record<string, string[]> = {
  profile: ["username", "profileUrl"],
  repositories: ["repositories"],
  starred: ["starred"],
  events: ["events", "fetchedAt"],
  contributions: ["days", "fetchedAt"],
  history: ["pullRequests", "issues", "fetchedAt"],
};
const legacyEventsWindowDescription =
  "Up to 300 most recent public events across all repositories (≈90 days, GitHub API limit)";

function browserBinding(stream: string): LegacyScopeBinding {
  const scope = `github.${stream}`;
  const fields = fieldsByStream[stream];
  return {
    scope,
    pdppSource: browserSource,
    pdppStreams: [stream],
    legacySchemaPath: `${scope}.json`,
    fieldsRead: { [stream]: fields },
    primaryKey: { [stream]: ["id"] },
    lossy: [],
    provenance: [
      {
        kind: "oci",
        ref: "ghcr.io/pdp-connect/connector/github-browser:0.2.1",
        digest: artifactDigest,
        path: `collection-profile.json#streams[name=${stream}]`,
      },
    ],
    project(records: PdppRecord[], options): ProjectionResult {
      if (!options.fetchedStreams.includes(stream)) {
        return {
          ok: false,
          error: { kind: "missing_stream", scope, expectedStream: stream },
        };
      }
      const snapshots = records.filter((record) => record.stream === stream);
      if (snapshots.length !== 1) {
        return {
          ok: false,
          error: {
            kind: "incomplete_scope",
            scope,
            reason: `Expected one ${stream} snapshot, received ${snapshots.length}`,
          },
        };
      }
      const snapshot = snapshots[0].data;
      if (
        !snapshot ||
        typeof snapshot !== "object" ||
        Array.isArray(snapshot)
      ) {
        return {
          ok: false,
          error: {
            kind: "invalid_value",
            scope,
            reason: "Snapshot is not an object",
          },
        };
      }
      for (const field of requiredByStream[stream]) {
        if (snapshot[field] === undefined || snapshot[field] === null) {
          return {
            ok: false,
            error: {
              kind: "incomplete_scope",
              scope,
              reason: `${stream}.${field} is unavailable`,
            },
          };
        }
      }
      const payload: Record<string, unknown> = {};
      for (const field of fields) {
        if (Object.hasOwn(snapshot, field)) payload[field] = snapshot[field];
      }
      // github-browser 0.2.1 uses a new description for the same API window.
      // Keep the Vana legacy payload wording from github-playwright 1.5.1.
      if (stream === "events" && Object.hasOwn(payload, "windowDescription")) {
        payload.windowDescription = legacyEventsWindowDescription;
      }
      return { ok: true, payload };
    },
  };
}

export const GITHUB_BROWSER_BINDINGS: ReadonlyMap<string, LegacyScopeBinding> =
  new Map(
    Object.keys(fieldsByStream).map((stream) => [
      `github.${stream}`,
      browserBinding(stream),
    ]),
  );
