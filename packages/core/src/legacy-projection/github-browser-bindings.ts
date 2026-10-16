import { GITHUB_LEGACY_FIELDS as schemasByStream } from "./github-legacy-fields.js";
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

type LegacySchema = {
  properties?: Record<string, LegacySchema>;
  items?: LegacySchema;
};

// Follow the schema-pinned field tree: canonical additions must never leak
// into these closed legacy objects, including nested rows and nullable objects.
function projectDeclared(value: unknown, schema: LegacySchema): unknown {
  if (Array.isArray(value) && schema.items) {
    const items = schema.items;
    return value.map((item) => projectDeclared(item, items));
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value) && schema.properties) {
    const object = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.entries(schema.properties)
        .filter(([key]) => Object.hasOwn(object, key))
        .map(([key, child]) => [key, projectDeclared(object[key], child)]),
    );
  }
  return value;
}

// Verified github-playwright 1.5.0 collector defaults, supplied with assignment
// build-ps-legacy-contract-gh-meta-4884292 (profile :268-337,
// repositories :416-425, starred :568-575). These are compatibility defaults,
// not new facts in the canonical records. Required identities stay guarded.
const profileDefaults: Record<string, unknown> = {
  fullName: "", bio: "", company: "", location: "", website: "", avatarUrl: "",
  followers: 0, following: 0, repositoryCount: 0,
  pinnedRepositories: [], organizations: [], achievements: [],
  contributionsLastYear: null,
};
const rowDefaults: Record<string, Record<string, unknown>> = {
  pinnedRepositories: { url: null, description: "", language: null, stars: 0 },
  organizations: { avatarUrl: null },
  achievements: { iconUrl: null },
  repositories: {
    description: "", language: "", stars: 0, forks: 0,
    visibility: "Public", topics: [], updatedAt: null,
  },
  starred: { description: "", language: "", stars: 0, updatedAt: null },
};

function fillAbsent(object: Record<string, unknown>, defaults: Record<string, unknown>): void {
  for (const [key, value] of Object.entries(defaults)) {
    if (object[key] === undefined) object[key] = Array.isArray(value) ? [...value] : value;
  }
}

function fillLegacyDefaults(stream: string, payload: Record<string, unknown>): void {
  if (stream === "profile") fillAbsent(payload, profileDefaults);
  const fields = stream === "profile"
    ? ["pinnedRepositories", "organizations", "achievements"]
    : stream === "repositories" || stream === "starred" ? [stream] : [];
  for (const field of fields) {
    const rows = payload[field];
    if (!Array.isArray(rows)) continue;
    for (const row of rows) {
      if (row !== null && typeof row === "object" && !Array.isArray(row)) {
        // github-playwright derives missing pinned URLs from the repository identity.
        // Preserve every supplied canonical URL, including empty strings and null.
        if (field === "pinnedRepositories" && row.url === undefined) {
          row.url = row.fullName ? `https://github.com/${row.fullName}` : null;
        }
        fillAbsent(row as Record<string, unknown>, rowDefaults[field]);
      }
    }
  }
}

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
      const payload = projectDeclared(snapshot, schemasByStream[stream]) as Record<string, unknown>;
      fillLegacyDefaults(stream, payload);
      // github-browser 0.2.1 uses a new description for the same API window.
      // Keep the Vana legacy payload wording from github-playwright 1.5.1.
      if (stream === "events" && Object.hasOwn(payload, "windowDescription")) {
        payload.windowDescription = legacyEventsWindowDescription;
      }
      if (stream === "history" && Object.hasOwn(payload, "windowDescription")) {
        payload.windowDescription =
          "Full lifetime authored PRs and Issues from /search/issues, up to 1000 per type.";
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
