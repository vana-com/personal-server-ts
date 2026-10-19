import { GITHUB_LEGACY_FIELDS } from "./github-legacy-fields.js";
import Ajv from "ajv";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import profile from "./declarations/github-browser.collection-profile.json";
import provenance from "./declarations/github-browser.provenance.json";
import {
  GITHUB_BROWSER_BINDINGS,
  legacyScopeToPdppSelection,
  projectPdppRecordsToLegacyPayload,
} from "./index.js";
import profileSchema from "./legacy-schemas/github.profile.json";
import repositoriesSchema from "./legacy-schemas/github.repositories.json";
import starredSchema from "./legacy-schemas/github.starred.json";
import eventsSchema from "./legacy-schemas/github.events.json";
import contributionsSchema from "./legacy-schemas/github.contributions.json";
import historySchema from "./legacy-schemas/github.history.json";
import {
  collectModernGithubBrowserFixtureSnapshot,
  GITHUB_BROWSER_PROTECTED_SCOPE_FIXTURES,
  matchesFrozenGithubLegacyOutput,
} from "./github-browser-parity-fixtures.js";

const schemas = {
  profile: profileSchema,
  repositories: repositoriesSchema,
  starred: starredSchema,
  events: eventsSchema,
  contributions: contributionsSchema,
  history: historySchema,
};
const snapshots: Record<keyof typeof schemas, Record<string, unknown>> = {
  profile: {
    id: "octocat",
    username: "octocat",
    fullName: "",
    bio: "",
    company: "",
    location: "",
    website: "",
    avatarUrl: "",
    followers: 0,
    following: 0,
    repositoryCount: 0,
    profileUrl: "https://github.com/octocat",
    pinnedRepositories: [
      {
        fullName: "octocat/Hello-World",
        description: "",
        language: null,
        stars: 0,
        url: "https://github.com/octocat/Hello-World",
      },
    ],
    organizations: [{ login: "github", label: "GitHub", avatarUrl: null }],
    achievements: [{ name: "Pull Shark", iconUrl: null }],
    contributionsLastYear: 4,
  },
  repositories: {
    id: "octocat",
    repositories: [
      {
        name: "Hello-World",
        description: "",
        language: "",
        updatedAt: null,
        url: "https://github.com/octocat/Hello-World",
        stars: 1,
        forks: 0,
        visibility: "Public",
        topics: [],
      },
    ],
  },
  starred: {
    id: "octocat",
    starred: [
      {
        fullName: "other/repo",
        description: "",
        language: "",
        url: "https://github.com/other/repo",
        stars: 3,
        updatedAt: null,
      },
    ],
  },
  events: GITHUB_BROWSER_PROTECTED_SCOPE_FIXTURES["github.events"].snapshot,
  contributions:
    GITHUB_BROWSER_PROTECTED_SCOPE_FIXTURES["github.contributions"].snapshot,
  history: {
    id: "octocat",
    pullRequests: [
      {
        id: "pr-1",
        type: "pr",
        repo: "other/repo",
        labels: [],
        comments: 0,
        reactionsTotal: 0,
        isDraft: false,
      },
    ],
    issues: [],
    fetchedAt: "2026-09-23T00:00:00Z",
  },
};

const ajv = new Ajv({ strict: false });

describe("github-browser alternate legacy bindings", () => {
  it("pins the signed 0.2.1 profile bytes and checks every field and primary key", () => {
    const profileDigest = `sha256:${createHash("sha256")
      .update(
        readFileSync(
          new URL(
            "./declarations/github-browser.collection-profile.json",
            import.meta.url,
          ),
        ),
      )
      .digest("hex")}`;
    expect(profile.connector_key).toBe("github-browser");
    expect(profile.connector_id).toBe(
      "https://registry.pdpp.dev/connectors/github-browser",
    );
    expect(profile.version).toBe("0.2.1");
    expect(provenance.source.revision).toBe(
      "427deb1957efebf0f23f87b1d13183dc07b10d23",
    );
    expect(provenance.outputs["collection-profile.json"]).toBe(profileDigest);
    expect(profileDigest).toBe(
      "sha256:1d1ddb397072eb92649b047de4709be3536b5d93e997a2fbcbbc5ff0369a1154",
    );
    for (const [scope, binding] of GITHUB_BROWSER_BINDINGS) {
      const streamName = binding.pdppStreams[0];
      const stream = profile.streams.find((item) => item.name === streamName);
      expect(stream, scope).toBeDefined();
      expect(binding.primaryKey[streamName]).toEqual(stream?.primary_key);
      expect(binding.provenance[0]).toEqual({
        kind: "oci",
        ref: "ghcr.io/pdp-connect/connector/github-browser:0.2.1",
        digest:
          "sha256:f3c345b4aaac1a42887dc0e9fa021f591c618e642a1814ca8b0dfe9adc743dd8",
        path: `collection-profile.json#streams[name=${streamName}]`,
      });
      expect(binding.fieldsRead[streamName]).toEqual(
        Object.keys(stream?.schema.properties ?? {}).filter(
          (field) => field !== "id",
        ),
      );
      const legacy = schemas[streamName as keyof typeof schemas].schema;
      expect(
        Object.keys(stream?.schema.properties ?? {}).filter(
          (field) => field !== "id",
        ),
      ).toEqual(Object.keys(legacy.properties));
      expect(stream?.schema.required.filter((field) => field !== "id")).toEqual(
        legacy.required,
      );
    }
  });

  for (const stream of Object.keys(schemas) as (keyof typeof schemas)[]) {
    it(`selects and projects github.${stream} through the public adapter`, () => {
      const scope = `github.${stream}`;
      expect(
        legacyScopeToPdppSelection(scope, { profileKey: "github-browser" }),
      ).toEqual({
        ok: true,
        selection: { source: profile.connector_id, streams: [stream] },
      });
      const result = projectPdppRecordsToLegacyPayload(
        scope,
        [{ stream, data: snapshots[stream] }],
        { fetchedStreams: [stream], profileKey: "github-browser" },
      );
      expect(result.ok, JSON.stringify(result)).toBe(true);
      if (!result.ok) return;
      expect(result.payload).not.toHaveProperty("id");
      const validate = ajv.compile(schemas[stream].schema);
      expect(validate(result.payload), JSON.stringify(validate.errors)).toBe(
        true,
      );
      const expectedPayload =
        stream === "events"
          ? GITHUB_BROWSER_PROTECTED_SCOPE_FIXTURES["github.events"]
              .expectedLegacy
          : Object.fromEntries(
              Object.entries(snapshots[stream]).filter(([key]) => key !== "id"),
            );
      expect(result.payload).toEqual(expectedPayload);
    });
  }

  it("keeps the PAT choice and rejects unsupported selected profiles", () => {
    expect(legacyScopeToPdppSelection("github.profile")).toMatchObject({
      ok: true,
      selection: { source: "https://registry.pdpp.dev/connectors/github" },
    });
    expect(
      legacyScopeToPdppSelection("github.profile", { profileKey: "github" }),
    ).toMatchObject({ ok: true });
    expect(
      legacyScopeToPdppSelection("github.profile", { profileKey: "unmapped" }),
    ).toEqual({
      ok: false,
      error: {
        kind: "unsupported_profile",
        scope: "github.profile",
        profileKey: "unmapped",
      },
    });
    expect(
      projectPdppRecordsToLegacyPayload("github.profile", [], {
        fetchedStreams: [],
        profileKey: "unmapped",
      }),
    ).toEqual({
      ok: false,
      error: {
        kind: "unsupported_profile",
        scope: "github.profile",
        profileKey: "unmapped",
      },
    });
  });

  it("does not turn an absent or malformed snapshot into an empty legacy inventory", () => {
    expect(
      projectPdppRecordsToLegacyPayload("github.repositories", [], {
        fetchedStreams: ["repositories"],
        profileKey: "github-browser",
      }),
    ).toMatchObject({ ok: false, error: { kind: "incomplete_scope" } });
    expect(
      projectPdppRecordsToLegacyPayload(
        "github.repositories",
        [{ stream: "repositories", data: { id: "octocat" } }],
        { fetchedStreams: ["repositories"], profileKey: "github-browser" },
      ),
    ).toMatchObject({ ok: false, error: { kind: "incomplete_scope" } });
    expect(
      projectPdppRecordsToLegacyPayload(
        "github.repositories",
        [{ stream: "repositories", data: { repositories: [] } }],
        { fetchedStreams: ["repositories"], profileKey: "github-browser" },
      ),
    ).toMatchObject({ ok: false, error: { kind: "incomplete_scope" } });
  });

  it.each(Object.entries(GITHUB_BROWSER_PROTECTED_SCOPE_FIXTURES))(
    "projects raw-source-derived %s snapshots to frozen legacy output",
    async (scope, fixture) => {
      const modernSnapshot = await collectModernGithubBrowserFixtureSnapshot(
        scope,
        fixture.rawInput,
      );
      expect(modernSnapshot).toEqual(fixture.snapshot);
      const result = projectPdppRecordsToLegacyPayload(
        scope,
        [{ stream: fixture.stream, data: modernSnapshot }],
        { fetchedStreams: [fixture.stream], profileKey: "github-browser" },
      );
      expect(result.ok).toBe(true);
      if (result.ok)
        expect(matchesFrozenGithubLegacyOutput(scope, result.payload)).toBe(
          true,
        );
    },
  );
});

function project(
  stream: string,
  data: Record<string, unknown>,
  profileKey = "github-browser",
) {
  const result = projectPdppRecordsToLegacyPayload(
    `${profileKey === "meta" ? "instagram" : "github"}.${stream}`,
    [{ stream, data: { id: "fixture", ...data } }],
    { fetchedStreams: [stream], profileKey },
  );
  expect(result.ok, JSON.stringify(result)).toBe(true);
  if (!result.ok) throw new Error(JSON.stringify(result.error));
  return result.payload;
}

type Schema = {
  type: string | string[];
  properties?: Record<string, Schema>;
  items?: Schema;
};
function sample(schema: Schema, extras: boolean): unknown {
  if (schema.properties) {
    return {
      ...Object.fromEntries(
        Object.entries(schema.properties).map(([key, child]) => [
          key,
          sample(child, extras),
        ]),
      ),
      ...(extras
        ? {
            forkedFrom: "canonical-only",
            license: { name: "MIT" },
            unexpected: 1,
          }
        : {}),
    };
  }
  if (schema.items) return [sample(schema.items, extras)];
  const type = Array.isArray(schema.type) ? schema.type[0] : schema.type;
  return type === "number" ? 7 : type === "boolean" ? true : "real-value";
}

describe("frozen legacy GitHub and Meta contracts", () => {
  it.each(
    Object.entries(schemas).map(
      ([stream, document]) => [stream, document.schema] as const,
    ),
  )(
    "filters %s at every object level using its frozen schema",
    (stream, schema) => {
      const canonical = sample(schema, true) as Record<string, unknown>;
      const before = JSON.stringify(canonical);
      const expected = sample(schema, false) as Record<string, unknown>;
      if (stream === "events")
        expected.windowDescription =
          "Up to 300 most recent public events across all repositories (≈90 days, GitHub API limit)";
      if (stream === "history")
        expected.windowDescription =
          "Full lifetime authored PRs and Issues from /search/issues, up to 1000 per type.";
      expect(project(stream, canonical)).toEqual(expected);
      expect(JSON.stringify(canonical)).toBe(before);
    },
  );

  // Defaults are copied from the GitHub 1.5.0 collector evidence supplied in
  // assignment build-ps-legacy-contract-gh-meta-4884292, not schema optionality.
  const defaults = {
    fullName: "",
    bio: "",
    company: "",
    location: "",
    website: "",
    avatarUrl: "",
    followers: 0,
    following: 0,
    repositoryCount: 0,
    pinnedRepositories: [],
    organizations: [],
    achievements: [],
    contributionsLastYear: null,
  };
  it("fills only the documented profile defaults without changing canonical data", () => {
    const canonical = {
      username: "octocat",
      profileUrl: "https://github.com/octocat",
    };
    expect(project("profile", canonical)).toEqual({
      ...canonical,
      ...defaults,
    });
    expect(canonical).toEqual({
      username: "octocat",
      profileUrl: "https://github.com/octocat",
    });
  });
  it("does not share default arrays between projections", () => {
    const canonical = {
      username: "octocat",
      profileUrl: "https://github.com/octocat",
    };
    (project("profile", canonical).pinnedRepositories as unknown[]).push({
      fullName: "changed",
    });
    expect(project("profile", canonical).pinnedRepositories).toEqual([]);
  });

  const cases: [
    string,
    string,
    Record<string, unknown>,
    Record<string, unknown>,
  ][] = [
    [
      "profile",
      "pinnedRepositories",
      { fullName: "a/b" },
      {
        url: "https://github.com/a/b",
        description: "",
        language: null,
        stars: 0,
      },
    ],
    [
      "profile",
      "organizations",
      { login: "org", label: "Org", url: "https://github.com/org" },
      { avatarUrl: null },
    ],
    ["profile", "achievements", { name: "Pull Shark" }, { iconUrl: null }],
    [
      "repositories",
      "repositories",
      { name: "repo", url: "https://github.com/a/repo" },
      {
        description: "",
        language: "",
        stars: 0,
        forks: 0,
        visibility: "Public",
        topics: [],
        updatedAt: null,
      },
    ],
    [
      "starred",
      "starred",
      { fullName: "a/repo", url: "https://github.com/a/repo" },
      {
        description: "",
        language: "",
        stars: 0,
        updatedAt: null,
      },
    ],
  ];
  it.each(cases)(
    "restores exact absent defaults for %s.%s",
    (stream, field, identity, rowDefaults) => {
      const canonical = {
        username: "octocat",
        profileUrl: "https://github.com/octocat",
        [field]: [identity],
      };
      expect(project(stream, canonical)[field]).toEqual([
        { ...identity, ...rowDefaults },
      ]);
      expect(canonical[field]).toEqual([identity]);
      const actual = Object.fromEntries(
        Object.entries(rowDefaults).map(([key, value]) => [
          key,
          Array.isArray(value)
            ? ["real-topic"]
            : typeof value === "number"
              ? 9
              : "real-value",
        ]),
      );
      expect(
        project(stream, {
          ...canonical,
          [field]: [{ ...identity, ...actual }],
        })[field],
      ).toEqual([{ ...identity, ...actual }]);
    },
  );

  it.each<[Record<string, unknown>, string | null]>([
    [{ fullName: "a/b" }, "https://github.com/a/b"],
    [{ fullName: "a/b", url: undefined }, "https://github.com/a/b"],
    [{ fullName: "" }, null],
    [{}, null],
    [
      { fullName: "a/b", url: "https://example.com/canonical" },
      "https://example.com/canonical",
    ],
    [{ fullName: "a/b", url: "" }, ""],
    [{ fullName: "a/b", url: null }, null],
  ])("derives only absent pinned repository URLs for %j", (row, url) => {
    const before = { ...row };
    const canonical = {
      username: "octocat",
      profileUrl: "https://github.com/octocat",
      pinnedRepositories: [row],
    };
    expect(project("profile", canonical).pinnedRepositories).toEqual([
      {
        ...row,
        url,
        description: "",
        language: null,
        stars: 0,
      },
    ]);
    expect(canonical.pinnedRepositories).toStrictEqual([before]);
  });

  it("preserves null contribution totals and does not invent absent history fields", () => {
    expect(
      project("profile", {
        username: "a",
        profileUrl: "url",
        contributionsLastYear: null,
      }).contributionsLastYear,
    ).toBeNull();
    expect(
      project("history", { pullRequests: [], issues: [], fetchedAt: "now" }),
    ).toEqual({ pullRequests: [], issues: [], fetchedAt: "now" });
  });

  it.each([
    {},
    { bio: null, external_url: null },
    { bio: "", external_url: "" },
  ])("restores Meta's empty-string defaults for %j", (fields) => {
    const canonical = { username: "octocat", ...fields };
    const before = JSON.stringify(canonical);
    expect(project("profile", canonical, "meta")).toEqual({
      username: "octocat",
      full_name: "",
      bio: "",
      external_url: "",
    });
    expect(JSON.stringify(canonical)).toBe(before);
  });
  it("preserves supplied Meta strings and does not fill unrelated optional fields", () => {
    expect(
      project(
        "profile",
        {
          username: "octocat",
          full_name: "Octo Cat",
          bio: "Hello",
          external_url: "https://example.com",
        },
        "meta",
      ),
    ).toEqual({
      username: "octocat",
      full_name: "Octo Cat",
      bio: "Hello",
      external_url: "https://example.com",
    });
  });
});

function fieldTree(schema: Schema): unknown {
  return {
    ...(schema.properties
      ? {
          properties: Object.fromEntries(
            Object.entries(schema.properties).map(([key, child]) => [
              key,
              fieldTree(child),
            ]),
          ),
        }
      : {}),
    ...(schema.items ? { items: fieldTree(schema.items) } : {}),
  };
}

it("pins every declared GitHub field and nested field to the frozen schemas", () => {
  expect(GITHUB_LEGACY_FIELDS).toEqual(
    Object.fromEntries(
      Object.entries(schemas).map(([stream, document]) => [
        stream,
        fieldTree(document.schema),
      ]),
    ),
  );
});
