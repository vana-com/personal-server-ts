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
    profileUrl: "https://github.com/octocat",
    pinnedRepositories: [
      {
        fullName: "octocat/Hello-World",
        url: "https://github.com/octocat/Hello-World",
      },
    ],
    organizations: [{ login: "github", label: "GitHub" }],
    achievements: [{ name: "Pull Shark" }],
    contributionsLastYear: 4,
  },
  repositories: {
    id: "octocat",
    repositories: [
      {
        name: "Hello-World",
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
