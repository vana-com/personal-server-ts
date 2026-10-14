/**
 * Captured connector parity and explicitly labelled binding regression goldens.
 * Captured goldens pair the PDPP streams
 * a PDPP bundle stored with the body the frozen legacy connector delivered,
 * both produced from the same upstream responses (see parity-oracle/). The
 * projection must reproduce that body except for the reviewed differences
 * the golden lists, and must validate against the pinned legacy schema.
 * Shop/Spotify/LinkedIn/Instagram/YouTube/Grocery and MISC_SCOPES expectations are current binding output,
 * not captured legacy-connector output; passing does not establish legacy parity.
 * Social fixtures separately expose synthetic consumer-contract differences.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import Ajv from "ajv";
import { describe, expect, it } from "vitest";
import { diffBodies, type BodyDifference } from "./__fixtures__/parity/diff.js";
import { projectPdppRecordsToLegacyPayload } from "./index.js";
import type {
  PdppRecord,
  ProjectionDiagnostic,
  ProjectionErr,
} from "./types.js";

interface Golden {
  scope: string;
  profileKey?: string;
  case?: string;
  cases?: Golden[];
  expectedResult?: ProjectionErr;
  expectedDiagnostics?: ProjectionDiagnostic[];
  provenance: {
    legacyConnector: string;
    pdppBundle: string;
    rawSourceAndExpectedFiles?: string[];
    profileCaveat?: string;
    emptyOrNullEdge?: string;
    expectedSideNote?: string;
    consumerContractNote?: string;
    outputKeysAndTypes?: string;
    legacySchemaNote?: string;
    outputContractNote?: string;
    behaviorNote?: string;
    legacySchemaComparison?: string;
    inputHandling?: string;
  };
  fetchedStreams: string[];
  streams: Record<string, Record<string, unknown>[]>;
  legacyBody?: Record<string, unknown>;
  // Synthetic consumer field-preservation probe, never a captured legacy body.
  // When present, reviewedDifferences compare this probe to legacyBody; the
  // traced current output is independently asserted without any exceptions.
  consumerContractBody?: Record<string, unknown>;
  expectedLegacySha256?: string;
  legacyBodyKeys?: string[];
  reviewedDifferences: (BodyDifference & { reason: string })[];
}

// The clock both scripts ran under; legacy stamped it into fetched_at and
// into a memory's null created_at.
const ORACLE_CLOCK = "2026-10-01T00:00:00.000Z";
const SOCIAL_SCOPES = [
  "linkedin.profile",
  "linkedin.experience",
  "linkedin.education",
  "instagram.profile",
  "instagram.posts",
];
const YOUTUBE_SCOPES = [
  "youtube.profile",
  "youtube.subscriptions",
  "youtube.playlists",
  "youtube.playlistItems",
  "youtube.likes",
  "youtube.watchLater",
  "youtube.history",
];
const GROCERY_SCOPES = [
  "heb.profile",
  "heb.orders",
  "heb.nutrition",
  "wholefoods.profile",
  "wholefoods.orders",
  "wholefoods.nutrition",
];
const FROZEN_DESKTOP_SCHEMA_PROVENANCE: Record<
  string,
  { path: string; sha256: string }
> = {
  "heb.profile": {
    path: "apps/desktop/connectors/heb/schemas/heb.profile.json",
    sha256: "0a27981ccdcffad91afd2a78a80407c67227b05ea1cf0c918ddfa5cb6338a3e0",
  },
  "heb.orders": {
    path: "apps/desktop/connectors/heb/schemas/heb.orders.json",
    sha256: "d3579f4ae1b163a1bbcbfb9d2177892d81c395cd29cc81937ac21b8d8cff2b45",
  },
  "heb.nutrition": {
    path: "apps/desktop/connectors/heb/schemas/heb.nutrition.json",
    sha256: "2dbc47a40391b7ee11c8601a2b2cd5bf327aaa552898f0d8c957dc111d92807c",
  },
  "wholefoods.profile": {
    path: "apps/desktop/connectors/wholefoods/schemas/wholefoods.profile.json",
    sha256: "53643cbb7f783a759691ad7eb25c06d41a4d6e245bde0e948fbccf2e60379bf1",
  },
  "wholefoods.orders": {
    path: "apps/desktop/connectors/wholefoods/schemas/wholefoods.orders.json",
    sha256: "0e3cfe49b006ea9811df4d398c131cc5c8f4a14137aea359a20777162bed1b1b",
  },
  "wholefoods.nutrition": {
    path: "apps/desktop/connectors/wholefoods/schemas/wholefoods.nutrition.json",
    sha256: "e362ab6d391debd007fa13df8fe8743a67439ce5e2395d41c14aa89f987882fa",
  },
  "chatgpt.conversations": {
    path: "apps/desktop/connectors/openai/schemas/chatgpt.conversations.json",
    sha256: "c83eba044962dfe4401c6f8637daac7aa7273fe88eaa9cd1734b7f51ca61265b",
  },
  "shop.orders": {
    path: "apps/desktop/connectors/shopify/schemas/shop.orders.json",
    sha256: "13ace1a15d6d5e4d19ed1e77169d50d203fd9f16d608e8e8f133a55b06199713",
  },
  "youtube.history": {
    path: "apps/desktop/connectors/google/schemas/youtube.history.json",
    sha256: "224811b6b73834e542f5d84f54a82acba095dfa64688592b658b0c97a73ba352",
  },
};
// Current-binding regressions at the 71a43bce cutover pin.
const MISC_SCOPES = [
  "github.repositories",
  "github.starred",
  "github.history",
  "icloud_notes.folders",
  "icloud_notes.notes",
  "linkedin.skills",
  "linkedin.languages",
  "linkedin.connections",
  "instagram.following",
  "instagram.ads",
];
const SCOPES = [
  "chatgpt.conversations",
  "chatgpt.memories",
  "claude.conversations",
  "claude.projects",
  "github.profile",
  "github.events",
  "github.contributions",
  "oura.readiness",
  "oura.sleep",
  "oura.activity",
  "shop.orders",
  "spotify.profile",
  "spotify.playlists",
  ...SOCIAL_SCOPES,
  ...YOUTUBE_SCOPES,
  ...GROCERY_SCOPES,
  ...MISC_SCOPES,
];
// Ajv follows each frozen schema's explicit additionalProperties rules. Some
// Desktop schemas intentionally leave selected objects open.
const ajv = new Ajv({ allErrors: true });

function load(scope: string): Golden {
  return JSON.parse(
    readFileSync(
      new URL(`./__fixtures__/parity/${scope}.json`, import.meta.url),
      "utf8",
    ),
  ) as Golden;
}

function records(golden: Golden): PdppRecord[] {
  return Object.entries(golden.streams).flatMap(([stream, rows]) =>
    rows.map((data) => ({ stream, data })),
  );
}

function schemaFor(scope: string): Record<string, unknown> {
  const file = JSON.parse(
    readFileSync(
      new URL(`./legacy-schemas/${scope}.json`, import.meta.url),
      "utf8",
    ),
  ) as { schema: Record<string, unknown> };
  return file.schema;
}

function frozenDesktopSchemaFor(scope: string): Record<string, unknown> {
  // The 33 matching Desktop schemas stay in legacy-schemas. These nine need
  // separate frozen copies because three active PS schemas were revised and
  // six were missing at the base revision.
  const directory = FROZEN_DESKTOP_SCHEMA_PROVENANCE[scope]
    ? "./__fixtures__/desktop-schemas"
    : "./legacy-schemas";
  const file = JSON.parse(
    readFileSync(
      new URL(`${directory}/${scope}.json`, import.meta.url),
      "utf8",
    ),
  ) as { schema: Record<string, unknown> };
  return file.schema;
}

// Exact per-case output keys/types keep the intentionally synthetic grocery
// binding regressions inspectable alongside the frozen Desktop schema oracle.
function outputKeyTypes(
  value: unknown,
  path = "$",
  result: Record<string, string> = {},
): Record<string, string> {
  result[path] =
    value === null ? "null" : Array.isArray(value) ? "array" : typeof value;
  if (value !== null && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      outputKeyTypes(
        child,
        Array.isArray(value) ? `${path}[${key}]` : `${path}.${key}`,
        result,
      );
    }
  }
  return result;
}

type SchemaIssue = {
  case: string;
  body: "expected" | "projected";
  path: string;
  rule: string;
};

// Filled from the frozen Desktop schema oracle below. A listed violation is a
// visible parity gap, and the companion `it.fails` case keeps it visible in the
// test report while the exact register prevents new or changed violations.
const KNOWN_FROZEN_SCHEMA_GAPS: Record<string, SchemaIssue[]> = {
  "chatgpt.conversations": [
    {
      case: "normal",
      body: "expected",
      path: "$.conversations[*].fetched_at",
      rule: "additionalProperties: should NOT have additional properties",
    },
    {
      case: "normal",
      body: "expected",
      path: "$.conversations[*].create_time",
      rule: "type: should be string",
    },
    {
      case: "normal",
      body: "projected",
      path: "$.conversations[*].fetched_at",
      rule: "additionalProperties: should NOT have additional properties",
    },
  ],
  "shop.orders": [
    ...["normal", "empty", "dirty-row"].flatMap((caseName) =>
      (["expected", "projected"] as const).map((body) => ({
        case: caseName,
        body,
        path: "$.total",
        rule: "additionalProperties: should NOT have additional properties",
      })),
    ),
  ],
  "youtube.history": [
    {
      case: "normal",
      body: "expected",
      path: "$.history[*].watchedAt",
      rule: "additionalProperties: should NOT have additional properties",
    },
    {
      case: "normal",
      body: "projected",
      path: "$.history[*].watchedAt",
      rule: "additionalProperties: should NOT have additional properties",
    },
  ],
};

function schemaIssues(
  scope: string,
  caseName: string,
  body: "expected" | "projected",
  payload: Record<string, unknown>,
): SchemaIssue[] {
  const validate = ajv.compile(frozenDesktopSchemaFor(scope));
  if (validate(payload)) return [];
  const issues = (validate.errors ?? []).map((error) => {
    const legacyDataPath = (error as { dataPath?: string }).dataPath;
    const rawPath =
      error.instancePath ||
      (legacyDataPath ?? "")
        .replace(/\[(\d+)\]/g, "[*]")
        .replace(/^\./, (path) => `$${path}`);
    const parentPath = rawPath || "$";
    const issuePath =
      error.keyword === "additionalProperties" &&
      typeof error.params.additionalProperty === "string"
        ? `${parentPath}.${error.params.additionalProperty}`
        : parentPath;
    return {
      case: caseName,
      body,
      path: issuePath,
      rule: `${error.keyword}: ${error.message}`,
    };
  });
  return [
    ...new Map(issues.map((issue) => [JSON.stringify(issue), issue])).values(),
  ];
}

function frozenSchemaIssuesForScope(scope: string): SchemaIssue[] {
  const golden = load(scope);
  const goldens = [golden, ...(golden.cases ?? [])];
  return goldens.flatMap((entry) => {
    if (entry.expectedResult) return [];
    const result = projectPdppRecordsToLegacyPayload(scope, records(entry), {
      fetchedStreams: entry.fetchedStreams,
      now: ORACLE_CLOCK,
      profileKey: entry.profileKey,
    });
    if (!result.ok) {
      throw new Error(
        `Cannot validate projected ${scope} ${entry.case ?? "normal"}: ${result.error.kind}`,
      );
    }
    // GitHub contributions stores its expected body as a SHA-256 plus key list.
    // The existing golden hash assertion binds this projected value to that
    // compact expected body before it is validated as both expected and output.
    const expectedBody =
      entry.legacyBody ??
      (entry.expectedLegacySha256 &&
      payloadSha256(result.payload) === entry.expectedLegacySha256
        ? result.payload
        : undefined);
    if (!expectedBody) {
      throw new Error(
        `Missing expected legacy body for ${scope} ${entry.case ?? "normal"}`,
      );
    }
    const expectedIssues = schemaIssues(
      scope,
      entry.case ?? "normal",
      "expected",
      expectedBody,
    );
    const projectedIssues = schemaIssues(
      scope,
      entry.case ?? "normal",
      "projected",
      result.payload,
    );
    return [...expectedIssues, ...projectedIssues];
  });
}

describe("frozen Desktop schema conformance", () => {
  it("keeps the vendored Desktop schemas byte-identical", () => {
    for (const [scope, provenance] of Object.entries(
      FROZEN_DESKTOP_SCHEMA_PROVENANCE,
    )) {
      const bytes = readFileSync(
        new URL(
          `./__fixtures__/desktop-schemas/${scope}.json`,
          import.meta.url,
        ),
      );
      expect(createHash("sha256").update(bytes).digest("hex"), scope).toBe(
        provenance.sha256,
      );
      if (
        [
          "heb.profile",
          "heb.orders",
          "heb.nutrition",
          "wholefoods.profile",
          "wholefoods.orders",
          "wholefoods.nutrition",
        ].includes(scope)
      ) {
        const legacyBytes = readFileSync(
          new URL(`./legacy-schemas/${scope}.json`, import.meta.url),
        );
        expect(legacyBytes.equals(bytes), `${scope} legacy copy`).toBe(true);
      }
    }
  });

  it("matches the explicit known-gap register", () => {
    const actual = Object.fromEntries(
      SCOPES.map((scope) => [scope, frozenSchemaIssuesForScope(scope)]),
    );
    const actualGaps = Object.fromEntries(
      Object.entries(actual).filter(([, issues]) => issues.length > 0),
    );
    expect(actualGaps).toEqual(KNOWN_FROZEN_SCHEMA_GAPS);
  });

  for (const scope of SCOPES) {
    const gaps = KNOWN_FROZEN_SCHEMA_GAPS[scope];
    if (gaps) {
      it.fails(
        `${scope} is a known frozen-schema GAP: ${gaps.map((gap) => `${gap.path} ${gap.rule}`).join("; ")}`,
        () => {
          expect(frozenSchemaIssuesForScope(scope)).toEqual([]);
        },
      );
    } else {
      it(`${scope} expected and projected bodies validate`, () => {
        expect(frozenSchemaIssuesForScope(scope)).toEqual([]);
      });
    }
  }
});

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`,
      )
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function payloadSha256(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function expectGoldenBody(golden: Golden, payload: Record<string, unknown>) {
  const expectedDifferences = golden.reviewedDifferences.map(
    ({ path, legacy, projected }) => ({ path, legacy, projected }),
  );
  if (golden.consumerContractBody) {
    // Reviewed consumer losses cannot mask a regression in the binding output.
    expect(payload).toEqual(golden.legacyBody);
    expect(diffBodies(golden.consumerContractBody, payload)).toEqual(
      expectedDifferences,
    );
    for (const difference of golden.reviewedDifferences) {
      expect(difference.reason.trim().length).toBeGreaterThan(0);
    }
  } else {
    expect(diffBodies(golden.legacyBody, payload)).toEqual(expectedDifferences);
  }
}

function expectMiscProvenance(golden: Golden) {
  expect(golden.provenance.legacyConnector).toMatch(
    /^current binding output, not captured legacy-connector output; (github\.(repositories|starred|history)|icloud_notes\.(notes|folders)|linkedin\.(skills|languages|connections)|instagram\.(following|ads)|chatgpt\.memories) from packages\/core\/src\/legacy-projection\/bindings\.ts at personal-server-ts commit 71a43bce98f0dde2ec1ddc3d7ad03d701cc0f665$/,
  );
  expect(golden.provenance.pdppBundle).toMatch(
    /^synthetic (github\.(repositories|starred|history)|icloud_notes\.(notes|folders)|linkedin\.(skills|languages|connections)|instagram\.(following|ads)|chatgpt\.memories) records against vendored declarations at personal-server-ts commit 71a43bce98f0dde2ec1ddc3d7ad03d701cc0f665; no bundle executed$/,
  );
  expect(golden.provenance.legacyConnector).toContain(
    "; " + golden.scope + " from ",
  );
  expect(golden.provenance.pdppBundle).toContain(
    "synthetic " + golden.scope + " records ",
  );
  expect(golden.provenance.expectedSideNote).toBe(
    "current binding output, not captured legacy-connector output",
  );
  expect(golden.provenance.outputKeysAndTypes).toBeTruthy();
  expect(golden.provenance.legacySchemaComparison).toBe(
    "Frozen Desktop schema is checked by parity-goldens.test.ts. These expectations establish current-binding regression coverage only.",
  );
  expect(golden.case).toBe("normal");
  expect(golden.reviewedDifferences).toEqual([]);
  expect(golden.profileKey).toBe(
    golden.scope.startsWith("instagram.") ? "meta" : undefined,
  );
}

describe.each(SCOPES)("%s golden projection contract", (scope) => {
  const golden = load(scope);

  it("records the legacy and fixture provenance", () => {
    expect(golden.scope).toBe(scope);
    if (
      [
        "chatgpt.conversations",
        "chatgpt.memories",
        "claude.conversations",
        "claude.projects",
      ].includes(scope)
    ) {
      expect(golden.provenance.legacyConnector).toMatch(
        /^(chatgpt-4\.0\.0-vana\.1\.js|claude-export-playwright\.js) .* sha256:[0-9a-f]{64}$/,
      );
      expect(golden.provenance.pdppBundle).toMatch(/sha256:[0-9a-f]{64}$/);
    } else if (MISC_SCOPES.includes(scope)) {
      expectMiscProvenance(golden);
    } else if (scope.startsWith("github.")) {
      expect(golden.provenance.legacyConnector).toMatch(
        /^frozen github-playwright 1\.5\.1; archive sha256:[0-9a-f]{64}; script\.js sha256:[0-9a-f]{64}; expected output and PDPP record source: .*github-browser-parity-fixtures\.ts at unity-surfaces commit [0-9a-f]{40} sha256:[0-9a-f]{64}$/,
      );
      expect(golden.provenance.pdppBundle).toMatch(
        /^github-browser 0\.2\.0 snapshots from PDP-Connect\/data-connectors commit [0-9a-f]{40}; frozen inputs recorded in github-browser-parity-fixtures\.ts; provenance source: .*github-browser-parity-fixtures\.ts at unity-surfaces commit [0-9a-f]{40} sha256:[0-9a-f]{64}; read-time projection source: personal-server-ts commit [0-9a-f]{40}; fixture source sha256:[0-9a-f]{64}$/,
      );
    } else if (
      ["shop.orders", "spotify.profile", "spotify.playlists"].includes(scope)
    ) {
      expect(golden.provenance.legacyConnector).toMatch(
        /^current binding output, not captured legacy-connector output; (shop\.orders|spotify\.(profile|playlists)) from packages\/core\/src\/legacy-projection\/bindings\.ts at personal-server-ts commit 81e63d84c38dd45c47073daf790b8905c834c553$/,
      );
      expect(golden.provenance.pdppBundle).toMatch(
        /^synthetic (shop\.orders|spotify\.(profile|playlists)) records against vendored declarations at personal-server-ts commit 81e63d84c38dd45c47073daf790b8905c834c553; no bundle executed$/,
      );
      expect(golden.provenance.expectedSideNote).toBe(
        "current binding output, not captured legacy-connector output",
      );
    } else if (GROCERY_SCOPES.includes(scope)) {
      expect(golden.provenance.legacyConnector).toMatch(
        /^current binding output, not captured legacy-connector output; (heb|wholefoods)\.(profile|orders|nutrition) from packages\/core\/src\/legacy-projection\/bindings\.ts at personal-server-ts commit 71a43bce98f0dde2ec1ddc3d7ad03d701cc0f665$/,
      );
      expect(golden.provenance.pdppBundle).toMatch(
        /^synthetic (heb|wholefoods)\.(profile|orders|nutrition) records against vendored declarations at personal-server-ts commit 71a43bce98f0dde2ec1ddc3d7ad03d701cc0f665; no bundle executed$/,
      );
      expect(golden.provenance.expectedSideNote).toBe(
        "current binding output, not captured legacy-connector output",
      );
      const schemaProvenance = FROZEN_DESKTOP_SCHEMA_PROVENANCE[scope];
      expect(schemaProvenance).toBeDefined();
      expect(golden.provenance.legacySchemaNote).toBe(
        `Frozen Desktop schema from vana-com/unity-surfaces commit 9155456f7a90a10b7af902c7ae5ea68ee8cef12d, ${schemaProvenance.path}; sha256:${schemaProvenance.sha256}.`,
      );
      expect(
        createHash("sha256")
          .update(
            readFileSync(
              new URL(
                `./__fixtures__/desktop-schemas/${scope}.json`,
                import.meta.url,
              ),
            ),
          )
          .digest("hex"),
      ).toBe(schemaProvenance.sha256);
      expect(golden.provenance.consumerContractNote).toBe(
        "consumerContractBody is a synthetic input-field-preservation probe, not captured legacy output; reviewedDifferences contain only fields actually present in the input and omitted by the binding.",
      );
      expect(golden.case).toBe("normal");
      expect(golden.provenance.behaviorNote?.length).toBeGreaterThan(0);
      expect(JSON.parse(golden.provenance.outputContractNote!)).toEqual(
        Object.fromEntries(
          [golden, ...(golden.cases ?? [])].map((entry) => [
            entry.case,
            outputKeyTypes(entry.legacyBody ?? entry.expectedResult),
          ]),
        ),
      );
    } else if (SOCIAL_SCOPES.includes(scope)) {
      expect(golden.provenance.legacyConnector).toMatch(
        /^current binding output, not captured legacy-connector output; (linkedin\.(profile|experience|education) from packages\/core\/src\/legacy-projection\/bindings\.ts|instagram\.(profile|posts) from packages\/core\/src\/legacy-projection\/bindings\.ts \+ meta-040-bindings\.ts \(profileKey=meta\)) at personal-server-ts commit 0369cea68154b9bc01c37acccb66c2d5c01e4382$/,
      );
      expect(golden.provenance.pdppBundle).toMatch(
        /^synthetic (linkedin\.(profile|experience|education)|instagram\.(profile|posts)) records against vendored declarations at personal-server-ts commit 0369cea68154b9bc01c37acccb66c2d5c01e4382; no bundle executed$/,
      );
      expect(golden.provenance.expectedSideNote).toBe(
        "current binding output, not captured legacy-connector output",
      );
      expect(golden.provenance.consumerContractNote).toBe(
        "consumerContractBody is a synthetic field-preservation probe, not captured legacy output; legacyBody is the traced current binding output. reviewedDifferences compare the probe with that output and do not certify consumer compatibility.",
      );
      expect(golden.case).toBe("normal");
      expect(golden.consumerContractBody).toBeDefined();
      expect(golden.reviewedDifferences.length).toBeGreaterThan(0);
      expect(golden.profileKey).toBe(
        scope.startsWith("instagram.") ? "meta" : undefined,
      );
    } else if (YOUTUBE_SCOPES.includes(scope)) {
      expect(golden.provenance.legacyConnector).toMatch(
        /^current binding output, not captured legacy-connector output; youtube\.(profile|subscriptions|playlists|playlistItems|likes|watchLater|history) from packages\/core\/src\/legacy-projection\/bindings\.ts at personal-server-ts commit 71a43bce98f0dde2ec1ddc3d7ad03d701cc0f665$/,
      );
      expect(golden.provenance.pdppBundle).toMatch(
        /^synthetic youtube\.(profile|subscriptions|playlists|playlistItems|likes|watchLater|history) records against vendored declarations at personal-server-ts commit 71a43bce98f0dde2ec1ddc3d7ad03d701cc0f665; no bundle executed$/,
      );
      expect(golden.provenance.expectedSideNote).toBe(
        "current binding output, not captured legacy-connector output",
      );
      expect(golden.provenance.outputKeysAndTypes).toBeTruthy();
      expect(golden.case).toBe("normal");
      expect(golden.reviewedDifferences).toEqual([]);
    } else {
      expect(golden.provenance.legacyConnector).toMatch(
        /^OpenPet nullable-score contract from .*\/client-reconciliation\.md sha256:[0-9a-f]{64} \(evidence checkout has no Git metadata\); expected field assertions from .*\/oura-browser\.test\.ts at unity-surfaces commit [0-9a-f]{40} sha256:[0-9a-f]{64}$/,
      );
      expect(golden.provenance.pdppBundle).toMatch(
        /^oura-browser 0\.1\.2 stream binding from .*\/oura-browser\.test\.ts at unity-surfaces commit [0-9a-f]{40} sha256:[0-9a-f]{64}; PS projection source: personal-server-ts commit [0-9a-f]{40}; fixture source sha256:[0-9a-f]{64}$/,
      );
      expect(golden.provenance.expectedSideNote).toBe(
        "OpenPet-shaped expectation from Desktop's oura-browser test, not a captured legacy-connector output.",
      );
    }
    if (golden.provenance.rawSourceAndExpectedFiles) {
      expect(
        golden.provenance.rawSourceAndExpectedFiles.length,
      ).toBeGreaterThan(0);
      expect(golden.provenance.profileCaveat).toBeTruthy();
      expect(golden.provenance.emptyOrNullEdge).toBeTruthy();
    }
  });

  it.each([
    ["source order", false],
    ["primary-key order", true],
  ])(
    "projects to the legacy body except the reviewed differences (%s)",
    (_label, orderByPrimaryKey) => {
      const result = projectPdppRecordsToLegacyPayload(scope, records(golden), {
        fetchedStreams: golden.fetchedStreams,
        now: ORACLE_CLOCK,
        orderByPrimaryKey,
        profileKey: golden.profileKey,
      });

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.diagnostics).toEqual(golden.expectedDiagnostics);
      if (golden.expectedLegacySha256) {
        expect(payloadSha256(result.payload)).toBe(golden.expectedLegacySha256);
      } else {
        expect(golden.legacyBody).toBeDefined();
        expectGoldenBody(golden, result.payload);
      }
    },
  );

  it("keeps the legacy body's top-level keys", () => {
    const result = projectPdppRecordsToLegacyPayload(scope, records(golden), {
      fetchedStreams: golden.fetchedStreams,
      now: ORACLE_CLOCK,
      profileKey: golden.profileKey,
    });
    const expectedKeys = golden.legacyBody
      ? Object.keys(golden.legacyBody)
      : golden.legacyBodyKeys;
    expect(result.ok && Object.keys(result.payload)).toEqual(expectedKeys);
  });

  it("reviews each time-format difference as the same instant", () => {
    for (const difference of golden.reviewedDifferences) {
      if (!difference.reason.startsWith("time format")) continue;
      const instant = (value: unknown) =>
        typeof value === "number"
          ? value * 1000
          : Date.parse(String(value).replace(/(\.\d{3})\d+/, "$1"));
      expect(instant(difference.legacy), difference.path).toBe(
        instant(difference.projected),
      );
    }
  });
});

describe.each([
  "shop.orders",
  "spotify.profile",
  "spotify.playlists",
  ...SOCIAL_SCOPES,
  ...YOUTUBE_SCOPES,
  ...GROCERY_SCOPES,
  ...MISC_SCOPES,
])("%s current-binding empty and dirty-row regressions", (scope) => {
  const golden = load(scope);

  it("includes both required edge cases", () => {
    expect(golden.cases?.map((entry) => entry.case)).toEqual([
      "empty",
      "dirty-row",
    ]);
  });

  describe.each(golden.cases ?? [])("$case", (edge) => {
    it("retains the explicitly non-legacy provenance", () => {
      expect(edge.scope).toBe(scope);
      expect(edge.provenance).toEqual(golden.provenance);
      expect(edge.profileKey).toBe(golden.profileKey);
      if (SOCIAL_SCOPES.includes(scope) && edge.case === "dirty-row") {
        expect(edge.consumerContractBody).toBeDefined();
        expect(edge.reviewedDifferences.length).toBeGreaterThan(0);
      } else if (GROCERY_SCOPES.includes(scope) && edge.consumerContractBody) {
        expect(edge.reviewedDifferences.length).toBeGreaterThan(0);
        expect(
          edge.reviewedDifferences.every(
            (entry) => entry.projected === "<absent>",
          ),
        ).toBe(true);
      } else {
        expect(edge.reviewedDifferences).toEqual([]);
      }
    });

    it.each([
      ["source order", false],
      ["primary-key order", true],
    ])(
      "matches the traced binding result (%s)",
      (_label, orderByPrimaryKey) => {
        const result = projectPdppRecordsToLegacyPayload(scope, records(edge), {
          fetchedStreams: edge.fetchedStreams,
          now: ORACLE_CLOCK,
          orderByPrimaryKey,
          profileKey: edge.profileKey,
        });

        if (
          ["spotify.profile", "linkedin.profile", "instagram.profile"].includes(
            scope,
          ) &&
          edge.case === "empty"
        ) {
          const expected = {
            ok: false,
            error: { kind: "empty_singleton", scope },
          };
          expect(edge.expectedResult).toEqual(expected);
          expect(edge.legacyBody).toBeUndefined();
          expect(result).toEqual(expected);
          return;
        }

        if (edge.expectedResult) {
          expect(edge.expectedResult.error.scope).toBe(scope);
          expect(edge.legacyBody).toBeUndefined();
          expect(edge.expectedDiagnostics).toBeUndefined();
          expect(result).toEqual(edge.expectedResult);
          return;
        }

        expect(edge.expectedResult).toBeUndefined();
        expect(edge.legacyBody).toBeDefined();
        expect(result.ok).toBe(true);
        if (!result.ok) return;
        expect(result.diagnostics).toEqual(edge.expectedDiagnostics);
        expect(result.payload).toEqual(edge.legacyBody);
        expectGoldenBody(edge, result.payload);
        expect(Object.keys(result.payload)).toEqual(
          Object.keys(edge.legacyBody!),
        );
      },
    );
  });
});

describe("the parity diff", () => {
  const conversations = [{ id: "a" }, { id: "b" }, { id: "c" }];

  it("reports a different element order", () => {
    expect(
      diffBodies(
        { conversations },
        { conversations: [...conversations].reverse() },
      ),
    ).toEqual([
      {
        path: "conversations[order]",
        legacy: ["a", "b", "c"],
        projected: ["c", "b", "a"],
      },
    ]);
  });

  it("reports a duplicated element", () => {
    expect(
      diffBodies(
        { conversations },
        { conversations: [...conversations, conversations[0]] },
      ),
    ).toEqual([{ path: "conversations[id=a]#count", legacy: 1, projected: 2 }]);
  });
});

describe("chatgpt.conversations in a stable order", () => {
  it("follows legacy's newest-update-first order whatever order rows were stored in", () => {
    const golden = load("chatgpt.conversations");
    const shuffled = records(golden).reverse();
    const result = projectPdppRecordsToLegacyPayload(
      "chatgpt.conversations",
      shuffled,
      {
        fetchedStreams: golden.fetchedStreams,
        now: ORACLE_CLOCK,
        orderByPrimaryKey: true,
      },
    );
    const ids = (body: unknown) =>
      (body as { conversations: { id: string }[] }).conversations.map(
        (conversation) => conversation.id,
      );
    expect(result.ok && ids(result.payload)).toEqual(ids(golden.legacyBody));
  });

  it("breaks an update_time tie by id and puts a missing time last", () => {
    const conversation = (id: string, update_time: string | null) => ({
      stream: "conversations",
      data: {
        id,
        title: id,
        create_time: null,
        update_time,
        current_node: null,
        message_count_on_current_branch: 0,
      },
    });
    const result = projectPdppRecordsToLegacyPayload(
      "chatgpt.conversations",
      [
        conversation("z", null),
        conversation("c", "2026-09-01T00:00:00.000Z"),
        conversation("b", "2026-09-02T00:00:00.000Z"),
        conversation("a", "2026-09-01T00:00:00.000Z"),
      ],
      {
        fetchedStreams: ["conversations", "messages"],
        now: ORACLE_CLOCK,
        orderByPrimaryKey: true,
      },
    );
    expect(
      result.ok &&
        (
          result.payload as { conversations: { id: string }[] }
        ).conversations.map((c) => c.id),
    ).toEqual(["b", "a", "c", "z"]);
  });
});

describe("ChatGPT edge-case parity observations", () => {
  const conversation = (
    id: string,
    update_time: string,
    extras: Record<string, unknown> = {},
  ): PdppRecord => ({
    stream: "conversations",
    data: {
      id,
      title: id,
      create_time: "2026-09-01T00:00:00.000Z",
      update_time,
      current_node: null,
      message_count_on_current_branch: 0,
      ...extras,
    },
  });

  it("projects a conversation with zero messages as an empty message list", () => {
    // Current behavior, not legacy-verified: the ChatGPT parity fixture has
    // no zero-message row; the Unity adapter test is a projector assertion,
    // not a captured legacy output (Unity commit 01164027ecac1403b867d8b5fef9a930dbcf69eb).
    const result = projectPdppRecordsToLegacyPayload(
      "chatgpt.conversations",
      [conversation("empty", "2026-09-01T00:00:00.000Z")],
      { fetchedStreams: ["conversations", "messages"], now: ORACLE_CLOCK },
    );

    expect(result).toEqual({
      ok: true,
      payload: {
        conversations: [
          {
            id: "empty",
            title: "empty",
            create_time: "2026-09-01T00:00:00.000Z",
            update_time: "2026-09-01T00:00:00.000Z",
            message_count: 0,
            messages: [],
            fetched_at: ORACLE_CLOCK,
          },
        ],
        total: 1,
      },
    });
  });

  it("omits the bad-timestamp peer, falls back for a missing title, and keeps the valid peer", () => {
    // Current behavior, not legacy-verified: neither the PS ChatGPT parity
    // fixture nor Unity's legacy-scope-adapter index.test.ts captures output
    // from the legacy connector for these peers (Unity commit above).
    const result = projectPdppRecordsToLegacyPayload(
      "chatgpt.conversations",
      [
        conversation("valid", "2026-09-03T00:00:00.000Z"),
        conversation("bad-time", "2026-09-02T00:00:00.000Z", {
          create_time: 17,
        }),
        conversation("missing-title", "2026-09-01T00:00:00.000Z", {
          title: undefined,
        }),
      ],
      {
        fetchedStreams: ["conversations", "messages"],
        now: ORACLE_CLOCK,
        orderByPrimaryKey: true,
      },
    );

    expect(result).toEqual({
      ok: true,
      payload: {
        conversations: [
          {
            id: "valid",
            title: "valid",
            create_time: "2026-09-01T00:00:00.000Z",
            update_time: "2026-09-03T00:00:00.000Z",
            message_count: 0,
            messages: [],
            fetched_at: ORACLE_CLOCK,
          },
          {
            id: "missing-title",
            title: "Untitled",
            create_time: "2026-09-01T00:00:00.000Z",
            update_time: "2026-09-01T00:00:00.000Z",
            message_count: 0,
            messages: [],
            fetched_at: ORACLE_CLOCK,
          },
        ],
        total: 2,
      },
      diagnostics: [
        {
          kind: "records_dropped",
          scope: "chatgpt.conversations",
          stream: "conversations",
          count: 1,
          reasons: ["Conversation timestamps must be strings, null, or absent"],
        },
      ],
    });
  });

  it("projects a zero-row fetched memories stream as an empty payload", () => {
    // Current behavior, not legacy-verified: the existing captured memories
    // fixture contains rows, while Unity's zero-row case is a projector test.
    const result = projectPdppRecordsToLegacyPayload("chatgpt.memories", [], {
      fetchedStreams: ["memories"],
      now: ORACLE_CLOCK,
    });

    expect(result).toEqual({
      ok: true,
      payload: { memories: [], total: 0 },
    });
  });

  it("orders reverse-supplied conversations by newest update first", () => {
    const result = projectPdppRecordsToLegacyPayload(
      "chatgpt.conversations",
      [
        conversation("newer", "2026-09-03T00:00:00.000Z"),
        conversation("older", "2026-09-01T00:00:00.000Z"),
      ],
      {
        fetchedStreams: ["conversations", "messages"],
        now: ORACLE_CLOCK,
        orderByPrimaryKey: true,
      },
    );

    expect(
      result.ok &&
        (result.payload.conversations as { id: string }[]).map(({ id }) => id),
    ).toEqual(["newer", "older"]);
  });
});

// Keep the existing captured chatgpt.memories golden and its provenance intact.
describe("chatgpt.memories supplementary current-binding goldens", () => {
  const golden = load("chatgpt.memories.edges");

  it("records the separate current-binding provenance and required cases", () => {
    expect(golden.scope).toBe("chatgpt.memories");
    expectMiscProvenance(golden);
    expect(golden.cases?.map((entry) => entry.case)).toEqual([
      "empty",
      "dirty-row",
    ]);
  });

  describe.each([golden, ...(golden.cases ?? [])])("$case", (entry) => {
    it.each([
      ["source order", false],
      ["primary-key order", true],
    ])("matches the traced memory output (%s)", (_label, orderByPrimaryKey) => {
      expect(entry.scope).toBe(golden.scope);
      expect(entry.provenance).toEqual(golden.provenance);
      expect(entry.profileKey).toBeUndefined();
      expect(entry.reviewedDifferences).toEqual([]);
      expect(entry.expectedResult).toBeUndefined();
      const result = projectPdppRecordsToLegacyPayload(
        entry.scope,
        records(entry),
        {
          fetchedStreams: entry.fetchedStreams,
          now: ORACLE_CLOCK,
          orderByPrimaryKey,
        },
      );
      expect(result).toEqual({ ok: true, payload: entry.legacyBody });
      if (!result.ok) return;
      expectGoldenBody(entry, result.payload);
      expect(Object.keys(result.payload)).toEqual(
        Object.keys(entry.legacyBody!),
      );
      const validate = ajv.compile(schemaFor(entry.scope));
      expect(
        validate(result.payload),
        JSON.stringify(validate.errors, null, 2),
      ).toBe(true);
    });
  });
});
