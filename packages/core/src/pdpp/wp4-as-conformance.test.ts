/**
 * Locked PDPP Core v0.1.0 §9 AS items covered by work package 4, at the Core
 * layer: public detail validation (items 2, 5, 6, 11, 14, 27, 31, 33, case
 * O7), language maps and display-language choice (items 22, 34), review
 * digest binding (item 15), envelope disclosure (item 31), ineligible
 * streams (item 53), the `{ type, grant }` result (item 32) and RFC 7009
 * revocation with dispositions (items 25, 44).
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  APPENDIX_A_PURPOSE_CODES,
  SUPPORTED_PROCESSING_PERMISSIONS,
  validatePublicDetail,
} from "./public-validation.js";
import {
  chooseLanguageVersion,
  isWellFormedLanguageTag,
  parseUiLocales,
  validateLanguageMap,
} from "./language.js";
import { parseDeclaration } from "./declaration.js";
import {
  buildConsentReview,
  ENVELOPE_DISCLOSURE_STATEMENT,
  type RequesterIdentity,
} from "./review.js";
import { resolveSelection } from "./resolve.js";
import { openPdppAuthStore, type PdppAuthStore } from "./store.js";
import { PdppTokenService, toAuthorizationEntry } from "./tokens.js";
import {
  PDPP_DATA_ACCESS_TYPE,
  PDPP_DATA_ACCESS_TYPE_CANDIDATE,
  PDPP_DATA_ACCESS_TYPE_V02,
  type DeclarationSnapshot,
  type Grant,
  type SelectionRequest,
} from "./types.js";

const SOURCE = "https://registry.pdpp.dev/connectors/spotify";

function detail(overrides: Record<string, unknown> = {}) {
  return {
    type: PDPP_DATA_ACCESS_TYPE,
    source: { id: SOURCE },
    purpose_code: "https://pdpp.dev/purpose/personalization",
    access_mode: "continuous",
    streams: [{ name: "top_artists", fields: ["*"] }],
    ...overrides,
  };
}

function rejected(value: unknown, opts = {}) {
  const result = validatePublicDetail(value, opts);
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error("unreachable");
  expect(result.failure.code).toBe("invalid_authorization_details");
  return result.failure.message;
}

describe("AS items 5, 33 — types and undefined members", () => {
  it("accepts a well-formed locked detail", () => {
    expect(validatePublicDetail(detail()).ok).toBe(true);
  });

  it("rejects an unsupported type", () => {
    rejected(detail({ type: "https://example.com/other" }));
  });

  it("rejects the candidate alias unless the deployment enables it", () => {
    rejected(detail({ type: PDPP_DATA_ACCESS_TYPE_CANDIDATE }));
    expect(
      validatePublicDetail(detail({ type: PDPP_DATA_ACCESS_TYPE_CANDIDATE }), {
        candidateEnabled: true,
      }).ok,
    ).toBe(true);
  });

  it("rejects an undefined member on the detail (RFC 9396 §5, L1099)", () => {
    expect(rejected(detail({ future_control: true }))).toMatch(
      /future_control/,
    );
  });

  it("rejects an undefined member on a stream request", () => {
    rejected(detail({ streams: [{ name: "a", fields: ["*"], sort: "x" }] }));
  });

  it("rejects a source carrying anything but id (provenance is derived)", () => {
    rejected(detail({ source: { id: SOURCE, kind: "connector" } }));
  });

  it("rejects both and neither of streams / selection_preset", () => {
    rejected(detail({ selection_preset: "p" }));
    const neither = detail();
    delete (neither as { streams?: unknown }).streams;
    rejected(neither);
  });

  it("rejects a stream with neither fields nor view, or with both", () => {
    rejected(detail({ streams: [{ name: "a" }] }));
    rejected(detail({ streams: [{ name: "a", view: "v", fields: ["x"] }] }));
  });

  it("applies the member rule to the v0.2 type too", () => {
    rejected(
      detail({
        type: PDPP_DATA_ACCESS_TYPE_V02,
        streams: [{ name: "a", x: 1 }],
      }),
    );
  });
});

describe("AS item 14 / case O7 — closed processing permissions", () => {
  it("advertises and supports none", () => {
    expect(SUPPORTED_PROCESSING_PERMISSIONS).toEqual([]);
  });

  it("rejects the reserved AI training permission (L1132 example)", () => {
    rejected(
      detail({
        processing_permissions: ["https://pdpp.dev/processing/ai_training"],
      }),
    );
  });

  it("rejects an unknown release permission (O7)", () => {
    rejected(
      detail({
        processing_permissions: ["https://example.com/processing/release"],
      }),
    );
  });

  it.each([
    ["not an array", "https://pdpp.dev/processing/ai_training"],
    ["a relative reference", ["ai_training"]],
    ["a non-string", [42]],
    [
      "a duplicate",
      [
        "https://pdpp.dev/processing/ai_training",
        "https://pdpp.dev/processing/ai_training",
      ],
    ],
  ])("rejects a malformed set: %s", (_label, value) => {
    rejected(detail({ processing_permissions: value }));
  });

  it("accepts an empty set, which requests nothing (L1116)", () => {
    expect(
      validatePublicDetail(detail({ processing_permissions: [] })).ok,
    ).toBe(true);
  });
});

describe("AS item 6 — purposes outside Appendix A", () => {
  it("names the Appendix A purposes as published (L3225)", () => {
    expect([...APPENDIX_A_PURPOSE_CODES].sort()).toEqual(
      [
        "https://pdpp.dev/purpose/agent_context",
        "https://pdpp.dev/purpose/analytics",
        "https://pdpp.dev/purpose/export",
        "https://pdpp.dev/purpose/personalization",
        "https://pdpp.dev/purpose/research",
      ].sort(),
    );
  });

  it("rejects a non-Appendix-A code without a description", () => {
    rejected(detail({ purpose_code: "https://w3id.org/dpv#ServiceProvision" }));
    rejected(
      detail({
        purpose_code: "https://w3id.org/dpv#ServiceProvision",
        purpose_description: "   ",
      }),
    );
  });

  it("does not reject a non-Appendix-A code that carries a description", () => {
    expect(
      validatePublicDetail(
        detail({
          purpose_code: "https://w3id.org/dpv#ServiceProvision",
          purpose_description: "Run the service you signed up for",
        }),
      ).ok,
    ).toBe(true);
  });

  it("treats the withdrawn ai_training purpose as an ordinary non-Appendix-A code", () => {
    rejected(detail({ purpose_code: "https://pdpp.dev/purpose/ai_training" }));
  });

  it("does not require a description for an Appendix A code", () => {
    expect(
      validatePublicDetail(
        detail({ purpose_code: "https://pdpp.dev/purpose/export" }),
      ).ok,
    ).toBe(true);
  });
});

describe("AS item 31 — retention.max_duration is PnD", () => {
  it.each(["P1D", "P30D", "P365D"])("accepts %s", (max) => {
    expect(
      validatePublicDetail(
        detail({ retention: { max_duration: max, on_expiry: "delete" } }),
      ).ok,
    ).toBe(true);
  });

  it.each(["P1M", "PT1H", "P0D", "P1W", "30D", "P1Y2D"])(
    "rejects %s",
    (max) => {
      rejected(
        detail({ retention: { max_duration: max, on_expiry: "delete" } }),
      );
    },
  );
});

describe("AS item 11 — resources are canonical, never percent-decoded", () => {
  it("accepts a canonical compound key and a literal %-sequence", () => {
    expect(
      validatePublicDetail(
        detail({
          streams: [
            { name: "a", fields: ["*"], resources: ['["x","y"]', "a%2Fb"] },
          ],
        }),
      ).ok,
    ).toBe(true);
  });

  it.each([['[ "x","y"]'], ['["x", "y"]'], ['["x",1]'], ["[]"], ['["x"']])(
    "rejects the non-canonical compound key %s",
    (raw) => {
      rejected(
        detail({ streams: [{ name: "a", fields: ["*"], resources: [raw] }] }),
      );
    },
  );

  it("freezes a %-sequence into the grant exactly as sent, never decoded", () => {
    const result = resolveSelection(
      lockedRequest({
        streams: [{ name: "top_artists", fields: ["*"], resources: ["a%2Fb"] }],
      }),
      snapshot,
      { eligibleFor: () => ["i"] },
    );
    expect(result.ok && result.streams[0].resources).toEqual(["a%2Fb"]);
  });

  it("rejects resources on a stream with more than one instance_ids entry", () => {
    rejected(
      detail({
        streams: [
          {
            name: "a",
            fields: ["*"],
            instance_ids: ["i1", "i2"],
            resources: ["r"],
          },
        ],
      }),
    );
  });
});

describe("AS item 27 — public time bounds", () => {
  it.each([
    ["no bound", {}],
    ["an unknown member", { since: "2026-01-01", from: "x" }],
    ["an invalid date", { since: "2026-02-30" }],
    ["mixed types", { since: "2026-01-01", until: "2026-02-01T00:00:00Z" }],
    ["since not before until", { since: "2026-02-01", until: "2026-01-01" }],
    ["a date-time without offset", { since: "2026-01-01T00:00:00" }],
  ])("rejects %s", (_label, range) => {
    rejected(
      detail({ streams: [{ name: "a", fields: ["*"], time_range: range }] }),
    );
  });

  it("rejects a minimum window outside the requested window", () => {
    rejected(
      detail({
        streams: [
          {
            name: "a",
            fields: ["*"],
            time_range: { since: "2026-03-01" },
            minimum: {
              time_range: { since: "2026-01-01", until: "2026-04-01" },
            },
          },
        ],
      }),
    );
  });
});

describe("AS item 22 — language tags and maps", () => {
  it.each([
    "en",
    "es-MX",
    "zh-Hant-TW",
    "sr-Latn-RS",
    "x-private",
    "i-klingon",
    "de-CH-1996",
  ])("accepts the well-formed tag %s", (tag) =>
    expect(isWellFormedLanguageTag(tag)).toBe(true),
  );

  it.each(["", "e", "english-language-tag", "en_US", "en--US", "a-b-a-c"])(
    "rejects the malformed tag %s",
    (tag) => expect(isWellFormedLanguageTag(tag)).toBe(false),
  );

  it("rejects maps that break a structural rule", () => {
    expect(validateLanguageMap({})).not.toBeNull();
    expect(validateLanguageMap({ en: "" })).not.toBeNull();
    expect(validateLanguageMap({ en: "a", EN: "b" })).not.toBeNull();
    expect(validateLanguageMap({ en_US: "a" })).not.toBeNull();
    expect(validateLanguageMap({ en: "a", es: "b" })).toBeNull();
  });

  function normative(
    display: Record<string, unknown>,
    streamDisplay?: unknown,
  ) {
    return JSON.stringify({
      protocol_version: "0.1.0",
      source: { kind: "connector", id: SOURCE },
      declaration_version: "v1",
      display,
      streams: [
        {
          name: "following",
          semantics: "mutable_state",
          primary_key: ["id"],
          ...(streamDisplay !== undefined && { display: streamDisplay }),
          schema: {
            type: "object",
            properties: { id: { type: "string" } },
            required: ["id"],
          },
        },
      ],
    });
  }

  it("accepts a language map with a matching default_language and projects it", () => {
    const result = parseDeclaration(
      normative(
        {
          name: { en: "Instagram", es: "Instagram ES" },
          default_language: "EN",
        },
        { label: { en: "Who you follow", es: "A quién sigues" } },
      ),
      SOURCE,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.snapshot.display?.name).toBe("Instagram");
    expect(result.snapshot.display?.default_language).toBe("EN");
    expect(result.snapshot.streams[0].display?.label).toBe("Who you follow");
    expect(result.snapshot.streams[0].display?.label_map).toEqual({
      en: "Who you follow",
      es: "A quién sigues",
    });
  });

  it("rejects a language map without display.default_language", () => {
    const result = parseDeclaration(
      normative({ name: "Instagram" }, { label: { en: "Who you follow" } }),
      SOURCE,
    );
    expect(result.ok).toBe(false);
  });

  it("rejects a map with no key matching default_language", () => {
    const result = parseDeclaration(
      normative(
        { name: "Instagram", default_language: "fr" },
        { label: { en: "Who you follow" } },
      ),
      SOURCE,
    );
    expect(result.ok).toBe(false);
  });

  it("rejects a malformed default_language", () => {
    const result = parseDeclaration(
      normative({ name: "Instagram", default_language: "english!" }),
      SOURCE,
    );
    expect(result.ok).toBe(false);
  });

  it("rejects a malformed key in a display.fields entry", () => {
    const result = parseDeclaration(
      normative(
        { name: "Instagram", default_language: "en" },
        { fields: { id: { label: { "e n": "x", en: "y" } } } },
      ),
      SOURCE,
    );
    expect(result.ok).toBe(false);
  });

  it("rejects an unknown source.kind and streams[].semantics", () => {
    const kind = JSON.parse(normative({ name: "x" }));
    kind.source.kind = "scraper";
    expect(parseDeclaration(JSON.stringify(kind), SOURCE).ok).toBe(false);
    const semantics = JSON.parse(normative({ name: "x" }));
    semantics.streams[0].semantics = "event_log";
    expect(parseDeclaration(JSON.stringify(semantics), SOURCE).ok).toBe(false);
  });
});

describe("AS item 34 — display language (L1077-L1083)", () => {
  const map = { en: "Who you follow", es: "A quién sigues" };

  it("looks up a regional preference by truncation", () => {
    expect(chooseLanguageVersion(map, ["es-MX"], "en")).toEqual({
      value: "A quién sigues",
      language: "es",
    });
  });

  it("falls back to default_language without regard to case", () => {
    expect(chooseLanguageVersion(map, ["fr"], "EN")).toEqual({
      value: "Who you follow",
      language: "en",
    });
    expect(chooseLanguageVersion(map, [], "en")?.language).toBe("en");
  });

  it("ignores unparseable ui_locales tags instead of rejecting", () => {
    expect(parseUiLocales("en_US !! es-MX")).toEqual(["es-MX"]);
    expect(parseUiLocales(42)).toEqual([]);
  });

  it("states no language for a plain string without default_language", () => {
    expect(chooseLanguageVersion("x", ["en"], undefined)).toEqual({
      value: "x",
    });
  });
});

const snapshot: DeclarationSnapshot = {
  source_id: SOURCE,
  source_kind: "connector",
  version: "v1",
  digest: "d".repeat(64),
  display: {
    name: "Spotify",
    name_map: { en: "Spotify", es: "Spotify (ES)" },
    default_language: "en",
  },
  streams: [
    {
      name: "top_artists",
      fields: ["id", "name"],
      required_fields: ["id"],
      primary_key: ["id"],
      display: {
        label: "Top artists",
        label_map: { en: "Top artists", es: "Artistas principales" },
      },
    },
  ],
};

const requester: RequesterIdentity = {
  client_id: "c",
  display_name: "Concert Finder",
  display: { name: "Concert Finder", policy_uri: "https://c.example/p" },
  app_approved: false,
};

function lockedRequest(
  overrides: Partial<SelectionRequest> = {},
): SelectionRequest {
  return {
    type: PDPP_DATA_ACCESS_TYPE,
    source: { id: SOURCE },
    purpose_code: "https://pdpp.dev/purpose/personalization",
    access_mode: "single_use",
    streams: [{ name: "top_artists", fields: ["*"] }],
    ...overrides,
  };
}

function lockedReview(input: {
  languagePriority?: string[];
  requester?: RequesterIdentity;
}) {
  return buildConsentReview({
    subjectId: "s",
    request: lockedRequest(),
    snapshot,
    resolvedStreams: [
      {
        name: "top_artists",
        instance_ids: ["i"],
        fields: ["id", "name"],
        required_fields: ["id"],
      },
    ],
    requester: input.requester ?? requester,
    ...(input.languagePriority && { languagePriority: input.languagePriority }),
  });
}

describe("AS items 15, 34 — the digest binds what review shows", () => {
  it("renders and binds the chosen language versions with their tags", () => {
    const review = lockedReview({ languagePriority: ["es-MX"] });
    expect(review.data.source.display_name).toBe("Spotify (ES)");
    expect(review.data.streams[0].display_label).toBe("Artistas principales");
    expect(review.display_values).toEqual([
      { id: "display.name", value: "Spotify (ES)", language: "es" },
      {
        id: "streams[top_artists].display.label",
        value: "Artistas principales",
        language: "es",
      },
    ]);
  });

  it("moves the digest when a different language version is shown", () => {
    expect(lockedReview({ languagePriority: ["es"] }).review_digest).not.toBe(
      lockedReview({ languagePriority: ["en"] }).review_digest,
    );
  });

  it("moves the digest when the client display shown changes", () => {
    const other = { ...requester, display: { name: "Concert Finder" } };
    expect(lockedReview({}).review_digest).not.toBe(
      lockedReview({ requester: other }).review_digest,
    );
  });

  it("is stable for the same inputs", () => {
    expect(lockedReview({}).review_digest).toBe(lockedReview({}).review_digest);
  });
});

describe("AS item 31 — envelope identifiers are disclosed in review", () => {
  it("states the disclosure and names each stream's identifiers", () => {
    const review = lockedReview({});
    expect(review.envelope_disclosure?.statement).toBe(
      ENVELOPE_DISCLOSURE_STATEMENT,
    );
    expect(review.data.streams[0].envelope_identifiers).toEqual({
      primary_key: ["id"],
      stream: "top_artists",
      instance_ids: ["i"],
    });
  });
});

describe("AS item 53 — ineligible streams", () => {
  const twoStreams: DeclarationSnapshot = {
    ...snapshot,
    streams: [
      snapshot.streams[0],
      {
        name: "profile",
        fields: ["id"],
        required_fields: ["id"],
        primary_key: ["id"],
      },
    ],
  };
  const onlyTopArtists = {
    eligibleFor: (s: string) => (s === "top_artists" ? ["i"] : []),
  };

  it("omits an optional ineligible stream", () => {
    const result = resolveSelection(
      lockedRequest({
        streams: [
          { name: "top_artists", fields: ["*"] },
          { name: "profile", fields: ["*"] },
        ],
      }),
      twoStreams,
      onlyTopArtists,
    );
    expect(result.ok && result.omittedStreams).toEqual(["profile"]);
  });

  it("refuses a required ineligible stream", () => {
    const result = resolveSelection(
      lockedRequest({
        streams: [
          { name: "top_artists", fields: ["*"] },
          { name: "profile", necessity: "required", fields: ["*"] },
        ],
      }),
      twoStreams,
      onlyTopArtists,
    );
    expect(!result.ok && result.failure.code).toBe(
      "required_stream_ineligible",
    );
  });
});

describe("AS item 32 — { type, grant } result", () => {
  const grant: Grant = {
    version: "0.1.0",
    grant_id: "g",
    issued_at: "2026-01-01T00:00:00Z",
    subject: { id: "s" },
    client: { client_id: "c", client_display: { name: "C" } },
    source: { kind: "connector", id: SOURCE },
    source_declaration: { version: "v1" },
    purpose_code: "https://pdpp.dev/purpose/personalization",
    access_mode: "continuous",
    retention: { max_duration: "P30D", on_expiry: "delete" },
    expires_at: "2027-01-01T00:00:00Z",
    streams: [
      {
        name: "a",
        instance_ids: ["i"],
        fields: ["id"],
        required_fields: ["id"],
      },
    ],
  };

  it("returns the complete immutable grant under the locked type", () => {
    expect(toAuthorizationEntry(grant)).toEqual({
      type: PDPP_DATA_ACCESS_TYPE,
      grant,
    });
  });

  it("keeps the v0.2 element unchanged", () => {
    const v02 = { ...grant, version: "0.2.0" };
    expect(toAuthorizationEntry(v02)).toEqual({
      type: PDPP_DATA_ACCESS_TYPE_V02,
      grant: v02,
    });
  });
});

describe("AS items 25, 44 — RFC 7009 client revocation", () => {
  let dir: string;
  let store: PdppAuthStore;
  let tokens: PdppTokenService;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "pdpp-wp4-"));
    store = openPdppAuthStore(join(dir, "auth.db"));
    tokens = new PdppTokenService(store);
  });
  afterEach(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });

  function seed(accessMode: "single_use" | "continuous", clientId = "c") {
    const grant: Grant = {
      version: "0.1.0",
      grant_id: `g_${Math.random().toString(36).slice(2)}`,
      issued_at: new Date().toISOString(),
      subject: { id: "s" },
      client: { client_id: clientId },
      source: { kind: "connector", id: SOURCE },
      source_declaration: { version: "v1" },
      purpose_code: "https://pdpp.dev/purpose/personalization",
      access_mode: accessMode,
      streams: [
        {
          name: "a",
          instance_ids: ["i"],
          fields: ["id"],
          required_fields: ["id"],
        },
      ],
    };
    const code = `code_${grant.grant_id}`;
    store.insertGrantWithAuthCode({
      grant,
      subjectId: "s",
      reviewDigest: "r",
      consentEvidence: {} as never,
      code,
      authCode: {
        grantId: grant.grant_id,
        clientId,
        redirectUri: "https://c.example/cb",
        codeChallenge: null,
        codeChallengeMethod: null,
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      },
    });
    const issued = tokens.redeemAuthorizationCode({
      code,
      clientId,
      redirectUri: "https://c.example/cb",
    });
    if (!issued.ok) throw new Error(issued.failure.message);
    return { grant, issued: issued.issued };
  }

  it("ends the grant when the refresh token is revoked, and records the disposition", () => {
    const { grant, issued } = seed("continuous");
    const result = tokens.revokeClientToken({
      token: issued.refresh_token!,
      clientId: "c",
      disposition: "delete",
      reportedAt: "2026-11-26T10:00:00Z",
    });
    expect(result).toEqual({
      ok: true,
      endedGrants: [grant.grant_id],
      dispositionRecorded: true,
    });
    expect(tokens.introspect(issued.access_token)).toEqual({ active: false });
    expect(tokens.refresh({ refreshToken: issued.refresh_token! }).ok).toBe(
      false,
    );
    expect(store.listDispositions(grant.grant_id)).toMatchObject([
      {
        clientId: "c",
        disposition: "delete",
        reportedAt: "2026-11-26T10:00:00Z",
        credential: "refresh_token",
      },
    ]);
  });

  it("ends the grant but records no disposition for a superseded refresh token (P4 variant)", () => {
    const { grant, issued } = seed("continuous");
    const rotated = tokens.refresh({ refreshToken: issued.refresh_token! });
    expect(rotated.ok).toBe(true);
    // A second refresh with the old token would be reuse; revoke instead.
    const result = tokens.revokeClientToken({
      token: issued.refresh_token!,
      clientId: "c",
      disposition: "keep",
    });
    expect(result).toMatchObject({ ok: true, dispositionRecorded: false });
    expect(store.getGrant(grant.grant_id)?.revokedAt).not.toBeNull();
    expect(store.listDispositions(grant.grant_id)).toEqual([]);
  });

  it("revoking an access token covered by a family ends only that token", () => {
    const { grant, issued } = seed("continuous");
    const result = tokens.revokeClientToken({
      token: issued.access_token,
      clientId: "c",
    });
    expect(result).toMatchObject({ ok: true, endedGrants: [] });
    expect(tokens.introspect(issued.access_token)).toEqual({ active: false });
    expect(store.getGrant(grant.grant_id)?.revokedAt).toBeNull();
    expect(tokens.refresh({ refreshToken: issued.refresh_token! }).ok).toBe(
      true,
    );
  });

  it("ends the access token but records no disposition when a family still covers the grant", () => {
    const { grant, issued } = seed("continuous");
    expect(
      tokens.revokeClientToken({
        token: issued.access_token,
        clientId: "c",
        disposition: "delete",
      }),
    ).toEqual({ ok: true, endedGrants: [], dispositionRecorded: false });
    // L2777: the token is ended regardless.
    expect(tokens.introspect(issued.access_token)).toEqual({ active: false });
    expect(store.listDispositions(grant.grant_id)).toEqual([]);
  });

  it("does not rewrite an expired grant as revoked", () => {
    const { grant, issued } = seed("continuous");
    // Expire the grant in place.
    (
      store as unknown as {
        db: { prepare(s: string): { run(...a: unknown[]): void } };
      }
    ).db
      .prepare("UPDATE pdpp_grants SET expires_at = ? WHERE grant_id = ?")
      .run("2020-01-01T00:00:00.000Z", grant.grant_id);
    const result = tokens.revokeClientToken({
      token: issued.refresh_token!,
      clientId: "c",
    });
    expect(result).toMatchObject({ ok: true, endedGrants: [] });
    expect(store.getGrant(grant.grant_id)?.revokedAt).toBeNull();
  });

  it("revoking a single_use access token ends its grant (no family)", () => {
    const { grant, issued } = seed("single_use");
    const result = tokens.revokeClientToken({
      token: issued.access_token,
      clientId: "c",
      disposition: "keep",
    });
    expect(result).toEqual({
      ok: true,
      endedGrants: [grant.grant_id],
      dispositionRecorded: true,
    });
    expect(store.getGrant(grant.grant_id)?.revokedAt).not.toBeNull();
  });

  it("refuses a token issued to another client", () => {
    const { issued } = seed("continuous", "other");
    expect(
      tokens.revokeClientToken({ token: issued.access_token, clientId: "c" }),
    ).toMatchObject({ ok: false, code: "unauthorized_client" });
    expect(tokens.introspect(issued.access_token).active).toBe(true);
  });

  it("treats an unknown token as success with no effect (RFC 7009 §2.2)", () => {
    expect(
      tokens.revokeClientToken({ token: "pdpp_at_nope", clientId: "c" }),
    ).toEqual({ ok: true, endedGrants: [], dispositionRecorded: false });
  });

  it("does not move an already-ended grant's revoked_at, nor re-record a retry", () => {
    const { grant, issued } = seed("continuous");
    tokens.revokeGrant(grant.grant_id, new Date("2026-01-01T00:00:00Z"));
    const before = store.getGrant(grant.grant_id)?.revokedAt;
    tokens.revokeClientToken({ token: issued.refresh_token!, clientId: "c" });
    expect(store.getGrant(grant.grant_id)?.revokedAt).toBe(before);
  });
});
