import Ajv from "ajv";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { LEGACY_SCOPE_BINDINGS } from "./bindings.js";
import amazonDeclaration from "./declarations/amazon.collection-profile.json";
import chatgptDeclaration from "./declarations/chatgpt.collection-profile.json";
import chatgpt020Declaration from "./declarations/chatgpt-0.2.0.collection-profile.json";
import githubDeclaration from "./declarations/github.collection-profile.json";
import githubProvenance from "./declarations/github.provenance.json";
import hebDeclaration from "./declarations/heb.collection-profile.json";
import hebProvenance from "./declarations/heb.provenance.json";
import icloudNotesDeclaration from "./declarations/icloud-notes.collection-profile.json";
import linkedinDeclaration from "./declarations/linkedin.collection-profile.json";
import metaDeclaration from "./declarations/meta.collection-profile.json";
import ouraDeclaration from "./declarations/oura.collection-profile.json";
import shopifyDeclaration from "./declarations/shopify.collection-profile.json";
import spotifyDeclaration from "./declarations/spotify.collection-profile.json";
import wholefoodsDeclaration from "./declarations/wholefoods.collection-profile.json";
import wholefoodsProvenance from "./declarations/wholefoods.provenance.json";
import youtubeDeclaration from "./declarations/youtube.collection-profile.json";
import youtubeProvenance from "./declarations/youtube.provenance.json";
import anthropicDeclaration from "./declarations/anthropic-0.1.3.collection-profile.json";
import amazonOrdersSchema from "./legacy-schemas/amazon.orders.json";
import chatgptMemoriesSchema from "./legacy-schemas/chatgpt.memories.json";
import chatgptConversationsSchema from "./legacy-schemas/chatgpt.conversations.json";
import githubRepositoriesSchema from "./legacy-schemas/github.repositories.json";
import githubStarredSchema from "./legacy-schemas/github.starred.json";
import icloudNotesSchema from "./legacy-schemas/icloud_notes.notes.json";
import icloudFoldersSchema from "./legacy-schemas/icloud_notes.folders.json";
import linkedinConnectionsSchema from "./legacy-schemas/linkedin.connections.json";
import spotifySavedTracksSchema from "./legacy-schemas/spotify.savedTracks.json";
import instagramPostsSchema from "./legacy-schemas/instagram.posts.json";
import instagramAdsSchema from "./legacy-schemas/instagram.ads.json";
import instagramFollowingSchema from "./legacy-schemas/instagram.following.json";
import githubHistorySchema from "./legacy-schemas/github.history.json";
import githubProfileSchema from "./legacy-schemas/github.profile.json";
import githubEventsSchema from "./legacy-schemas/github.events.json";
import githubContributionsSchema from "./legacy-schemas/github.contributions.json";
import instagramProfileSchema from "./legacy-schemas/instagram.profile.json";
import linkedinEducationSchema from "./legacy-schemas/linkedin.education.json";
import linkedinExperienceSchema from "./legacy-schemas/linkedin.experience.json";
import linkedinProfileSchema from "./legacy-schemas/linkedin.profile.json";
import linkedinSkillsSchema from "./legacy-schemas/linkedin.skills.json";
import linkedinLanguagesSchema from "./legacy-schemas/linkedin.languages.json";
import shopOrdersSchema from "./legacy-schemas/shop.orders.json";
import ouraActivitySchema from "./legacy-schemas/oura.activity.json";
import ouraReadinessSchema from "./legacy-schemas/oura.readiness.json";
import ouraSleepSchema from "./legacy-schemas/oura.sleep.json";
import hebOrdersSchema from "./__fixtures__/desktop-schemas/heb.orders.json";
import hebProfileSchema from "./__fixtures__/desktop-schemas/heb.profile.json";
import hebNutritionSchema from "./__fixtures__/desktop-schemas/heb.nutrition.json";
import wholefoodsProfileSchema from "./__fixtures__/desktop-schemas/wholefoods.profile.json";
import wholefoodsOrdersSchema from "./__fixtures__/desktop-schemas/wholefoods.orders.json";
import wholefoodsNutritionSchema from "./__fixtures__/desktop-schemas/wholefoods.nutrition.json";
import youtubeProfileSchema from "./legacy-schemas/youtube.profile.json";
import youtubeHistorySchema from "./legacy-schemas/youtube.history.json";
import youtubeSubscriptionsSchema from "./legacy-schemas/youtube.subscriptions.json";
import youtubePlaylistsSchema from "./legacy-schemas/youtube.playlists.json";
import youtubePlaylistItemsSchema from "./legacy-schemas/youtube.playlistItems.json";
import youtubeLikesSchema from "./legacy-schemas/youtube.likes.json";
import youtubeWatchLaterSchema from "./legacy-schemas/youtube.watchLater.json";
import spotifyPlaylistsSchema from "./legacy-schemas/spotify.playlists.json";
import spotifyProfileSchema from "./legacy-schemas/spotify.profile.json";
import claudeConversationsSchema from "./legacy-schemas/claude.conversations.json";
import claudeProjectsSchema from "./legacy-schemas/claude.projects.json";
import type { PdppRecord } from "./types.js";

interface CollectionProfileStream {
  name: string;
  primary_key?: string[];
  schema?: {
    properties?: Record<string, { type?: string | string[] } | undefined>;
    required?: string[];
  };
}
interface CollectionProfile {
  connector_id: string;
  version: string;
  streams: CollectionProfileStream[];
}

const DECLARATIONS: Record<string, CollectionProfile> = {
  amazon: amazonDeclaration as CollectionProfile,
  chatgpt: chatgptDeclaration as CollectionProfile,
  "chatgpt-0.2.0": chatgpt020Declaration as CollectionProfile,
  github: githubDeclaration as CollectionProfile,
  heb: hebDeclaration as CollectionProfile,
  "icloud-notes": icloudNotesDeclaration as CollectionProfile,
  linkedin: linkedinDeclaration as CollectionProfile,
  meta: metaDeclaration as CollectionProfile,
  oura: ouraDeclaration as CollectionProfile,
  shopify: shopifyDeclaration as CollectionProfile,
  spotify: spotifyDeclaration as CollectionProfile,
  wholefoods: wholefoodsDeclaration as CollectionProfile,
  youtube: youtubeDeclaration as CollectionProfile,
  "anthropic-0.1.3": anthropicDeclaration as CollectionProfile,
};

const LEGACY_SCHEMAS: Record<string, { schema: unknown }> = {
  "instagram.posts.json": instagramPostsSchema,
  "instagram.ads.json": instagramAdsSchema,
  "instagram.following.json": instagramFollowingSchema,
  "github.history.json": githubHistorySchema,
  "github.profile.json": githubProfileSchema,
  "github.events.json": githubEventsSchema,
  "github.contributions.json": githubContributionsSchema,
  "instagram.profile.json": instagramProfileSchema,
  "icloud_notes.folders.json": icloudFoldersSchema,
  "linkedin.connections.json": linkedinConnectionsSchema,
  "spotify.savedTracks.json": spotifySavedTracksSchema,
  "github.repositories.json": githubRepositoriesSchema,
  "github.starred.json": githubStarredSchema,
  "chatgpt.memories.json": chatgptMemoriesSchema,
  "linkedin.education.json": linkedinEducationSchema,
  "chatgpt.conversations.json": chatgptConversationsSchema,
  "linkedin.experience.json": linkedinExperienceSchema,
  "linkedin.languages.json": linkedinLanguagesSchema,
  "linkedin.profile.json": linkedinProfileSchema,
  "linkedin.skills.json": linkedinSkillsSchema,
  "shop.orders.json": shopOrdersSchema,
  "spotify.playlists.json": spotifyPlaylistsSchema,
  "spotify.profile.json": spotifyProfileSchema,
  "claude.conversations.json": claudeConversationsSchema,
  "claude.projects.json": claudeProjectsSchema,
  "amazon.orders.json": amazonOrdersSchema,
  "oura.activity.json": ouraActivitySchema,
  "oura.readiness.json": ouraReadinessSchema,
  "oura.sleep.json": ouraSleepSchema,
  "icloud_notes.notes.json": icloudNotesSchema,
  "heb.orders.json": hebOrdersSchema,
  "heb.profile.json": hebProfileSchema,
  "heb.nutrition.json": hebNutritionSchema,
  "wholefoods.profile.json": wholefoodsProfileSchema,
  "wholefoods.orders.json": wholefoodsOrdersSchema,
  "wholefoods.nutrition.json": wholefoodsNutritionSchema,
  "youtube.profile.json": youtubeProfileSchema,
  "youtube.history.json": youtubeHistorySchema,
  "youtube.subscriptions.json": youtubeSubscriptionsSchema,
  "youtube.playlists.json": youtubePlaylistsSchema,
  "youtube.playlistItems.json": youtubePlaylistItemsSchema,
  "youtube.likes.json": youtubeLikesSchema,
  "youtube.watchLater.json": youtubeWatchLaterSchema,
};

const ajv = new Ajv({ allErrors: true, strict: false });

function collectionProfileDigest(fileName: string): string {
  return `sha256:${createHash("sha256")
    .update(
      readFileSync(
        new URL(
          `./declarations/${fileName}.collection-profile.json`,
          import.meta.url,
        ),
      ),
    )
    .digest("hex")}`;
}

/**
 * Each binding's `pdppSource` is a full connector_id URI
 * (https://registry.pdpp.dev/connectors/<key>); the vendored declarations
 * are keyed here by the short connector_key for lookup convenience only.
 * This map resolves one to the other and asserts the URI is byte-identical
 * to what the cited declaration itself declares (B5).
 */
const SOURCE_ID_TO_KEY: Record<string, string> = Object.fromEntries(
  Object.entries(DECLARATIONS)
    .filter(([key]) => key !== "chatgpt-0.2.0")
    .map(([key, decl]) => [decl.connector_id, key]),
);

function declarationFor(binding: {
  provenance: { path: string }[];
}): CollectionProfile {
  const key = binding.provenance[0]?.path.match(
    /^declarations\/([\w.-]+)\.collection-profile\.json/,
  )?.[1];
  return DECLARATIONS[key ?? ""];
}

/**
 * Every binding's provenance cites a `path` of the form
 * "declarations/<source>.collection-profile.json#streams[name=<a>,<b>,...]".
 * This test resolves that citation against the vendored declaration JSON and
 * fails loudly if the binding's pdppStreams disagree with what the cited
 * file actually declares — the mechanism the brief asked for: "when
 * canonical declarations land, swapping the inputs re-checks every mapping."
 */
describe("legacy scope binding self-check", () => {
  it("pins every GitHub projection to the verified 0.7.2 artifact and vendored profile bytes", () => {
    expect(githubDeclaration.version).toBe("0.7.2");
    expect(githubProvenance.source.revision).toBe(
      "7b18ff6968b8ee9496b3e16f31ce5b6c65dc2c40",
    );
    expect(collectionProfileDigest("github")).toBe(
      githubProvenance.outputs["collection-profile.json"],
    );

    for (const scope of [
      "github.repositories",
      "github.starred",
      "github.history",
      "github.profile",
      "github.events",
      "github.contributions",
    ]) {
      expect(LEGACY_SCOPE_BINDINGS.get(scope)?.provenance[0]).toMatchObject({
        kind: "oci",
        ref: "ghcr.io/pdp-connect/connector/github:0.7.2",
        digest:
          "sha256:5501bb109cdca02d2acd08aa6891613c7af0bbe0869c30eba2a8070836b0d2f7",
      });
    }
  });

  it("pins grocery bindings to the published signed artifacts", () => {
    const binding = LEGACY_SCOPE_BINDINGS.get("heb.orders");
    expect(hebDeclaration.version).toBe("0.5.3");
    expect(hebDeclaration.connector_id).toBe(
      "https://registry.pdpp.dev/connectors/heb",
    );
    expect(hebProvenance.source.revision).toBe(
      "fe258e316a0318d6e225e8b07b8d289b60016a81",
    );
    expect(binding?.provenance[0]).toEqual({
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/heb:0.5.3",
      digest:
        "sha256:9de1c9203453b3897305ca99dfe93755f0e5528b3e7e79d0a9e6c8313445c02a",
      path: "declarations/heb.collection-profile.json#streams[name=orders,order_items]",
    });
    expect(collectionProfileDigest("heb")).toBe(
      hebProvenance.outputs["collection-profile.json"],
    );
    expect(binding?.provenance[0]?.path).toBe(
      "declarations/heb.collection-profile.json#streams[name=orders,order_items]",
    );

    for (const scope of [
      "heb.profile",
      "heb.nutrition",
      "wholefoods.profile",
      "wholefoods.orders",
      "wholefoods.nutrition",
    ]) {
      expect(LEGACY_SCOPE_BINDINGS.has(scope), scope).toBe(true);
    }

    const wholeFoodsStreamNames = wholefoodsDeclaration.streams.map(
      (stream) => stream.name,
    );
    expect(wholefoodsDeclaration.version).toBe("0.3.0");
    expect(wholeFoodsStreamNames).toEqual([
      "profile",
      "orders",
      "order_items",
      "nutrition",
    ]);
    expect(wholefoodsProvenance.source.revision).toBe(
      "4e1f6e4cc5b66c4a70bd6fa38c3579eb22956c10",
    );
    expect(
      LEGACY_SCOPE_BINDINGS.get("wholefoods.profile")?.provenance[0],
    ).toEqual({
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/wholefoods:0.3.0",
      digest:
        "sha256:873e287a153673bb9b96cae87dfe64e36730e18b30ea2e5c1731bdcff8d4432c",
      path: "declarations/wholefoods.collection-profile.json#streams[name=profile]",
    });
    expect(collectionProfileDigest("wholefoods")).toBe(
      wholefoodsProvenance.outputs["collection-profile.json"],
    );
  });

  it("shop.orders is bound to the pinned Shopify 0.2.0 artifact", () => {
    const binding = LEGACY_SCOPE_BINDINGS.get("shop.orders");
    expect(binding).toBeDefined();
    expect(shopifyDeclaration.version).toBe("0.2.0");
    expect(binding?.provenance).toContainEqual({
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/shopify:0.2.0",
      digest:
        "sha256:167cff474a653ad7bce036c973a78adcfc3a3e8e73925a6e24c74961f979ac0e",
      path: "declarations/shopify.collection-profile.json#streams[name=orders]",
    });
  });

  it("pins YouTube bindings to the browser-first source declaration", () => {
    expect(youtubeDeclaration.version).toBe("0.2.0");
    expect(youtubeDeclaration.connector_id).toBe(
      "https://registry.pdpp.dev/connectors/youtube",
    );
    expect(collectionProfileDigest("youtube")).toBe(
      youtubeProvenance.outputs["collection-profile.json"],
    );
    for (const scope of [
      "youtube.profile",
      "youtube.subscriptions",
      "youtube.playlists",
      "youtube.playlistItems",
      "youtube.likes",
      "youtube.watchLater",
      "youtube.history",
    ]) {
      expect(LEGACY_SCOPE_BINDINGS.has(scope), scope).toBe(true);
    }
  });

  it("instagram.posts is bound to the signed Meta 0.4.0 artifact", () => {
    const binding = LEGACY_SCOPE_BINDINGS.get("instagram.posts");
    expect(binding).toBeDefined();
    expect(metaDeclaration.version).toBe("0.4.0");
    expect(binding?.provenance).toContainEqual({
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/meta:0.4.0",
      digest:
        "sha256:9805c13ab4ad45caf904b4ce834764e701e426f5c3d2f3697fbab2705d1636ea",
      path: "declarations/meta.collection-profile.json#streams[name=posts,post_likes]",
    });
  });

  it("icloud_notes.notes cites the signed iCloud Notes 0.1.0 profile", () => {
    const binding = LEGACY_SCOPE_BINDINGS.get("icloud_notes.notes");
    expect(icloudNotesDeclaration.version).toBe("0.1.0");
    expect(binding?.provenance).toEqual([
      {
        kind: "oci",
        ref: "ghcr.io/pdp-connect/connector/icloud-notes:0.1.0",
        digest:
          "sha256:fe5497bb79b0d567c30790cc71b1e591b955fe474725679b996441bd70c09944",
        path: "declarations/icloud-notes.collection-profile.json#streams[name=notes,folders]",
      },
    ]);
  });

  for (const [scope, binding] of LEGACY_SCOPE_BINDINGS) {
    const sourceKey = SOURCE_ID_TO_KEY[binding.pdppSource];

    it(`${scope}: pdppSource is the declaration's own connector_id, not the connector key`, () => {
      expect(
        sourceKey,
        `binding.pdppSource "${binding.pdppSource}" does not match any vendored declaration's connector_id`,
      ).toBeTruthy();
    });

    it(`${scope}: provenance cites streams that exist in its vendored declaration`, () => {
      expect(binding.provenance.length).toBeGreaterThan(0);

      for (const prov of binding.provenance) {
        expect(prov.path).toMatch(
          /^declarations\/[\w.-]+\.collection-profile\.json#streams\[name=/,
        );
        if (prov.kind === "oci") {
          expect(prov.digest).toMatch(/^sha256:[0-9a-f]{64,}$/);
        }

        const pathSourceMatch = prov.path.match(
          /^declarations\/([\w.-]+)\.collection-profile\.json/,
        );
        expect(
          pathSourceMatch,
          `unparseable provenance path: ${prov.path}`,
        ).toBeTruthy();
        const pathSource = pathSourceMatch?.[1] as string;
        const declaration = DECLARATIONS[pathSource];
        expect(
          declaration,
          `no vendored declarations/${pathSource}.collection-profile.json is imported by this test`,
        ).toBeTruthy();
        expect(declaration.connector_id).toBe(binding.pdppSource);

        const declaredStreamNames = new Set(
          declaration.streams.map((s) => s.name),
        );

        for (const streamName of binding.pdppStreams) {
          expect(
            declaredStreamNames.has(streamName),
            `binding for ${scope} cites stream "${streamName}" on source "${pathSource}", ` +
              `but declarations/${pathSource}.collection-profile.json declares only: ` +
              `${[...declaredStreamNames].join(", ")}`,
          ).toBe(true);
        }
      }
    });

    it(`${scope}: missing_stream is returned for every bound stream, one at a time`, () => {
      for (const missing of binding.pdppStreams) {
        const fetchedStreams = binding.pdppStreams.filter((s) => s !== missing);
        const records: PdppRecord[] = fetchedStreams.map((s) => ({
          stream: s,
          data: { id: "present" },
        }));
        const result = binding.project(records, { fetchedStreams });
        expect(
          result,
          `${scope}: expected missing_stream for "${missing}" when only [${fetchedStreams.join(", ")}] were fetched`,
        ).toEqual({
          ok: false,
          error: {
            kind: "missing_stream",
            scope,
            expectedStream: missing,
          },
        });
      }
    });

    it(`${scope}: fetched content streams with zero rows project an empty result when required profile identity exists (N-B1)`, () => {
      const fetchedStreams = [...binding.pdppStreams];
      const records: PdppRecord[] = scope.startsWith("claude.")
        ? [
            {
              stream: "account_profile",
              data: {
                id: "org-1",
                organization_id: "org-1",
                full_name: null,
                plan: null,
                name_source: "none",
                metadata_status: "absent",
              },
            },
          ]
        : [];
      const result = binding.project(records, { fetchedStreams });
      // Claude needs exactly one verified profile even when its content streams are empty.
      // Other singleton scopes reject a genuinely empty record set.
      const expectedOk =
        scope !== "instagram.profile" &&
        scope !== "linkedin.profile" &&
        scope !== "spotify.profile" &&
        scope !== "github.profile" &&
        scope !== "heb.profile" &&
        scope !== "wholefoods.profile";
      expect(
        result.ok,
        `${scope}: expected ok=${expectedOk} when every stream was fetched but returned zero records, got ${JSON.stringify(result)}`,
      ).toBe(expectedOk);
    });

    it(`${scope}: a null-filled declared record projects validly or fails closed when evidence is missing (B3)`, () => {
      const legacySchema = LEGACY_SCHEMAS[binding.legacySchemaPath];
      expect(
        legacySchema,
        `no vendored legacy-schemas/${binding.legacySchemaPath} imported by this test`,
      ).toBeTruthy();

      const declaration = declarationFor(binding);
      const records: PdppRecord[] = binding.pdppStreams.map((streamName) => {
        if (scope.startsWith("claude.") && streamName === "account_profile") {
          return {
            stream: streamName,
            data: {
              id: "org-1",
              organization_id: "org-1",
              full_name: null,
              plan: null,
              name_source: "none",
              metadata_status: "absent",
            },
          };
        }
        const stream = declaration.streams.find((s) => s.name === streamName);
        const declaredFields = Object.keys(stream?.schema?.properties ?? {});
        const required = new Set(stream?.schema?.required ?? []);
        if (scope === "icloud_notes.notes") {
          return {
            stream: streamName,
            data:
              streamName === "notes"
                ? {
                    id: "note-1",
                    title: null,
                    snippet: null,
                    folder_id: null,
                    is_pinned: false,
                    created_at: null,
                    modified_at: null,
                    has_attachments: false,
                    text_content: null,
                  }
                : { id: "folder-1", name: "Folder" },
          };
        }
        const nullFilled: Record<string, unknown> = {};
        for (const field of declaredFields) {
          const type = stream?.schema?.properties?.[field]?.type;
          if (
            !required.has(field) &&
            Array.isArray(type) &&
            type.includes("null")
          ) {
            nullFilled[field] = null;
          } else {
            const scalarType = Array.isArray(type)
              ? type.find((entry) => entry !== "null")
              : type;
            nullFilled[field] =
              scalarType === "string"
                ? "required-value"
                : scalarType === "number" || scalarType === "integer"
                  ? 1
                  : scalarType === "boolean"
                    ? false
                    : scalarType === "array"
                      ? []
                      : {};
          }
        }
        return { stream: streamName, data: nullFilled };
      });

      const result = binding.project(records, {
        fetchedStreams: [...binding.pdppStreams],
      });
      if (scope === "chatgpt.conversations") {
        expect(result).toMatchObject({
          ok: false,
          error: {
            kind: "invalid_value",
            scope,
          },
        });
        return;
      }
      // These bindings require evidence that a null-filled declaration row
      // cannot provide. Whole Foods 0.3.0 can project its declared item row;
      // the production gate still rejects unproven collection completeness.
      if (
        [
          "github.history",
          "heb.orders",
          "heb.nutrition",
          "wholefoods.nutrition",
        ].includes(scope)
      ) {
        expect(result).toMatchObject({
          ok: false,
          error: { kind: "incomplete_scope", scope },
        });
        return;
      }
      expect(result.ok, JSON.stringify(result)).toBe(true);
      if (result.ok) {
        const validate = ajv.compile(
          legacySchema.schema as Record<string, unknown>,
        );
        const valid = validate(result.payload);
        expect(valid, JSON.stringify(validate.errors, null, 2)).toBe(true);
      }
    });

    it(`${scope}: fieldsRead names only fields the declaration actually declares, per bound stream (S1)`, () => {
      const declaration = declarationFor(binding);
      for (const streamName of binding.pdppStreams) {
        const stream = declaration.streams.find((s) => s.name === streamName);
        expect(
          stream,
          `stream "${streamName}" not found on ${sourceKey} declaration`,
        ).toBeTruthy();
        const declaredFields = new Set(
          Object.keys(stream?.schema?.properties ?? {}),
        );

        const claimedFields = binding.fieldsRead[streamName];
        expect(
          claimedFields,
          `binding for ${scope} declares no fieldsRead entry for stream "${streamName}"`,
        ).toBeTruthy();

        for (const field of claimedFields ?? []) {
          expect(
            declaredFields.has(field),
            `binding for ${scope} claims to read field "${field}" on stream ` +
              `"${streamName}", but declarations/${sourceKey}.collection-profile.json ` +
              `no longer declares it (deleted or renamed) — this must fail (S1)`,
          ).toBe(true);
        }
      }
    });

    it(`${scope}: primaryKey matches the declaration's own primary_key exactly, per bound stream (S1)`, () => {
      const declaration = declarationFor(binding);
      for (const streamName of binding.pdppStreams) {
        const stream = declaration.streams.find((s) => s.name === streamName);
        expect(
          stream?.primary_key,
          `stream "${streamName}" on ${sourceKey} declares no primary_key`,
        ).toBeTruthy();

        const claimedKey = binding.primaryKey[streamName];
        expect(
          claimedKey,
          `binding for ${scope} declares no primaryKey entry for stream "${streamName}"`,
        ).toBeTruthy();

        expect(
          claimedKey,
          `binding for ${scope}'s primaryKey for "${streamName}" is ` +
            `[${(claimedKey ?? []).join(", ")}], but the declaration's own ` +
            `primary_key is [${(stream?.primary_key ?? []).join(", ")}] — ` +
            `a declared-but-wrong key must fail this check (S1)`,
        ).toEqual(stream?.primary_key);
      }
    });
  }
});
