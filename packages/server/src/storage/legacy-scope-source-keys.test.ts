import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type Database from "better-sqlite3";
import { createLegacyScopeView } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import { legacyBindingsForProfile } from "@opendatalabs/personal-server-ts-core/legacy-projection";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { initializeDatabase } from "./index-schema.js";

interface Fixture {
  scope: string;
  profileKey?: string;
  streams: Record<string, Record<string, unknown>[]>;
  legacyBody: Record<string, unknown>;
  consumerContractBody?: Record<string, unknown>;
}

function fixture(scope: string): Fixture {
  return JSON.parse(
    readFileSync(
      new URL(
        `../../../core/src/legacy-projection/__fixtures__/parity/${scope}.json`,
        import.meta.url,
      ),
      "utf8",
    ),
  ) as Fixture;
}

const collectedAt = "2026-10-10T00:00:00.000Z";

describe("completed replacement and unreceipted historical comparison", () => {
  let db: InstanceType<typeof Database>;
  let store: ReturnType<typeof createSqliteRecordStore>;
  beforeEach(() => {
    db = initializeDatabase(":memory:");
    store = createSqliteRecordStore(db);
  });
  afterEach(() => store.close());

  function setup(
    input: Fixture,
    complete = true,
    legacyCollectedAt = collectedAt,
    receipted = false,
  ) {
    const method = input.profileKey ?? input.scope.split(".")[0]!;
    const sourceId = `https://registry.pdpp.dev/sources/${method === "github-browser" ? "github" : method}`;
    const instance = "conn_source_keys";
    store.registerConnection({ instance, sourceId, method, label: "" });
    const binding = legacyBindingsForProfile(method).get(input.scope)!;
    for (const [stream, rows] of Object.entries(input.streams)) {
      if (!binding.pdppStreams.includes(stream)) continue;
      store.replaceStream({
        instance,
        stream,
        method,
        generation: 1,
        primaryKey: [...binding.primaryKey[stream]!],
        emittedAt: collectedAt,
        sourceCollectedAt: collectedAt,
        envelopes: rows.map((data) => ({
          instance,
          stream,
          key: binding.primaryKey[stream]!.map((field) =>
            String(data[field]),
          ).join(":"),
          data,
          emitted_at: collectedAt,
        })),
      });
    }
    if (!complete) {
      // Missing rows without a completion receipt cannot prove deletion.
      const stream = Object.keys(input.streams)[0]!;
      store.replaceStream({
        instance,
        stream,
        method,
        generation: 1,
        primaryKey: ["id"],
        emittedAt: collectedAt,
        envelopes: [],
      });
    }
    if (!receipted) {
      // The historical comparison cases exercise fallback without completion proof.
      db.prepare("DELETE FROM pdpp_stream_completion WHERE instance = ?").run(
        instance,
      );
    }
    db.prepare(
      "INSERT INTO data_files (path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?)",
    ).run("source/old.json", input.scope, legacyCollectedAt, 1);
    const envelope = {
      version: "1.0" as const,
      scope: input.scope,
      collectedAt: legacyCollectedAt,
      data: input.legacyBody,
    };
    return createLegacyScopeView({
      authority: createLegacyScopeAuthority(db),
      records: store,
      configuredMethods: (source) => (source === sourceId ? [method] : []),
      readLegacyHead: async () => envelope,
    });
  }

  function spotify(
    scope: "spotify.savedTracks" | "spotify.playlists",
  ): Fixture {
    if (scope === "spotify.playlists") {
      const input = fixture(scope);
      for (const row of input.streams.playlist_items!) row.artist_names = [];
      for (const playlist of input.legacyBody.playlists as {
        tracks: { artists: unknown[] }[];
      }[])
        for (const track of playlist.tracks) track.artists = [];
      return input;
    }
    return {
      scope,
      streams: {
        saved_tracks: [
          {
            id: "track-a",
            name: "Song",
            artist_names: [],
            album_name: "Album",
            album_artist_names: [],
            uri: "spotify:track:track-a",
            added_at: "2026-10-01T00:00:00.000Z",
            duration_ms: 120000,
            explicit: false,
          },
        ],
      },
      legacyBody: {
        savedTracks: [
          {
            name: "Song",
            artists: [],
            album: { name: "Album", artists: [] },
            uri: "spotify:track:track-a",
            added_at: "2026-10-01T00:00:00.000Z",
            duration_ms: 120000,
            explicit: false,
          },
        ],
        total: 1,
      },
    };
  }

  function githubProfile(): Fixture {
    const input = fixture("github.profile");
    const extra = {
      pinnedRepositories: [
        {
          fullName: "example/project",
          url: "https://github.com/example/project",
          description: "",
          language: null,
          stars: 1,
        },
      ],
      organizations: [
        {
          login: "example",
          label: "Example",
          url: "https://github.com/example",
          avatarUrl: null,
        },
      ],
    };
    Object.assign(input.streams.profile![0]!, extra);
    Object.assign(input.legacyBody, extra);
    return input;
  }

  function playlistMetadata(): Fixture {
    const input = fixture("spotify.playlists");
    for (const playlist of input.legacyBody.playlists as {
      tracks: unknown[];
      tracks_total: number;
    }[]) {
      playlist.tracks = [];
      playlist.tracks_total = 0;
    }
    return input;
  }

  it.each([
    "linkedin.connections",
    "linkedin.experience",
    "linkedin.education",
    "linkedin.skills",
    "linkedin.languages",
    "github.profile",
    "github.repositories",
    "github.starred",
    "spotify.savedTracks",
    "spotify.playlists",
    "instagram.ads",
    "heb.profile",
  ])(
    "replaces keyless historical %s data after its fresh sync completes",
    async (scope) => {
      const input =
        scope === "spotify.savedTracks" || scope === "spotify.playlists"
          ? spotify(scope)
          : scope === "github.profile"
            ? githubProfile()
            : fixture(scope);
      input.legacyBody = { oldOnly: [{ arbitrary: "no historical key" }] };
      const view = setup(input, true, collectedAt, true);
      const indexed = db.prepare("SELECT * FROM data_files").all();
      const read = await view.readLatest(scope);
      expect(read.kind).toBe("canonical");
      if (read.kind !== "canonical")
        throw new Error("Fresh sync did not replace history");
      expect(read.envelope.data).not.toHaveProperty("oldOnly");
      expect(view.listingFor(scope).kind).toBe("canonical");
      expect(view.verdictFor(scope)).toEqual([]);
      expect(
        db
          .prepare("SELECT replacement_cursor FROM legacy_scope_takeovers")
          .all(),
      ).toEqual([{ replacement_cursor: expect.any(String) }]);
      expect(db.prepare("SELECT * FROM data_files").all()).toEqual(indexed);
    },
  );

  it("takes over playlist metadata when no old track entities need an identity", async () => {
    const input = playlistMetadata();
    const read = await setup(
      input,
      true,
      "2026-10-09T00:00:00.000Z",
    ).readLatest(input.scope);
    expect(read.kind).toBe("canonical");
    if (read.kind === "canonical")
      expect(read.envelope.data).toEqual(fixture(input.scope).legacyBody);
  });

  it("allows newer playlist metadata under the same opaque playlist URI", async () => {
    const input = playlistMetadata();
    input.streams.playlists![0]!.name = "Updated playlist name";
    const read = await setup(
      input,
      true,
      "2026-10-09T00:00:00.000Z",
    ).readLatest(input.scope);
    expect(read.kind).toBe("canonical");
    if (read.kind === "canonical")
      expect(read.envelope.data.playlists).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ name: "Updated playlist name" }),
        ]),
      );
  });

  it.each(["spotify.savedTracks", "spotify.playlists"] as const)(
    "keeps artist-free %s track lists unkeyed because URIs can encode local metadata",
    async (scope) => {
      const input = spotify(scope);
      const view = setup(input);
      expect(await view.readLatest(scope)).toMatchObject({ kind: "file" });
      expect(view.verdictFor(scope)[0]).toMatchObject({
        reason: { reason: "no_stable_key" },
      });
    },
  );

  it("keeps GitHub profile lists unkeyed because repository names and logins are reusable", async () => {
    const input = githubProfile();
    const read = await setup(input).readLatest(input.scope);
    expect(read.kind).toBe("file");
  });

  it.each([
    "spotify.savedTracks",
    "spotify.playlists",
    "github.profile",
  ] as const)("keeps the old file for an incomplete %s read", async (scope) => {
    const input =
      scope === "github.profile"
        ? githubProfile()
        : scope === "spotify.playlists"
          ? playlistMetadata()
          : spotify(scope);
    expect(await setup(input, false).readLatest(scope)).toMatchObject({
      kind: "file",
    });
  });

  it.each([
    "linkedin.profile",
    "spotify.profile",
    "instagram.profile",
    "youtube.profile",
    "wholefoods.profile",
    "heb.nutrition",
    "wholefoods.nutrition",
  ])(
    "already covers %s within its selected connection without an array key",
    async (scope) => {
      const input = fixture(scope);
      const read = await setup(input).readLatest(scope);
      expect(read.kind).toBe("canonical");
      if (read.kind === "canonical")
        expect(read.envelope.data).toEqual(input.legacyBody);
    },
  );

  it.each([
    "linkedin.connections",
    "github.repositories",
    "github.starred",
    "linkedin.experience",
    "linkedin.education",
    "linkedin.skills",
    "linkedin.languages",
    "instagram.ads",
    "heb.profile",
    "spotify.playlists",
  ])(
    "keeps %s unkeyed where the legacy object lists retain no upstream identifier",
    async (scope) => {
      const view = setup(fixture(scope));
      expect(await view.readLatest(scope)).toMatchObject({ kind: "file" });
      expect(view.verdictFor(scope)[0]).toMatchObject({
        verdict: "not_covered",
        reason: { reason: "no_stable_key" },
      });
    },
  );

  it.each(["linkedin.connections", "github.repositories", "github.starred"])(
    "keeps the old file for an incomplete %s read",
    async (scope) => {
      const view = setup(fixture(scope), false);
      expect(await view.readLatest(scope)).toMatchObject({ kind: "file" });
      expect(view.verdictFor(scope)[0]).toMatchObject({
        verdict: "not_covered",
      });
    },
  );

  it.each(["spotify.savedTracks", "spotify.playlists"] as const)(
    "keeps %s artist names unkeyed even when track URIs match",
    async (scope) => {
      const input = spotify(scope);
      const stream =
        scope === "spotify.savedTracks" ? "saved_tracks" : "playlist_items";
      input.streams[stream]![0]!.artist_names = ["Same display name"];
      const body = input.legacyBody as {
        savedTracks?: { artists: unknown[] }[];
        playlists?: { tracks: { artists: unknown[] }[] }[];
      };
      // playlist_items are sorted by position in the legacy view.
      const track = body.savedTracks?.[0] ?? body.playlists![0]!.tracks[1]!;
      track.artists = [{ name: "Same display name" }];
      const view = setup(input);
      expect(await view.readLatest(scope)).toMatchObject({ kind: "file" });
      expect(view.verdictFor(scope)[0]).toMatchObject({
        reason: { reason: "no_stable_key" },
      });
    },
  );

  it("refuses duplicate Spotify playlist track URIs rather than keying by position", async () => {
    const input = spotify("spotify.playlists");
    const uri = "spotify:track:1234567890123456789012";
    for (const row of input.streams.playlist_items!) row.uri = uri;
    const playlists = input.legacyBody.playlists as {
      tracks: { uri: string }[];
    }[];
    for (const track of playlists[0]!.tracks) track.uri = uri;
    const view = setup(input);
    expect(await view.readLatest(input.scope)).toMatchObject({ kind: "file" });
    expect(view.verdictFor(input.scope)[0]).toMatchObject({
      reason: { reason: "no_stable_key" },
    });
  });

  it.each(["missing", "duplicate"])(
    "refuses %s LinkedIn source URLs",
    async (kind) => {
      const input = fixture("linkedin.connections");
      const row = input.streams.connections![0]!;
      const connections = input.legacyBody.connections as Record<
        string,
        unknown
      >[];
      if (kind === "missing") {
        row.profile_url = "";
        connections[0]!.profileUrl = "";
      } else {
        input.streams.connections!.push({
          ...row,
          id: "different-source-member",
        });
        connections.push({ ...connections[0]! });
      }
      const view = setup(input);
      expect(await view.readLatest(input.scope)).toMatchObject({
        kind: "file",
      });
      expect(view.verdictFor(input.scope)[0]).toMatchObject({
        reason: { reason: "no_stable_key" },
      });
    },
  );

  it("keeps GitHub achievement labels unkeyed", async () => {
    const input = githubProfile();
    const achievements = [{ name: "Badge", iconUrl: null }];
    input.streams.profile![0]!.achievements = achievements;
    input.legacyBody.achievements = achievements;
    const view = setup(input);
    expect(await view.readLatest(input.scope)).toMatchObject({ kind: "file" });
    expect(view.verdictFor(input.scope)[0]).toMatchObject({
      reason: { reason: "no_stable_key" },
    });
  });

  it.each(["linkedin.profile", "instagram.profile"])(
    "keeps the old %s file when app-facing fields are absent from the projection",
    async (scope) => {
      const input = fixture(scope);
      // Existing synthetic consumer probes include Career Quest aliases and
      // Hoe-kemon's id/post_count. They are not captured connector payloads.
      input.legacyBody = input.consumerContractBody!;
      const view = setup(input);
      expect(await view.readLatest(scope)).toMatchObject({ kind: "file" });
      expect(
        view.verdictFor(scope)[0]!.reasonCounts.missing_field,
      ).toBeGreaterThan(0);
    },
  );
});
