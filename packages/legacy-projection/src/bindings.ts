import type {
  LegacyScopeBinding,
  PdppRecord,
  ProjectPdppRecordsOptions,
  ProjectionErr,
  ProjectionResult,
} from "./types.js";
import type { LegacyScopeBindingProvenance } from "./provenance.js";

/**
 * Every entry cites source evidence in ./declarations. Published OCI profiles
 * carry immutable artifact digests; where the OCI manifest pin is unavailable,
 * the generated collection-profile output digest is recorded explicitly. No
 * entry here uses a fabricated field. Every legacy field
 * this phase cannot reconstruct is a documented gap (either the whole scope
 * is absent from
 * LEGACY_SCOPE_BINDINGS and appears in the report's gap table, or the field
 * is listed in the binding's `lossy` array and called out in this file's
 * comments plus the report).
 *
 * `pdppSource` is each declaration's own `connector_id`
 * (`https://registry.pdpp.dev/connectors/<key>`), verified byte-identical
 * per source below — never the short `connector_key` a Personal Server does
 * not key sources by.
 *
 * `fieldsRead` and `primaryKey` name exactly the declared fields each
 * binding depends on, per bound stream. The self-check
 * (bindings-self-check.test.ts) compares both against the vendored
 * declaration's own `schema.properties` / `primary_key` — deleting or
 * renaming a field this binding reads, or pointing `primaryKey` at the
 * wrong (but still declared) field, must fail that check (S1).
 */

function byStream(
  records: PdppRecord[],
  stream: string,
): Record<string, unknown>[] {
  return records.filter((r) => r.stream === stream).map((r) => r.data);
}

function ifDefined(
  record: Record<string, unknown>,
  sourceField: string,
  targetField: string,
): Record<string, unknown> {
  return record[sourceField] === undefined
    ? {}
    : { [targetField]: record[sourceField] };
}

function missingStream(
  scope: string,
  expectedStream: string,
): ProjectionResult {
  return {
    ok: false,
    error: { kind: "missing_stream", scope, expectedStream },
  };
}

/**
 * A stream the caller never fetched must be a `missing_stream` error, not
 * silently indistinguishable from "fetched, zero rows" (a valid state for a
 * list-shaped stream). "Fetched" is expressed explicitly via
 * `options.fetchedStreams` — the set of streams the caller actually asked
 * the Personal Server for — independent of how many records came back. A
 * stream in `fetchedStreams` with zero matching `records` is a real, empty
 * result (N-B1), not an error.
 */
function requireStreams(
  scope: string,
  options: ProjectPdppRecordsOptions,
  expectedStreams: string[],
): ProjectionResult | undefined {
  for (const stream of expectedStreams) {
    if (!options.fetchedStreams.includes(stream)) {
      return missingStream(scope, stream);
    }
  }
  return;
}

/**
 * Legacy connectors that hit a missing/null value at the pin emit `''`
 * (verified per call site: linkedin-playwright.js `pos.title || ''`,
 * `edu.grade || ''`; amazon-playwright.js `price: ''`; shop-playwright.js
 * DOM-fallback `orderNumber: ''`). A legacy-typed string field therefore
 * defaults to `''`, matching the pinned connector's own behavior, so the
 * projected payload never fails the legacy schema on a null/undefined PDPP
 * field. This is real, cited legacy behavior, not an invented default.
 */
function orEmptyString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

/**
 * Legacy connectors that hit a missing/null count emit `0`
 * (linkedin-playwright.js `sk.endorsementCount || sk.endorsements || 0`).
 */
function orZero(value: unknown): number {
  return typeof value === "number" ? value : 0;
}

function youtubeStringOrNull(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function youtubeRequiredString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function youtubeLegacyProjection(
  scope: string,
  skipped: number,
  fields: string[],
  payload: Record<string, unknown>,
): ProjectionResult {
  return {
    ok: true,
    payload,
    ...(skipped > 0
      ? {
          diagnostics: [
            {
              kind: "records_skipped" as const,
              scope,
              count: skipped,
              missingFields: fields,
            },
          ],
        }
      : {}),
  };
}

const youtubeProvenance: LegacyScopeBindingProvenance[] = [
  {
    kind: "collection-profile",
    ref: "https://github.com/PDP-Connect/data-connectors/tree/fe871c128acd801849551e1d75db0b570b5279df/connectors/youtube",
    digest:
      "sha256:bc6bcb2704bd52d9c002eb0c1810bceb15c4a07469f07a326ff08553b3b5e41f",
    path: "declarations/youtube.collection-profile.json#streams[name=profile,subscriptions,playlists,playlist_items,likes,watch_later,watch_history]",
  },
];

const youtubeProfile: LegacyScopeBinding = {
  scope: "youtube.profile",
  pdppSource: "https://registry.pdpp.dev/connectors/youtube",
  pdppStreams: ["profile"],
  legacySchemaPath: "youtube.profile.json",
  fieldsRead: {
    profile: [
      "id",
      "channel_url",
      "title",
      "handle",
      "email",
      "joined_at",
      "avatar_url",
      "description",
      "country",
      "subscriber_count",
      "view_count",
      "video_count",
    ],
  },
  primaryKey: { profile: ["id"] },
  lossy: [
    "Browser-visible profile values map to the retained legacy fields; values absent from the signed-in page remain null.",
  ],
  provenance: youtubeProvenance,
  project(records, options): ProjectionResult {
    const guard = requireStreams("youtube.profile", options, ["profile"]);
    if (guard) return guard;
    const profile = byStream(records, "profile")[0];
    if (!profile) return { ok: true, payload: {} };
    const channelId = youtubeRequiredString(profile.id);
    if (!channelId)
      return {
        ok: false,
        error: {
          kind: "invalid_value",
          scope: "youtube.profile",
          reason: "YouTube profile is missing its declared id",
        },
      };
    return youtubeLegacyProjection("youtube.profile", 0, [], {
      email: youtubeStringOrNull(profile.email),
      channelUrl: youtubeStringOrNull(profile.channel_url),
      handle: youtubeStringOrNull(profile.handle),
      joinedDate: youtubeStringOrNull(profile.joined_at),
      channelTitle: youtubeStringOrNull(profile.title),
      channelId,
      avatarUrl: youtubeStringOrNull(profile.avatar_url),
      description: youtubeStringOrNull(profile.description),
      country: youtubeStringOrNull(profile.country),
      subscriberCount:
        typeof profile.subscriber_count === "number"
          ? profile.subscriber_count
          : null,
      viewCount:
        typeof profile.view_count === "number" ? profile.view_count : null,
      videoCount:
        typeof profile.video_count === "number" ? profile.video_count : null,
    });
  },
};

const youtubeSubscriptions: LegacyScopeBinding = {
  scope: "youtube.subscriptions",
  pdppSource: youtubeProfile.pdppSource,
  pdppStreams: ["subscriptions"],
  legacySchemaPath: "youtube.subscriptions.json",
  fieldsRead: {
    subscriptions: [
      "channel_id",
      "channel_title",
      "channel_url",
      "handle",
      "avatar_url",
      "subscriber_count",
      "description",
      "is_verified",
      "notifications",
    ],
  },
  primaryKey: { subscriptions: ["id"] },
  lossy: [
    "Rows without legacy-required channelTitle/channelUrl or required notification booleans are skipped and reported.",
  ],
  provenance: youtubeProvenance,
  project(records, options): ProjectionResult {
    const guard = requireStreams("youtube.subscriptions", options, [
      "subscriptions",
    ]);
    if (guard) return guard;
    let skipped = 0;
    const missing = new Set<string>();
    const subscriptions = byStream(records, "subscriptions").flatMap((row) => {
      const channelTitle = youtubeRequiredString(row.channel_title);
      const channelUrl = youtubeRequiredString(row.channel_url);
      if (
        !channelTitle ||
        !channelUrl ||
        typeof row.is_verified !== "boolean" ||
        typeof row.notifications !== "boolean"
      ) {
        skipped++;
        if (!channelTitle) missing.add("subscriptions.channel_title");
        if (!channelUrl) missing.add("subscriptions.channel_url");
        if (typeof row.is_verified !== "boolean")
          missing.add("subscriptions.is_verified");
        if (typeof row.notifications !== "boolean")
          missing.add("subscriptions.notifications");
        return [];
      }
      return [
        {
          channelTitle,
          channelUrl,
          handle: youtubeStringOrNull(row.handle),
          channelId: youtubeStringOrNull(row.channel_id),
          avatarUrl: youtubeStringOrNull(row.avatar_url),
          subscriberCountText: null,
          subscriberCount:
            typeof row.subscriber_count === "number"
              ? row.subscriber_count
              : null,
          description: youtubeStringOrNull(row.description),
          isVerified: row.is_verified,
          isBellNotification: row.notifications,
        },
      ];
    });
    return youtubeLegacyProjection(
      "youtube.subscriptions",
      skipped,
      [...missing],
      { subscriptions },
    );
  },
};

const youtubePlaylists: LegacyScopeBinding = {
  scope: "youtube.playlists",
  pdppSource: youtubeProfile.pdppSource,
  pdppStreams: ["playlists"],
  legacySchemaPath: "youtube.playlists.json",
  fieldsRead: {
    playlists: [
      "id",
      "url",
      "title",
      "owner",
      "owner_url",
      "visibility",
      "video_count",
      "view_count",
    ],
  },
  primaryKey: { playlists: ["id"] },
  lossy: [
    "Rows without a legacy-required URL are skipped and reported. Browser collection is a bounded snapshot.",
  ],
  provenance: youtubeProvenance,
  project(records, options): ProjectionResult {
    const guard = requireStreams("youtube.playlists", options, ["playlists"]);
    if (guard) return guard;
    let skipped = 0;
    const playlists = byStream(records, "playlists").flatMap((row) => {
      const playlistId = youtubeRequiredString(row.id);
      const url = youtubeRequiredString(row.url);
      if (!playlistId || !url) {
        skipped++;
        return [];
      }
      const privacy =
        typeof row.visibility === "string" &&
        ["Public", "Private", "Unlisted"].includes(row.visibility)
          ? row.visibility
          : null;
      return [
        {
          playlistId,
          url,
          title: youtubeStringOrNull(row.title),
          owner: youtubeStringOrNull(row.owner),
          ownerUrl: youtubeStringOrNull(row.owner_url),
          privacy,
          videoCount:
            typeof row.video_count === "number" ? row.video_count : null,
          views: typeof row.view_count === "number" ? row.view_count : null,
        },
      ];
    });
    return youtubeLegacyProjection(
      "youtube.playlists",
      skipped,
      skipped ? ["playlists.id", "playlists.url"] : [],
      { playlists },
    );
  },
};

function youtubeVideo(
  row: Record<string, unknown>,
): Record<string, unknown> | undefined {
  const videoUrl = youtubeRequiredString(row.video_url);
  const videoTitle = youtubeRequiredString(row.video_title);
  if (!videoUrl || !videoTitle) return undefined;
  const duration =
    typeof row.duration_seconds === "number" ? row.duration_seconds : null;
  const durationText =
    duration === null
      ? null
      : duration >= 3600
        ? `${Math.floor(duration / 3600)}:${String(Math.floor((duration % 3600) / 60)).padStart(2, "0")}:${String(duration % 60).padStart(2, "0")}`
        : `${Math.floor(duration / 60)}:${String(duration % 60).padStart(2, "0")}`;
  return {
    videoId: youtubeStringOrNull(row.video_id),
    videoUrl,
    videoTitle,
    channelTitle: youtubeStringOrNull(row.channel_title),
    channelUrl: youtubeStringOrNull(row.channel_url),
    durationText,
    thumbnailUrl: youtubeStringOrNull(row.thumbnail_url),
  };
}

const youtubePlaylistItems: LegacyScopeBinding = {
  scope: "youtube.playlistItems",
  pdppSource: youtubeProfile.pdppSource,
  pdppStreams: ["playlist_items"],
  legacySchemaPath: "youtube.playlistItems.json",
  fieldsRead: {
    playlist_items: [
      "playlist_id",
      "video_id",
      "video_url",
      "video_title",
      "channel_title",
      "channel_url",
      "duration_seconds",
      "thumbnail_url",
    ],
  },
  primaryKey: { playlist_items: ["id"] },
  lossy: [
    "Playlist headers are unavailable on item rows. Records missing required videoTitle/videoUrl or playlist_id are skipped and reported. duration_seconds is formatted as m:ss.",
  ],
  provenance: youtubeProvenance,
  project(records, options): ProjectionResult {
    const guard = requireStreams("youtube.playlistItems", options, [
      "playlist_items",
    ]);
    if (guard) return guard;
    const grouped = new Map<
      string,
      { playlistId: string; items: Record<string, unknown>[] }
    >();
    let skipped = 0;
    for (const row of byStream(records, "playlist_items")) {
      const playlistId = youtubeRequiredString(row.playlist_id);
      const video = youtubeVideo(row);
      if (!playlistId || !video) {
        skipped++;
        continue;
      }
      const group = grouped.get(playlistId) ?? { playlistId, items: [] };
      group.items.push(video);
      grouped.set(playlistId, group);
    }
    return youtubeLegacyProjection(
      "youtube.playlistItems",
      skipped,
      skipped
        ? [
            "playlist_items.playlist_id",
            "playlist_items.video_url",
            "playlist_items.video_title",
          ]
        : [],
      {
        playlists: [...grouped.values()].map((group) => ({
          ...group,
          playlistTitle: null,
          playlistUrl: null,
        })),
      },
    );
  },
};

function youtubeNamedVideos(
  scope: "youtube.likes" | "youtube.watchLater",
  stream: "likes" | "watch_later",
  key: "likedVideos" | "watchLater",
): LegacyScopeBinding {
  return {
    scope,
    pdppSource: youtubeProfile.pdppSource,
    pdppStreams: [stream],
    legacySchemaPath: `${scope}.json`,
    fieldsRead: {
      [stream]: [
        "video_id",
        "video_url",
        "video_title",
        "channel_title",
        "channel_url",
        "duration_seconds",
        "thumbnail_url",
      ],
    },
    primaryKey: { [stream]: ["id"] },
    lossy: [
      "Legacy requires videoTitle and videoUrl; incomplete browser rows are skipped and reported.",
    ],
    provenance: youtubeProvenance,
    project(records, options): ProjectionResult {
      const guard = requireStreams(scope, options, [stream]);
      if (guard) return guard;
      let skipped = 0;
      const videos = byStream(records, stream).flatMap((row) => {
        const video = youtubeVideo(row);
        if (!video) {
          skipped++;
          return [];
        }
        return [video];
      });
      return youtubeLegacyProjection(
        scope,
        skipped,
        skipped ? [`${stream}.video_url`, `${stream}.video_title`] : [],
        { [key]: videos },
      );
    },
  };
}

const youtubeLikes = youtubeNamedVideos(
  "youtube.likes",
  "likes",
  "likedVideos",
);
const youtubeWatchLater = youtubeNamedVideos(
  "youtube.watchLater",
  "watch_later",
  "watchLater",
);

const youtubeHistory: LegacyScopeBinding = {
  scope: "youtube.history",
  pdppSource: youtubeProfile.pdppSource,
  pdppStreams: ["watch_history"],
  legacySchemaPath: "youtube.history.json",
  fieldsRead: {
    watch_history: [
      "position",
      "watched_date",
      "video_id",
      "video_url",
      "video_title",
      "channel_title",
      "channel_url",
      "view_count",
      "description",
    ],
  },
  primaryKey: { watch_history: ["id"] },
  lossy: [
    "Preserves page order by position and caps output at 50 entries. watchedAtText carries watched_date at day precision only; no timestamp is inferred. Integer view_count is rendered as '<count> views'; absent view_count remains null. Rows without required videoUrl are skipped and reported. Missing positions fail because page order cannot be preserved.",
  ],
  provenance: youtubeProvenance,
  project(records, options): ProjectionResult {
    const guard = requireStreams("youtube.history", options, ["watch_history"]);
    if (guard) return guard;
    let skipped = 0;
    const sourceRows = byStream(records, "watch_history");
    if (
      sourceRows.some(
        (row) =>
          typeof row.position !== "number" || !Number.isInteger(row.position),
      )
    ) {
      return {
        ok: false,
        error: {
          kind: "invalid_value",
          scope: "youtube.history",
          reason:
            "YouTube browser history is missing an integer position; page order cannot be preserved",
        },
      };
    }
    const rows = sourceRows
      .flatMap((row) => {
        const videoUrl = youtubeRequiredString(row.video_url);
        if (!videoUrl) {
          skipped++;
          return [];
        }
        const viewCount =
          typeof row.view_count === "number" ? row.view_count : null;
        return [
          {
            watchedAtText: youtubeStringOrNull(row.watched_date),
            videoId: youtubeStringOrNull(row.video_id),
            videoUrl,
            videoTitle: youtubeStringOrNull(row.video_title),
            channelTitle: youtubeStringOrNull(row.channel_title),
            views: viewCount === null ? null : `${viewCount} views`,
            description: youtubeStringOrNull(row.description),
            _position: row.position as number,
          },
        ];
      })
      .sort((a, b) => a._position - b._position);
    const history = rows
      .slice(0, 50)
      .map(({ _position: _ignored, ...row }) => row);
    return youtubeLegacyProjection(
      "youtube.history",
      skipped,
      skipped ? ["watch_history.video_url"] : [],
      { timeWindow: "top 50 most recent items", history },
    );
  },
};

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isOptionalString(value: unknown): value is string | null | undefined {
  return value === undefined || value === null || typeof value === "string";
}

/**
 * Validates that a string is a valid ISO 8601 date-time. Rejects invalid
 * formats so only valid date-times pass through to the payload (F5).
 */
function isValidIso8601DateTime(value: string): boolean {
  if (typeof value !== "string") return false;
  const date = new Date(value);
  // The string is valid if it parses to a valid date (not NaN).
  return !isNaN(date.getTime());
}

/**
 * Reformats an ISO-8601 date/date-time string to amazon-playwright.js's
 * captured legacy shape, `"March 5, 2024"` (verified: the connector's own
 * regex only ever matches `MonthName D, YYYY`,
 * connectors/amazon/amazon-playwright.js:184-187 at the pin). Returns `''`
 * (the connector's own no-match fallback) for anything that does not parse
 * as a date, rather than passing through a shape the legacy schema does not
 * expect.
 */
const MONTH_NAMES = [
  "January",
  "February",
  "March",
  "April",
  "May",
  "June",
  "July",
  "August",
  "September",
  "October",
  "November",
  "December",
];
function toLegacyLongDate(value: unknown): string {
  if (typeof value !== "string") {
    return "";
  }
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) {
    return "";
  }
  return `${MONTH_NAMES[d.getUTCMonth()]} ${d.getUTCDate()}, ${d.getUTCFullYear()}`;
}

/**
 * Reformats start/end date strings to linkedin-playwright.js's captured
 * legacy `dates` shape for experience and education, e.g.
 * `"1/2024 - Present"` (verified: `extractTimePeriod`,
 * connectors/linkedin/linkedin-playwright.js:129-145 — `(month + '/' ) +
 * year` per side, joined by `' - '`, `'Present'` for a missing end, then
 * `.trim()`-ed so a missing start reads `"- Present"` / `"- 3/2020"`). The
 * signed LinkedIn 0.3.1 declaration uses partial dates (`YYYY` or `YYYY-MM`),
 * so year-only values keep their source precision. Full ISO values keep the
 * earlier month/year behavior.
 */
function toLegacyTimePeriod(start: unknown, end: unknown): string {
  const part = (value: unknown): string => {
    if (typeof value !== "string") {
      return "";
    }
    const yearOnly = value.match(/^(\d{4})$/);
    if (yearOnly) {
      return yearOnly[1];
    }
    const yearMonth = value.match(/^(\d{4})-(\d{2})$/);
    if (yearMonth) {
      return `${Number(yearMonth[2])}/${yearMonth[1]}`;
    }
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) {
      return "";
    }
    return `${d.getUTCMonth() + 1}/${d.getUTCFullYear()}`;
  };
  const startPart = part(start);
  const endPart = typeof end === "string" ? part(end) : "";
  return `${startPart} - ${endPart || "Present"}`.trim();
}

// ---------------------------------------------------------------------------
// meta (instagram)
// declarations/meta.collection-profile.json, streams "profile" and "posts".
// connector_id (verified byte-identical to the vendored declaration):
// https://registry.pdpp.dev/connectors/meta
// ---------------------------------------------------------------------------

const instagramProfile: LegacyScopeBinding = {
  scope: "instagram.profile",
  pdppSource: "https://registry.pdpp.dev/connectors/meta",
  pdppStreams: ["profile"],
  legacySchemaPath: "instagram.profile.json",
  fieldsRead: {
    profile: [
      "username",
      "full_name",
      "bio",
      "profile_pic_url",
      "external_url",
      "follower_count",
      "following_count",
      "is_private",
      "is_verified",
      "is_business",
    ],
  },
  primaryKey: { profile: ["id"] },
  lossy: [
    "media_count (no PDPP equivalent; post_count is a different concept — Instagram's media_count includes non-post media types the posts stream does not cover)",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/meta:0.4.0",
      digest:
        "sha256:9805c13ab4ad45caf904b4ce834764e701e426f5c3d2f3697fbab2705d1636ea",
      path: "declarations/meta.collection-profile.json#streams[name=profile]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("instagram.profile", options, ["profile"]);
    if (guard) {
      return guard;
    }
    const [p] = byStream(records, "profile");
    if (!p) {
      return {
        ok: false,
        error: { kind: "empty_singleton", scope: "instagram.profile" },
      };
    }
    const username = p.username;
    if (typeof username !== "string") {
      return {
        ok: false,
        error: {
          kind: "invalid_value",
          scope: "instagram.profile",
          reason: "Meta profile is missing username",
        },
      };
    }
    const fullName =
      p.full_name == null
        ? ""
        : typeof p.full_name === "string"
          ? p.full_name
          : undefined;
    if (fullName === undefined) {
      return {
        ok: false,
        error: {
          kind: "invalid_value",
          scope: "instagram.profile",
          reason: "Meta profile full_name is not a string",
        },
      };
    }

    const payload: Record<string, unknown> = {
      username,
      full_name: fullName,
    };
    if (typeof p.bio === "string") payload.bio = p.bio;
    if (typeof p.profile_pic_url === "string") {
      payload.profile_pic_url = p.profile_pic_url;
    }
    if (typeof p.external_url === "string") {
      payload.external_url = p.external_url;
    }
    if (typeof p.follower_count === "number") {
      payload.follower_count = p.follower_count;
    }
    if (typeof p.following_count === "number") {
      payload.following_count = p.following_count;
    }
    if (typeof p.is_private === "boolean") payload.is_private = p.is_private;
    if (typeof p.is_verified === "boolean") payload.is_verified = p.is_verified;
    if (typeof p.is_business === "boolean") payload.is_business = p.is_business;

    return {
      ok: true,
      payload,
    };
  },
};

// ---------------------------------------------------------------------------
// instagram.posts
// declarations/meta.collection-profile.json#streams[name=posts]
// connector_id: https://registry.pdpp.dev/connectors/meta
// ---------------------------------------------------------------------------

const instagramPosts: LegacyScopeBinding = {
  scope: "instagram.posts",
  pdppSource: "https://registry.pdpp.dev/connectors/meta",
  pdppStreams: ["posts", "post_likes"],
  legacySchemaPath: "instagram.posts.json",
  fieldsRead: {
    posts: ["id", "media_url", "caption", "like_count", "taken_at"],
    post_likes: ["post_id", "user_id", "username"],
  },
  primaryKey: { posts: ["id"], post_likes: ["post_id", "liker_ordinal"] },
  lossy: [
    "nullable media_url, caption, and like_count use the retained collector's empty-string and zero sentinels; every source post is retained",
    "media_url is only available for images and the first image in a carousel; video posts and later carousel images are absent from the artifact's parser output",
    "who_liked.profile_pic_url is omitted because the post_likes stream does not declare it",
    "who_liked.pk and who_liked.id both use post_likes.user_id because the source exposes one liker identity field",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/meta:0.4.0",
      digest:
        "sha256:9805c13ab4ad45caf904b4ce834764e701e426f5c3d2f3697fbab2705d1636ea",
      path: "declarations/meta.collection-profile.json#streams[name=posts,post_likes]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("instagram.posts", options, [
      "posts",
      "post_likes",
    ]);
    if (guard) {
      return guard;
    }

    const sourcePosts = byStream(records, "posts");
    const likesByPost = new Map<string, Record<string, unknown>[]>();
    for (const liker of byStream(records, "post_likes")) {
      if (
        typeof liker.post_id !== "string" ||
        typeof liker.user_id !== "string" ||
        typeof liker.username !== "string"
      ) {
        continue;
      }
      const whoLiked = likesByPost.get(liker.post_id) ?? [];
      whoLiked.push({
        pk: liker.user_id,
        username: liker.username,
        id: liker.user_id,
      });
      likesByPost.set(liker.post_id, whoLiked);
    }
    const posts: Record<string, unknown>[] = [];
    for (const sourcePost of sourcePosts) {
      const projectedPost: Record<string, unknown> = {
        img_url: orEmptyString(sourcePost.media_url),
        caption: orEmptyString(sourcePost.caption),
        num_of_likes: orZero(sourcePost.like_count),
        who_liked:
          typeof sourcePost.id === "string"
            ? (likesByPost.get(sourcePost.id) ?? [])
            : [],
      };
      if (typeof sourcePost.taken_at === "string") {
        projectedPost.taken_at = sourcePost.taken_at;
      }
      posts.push(projectedPost);
    }

    return {
      ok: true,
      payload: { posts },
    };
  },
};

// ---------------------------------------------------------------------------
// instagram.following and instagram.ads
// declarations/meta.collection-profile.json#streams[name=following,ads]
// ---------------------------------------------------------------------------

const instagramFollowing: LegacyScopeBinding = {
  scope: "instagram.following",
  pdppSource: "https://registry.pdpp.dev/connectors/meta",
  pdppStreams: ["following"],
  legacySchemaPath: "instagram.following.json",
  fieldsRead: {
    following: [
      "id",
      "username",
      "full_name",
      "is_private",
      "is_verified",
      "profile_pic_url",
    ],
  },
  primaryKey: { following: ["id"] },
  lossy: [
    "rows without a non-empty string username are skipped because the legacy account schema requires username",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/meta:0.4.0",
      digest:
        "sha256:9805c13ab4ad45caf904b4ce834764e701e426f5c3d2f3697fbab2705d1636ea",
      path: "declarations/meta.collection-profile.json#streams[name=following]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("instagram.following", options, ["following"]);
    if (guard) return guard;
    const accounts = byStream(records, "following").flatMap((r) => {
      if (typeof r.username !== "string" || !r.username) return [];
      const account: Record<string, unknown> = {
        username: r.username,
        full_name: typeof r.full_name === "string" ? r.full_name : "",
        is_private: r.is_private === true,
        is_verified: r.is_verified === true,
        profile_pic_url:
          typeof r.profile_pic_url === "string" && r.profile_pic_url
            ? r.profile_pic_url
            : null,
      };
      if (typeof r.id === "string") account.pk = r.id;
      return [account];
    });
    return { ok: true, payload: { accounts, total: accounts.length } };
  },
};

const instagramAds: LegacyScopeBinding = {
  scope: "instagram.ads",
  pdppSource: "https://registry.pdpp.dev/connectors/meta",
  pdppStreams: ["ads"],
  legacySchemaPath: "instagram.ads.json",
  fieldsRead: { ads: ["kind", "name", "description"] },
  primaryKey: { ads: ["id"] },
  lossy: [
    "ads rows with a null description omit the optional legacy category description",
    "malformed ads rows without a string name or one of the declaration's three kinds are skipped",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/meta:0.4.0",
      digest:
        "sha256:9805c13ab4ad45caf904b4ce834764e701e426f5c3d2f3697fbab2705d1636ea",
      path: "declarations/meta.collection-profile.json#streams[name=ads]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("instagram.ads", options, ["ads"]);
    if (guard) return guard;
    const advertisers: Record<string, string>[] = [];
    const ad_topics: Record<string, string>[] = [];
    const categories: Record<string, unknown>[] = [];
    for (const row of byStream(records, "ads")) {
      if (typeof row.name !== "string") continue;
      if (row.kind === "advertiser") advertisers.push({ name: row.name });
      if (row.kind === "ad_topic") ad_topics.push({ name: row.name });
      if (row.kind === "ad_category") {
        categories.push({
          name: row.name,
          ...(typeof row.description === "string"
            ? { description: row.description }
            : {}),
        });
      }
    }
    return { ok: true, payload: { advertisers, ad_topics, categories } };
  },
};

// ---------------------------------------------------------------------------
// github
// declarations/github.collection-profile.json
// connector_id: https://registry.pdpp.dev/connectors/github
// ---------------------------------------------------------------------------

const githubRepositories: LegacyScopeBinding = {
  scope: "github.repositories",
  pdppSource: "https://registry.pdpp.dev/connectors/github",
  pdppStreams: ["repositories"],
  legacySchemaPath: "github.repositories.json",
  fieldsRead: {
    repositories: [
      "name",
      "html_url",
      "description",
      "language",
      "stargazers_count",
      "forks_count",
      "private",
      "topics",
      "updated_at",
    ],
  },
  primaryKey: { repositories: ["id"] },
  lossy: [
    "description, language, updatedAt: PDPP-side null projects as legacy's own '' / null default, not a fabricated value, but omission still differs from a populated legacy record",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/github:0.7.2",
      digest:
        "sha256:5501bb109cdca02d2acd08aa6891613c7af0bbe0869c30eba2a8070836b0d2f7",
      path: "declarations/github.collection-profile.json#streams[name=repositories]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("github.repositories", options, [
      "repositories",
    ]);
    if (guard) {
      return guard;
    }
    const items = byStream(records, "repositories");
    // Legacy requires name, url per item; allows description, language,
    // stars, forks, visibility, topics, updatedAt. `url` is `html_url` on
    // the repositories stream (a real GitHub URL field, not a template).
    // `visibility` is the literal text GitHub's own repo-list DOM renders,
    // capitalized "Public"/"Private" (github-playwright.js:416,
    // `row.querySelector('span.Label')?.textContent || 'Public'`) — derived
    // here from PDPP's boolean `private` field with the matching casing,
    // not lowercase.
    return {
      ok: true,
      payload: {
        repositories: items.map((r) => ({
          name: orEmptyString(r.name),
          url: orEmptyString(r.html_url),
          description: orEmptyString(r.description),
          language: orEmptyString(r.language),
          stars: orZero(r.stargazers_count),
          forks: orZero(r.forks_count),
          visibility: r.private === true ? "Private" : "Public",
          topics: Array.isArray(r.topics) ? r.topics : [],
          updatedAt: typeof r.updated_at === "string" ? r.updated_at : null,
        })),
      },
    };
  },
};

const githubStarred: LegacyScopeBinding = {
  scope: "github.starred",
  pdppSource: "https://registry.pdpp.dev/connectors/github",
  pdppStreams: ["starred"],
  legacySchemaPath: "github.starred.json",
  fieldsRead: {
    starred: [
      "full_name",
      "html_url",
      "description",
      "language",
      "stargazers_count",
    ],
  },
  primaryKey: { starred: ["id"] },
  lossy: [
    "updatedAt changes meaning: legacy is the repo's own last-updated time from the stars page (github-playwright.js:415, relative-time datetime); PDPP's starred stream only carries starred_at, the time the user starred it. Field is emitted as null (no PDPP source for repo update time), not omitted.",
    "description, language: PDPP-side null projects as ''",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/github:0.7.2",
      digest:
        "sha256:5501bb109cdca02d2acd08aa6891613c7af0bbe0869c30eba2a8070836b0d2f7",
      path: "declarations/github.collection-profile.json#streams[name=starred]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("github.starred", options, ["starred"]);
    if (guard) {
      return guard;
    }
    const items = byStream(records, "starred");
    return {
      ok: true,
      payload: {
        starred: items.map((r) => ({
          fullName: orEmptyString(r.full_name),
          url: orEmptyString(r.html_url),
          description: orEmptyString(r.description),
          language: orEmptyString(r.language),
          stars: orZero(r.stargazers_count),
          updatedAt: null,
        })),
      },
    };
  },
};

// github.history can be projected from authored pull_requests plus authored
// issues. The signed issues stream also contains assigned issues, so it is
// filtered against the signed user.login singleton before projection.
const githubHistory: LegacyScopeBinding = {
  scope: "github.history",
  pdppSource: "https://registry.pdpp.dev/connectors/github",
  pdppStreams: ["user", "issues", "pull_requests"],
  legacySchemaPath: "github.history.json",
  fieldsRead: {
    user: ["login"],
    issues: [
      "id",
      "number",
      "title",
      "body",
      "state",
      "user_login",
      "labels",
      "repository_full_name",
      "html_url",
      "comments",
      "reactions_total_count",
      "created_at",
      "updated_at",
      "closed_at",
      "is_pull_request",
    ],
    pull_requests: [
      "id",
      "number",
      "title",
      "body",
      "state",
      "labels",
      "repository_full_name",
      "html_url",
      "comments",
      "reactions_total_count",
      "created_at",
      "updated_at",
      "closed_at",
      "merged_at",
      "draft",
    ],
  },
  primaryKey: { user: ["id"], issues: ["id"], pull_requests: ["id"] },
  lossy: [
    "legacy IDs used gh-issue-/gh-pr- prefixes; projection uses the signed PDPP record ID directly",
    "body is truncated to the legacy connector's 500-character limit",
    "repoUrl is omitted because no repository URL field is declared on issue or pull request streams",
    "fetchedAt is set at projection time because the legacy schema requires it and PDPP history records have no fetch timestamp",
    "items with missing required legacy repo names or malformed declared fields are skipped",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/github:0.7.2",
      digest:
        "sha256:5501bb109cdca02d2acd08aa6891613c7af0bbe0869c30eba2a8070836b0d2f7",
      path: "declarations/github.collection-profile.json#streams[name=user,issues,pull_requests]",
    },
  ],
  project(records, options): ProjectionResult {
    const streams = ["user", "issues", "pull_requests"];
    const guard = requireStreams("github.history", options, streams);
    if (guard) return guard;
    const login = byStream(records, "user")[0]?.login;
    const sourceIssues = byStream(records, "issues");
    if (typeof login !== "string" && sourceIssues.length > 0) {
      return {
        ok: false,
        error: {
          kind: "invalid_value",
          scope: "github.history",
          reason:
            "Signed user stream has no login for authored-issue filtering",
        },
      };
    }
    const projectItem = (r: Record<string, unknown>, type: "pr" | "issue") => {
      if (
        typeof r.id !== "string" ||
        typeof r.repository_full_name !== "string"
      )
        return null;
      const item: Record<string, unknown> = {
        id: r.id,
        type,
        repo: r.repository_full_name,
        comments: typeof r.comments === "number" ? r.comments : 0,
        reactionsTotal:
          typeof r.reactions_total_count === "number"
            ? r.reactions_total_count
            : 0,
        isDraft:
          type === "pr" &&
          r.draft === true &&
          r.state === "open" &&
          r.merged_at == null,
      };
      if (typeof r.number === "number") item.number = r.number;
      if (typeof r.title === "string" || r.title === null) item.title = r.title;
      if (typeof r.body === "string" || r.body === null) {
        item.body = typeof r.body === "string" ? r.body.slice(0, 500) : null;
      }
      if (typeof r.state === "string" || r.state === null) item.state = r.state;
      for (const [source, target] of [
        ["created_at", "createdAt"],
        ["updated_at", "updatedAt"],
        ["closed_at", "closedAt"],
        ["html_url", "url"],
      ]) {
        if (typeof r[source] === "string" || r[source] === null)
          item[target] = r[source];
      }
      if (
        type === "pr" &&
        (typeof r.merged_at === "string" || r.merged_at === null)
      ) {
        item.mergedAt = r.merged_at;
      }
      item.labels = Array.isArray(r.labels)
        ? r.labels.filter((label): label is string => typeof label === "string")
        : [];
      return item;
    };
    const pullRequests = byStream(records, "pull_requests").flatMap((r) => {
      const item = projectItem(r, "pr");
      return item ? [item] : [];
    });
    const issues = sourceIssues.flatMap((r) => {
      if (
        typeof r.is_pull_request !== "boolean" ||
        r.is_pull_request ||
        r.user_login !== login
      ) {
        return [];
      }
      const item = projectItem(r, "issue");
      return item ? [item] : [];
    });
    const authoredIssues = sourceIssues.filter(
      (r) =>
        typeof login === "string" &&
        typeof r.is_pull_request === "boolean" &&
        !r.is_pull_request &&
        r.user_login === login,
    );
    if (
      pullRequests.length !== byStream(records, "pull_requests").length ||
      issues.length !== authoredIssues.length
    ) {
      return {
        ok: false,
        error: {
          kind: "incomplete_scope",
          scope: "github.history",
          reason:
            "Cannot preserve every authored history row: required id or repository_full_name is missing",
        },
      };
    }
    return {
      ok: true,
      payload: { pullRequests, issues, fetchedAt: new Date().toISOString() },
    };
  },
};

const githubProfile: LegacyScopeBinding = {
  scope: "github.profile",
  pdppSource: "https://registry.pdpp.dev/connectors/github",
  pdppStreams: ["user", "user_stats", "pinned_repositories", "organizations"],
  legacySchemaPath: "github.profile.json",
  fieldsRead: {
    user: [
      "login",
      "name",
      "bio",
      "company",
      "location",
      "blog",
      "avatar_url",
      "achievements",
    ],
    user_stats: ["observed_on", "followers", "following", "public_repos"],
    pinned_repositories: [
      "full_name",
      "html_url",
      "description",
      "languages",
      "stargazers_count",
    ],
    organizations: ["login", "description", "avatar_url"],
  },
  primaryKey: {
    user: ["id"],
    user_stats: ["id"],
    pinned_repositories: ["id"],
    organizations: ["id"],
  },
  lossy: [
    "profileUrl is derived from the authenticated user's login using GitHub's canonical profile URL pattern",
    "organization label and URL are omitted because the organizations stream carries neither field; description is not substituted for label",
    "pinned repository description, language, URL, and stars are omitted when the source value is absent; languages is a list and legacy supports only one language, so the first collected language is used",
    "contributionsLastYear is omitted: daily contribution data may be an incremental or caller-limited window and cannot establish a complete rolling-year total",
    "follower, following, and repository counts use the newest observed_on stats record; no value is emitted if no stats record exists",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/github:0.7.2",
      digest:
        "sha256:5501bb109cdca02d2acd08aa6891613c7af0bbe0869c30eba2a8070836b0d2f7",
      path: "declarations/github.collection-profile.json#streams[name=user,user_stats,pinned_repositories,organizations]",
    },
  ],
  project(records, options): ProjectionResult {
    const streams = [
      "user",
      "user_stats",
      "pinned_repositories",
      "organizations",
    ];
    const guard = requireStreams("github.profile", options, streams);
    if (guard) return guard;
    const user = byStream(records, "user")[0];
    if (!user || typeof user.login !== "string") {
      return {
        ok: false,
        error: { kind: "empty_singleton", scope: "github.profile" },
      };
    }
    const payload: Record<string, unknown> = {
      username: user.login,
      profileUrl: `https://github.com/${user.login}`,
    };
    for (const [source, target] of [
      ["name", "fullName"],
      ["bio", "bio"],
      ["company", "company"],
      ["location", "location"],
      ["blog", "website"],
      ["avatar_url", "avatarUrl"],
    ]) {
      if (typeof user[source] === "string") payload[target] = user[source];
    }
    const stats = byStream(records, "user_stats")
      .filter((r) => typeof r.observed_on === "string")
      .sort((a, b) =>
        String(b.observed_on).localeCompare(String(a.observed_on)),
      )[0];
    if (stats) {
      for (const [source, target] of [
        ["followers", "followers"],
        ["following", "following"],
        ["public_repos", "repositoryCount"],
      ]) {
        if (typeof stats[source] === "number") payload[target] = stats[source];
      }
    }
    if (Array.isArray(user.achievements)) {
      payload.achievements = user.achievements.flatMap((value) => {
        if (!value || typeof value !== "object") return [];
        const item = value as Record<string, unknown>;
        if (typeof item.name !== "string") return [];
        return [
          {
            name: item.name,
            ...(typeof item.icon_url === "string" || item.icon_url === null
              ? { iconUrl: item.icon_url }
              : {}),
          },
        ];
      });
    }
    payload.pinnedRepositories = byStream(
      records,
      "pinned_repositories",
    ).flatMap((r) => {
      if (typeof r.full_name !== "string") return [];
      const item: Record<string, unknown> = { fullName: r.full_name };
      if (typeof r.html_url === "string" || r.html_url === null)
        item.url = r.html_url;
      if (typeof r.description === "string") item.description = r.description;
      if (Array.isArray(r.languages) && typeof r.languages[0] === "string")
        item.language = r.languages[0];
      if (typeof r.stargazers_count === "number")
        item.stars = r.stargazers_count;
      return [item];
    });
    payload.organizations = byStream(records, "organizations").flatMap((r) => {
      if (typeof r.login !== "string") return [];
      return [
        {
          login: r.login,
          ...(typeof r.avatar_url === "string" || r.avatar_url === null
            ? { avatarUrl: r.avatar_url }
            : {}),
        },
      ];
    });
    return { ok: true, payload };
  },
};

const githubEvents: LegacyScopeBinding = {
  scope: "github.events",
  pdppSource: "https://registry.pdpp.dev/connectors/github",
  pdppStreams: ["events"],
  legacySchemaPath: "github.events.json",
  fieldsRead: {
    events: ["id", "type", "created_at", "repository_full_name", "is_public"],
  },
  primaryKey: { events: ["id"] },
  lossy: [
    "the events API retains only roughly 90 days; the connector emits each collected public event as a legacy event",
    "legacy action, title, body, URL, branch, commit count, repository URL, and window description are omitted because events records do not declare those values",
    "fetchedAt is set at projection time because the stream has no collection timestamp",
    "malformed records missing legacy-required fields are skipped",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/github:0.7.2",
      digest:
        "sha256:5501bb109cdca02d2acd08aa6891613c7af0bbe0869c30eba2a8070836b0d2f7",
      path: "declarations/github.collection-profile.json#streams[name=events]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("github.events", options, ["events"]);
    if (guard) return guard;
    const events = byStream(records, "events").flatMap((r) => {
      if (
        typeof r.id !== "string" ||
        typeof r.type !== "string" ||
        typeof r.created_at !== "string" ||
        typeof r.repository_full_name !== "string" ||
        typeof r.is_public !== "boolean"
      )
        return [];
      return [
        {
          id: r.id,
          type: r.type,
          createdAt: r.created_at,
          repo: r.repository_full_name,
          isPublic: r.is_public,
        },
      ];
    });
    return {
      ok: true,
      payload: { events, fetchedAt: new Date().toISOString() },
    };
  },
};

const githubContributions: LegacyScopeBinding = {
  scope: "github.contributions",
  pdppSource: "https://registry.pdpp.dev/connectors/github",
  pdppStreams: ["contributions"],
  legacySchemaPath: "github.contributions.json",
  fieldsRead: { contributions: ["date", "contribution_count"] },
  primaryKey: { contributions: ["id"] },
  lossy: [
    "daily records are projected to legacy days; level is absent from the source and omitted",
    "totalContributionsLastYear, yearTotals, monthlyTotals, and topDay are omitted because collected contribution records may cover only an incremental or caller-limited interval",
    "fetchedAt is set at projection time because contribution records have no collection timestamp",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/github:0.7.2",
      digest:
        "sha256:5501bb109cdca02d2acd08aa6891613c7af0bbe0869c30eba2a8070836b0d2f7",
      path: "declarations/github.collection-profile.json#streams[name=contributions]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("github.contributions", options, [
      "contributions",
    ]);
    if (guard) return guard;
    const days = byStream(records, "contributions").flatMap((r) => {
      if (
        typeof r.date !== "string" ||
        typeof r.contribution_count !== "number"
      )
        return [];
      return [{ date: r.date, count: r.contribution_count }];
    });
    return { ok: true, payload: { days, fetchedAt: new Date().toISOString() } };
  },
};

// ---------------------------------------------------------------------------
// openai (chatgpt)
// declarations/chatgpt.collection-profile.json
// connector_id: https://registry.pdpp.dev/connectors/chatgpt
// ---------------------------------------------------------------------------

const chatgptMemories: LegacyScopeBinding = {
  scope: "chatgpt.memories",
  pdppSource: "https://registry.pdpp.dev/connectors/chatgpt",
  pdppStreams: ["memories"],
  legacySchemaPath: "chatgpt.memories.json",
  fieldsRead: { memories: ["id", "content", "created_at", "updated_at"] },
  primaryKey: { memories: ["id"] },
  lossy: [
    "type: legacy always emits it, defaulting to the literal string 'memory' when the upstream field is absent (chatgpt-playwright.js:645, `memory.type || 'memory'`); the memories stream has no `type` field at all, so this binding reproduces that same fallback rather than omitting the field the schema allows.",
    "created_at: a null value falls back to the wall clock at projection time (new Date().toISOString()), matching legacy's own `memory.created_at || new Date().toISOString()` fallback — this makes project() depend on the clock for that one field (N-M3).",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/chatgpt:0.1.0",
      digest:
        "sha256:811daaf8f2a9a346f1ff5109c118ea404212c8e00790cc5d448e89ad9fa9c4a4",
      path: "declarations/chatgpt.collection-profile.json#streams[name=memories]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("chatgpt.memories", options, ["memories"]);
    if (guard) {
      return guard;
    }
    const items = byStream(records, "memories");
    // created_at is required by the legacy schema; the stream types it
    // nullable, so a null value falls back to now() the same way the
    // legacy connector does (chatgpt-playwright.js: `created_at:
    // memory.created_at || new Date().toISOString()`), rather than
    // passing through a schema-invalid null.
    return {
      ok: true,
      payload: {
        memories: items.map((m) => ({
          id: orEmptyString(m.id),
          content: orEmptyString(m.content),
          created_at:
            typeof m.created_at === "string"
              ? m.created_at
              : new Date().toISOString(),
          type: "memory",
          ...(typeof m.updated_at === "string"
            ? { updated_at: m.updated_at }
            : {}),
        })),
        total: items.length,
      },
    };
  },
};

// Signed ChatGPT 0.1.1 is the source; Desktop ingest remains disabled until
// catalog admission and static_secret host setup land separately.
const chatgptConversations: LegacyScopeBinding = {
  scope: "chatgpt.conversations",
  pdppSource: "https://registry.pdpp.dev/connectors/chatgpt",
  pdppStreams: ["conversations", "messages"],
  legacySchemaPath: "chatgpt.conversations.json",
  fieldsRead: {
    conversations: [
      "id",
      "title",
      "create_time",
      "update_time",
      "current_node",
      "message_count_on_current_branch",
    ],
    messages: [
      "id",
      "conversation_id",
      "parent_id",
      "role",
      "content",
      "content_type",
      "model_slug",
      "create_time",
      "on_current_branch",
    ],
  },
  primaryKey: { conversations: ["id"], messages: ["id"] },
  lossy: [
    "Conversation create/update times pass through as null when the source lacks them, matching legacy's listed?.create_time ?? fetched.create_time ?? null fallback.",
    "fetched_at is generated at projection time, matching legacy's per-run toConversationRecord timestamp.",
    "Conversations without complete current-branch message evidence reject the projection; nested full threads are not invented.",
    "Only user/assistant text or multimodal_text messages with nonempty string content are retained, matching the legacy connector's walkMessages filter; message_count is the retained count.",
    "A missing title becomes 'Untitled', matching the legacy connector's toConversationRecord fallback; model_slug is renamed to model.",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/chatgpt:0.2.0",
      digest:
        "sha256:01777566b5163ca62bdb2bd21c316d09dd88f42c30a6d943ca101cfb635494ea",
      path: "declarations/chatgpt-0.2.0.collection-profile.json#streams[name=conversations,messages]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("chatgpt.conversations", options, [
      "conversations",
      "messages",
    ]);
    if (guard) return guard;

    const messagesByConversation = new Map<string, Record<string, unknown>[]>();
    for (const message of byStream(records, "messages")) {
      if (typeof message.conversation_id !== "string") continue;
      const group = messagesByConversation.get(message.conversation_id) ?? [];
      group.push(message);
      messagesByConversation.set(message.conversation_id, group);
    }

    const sourceConversations = byStream(records, "conversations");
    const sourceIds = new Set(sourceConversations.map((c) => c.id));
    if ([...messagesByConversation.keys()].some((id) => !sourceIds.has(id))) {
      return {
        ok: false,
        error: {
          kind: "invalid_value",
          scope: "chatgpt.conversations",
          reason: "Messages have no matching conversation",
        },
      };
    }
    const conversations: Record<string, unknown>[] = [];
    for (const conversation of sourceConversations) {
      const {
        id,
        create_time,
        update_time,
        current_node,
        message_count_on_current_branch,
      } = conversation;
      if (!isOptionalString(create_time) || !isOptionalString(update_time)) {
        return {
          ok: false,
          error: {
            kind: "invalid_value",
            scope: "chatgpt.conversations",
            reason: "Conversation timestamps must be strings, null, or absent",
          },
        };
      }
      if (
        !isNonEmptyString(id) ||
        typeof message_count_on_current_branch !== "number" ||
        !Number.isInteger(message_count_on_current_branch) ||
        message_count_on_current_branch < 0
      ) {
        return {
          ok: false,
          error: {
            kind: "invalid_value",
            scope: "chatgpt.conversations",
            reason: "Conversation lacks required branch identity or count",
          },
        };
      }

      const branch = (messagesByConversation.get(id) ?? []).filter(
        (m) => m.on_current_branch === true,
      );
      if (branch.length !== message_count_on_current_branch) {
        return {
          ok: false,
          error: {
            kind: "invalid_value",
            scope: "chatgpt.conversations",
            reason: "Current branch message count does not match conversation",
          },
        };
      }
      const byId = new Map(
        branch.filter((m) => typeof m.id === "string").map((m) => [m.id, m]),
      );
      const ordered: Record<string, unknown>[] = [];
      const seen = new Set<string>();
      let node = typeof current_node === "string" ? current_node : null;
      while (node && byId.has(node) && !seen.has(node)) {
        seen.add(node);
        const message = byId.get(node)!;
        ordered.push(message);
        node = typeof message.parent_id === "string" ? message.parent_id : null;
      }
      if (ordered.length !== branch.length) {
        return {
          ok: false,
          error: {
            kind: "invalid_value",
            scope: "chatgpt.conversations",
            reason: "Current branch message chain is incomplete",
          },
        };
      }
      ordered.reverse();
      const messages = ordered
        .filter(
          (m) =>
            (m.role === "user" || m.role === "assistant") &&
            (m.content_type === "text" ||
              m.content_type === "multimodal_text") &&
            typeof m.content === "string" &&
            m.content.length > 0,
        )
        .map((m) => ({
          id: m.id,
          role: m.role,
          content: m.content,
          content_type: m.content_type,
          create_time: typeof m.create_time === "string" ? m.create_time : null,
          model: typeof m.model_slug === "string" ? m.model_slug : null,
        }));
      conversations.push({
        id,
        title:
          typeof conversation.title === "string" &&
          conversation.title.length > 0
            ? conversation.title
            : "Untitled",
        create_time: create_time ?? null,
        update_time: update_time ?? null,
        message_count: messages.length,
        messages,
        fetched_at: new Date().toISOString(),
      });
    }
    return {
      ok: true,
      payload: { conversations, total: conversations.length },
    };
  },
};

// This is the merged 0.1.3 source declaration. Admission remains a separate
// decision; this local manifest hash is not the signed OCI artifact digest.
const anthropicProjectionSource =
  "https://registry.pdpp.dev/connectors/anthropic";
const anthropicProjectionProvenance: LegacyScopeBindingProvenance[] = [
  {
    kind: "collection-profile",
    ref: "PDP-Connect/data-connectors ae44adf769 (#160)",
    digest:
      "sha256:1a156e586c81a95cb3bb1ad9c09c639990a22212074cba7da62268c326593372",
    path: "declarations/anthropic-0.1.3.collection-profile.json#streams[name=account_profile,conversations,messages,projects,project_documents]",
  },
];

function claudeMetadata(
  scope: string,
  records: PdppRecord[],
):
  | {
      ok: true;
      profile: { name: string | null; plan: string | null };
      organizationId: string;
    }
  | ProjectionErr {
  const profiles = byStream(records, "account_profile");
  if (profiles.length !== 1) {
    return {
      ok: false,
      error: {
        kind: "incomplete_scope",
        scope,
        reason: "A single verified account_profile record is required",
      },
    };
  }
  const profile = profiles[0];
  if (
    typeof profile.id !== "string" ||
    !profile.id.trim() ||
    typeof profile.organization_id !== "string" ||
    !profile.organization_id.trim() ||
    profile.id !== profile.organization_id ||
    !(typeof profile.full_name === "string" || profile.full_name === null) ||
    !(typeof profile.plan === "string" || profile.plan === null) ||
    !["browser_menu", "users_json", "none"].includes(
      profile.name_source as string,
    ) ||
    !["valid", "absent", "malformed", "ambiguous", "mismatch"].includes(
      profile.metadata_status as string,
    )
  ) {
    return {
      ok: false,
      error: {
        kind: "invalid_value",
        scope,
        reason: "account_profile does not match its declared verified contract",
      },
    };
  }
  return {
    ok: true,
    profile: {
      name: profile.full_name as string | null,
      plan: profile.plan as string | null,
    },
    organizationId: profile.organization_id as string,
  };
}

function claudeConversationsBinding(): LegacyScopeBinding {
  const scope = "claude.conversations";
  return {
    scope,
    pdppSource: anthropicProjectionSource,
    pdppStreams: ["account_profile", "conversations", "messages"],
    legacySchemaPath: "claude.conversations.json",
    fieldsRead: {
      account_profile: [
        "id",
        "organization_id",
        "full_name",
        "plan",
        "name_source",
        "metadata_status",
      ],
      conversations: [
        "id",
        "title",
        "create_time",
        "update_time",
        "project_id",
        "message_count",
        "is_starred",
      ],
      messages: [
        "id",
        "conversation_id",
        "role",
        "parent_id",
        "content",
        "create_time",
        "update_time",
        "attachments",
      ],
    },
    primaryKey: {
      account_profile: ["id"],
      conversations: ["id"],
      messages: ["id"],
    },
    lossy: [
      "href is reconstructed from the retained Claude route convention; rawContent and unavailable fetchError are omitted.",
    ],
    provenance: anthropicProjectionProvenance,
    project(records, options): ProjectionResult {
      const guard = requireStreams(scope, options, [
        "account_profile",
        "conversations",
        "messages",
      ]);
      if (guard) return guard;
      const metadata = claudeMetadata(scope, records);
      if (!metadata.ok) return metadata;
      const conversations = byStream(records, "conversations");
      const messagesByConversation = new Map<
        string,
        Record<string, unknown>[]
      >();
      for (const message of byStream(records, "messages")) {
        if (typeof message.conversation_id !== "string")
          return {
            ok: false,
            error: {
              kind: "invalid_value",
              scope,
              reason: "Message has no conversation id",
            },
          };
        const rows = messagesByConversation.get(message.conversation_id) ?? [];
        rows.push(message);
        messagesByConversation.set(message.conversation_id, rows);
      }
      const ids = new Set(conversations.map((conversation) => conversation.id));
      if ([...messagesByConversation.keys()].some((id) => !ids.has(id)))
        return {
          ok: false,
          error: {
            kind: "invalid_value",
            scope,
            reason: "Messages have no matching conversation",
          },
        };
      const projected = [];
      for (const conversation of conversations) {
        if (
          typeof conversation.id !== "string" ||
          !conversation.id.trim() ||
          !(
            typeof conversation.title === "string" ||
            conversation.title === null
          )
        )
          return {
            ok: false,
            error: {
              kind: "invalid_value",
              scope,
              reason: "Conversation id or title has invalid source shape",
            },
          };
        const sourceMessages =
          messagesByConversation.get(conversation.id) ?? [];
        if (
          sourceMessages.some(
            (message) =>
              typeof message.id !== "string" ||
              !(
                typeof message.content === "string" || message.content === null
              ) ||
              !(
                Array.isArray(message.attachments) ||
                message.attachments === null
              ),
          )
        )
          return {
            ok: false,
            error: {
              kind: "invalid_value",
              scope,
              reason: "Message does not match declared source shape",
            },
          };
        const messages = [...sourceMessages]
          .sort(
            (a, b) =>
              (Date.parse((a.create_time as string | null) || "") || 0) -
              (Date.parse((b.create_time as string | null) || "") || 0),
          )
          .map((message) => {
            return {
              id: message.id,
              sender: message.role ?? null,
              parentId: message.parent_id ?? null,
              createdAt: message.create_time ?? null,
              updatedAt: message.update_time ?? null,
              content: message.content ?? "",
              attachments: message.attachments ?? [],
            };
          });
        const messageCount =
          typeof conversation.message_count === "number"
            ? conversation.message_count
            : messages.length;
        if (messageCount !== messages.length)
          return {
            ok: false,
            error: {
              kind: "incomplete_scope",
              scope,
              reason:
                "Fetched messages do not match conversation message_count",
            },
          };
        projected.push({
          id: conversation.id,
          title: conversation.title || "Untitled",
          href: `/chat/${conversation.id}`,
          createdAt: conversation.create_time ?? null,
          updatedAt: conversation.update_time ?? null,
          starred: conversation.is_starred ?? null,
          projectId: conversation.project_id ?? null,
          messageCount,
          messages,
        });
      }
      return {
        ok: true,
        payload: {
          profile: metadata.profile,
          organizationId: metadata.organizationId,
          conversations: projected,
          total: projected.length,
          messageTotal: projected.reduce(
            (total, conversation) =>
              total + (conversation.messageCount as number),
            0,
          ),
          source: "official-export",
        },
      };
    },
  };
}

const claudeConversations = claudeConversationsBinding();

const claudeProjects: LegacyScopeBinding = {
  scope: "claude.projects",
  pdppSource: anthropicProjectionSource,
  pdppStreams: ["account_profile", "projects", "project_documents"],
  legacySchemaPath: "claude.projects.json",
  fieldsRead: {
    account_profile: [
      "id",
      "organization_id",
      "full_name",
      "plan",
      "name_source",
      "metadata_status",
    ],
    projects: [
      "id",
      "name",
      "description",
      "create_time",
      "update_time",
      "is_archived",
      "prompt_template",
      "creator",
      "is_private",
      "is_starter_project",
      "archived_at",
      "raw_docs",
    ],
    project_documents: [
      "id",
      "project_id",
      "filename",
      "content",
      "create_time",
      "update_time",
    ],
  },
  primaryKey: {
    account_profile: ["id"],
    projects: ["id"],
    project_documents: ["id"],
  },
  lossy: [
    "detail carries only declared project and raw document fields. Other raw-only keys and documents dropped by source parsing cannot be recovered; href and label follow the legacy connector's route and label rules.",
  ],
  provenance: anthropicProjectionProvenance,
  project(records, options): ProjectionResult {
    const scope = "claude.projects";
    const guard = requireStreams(scope, options, [
      "account_profile",
      "projects",
      "project_documents",
    ]);
    if (guard) return guard;
    const metadata = claudeMetadata(scope, records);
    if (!metadata.ok) return metadata;
    const documents = byStream(records, "project_documents");
    const projects = byStream(records, "projects");
    const projectIds = new Set(projects.map((project) => project.id));
    if (
      documents.some(
        (document) =>
          typeof document.project_id !== "string" ||
          !projectIds.has(document.project_id),
      )
    )
      return {
        ok: false,
        error: {
          kind: "invalid_value",
          scope,
          reason: "Project document has no matching project",
        },
      };
    const projected = [];
    for (const project of projects) {
      if (
        typeof project.id !== "string" ||
        !project.id.trim() ||
        typeof project.name !== "string"
      )
        return {
          ok: false,
          error: {
            kind: "invalid_value",
            scope,
            reason: "Project id and name are required by the legacy payload",
          },
        };
      const docs = documents
        .filter((document) => document.project_id === project.id)
        .map((document) => ({
          uuid: document.id,
          filename: document.filename ?? null,
          content: document.content ?? null,
          created_at: document.create_time ?? null,
          updated_at: document.update_time ?? null,
        }));
      const detail: Record<string, unknown> = {
        uuid: project.id,
        name: project.name,
        docs,
      };
      for (const [sourceKey, legacyKey] of [
        ["description", "description"],
        ["create_time", "created_at"],
        ["update_time", "updated_at"],
        ["prompt_template", "prompt_template"],
      ] as const) {
        if (project[sourceKey] !== undefined)
          detail[legacyKey] = project[sourceKey];
      }
      for (const key of ["is_private", "is_starter_project"] as const) {
        const value = project[key];
        if (value !== undefined) {
          if (value !== null && typeof value !== "boolean")
            return {
              ok: false,
              error: {
                kind: "invalid_value",
                scope,
                reason: `${key} has invalid source shape`,
              },
            };
          detail[key] = value;
        }
      }
      if (project.archived_at !== undefined) {
        if (
          project.archived_at !== null &&
          typeof project.archived_at !== "string"
        )
          return {
            ok: false,
            error: {
              kind: "invalid_value",
              scope,
              reason: "archived_at has invalid source shape",
            },
          };
        detail.archived_at = project.archived_at;
      }
      if (project.creator !== undefined) {
        const creator = project.creator;
        if (
          creator !== null &&
          (typeof creator !== "object" || Array.isArray(creator))
        )
          return {
            ok: false,
            error: {
              kind: "invalid_value",
              scope,
              reason: "creator has invalid source shape",
            },
          };
        if (creator === null) detail.creator = null;
        else {
          const value = creator as Record<string, unknown>;
          if (
            ["uuid", "full_name"].some(
              (key) =>
                value[key] !== undefined && typeof value[key] !== "string",
            )
          )
            return {
              ok: false,
              error: {
                kind: "invalid_value",
                scope,
                reason: "creator fields have invalid source shape",
              },
            };
          detail.creator = Object.fromEntries(
            ["uuid", "full_name"]
              .filter((key) => value[key] !== undefined)
              .map((key) => [key, value[key]]),
          );
        }
      }
      if (project.raw_docs !== undefined) {
        if (!Array.isArray(project.raw_docs))
          return {
            ok: false,
            error: {
              kind: "invalid_value",
              scope,
              reason: "raw_docs has invalid source shape",
            },
          };
        const rawKeys = [
          "uuid",
          "filename",
          "content",
          "created_at",
          "updated_at",
        ];
        const rawDocs = [];
        for (const raw of project.raw_docs) {
          if (
            !raw ||
            typeof raw !== "object" ||
            Array.isArray(raw) ||
            rawKeys.some(
              (key) =>
                (raw as Record<string, unknown>)[key] !== undefined &&
                typeof (raw as Record<string, unknown>)[key] !== "string",
            )
          )
            return {
              ok: false,
              error: {
                kind: "invalid_value",
                scope,
                reason: "raw document has invalid source shape",
              },
            };
          const value = raw as Record<string, unknown>;
          rawDocs.push(
            Object.fromEntries(
              rawKeys
                .filter((key) => value[key] !== undefined)
                .map((key) => [key, value[key]]),
            ),
          );
        }
        detail.raw_docs = rawDocs;
      }
      projected.push({
        id: project.id,
        title: project.name,
        href: `/project/${project.id}`,
        label: `Project, ${project.name}`,
        createdAt: project.create_time ?? null,
        updatedAt: project.update_time ?? null,
        archived: project.is_archived ?? null,
        detail,
      });
    }
    return {
      ok: true,
      payload: {
        profile: metadata.profile,
        organizationId: metadata.organizationId,
        projects: projected,
        total: projected.length,
        source: "official-export",
      },
    };
  },
};

// ---------------------------------------------------------------------------
// linkedin
// declarations/linkedin.collection-profile.json
// connector_id: https://registry.pdpp.dev/connectors/linkedin
// ---------------------------------------------------------------------------

const linkedinProfile: LegacyScopeBinding = {
  scope: "linkedin.profile",
  pdppSource: "https://registry.pdpp.dev/connectors/linkedin",
  pdppStreams: ["profile"],
  legacySchemaPath: "linkedin.profile.json",
  fieldsRead: {
    profile: [
      "public_url",
      "full_name",
      "headline",
      "location",
      "connection_count",
      "profile_picture_url",
      "summary",
    ],
  },
  primaryKey: { profile: ["id"] },
  lossy: [
    "public_url, full_name, headline, location, profile_picture_url, summary: null/missing values become '' to satisfy the required legacy string fields",
    "connection_count: absent or non-finite/non-number values become '0'; the legacy connector could replace its initial '0' with a fetched connection count, which this projection does not derive",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/linkedin:0.3.1",
      digest:
        "sha256:7544a6c015bf4b730afdd97a7521608d10d1c077950af5e9f3adc9405609fd68",
      path: "declarations/linkedin.collection-profile.json#streams[name=profile]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("linkedin.profile", options, ["profile"]);
    if (guard) {
      return guard;
    }
    const [profile] = byStream(records, "profile");
    if (!profile) {
      return {
        ok: false,
        error: { kind: "empty_singleton", scope: "linkedin.profile" },
      };
    }
    return {
      ok: true,
      payload: {
        profileUrl: orEmptyString(profile.public_url),
        fullName: orEmptyString(profile.full_name),
        headline: orEmptyString(profile.headline),
        location: orEmptyString(profile.location),
        connections:
          typeof profile.connection_count === "number" &&
          Number.isFinite(profile.connection_count)
            ? String(profile.connection_count)
            : "0",
        profilePictureUrl: orEmptyString(profile.profile_picture_url),
        // The legacy connector reads this same Voyager summary as `about`.
        about: orEmptyString(profile.summary),
      },
    };
  },
};

const linkedinConnections: LegacyScopeBinding = {
  scope: "linkedin.connections",
  pdppSource: "https://registry.pdpp.dev/connectors/linkedin",
  pdppStreams: ["connections"],
  legacySchemaPath: "linkedin.connections.json",
  fieldsRead: {
    connections: ["id", "full_name", "headline", "profile_url", "connected_at"],
  },
  primaryKey: { connections: ["id"] },
  lossy: [
    "Null full_name, headline, and profile_url become empty strings, matching the legacy connector's own fallback; connected_at is reduced to the legacy YYYY-MM-DD date text, with missing/invalid values becoming the legacy empty-string fallback.",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/linkedin:0.3.1",
      digest:
        "sha256:7544a6c015bf4b730afdd97a7521608d10d1c077950af5e9f3adc9405609fd68",
      path: "declarations/linkedin.collection-profile.json#streams[name=connections]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("linkedin.connections", options, [
      "connections",
    ]);
    if (guard) return guard;
    return {
      ok: true,
      payload: {
        connections: byStream(records, "connections").map((r) => ({
          fullName: orEmptyString(r.full_name),
          headline: orEmptyString(r.headline),
          profileUrl: orEmptyString(r.profile_url),
          dateConnected:
            typeof r.connected_at === "string" &&
            !Number.isNaN(new Date(r.connected_at).getTime())
              ? new Date(r.connected_at).toISOString().slice(0, 10)
              : "",
        })),
      },
    };
  },
};

const linkedinExperience: LegacyScopeBinding = {
  scope: "linkedin.experience",
  pdppSource: "https://registry.pdpp.dev/connectors/linkedin",
  pdppStreams: ["experience"],
  legacySchemaPath: "linkedin.experience.json",
  fieldsRead: {
    experience: [
      "title",
      "company",
      "start_date",
      "end_date",
      "location",
      "description",
    ],
  },
  primaryKey: { experience: ["id"] },
  lossy: [
    "location, description: PDPP-side null projects as '' (matches legacy's own `pos.locationName || ''` / `pos.description || ''`)",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/linkedin:0.3.1",
      digest:
        "sha256:7544a6c015bf4b730afdd97a7521608d10d1c077950af5e9f3adc9405609fd68",
      path: "declarations/linkedin.collection-profile.json#streams[name=experience]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("linkedin.experience", options, [
      "experience",
    ]);
    if (guard) {
      return guard;
    }
    const items = byStream(records, "experience");
    // Legacy `dates` is one free-text field, "M/YYYY - M/YYYY" or
    // "M/YYYY - Present" (linkedin-playwright.js:129-145,
    // extractTimePeriod). PDPP declares separate start_date/end_date as
    // date-time strings; toLegacyTimePeriod reproduces the exact legacy
    // format from those two real fields, not a fabricated one.
    return {
      ok: true,
      payload: {
        experiences: items.map((e) => ({
          jobTitle: orEmptyString(e.title),
          companyName: orEmptyString(e.company),
          dates: toLegacyTimePeriod(e.start_date, e.end_date),
          location: orEmptyString(e.location),
          description: orEmptyString(e.description),
        })),
      },
    };
  },
};

const linkedinEducation: LegacyScopeBinding = {
  scope: "linkedin.education",
  pdppSource: "https://registry.pdpp.dev/connectors/linkedin",
  pdppStreams: ["education"],
  legacySchemaPath: "linkedin.education.json",
  fieldsRead: {
    education: [
      "school",
      "degree",
      "field_of_study",
      "start_date",
      "end_date",
      "grade",
      "logo_url",
    ],
  },
  primaryKey: { education: ["id"] },
  lossy: [
    "school, degree, grade, logo_url: null/missing values become '' to satisfy the required legacy string fields",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/linkedin:0.3.1",
      digest:
        "sha256:7544a6c015bf4b730afdd97a7521608d10d1c077950af5e9f3adc9405609fd68",
      path: "declarations/linkedin.collection-profile.json#streams[name=education]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("linkedin.education", options, ["education"]);
    if (guard) {
      return guard;
    }
    const items = byStream(records, "education");
    return {
      ok: true,
      payload: {
        education: items.map((e) => ({
          schoolName: orEmptyString(e.school),
          degree: [orEmptyString(e.degree), orEmptyString(e.field_of_study)]
            .filter(Boolean)
            .join(", "),
          years: toLegacyTimePeriod(e.start_date, e.end_date),
          grade: orEmptyString(e.grade),
          logoUrl: orEmptyString(e.logo_url),
        })),
      },
    };
  },
};

const linkedinLanguages: LegacyScopeBinding = {
  scope: "linkedin.languages",
  pdppSource: "https://registry.pdpp.dev/connectors/linkedin",
  pdppStreams: ["languages"],
  legacySchemaPath: "linkedin.languages.json",
  fieldsRead: { languages: ["name", "proficiency"] },
  primaryKey: { languages: ["id"] },
  lossy: [
    "proficiency: null/missing values become '' to satisfy the required legacy string field",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/linkedin:0.3.1",
      digest:
        "sha256:7544a6c015bf4b730afdd97a7521608d10d1c077950af5e9f3adc9405609fd68",
      path: "declarations/linkedin.collection-profile.json#streams[name=languages]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("linkedin.languages", options, ["languages"]);
    if (guard) {
      return guard;
    }
    const items = byStream(records, "languages");
    return {
      ok: true,
      payload: {
        languages: items.map((l) => ({
          name: orEmptyString(l.name),
          proficiency: orEmptyString(l.proficiency),
        })),
      },
    };
  },
};

const linkedinSkills: LegacyScopeBinding = {
  scope: "linkedin.skills",
  pdppSource: "https://registry.pdpp.dev/connectors/linkedin",
  pdppStreams: ["skills"],
  legacySchemaPath: "linkedin.skills.json",
  fieldsRead: { skills: ["name", "endorsement_count"] },
  primaryKey: { skills: ["id"] },
  lossy: [],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/linkedin:0.3.1",
      digest:
        "sha256:7544a6c015bf4b730afdd97a7521608d10d1c077950af5e9f3adc9405609fd68",
      path: "declarations/linkedin.collection-profile.json#streams[name=skills]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("linkedin.skills", options, ["skills"]);
    if (guard) {
      return guard;
    }
    const items = byStream(records, "skills");
    // Legacy `endorsements` is a string; PDPP `endorsement_count` is a
    // number. String-converted with legacy's own 0 fallback
    // (linkedin-playwright.js:551, `String(sk.endorsementCount || ... || 0)`).
    return {
      ok: true,
      payload: {
        skills: items.map((s) => ({
          name: orEmptyString(s.name),
          endorsements: String(orZero(s.endorsement_count)),
        })),
      },
    };
  },
};

// ---------------------------------------------------------------------------
// spotify
// declarations/spotify.collection-profile.json (0.1.4)
// connector_id: https://registry.pdpp.dev/connectors/spotify
// ---------------------------------------------------------------------------

const spotifyProfile: LegacyScopeBinding = {
  scope: "spotify.profile",
  pdppSource: "https://registry.pdpp.dev/connectors/spotify",
  pdppStreams: ["profile"],
  legacySchemaPath: "spotify.profile.json",
  fieldsRead: {
    profile: ["id", "display_name", "uri", "followers", "following", "images"],
  },
  primaryKey: { profile: ["id"] },
  lossy: [
    "display_name: PDPP permits null, but the legacy schema requires a string; null projects as ''.",
    "images: legacy stores string URLs. String entries are retained, and structured PDPP image entries project their string url field.",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/spotify:0.1.4",
      digest:
        "sha256:6989f4eceb2142456bebb7b3d442e0a81ce571ef762824aa6dca882afabcba08",
      path: "declarations/spotify.collection-profile.json#streams[name=profile]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("spotify.profile", options, ["profile"]);
    if (guard) {
      return guard;
    }
    const [profile] = byStream(records, "profile");
    if (!profile) {
      return {
        ok: false,
        error: { kind: "empty_singleton", scope: "spotify.profile" },
      };
    }

    return {
      ok: true,
      payload: {
        id: orEmptyString(profile.id),
        display_name: orEmptyString(profile.display_name),
        uri: orEmptyString(profile.uri),
        followers: orZero(profile.followers),
        following: orZero(profile.following),
        images: spotifyImageUrls(profile.images),
      },
    };
  },
};

const spotifySavedTracks: LegacyScopeBinding = {
  scope: "spotify.savedTracks",
  pdppSource: "https://registry.pdpp.dev/connectors/spotify",
  pdppStreams: ["saved_tracks"],
  legacySchemaPath: "spotify.savedTracks.json",
  fieldsRead: {
    saved_tracks: [
      "id",
      "name",
      "artist_names",
      "album_name",
      "duration_ms",
      "added_at",
      "uri",
      "explicit",
      "album_artist_names",
    ],
  },
  primaryKey: { saved_tracks: ["id"] },
  lossy: [
    "Rows without the required legacy name and artist list are skipped; nullable album and optional fields retain the connector's empty-string, zero, and false sentinels.",
    "isrc, popularity, and id have no corresponding legacy fields and are omitted.",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/spotify:0.1.4",
      digest:
        "sha256:6989f4eceb2142456bebb7b3d442e0a81ce571ef762824aa6dca882afabcba08",
      path: "declarations/spotify.collection-profile.json#streams[name=saved_tracks]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("spotify.savedTracks", options, [
      "saved_tracks",
    ]);
    if (guard) return guard;
    const tracks = byStream(records, "saved_tracks").flatMap((r) => {
      if (
        typeof r.name !== "string" ||
        !Array.isArray(r.artist_names) ||
        !r.artist_names.every((name) => typeof name === "string")
      )
        return [];
      return [
        {
          added_at: orEmptyString(r.added_at),
          name: r.name,
          artists: r.artist_names.map((name) => ({ name })),
          album: {
            name: orEmptyString(r.album_name),
            artists: Array.isArray(r.album_artist_names)
              ? r.album_artist_names
                  .filter((name): name is string => typeof name === "string")
                  .map((name) => ({ name }))
              : [],
          },
          duration_ms: orZero(r.duration_ms),
          uri: orEmptyString(r.uri),
          explicit: typeof r.explicit === "boolean" ? r.explicit : false,
        },
      ];
    });
    return { ok: true, payload: { savedTracks: tracks, total: tracks.length } };
  },
};

const spotifyPlaylists: LegacyScopeBinding = {
  scope: "spotify.playlists",
  pdppSource: "https://registry.pdpp.dev/connectors/spotify",
  pdppStreams: ["playlists", "playlist_items"],
  legacySchemaPath: "spotify.playlists.json",
  fieldsRead: {
    playlists: [
      "id",
      "name",
      "description",
      "owner_name",
      "uri",
      "followers",
      "images",
      "track_count",
    ],
    playlist_items: [
      "playlist_id",
      "position",
      "added_at",
      "added_by",
      "name",
      "artist_names",
      "album_name",
      "duration_ms",
      "track_id",
    ],
  },
  primaryKey: {
    playlists: ["id"],
    playlist_items: ["id"],
  },
  lossy: [
    "tracks[].uri: raw playlist item URIs are retained when available; older pinned records fall back to a canonical Spotify track ID, and a null ID uses the retained collector's empty-string sentinel.",
    "tracks_total counts joined fetched tracks, as in the retained collector; catalog track_count is not a fetched-row count.",
    "images: legacy stores string URLs. String entries are retained, and structured PDPP image entries project their string url field.",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/spotify:0.1.4",
      digest:
        "sha256:6989f4eceb2142456bebb7b3d442e0a81ce571ef762824aa6dca882afabcba08",
      path: "declarations/spotify.collection-profile.json#streams[name=playlists,playlist_items]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("spotify.playlists", options, [
      "playlists",
      "playlist_items",
    ]);
    if (guard) {
      return guard;
    }

    const itemsByPlaylist = new Map<string, Record<string, unknown>[]>();
    for (const item of byStream(records, "playlist_items")) {
      const playlistId = item.playlist_id;
      if (typeof playlistId !== "string") continue;
      const group = itemsByPlaylist.get(playlistId);
      if (group) {
        group.push(item);
      } else {
        itemsByPlaylist.set(playlistId, [item]);
      }
    }

    const sourcePlaylists = byStream(records, "playlists");
    const playlistIds = new Set(sourcePlaylists.map((playlist) => playlist.id));
    const unrepresentablePlaylist = [...itemsByPlaylist].some(
      ([id, tracks]) =>
        !playlistIds.has(id) ||
        tracks.some(
          (track) =>
            typeof track.uri !== "string" &&
            track.track_id != null &&
            (typeof track.track_id !== "string" ||
              !/^(?:spotify:track:)?[A-Za-z0-9]{22}$/.test(track.track_id)),
        ),
    );
    if (unrepresentablePlaylist) {
      return {
        ok: false,
        error: {
          kind: "incomplete_scope",
          scope: "spotify.playlists",
          reason:
            "Cannot join every playlist item or derive its Spotify track URI",
        },
      };
    }

    const playlists = sourcePlaylists.map((playlist) => {
      const id = typeof playlist.id === "string" ? playlist.id : "";
      const trackItems = [...(itemsByPlaylist.get(id) ?? [])].sort(
        (a, b) => orZero(a.position) - orZero(b.position),
      );
      return {
        name: orEmptyString(playlist.name),
        description: orEmptyString(playlist.description),
        owner: orEmptyString(playlist.owner_name),
        uri: orEmptyString(playlist.uri),
        followers: orZero(playlist.followers),
        images: spotifyImageUrls(playlist.images),
        tracks_total: trackItems.length,
        tracks: trackItems.map((track) => ({
          added_at: orEmptyString(track.added_at),
          added_by: orEmptyString(track.added_by),
          name: orEmptyString(track.name),
          artists: Array.isArray(track.artist_names)
            ? track.artist_names
                .filter(
                  (artist): artist is string => typeof artist === "string",
                )
                .map((name) => ({ name }))
            : [],
          album: orEmptyString(track.album_name),
          duration_ms: orZero(track.duration_ms),
          uri:
            typeof track.uri === "string"
              ? track.uri
              : typeof track.track_id === "string"
                ? track.track_id.startsWith("spotify:track:")
                  ? track.track_id
                  : `spotify:track:${track.track_id}`
                : "",
        })),
      };
    });

    return {
      ok: true,
      payload: { playlists, total: playlists.length },
    };
  },
};

function spotifyImageUrls(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((image): string[] => {
    if (typeof image === "string") return [image];
    if (typeof image !== "object" || image === null) return [];
    const url = (image as Record<string, unknown>).url;
    return typeof url === "string" ? [url] : [];
  });
}

// ---------------------------------------------------------------------------
// shopify (shop.orders)
// declarations/shopify.collection-profile.json (0.2.0)
// connector_id: https://registry.pdpp.dev/connectors/shopify
// ---------------------------------------------------------------------------

const shopOrders: LegacyScopeBinding = {
  scope: "shop.orders",
  pdppSource: "https://registry.pdpp.dev/connectors/shopify",
  pdppStreams: ["orders"],
  legacySchemaPath: "shop.orders.json",
  fieldsRead: {
    orders: [
      "id",
      "order_date",
      "merchant_name",
      "total_cents",
      "currency",
      "status",
      "item_count",
      "line_item_titles",
      "detail_url",
    ],
  },
  primaryKey: { orders: ["id"] },
  lossy: [
    "orderNumber: PDPP provides order_number, but the legacy connector derives orderNumber from id (shop-playwright.js:174); keep the existing value to preserve the scope contract",
    "status: legacy uses displayStatus free text scraped from the storefront; PDPP's normalized `status` value is not verified to match that text 1:1",
    "placedAt (F5): passed through only when the PDPP source value parses as a valid ISO 8601 date-time; otherwise omitted. legacy's own no-match fallback is '' (shop-playwright.js:175, `orderObj.createdAt || ''`), which the pinned schema does not accept (placedAt is `format: date-time`). A null-shaped legacy fallback would itself fail the pinned schema.",
    "total, itemCount (N-S1): legacy's own no-match fallbacks are null (:154, top-level total) and `totalItemCount ?? (itemTitles.length || null)` (:180) — none of which the pinned per-item schema accepts (both are `type: number`). A null-shaped legacy fallback would itself fail the pinned schema, and only `id` is required per item, so a missing PDPP value for these two fields is OMITTED from the payload entirely (not defaulted to 0) rather than invented — that omission is itself the disclosed lossy behavior.",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/shopify:0.2.0",
      digest:
        "sha256:167cff474a653ad7bce036c973a78adcfc3a3e8e73925a6e24c74961f979ac0e",
      path: "declarations/shopify.collection-profile.json#streams[name=orders]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("shop.orders", options, ["orders"]);
    if (guard) {
      return guard;
    }
    const items = byStream(records, "orders");
    // orderNumber: legacy's own value is String(orderObj.id)
    // (shop-playwright.js:174) on its primary extraction path — a real,
    // derivable transform of the same id PDPP carries, not an invented
    // field. placedAt/total/itemCount: omitted (not defaulted) when the PDPP
    // source value is absent — see the `lossy` entry above (N-S1). Only
    // `id` is required per item by the pinned schema, so omitting these is
    // schema-valid.
    return {
      ok: true,
      payload: {
        orders: items.map((o) => ({
          id: orEmptyString(o.id),
          orderNumber: orEmptyString(o.id),
          ...(typeof o.order_date === "string" &&
          isValidIso8601DateTime(o.order_date)
            ? { placedAt: o.order_date }
            : {}),
          merchantName: orEmptyString(o.merchant_name),
          ...(typeof o.total_cents === "number"
            ? { total: o.total_cents / 100 }
            : {}),
          currency: orEmptyString(o.currency),
          status: orEmptyString(o.status),
          ...(typeof o.item_count === "number"
            ? { itemCount: o.item_count }
            : {}),
          ...(Array.isArray(o.line_item_titles) &&
          o.line_item_titles.every((title) => typeof title === "string")
            ? { lineItemTitles: o.line_item_titles }
            : {}),
          ...(typeof o.detail_url === "string"
            ? { detailUrl: o.detail_url }
            : {}),
        })),
        total: items.length,
      },
    };
  },
};

// ---------------------------------------------------------------------------
// Oura (activity and readiness)
// declarations/oura.collection-profile.json (0.1.1, current OCI pin)
// connector_id: https://registry.pdpp.dev/connectors/oura
// ---------------------------------------------------------------------------

const ouraActivity: LegacyScopeBinding = {
  scope: "oura.activity",
  pdppSource: "https://registry.pdpp.dev/connectors/oura",
  pdppStreams: ["activity"],
  legacySchemaPath: "oura.activity.json",
  fieldsRead: {
    activity: [
      "id",
      "day",
      "score",
      "active_calories",
      "total_calories",
      "steps",
      "equivalent_walking_distance",
      "high_activity_time",
      "medium_activity_time",
      "low_activity_time",
      "sedentary_time",
      "resting_time",
      "inactivity_alerts",
      "contributors",
    ],
  },
  primaryKey: { activity: ["id"] },
  lossy: [
    "timestamp: no source field; omitted (legacy schema makes it optional)",
    "target_calories: has no legacy field and is not projected",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/oura:0.1.1",
      digest:
        "sha256:7e39080f5ca65b83f44911cb120f9b8fc5c696b874e6493b26c00f07172efcae",
      path: "declarations/oura.collection-profile.json#streams[name=activity]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("oura.activity", options, ["activity"]);
    if (guard) return guard;
    return {
      ok: true,
      payload: {
        days: byStream(records, "activity").map((r) => ({
          id: r.id,
          day: r.day,
          ...ifDefined(r, "score", "score"),
          ...ifDefined(r, "active_calories", "activeCalories"),
          ...ifDefined(r, "total_calories", "totalCalories"),
          ...ifDefined(r, "steps", "steps"),
          ...ifDefined(
            r,
            "equivalent_walking_distance",
            "equivalentWalkingDistance",
          ),
          ...ifDefined(r, "high_activity_time", "highActivityTime"),
          ...ifDefined(r, "medium_activity_time", "mediumActivityTime"),
          ...ifDefined(r, "low_activity_time", "lowActivityTime"),
          ...ifDefined(r, "sedentary_time", "sedentaryTime"),
          ...ifDefined(r, "resting_time", "restingTime"),
          ...ifDefined(r, "inactivity_alerts", "inactivityAlerts"),
          ...(r.contributors && typeof r.contributors === "object"
            ? { contributors: r.contributors }
            : {}),
        })),
      },
    };
  },
};

const ouraReadiness: LegacyScopeBinding = {
  scope: "oura.readiness",
  pdppSource: "https://registry.pdpp.dev/connectors/oura",
  pdppStreams: ["readiness"],
  legacySchemaPath: "oura.readiness.json",
  fieldsRead: {
    readiness: [
      "id",
      "day",
      "score",
      "temperature_deviation",
      "temperature_trend_deviation",
      "contributors",
    ],
  },
  primaryKey: { readiness: ["id"] },
  lossy: [
    "timestamp: no source field; omitted (legacy schema makes it optional)",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/oura:0.1.1",
      digest:
        "sha256:7e39080f5ca65b83f44911cb120f9b8fc5c696b874e6493b26c00f07172efcae",
      path: "declarations/oura.collection-profile.json#streams[name=readiness]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("oura.readiness", options, ["readiness"]);
    if (guard) return guard;
    return {
      ok: true,
      payload: {
        days: byStream(records, "readiness").map((r) => ({
          id: r.id,
          day: r.day,
          ...ifDefined(r, "score", "score"),
          ...ifDefined(r, "temperature_deviation", "temperatureDeviation"),
          ...ifDefined(
            r,
            "temperature_trend_deviation",
            "temperatureTrendDeviation",
          ),
          ...(r.contributors && typeof r.contributors === "object"
            ? { contributors: r.contributors }
            : {}),
        })),
      },
    };
  },
};

const ouraSleep: LegacyScopeBinding = {
  scope: "oura.sleep",
  pdppSource: "https://registry.pdpp.dev/connectors/oura",
  pdppStreams: ["sleep"],
  legacySchemaPath: "oura.sleep.json",
  fieldsRead: {
    sleep: [
      "id",
      "day",
      "sleep_score",
      "contributors",
      "type",
      "bedtime_start",
      "bedtime_end",
      "total_sleep_duration",
      "time_in_bed",
      "deep_sleep_duration",
      "light_sleep_duration",
      "rem_sleep_duration",
      "efficiency",
      "latency",
      "average_heart_rate",
      "average_hrv",
      "lowest_heart_rate",
      "average_breath",
      "restless_periods",
    ],
  },
  primaryKey: { sleep: ["id"] },
  lossy: [
    "awakeTime: no declared PDPP field and is omitted",
    "dailyScores.timestamp: no source field and is omitted",
    "sleepPeriods.averageHrv: PDPP allows a non-integer number but legacy schema allows only integer or null; non-integer values are omitted",
    "sleepPeriods.type: unrecognized or null values are omitted because the legacy enum accepts only long_sleep, short_sleep or rest",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/oura:0.1.1",
      digest:
        "sha256:7e39080f5ca65b83f44911cb120f9b8fc5c696b874e6493b26c00f07172efcae",
      path: "declarations/oura.collection-profile.json#streams[name=sleep]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("oura.sleep", options, ["sleep"]);
    if (guard) return guard;
    const rows = byStream(records, "sleep");
    const periods = rows.map((r) => ({
      id: r.id,
      day: r.day,
      ...(r.type === "long_sleep" ||
      r.type === "short_sleep" ||
      r.type === "rest"
        ? { type: r.type }
        : {}),
      ...ifDefined(r, "bedtime_start", "bedtimeStart"),
      ...ifDefined(r, "bedtime_end", "bedtimeEnd"),
      ...ifDefined(r, "total_sleep_duration", "totalSleepDuration"),
      ...ifDefined(r, "time_in_bed", "timeInBed"),
      ...ifDefined(r, "deep_sleep_duration", "deepSleepDuration"),
      ...ifDefined(r, "light_sleep_duration", "lightSleepDuration"),
      ...ifDefined(r, "rem_sleep_duration", "remSleepDuration"),
      ...ifDefined(r, "efficiency", "efficiency"),
      ...ifDefined(r, "latency", "latency"),
      ...ifDefined(r, "average_heart_rate", "averageHeartRate"),
      ...(r.average_hrv === null
        ? { averageHrv: null }
        : typeof r.average_hrv === "number" && Number.isInteger(r.average_hrv)
          ? { averageHrv: r.average_hrv }
          : {}),
      ...ifDefined(r, "lowest_heart_rate", "lowestHeartRate"),
      ...ifDefined(r, "average_breath", "averageBreath"),
      ...ifDefined(r, "restless_periods", "restlessPeriods"),
    }));
    return {
      ok: true,
      payload: {
        dailyScores: rows.map((r) => ({
          id: r.id,
          day: r.day,
          ...ifDefined(r, "sleep_score", "score"),
          ...(r.contributors && typeof r.contributors === "object"
            ? { contributors: r.contributors }
            : {}),
        })),
        sleepPeriods: periods,
      },
    };
  },
};

// ---------------------------------------------------------------------------
// amazon
// declarations/amazon.collection-profile.json, streams "orders" +
// "order_items" (joined on order_items.order_id === orders.id).
// connector_id: https://registry.pdpp.dev/connectors/amazon
// ---------------------------------------------------------------------------

const amazonOrders: LegacyScopeBinding = {
  scope: "amazon.orders",
  pdppSource: "https://registry.pdpp.dev/connectors/amazon",
  pdppStreams: ["orders", "order_items"],
  legacySchemaPath: "amazon.orders.json",
  fieldsRead: {
    orders: ["id", "order_date", "order_total", "delivery_status"],
    order_items: ["order_id", "name", "url", "unit_price"],
  },
  primaryKey: { orders: ["id"], order_items: ["id"] },
  lossy: [
    "items[].quantity: no legacy field (legacy schema does not carry quantity at all; PDPP-side quantity is simply not projected)",
    "items[].price (N-S2): legacy's own connector ALWAYS emits the literal constant '' for this field (amazon-playwright.js:222, `price: ''` — not a fallback for a missing value, the connector never scrapes a real price here at all). This projection instead emits PDPP's real `unit_price` when present, so an app reading this field gets a populated value where legacy always gave it an empty string — a value change, not a gap-fill, and the comment at the call site below previously implied the two matched when they do not.",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/amazon:0.1.0",
      digest:
        "sha256:dfddeffbc11c53fa2577c71f45428b87ccb25a69175218621398342a22b415d4",
      path: "declarations/amazon.collection-profile.json#streams[name=orders,order_items]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("amazon.orders", options, [
      "orders",
      "order_items",
    ]);
    if (guard) {
      return guard;
    }
    const orders = byStream(records, "orders");
    const items = byStream(records, "order_items");
    // orderDate: legacy scrapes "MonthName D, YYYY" out of card text via
    // regex (amazon-playwright.js:184-187); toLegacyLongDate reproduces
    // that exact text shape from PDPP's ISO order_date, not an ISO
    // passthrough. Item price: legacy ALWAYS emits the literal constant ''
    // here (amazon-playwright.js:222, `price: ''`) — it never scrapes a
    // real price for line items. This binding instead emits PDPP's real
    // `unit_price` when present, a disclosed value change, see `lossy`
    // (N-S2), not a match with legacy's own behavior.
    return {
      ok: true,
      payload: {
        orders: orders.map((o) => ({
          orderId: orEmptyString(o.id),
          orderDate: toLegacyLongDate(o.order_date),
          orderTotal: orEmptyString(o.order_total),
          deliveryStatus: orEmptyString(o.delivery_status),
          items: items
            .filter((i) => i.order_id === o.id)
            .map((i) => ({
              name: orEmptyString(i.name),
              url: orEmptyString(i.url),
              price: orEmptyString(i.unit_price),
            })),
        })),
        total: orders.length,
      },
    };
  },
};

// ---------------------------------------------------------------------------
// H-E-B 0.5.3 is pinned to the published, signature-verified OCI artifact.
// Product identity remains H-E-B's provider product_id.

const hebSource = "https://registry.pdpp.dev/connectors/heb";
const hebPublishedEvidence: LegacyScopeBindingProvenance = {
  kind: "oci",
  ref: "ghcr.io/pdp-connect/connector/heb:0.5.3",
  digest:
    "sha256:9de1c9203453b3897305ca99dfe93755f0e5528b3e7e79d0a9e6c8313445c02a",
  path: "declarations/heb.collection-profile.json#streams[name=profile]",
};

const hebProfile: LegacyScopeBinding = {
  scope: "heb.profile",
  pdppSource: hebSource,
  pdppStreams: ["profile"],
  legacySchemaPath: "heb.profile.json",
  fieldsRead: { profile: ["name", "email", "phone", "delivery_addresses"] },
  primaryKey: { profile: ["id"] },
  lossy: ["fetched_at is not part of the legacy profile payload."],
  provenance: [hebPublishedEvidence],
  project(records, options): ProjectionResult {
    const guard = requireStreams("heb.profile", options, ["profile"]);
    if (guard) return guard;
    const profiles = byStream(records, "profile");
    if (profiles.length === 0)
      return {
        ok: false,
        error: { kind: "empty_singleton", scope: "heb.profile" },
      };
    if (profiles.length !== 1)
      return {
        ok: false,
        error: {
          kind: "incomplete_scope",
          scope: "heb.profile",
          reason: "profile stream did not contain exactly one record",
        },
      };
    const [p] = profiles;
    if (
      (p.name != null && typeof p.name !== "string") ||
      (p.email != null && typeof p.email !== "string") ||
      (p.phone != null && typeof p.phone !== "string")
    ) {
      return {
        ok: false,
        error: {
          kind: "incomplete_scope",
          scope: "heb.profile",
          reason: "profile contains a malformed scalar value",
        },
      };
    }
    if (!Array.isArray(p.delivery_addresses)) {
      return {
        ok: false,
        error: {
          kind: "incomplete_scope",
          scope: "heb.profile",
          reason: "profile.delivery_addresses is unavailable",
        },
      };
    }
    if (
      Array.isArray(p.delivery_addresses) &&
      p.delivery_addresses.some(
        (entry) =>
          entry === null ||
          typeof entry !== "object" ||
          typeof entry.address !== "string" ||
          typeof entry.is_primary !== "boolean" ||
          !(typeof entry.label === "string" || entry.label === null),
      )
    ) {
      return {
        ok: false,
        error: {
          kind: "incomplete_scope",
          scope: "heb.profile",
          reason:
            "profile.delivery_addresses contains an unrepresentable address",
        },
      };
    }
    const deliveryAddresses = p.delivery_addresses.map((entry) => {
      const a = entry as Record<string, unknown>;
      return {
        address: a.address as string,
        isPrimary: a.is_primary as boolean,
        label: a.label as string | null,
      };
    });
    return {
      ok: true,
      payload: {
        name: typeof p.name === "string" ? p.name : null,
        email: typeof p.email === "string" ? p.email : null,
        phone: p.phone === undefined || p.phone === null ? null : p.phone,
        deliveryAddresses,
      },
    };
  },
};

// H-E-B emits one nutrition outcome for each distinct source order-item
// product. Keep the source item stream in this projection so missing outcomes
// cannot become a successful but incomplete legacy payload.
const hebNutritionFields = [
  "product_id",
  "name",
  "source",
  "confidence",
  "calories",
  "protein_g",
  "carbs_g",
  "fat_g",
  "sodium_mg",
  "fiber_g",
  "sugar_g",
  "saturated_fat_g",
  "trans_fat_g",
  "cholesterol_mg",
  "added_sugar_g",
  "calcium_mg",
  "iron_mg",
  "potassium_mg",
  "vitamin_d_mcg",
  "serving_size",
  "servings_per_container",
  "upc",
  "ingredients",
  "allergens",
  "category",
  "highlights",
  "product_url",
];
const hebNutrition: LegacyScopeBinding = {
  scope: "heb.nutrition",
  pdppSource: hebSource,
  pdppStreams: ["nutrition", "orders", "order_items"],
  legacySchemaPath: "heb.nutrition.json",
  fieldsRead: {
    nutrition: hebNutritionFields,
    orders: [],
    order_items: ["product_id", "name", "product_url"],
  },
  primaryKey: { nutrition: ["id"], orders: ["id"], order_items: ["id"] },
  lossy: [
    "The legacy map key is the declared H-E-B product_id; no global UPC identity is inferred.",
    "fetched_at is omitted.",
  ],
  provenance: [
    {
      ...hebPublishedEvidence,
      path: "declarations/heb.collection-profile.json#streams[name=orders,order_items,nutrition]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("heb.nutrition", options, [
      "nutrition",
      "orders",
      "order_items",
    ]);
    if (guard) return guard;
    const orderedProducts = new Map<
      string,
      { name: string; productUrl: string | null }
    >();
    for (const row of byStream(records, "order_items")) {
      // The source only creates nutrition targets for order lines with a
      // product_id, and deduplicates those targets by that id.
      if (!isNonEmptyString(row.product_id)) continue;
      if (
        !isNonEmptyString(row.name) ||
        (row.product_url !== null && !isNonEmptyString(row.product_url))
      ) {
        return {
          ok: false,
          error: {
            kind: "incomplete_scope",
            scope: "heb.nutrition",
            reason: "order item lacks its source product name or URL",
          },
        };
      }
      // The legacy browser connector deduplicates by product id and retains
      // the first observed order line as the product's name and URL.
      if (!orderedProducts.has(row.product_id)) {
        orderedProducts.set(row.product_id, {
          name: row.name,
          productUrl: row.product_url,
        });
      }
    }
    const items: Record<string, unknown> = Object.create(null);
    let found = 0,
      foundUSDA = 0,
      blocked = 0;
    for (const n of byStream(records, "nutrition")) {
      if (
        !isNonEmptyString(n.product_id) ||
        !orderedProducts.has(n.product_id) ||
        n.product_url !== orderedProducts.get(n.product_id)?.productUrl ||
        typeof n.source !== "string" ||
        ![
          "heb_product_page",
          "usda_fdc",
          "not_found",
          "error",
          "blocked",
        ].includes(n.source) ||
        (n.product_url === null && n.source !== "not_found")
      ) {
        return {
          ok: false,
          error: {
            kind: "incomplete_scope",
            scope: "heb.nutrition",
            reason:
              "nutrition row lacks a product id, matching product URL, or valid observed outcome",
          },
        };
      }
      if (Object.hasOwn(items, n.product_id)) {
        return {
          ok: false,
          error: {
            kind: "incomplete_scope",
            scope: "heb.nutrition",
            reason: "duplicate nutrition product id",
          },
        };
      }
      const item: Record<string, unknown> = {
        name: orderedProducts.get(n.product_id)!.name,
        productUrl: n.product_url,
        source: n.source,
      };
      if (["high", "medium", "low"].includes(String(n.confidence))) {
        item.confidence = n.confidence;
      }
      for (const field of hebNutritionFields.slice(4, 19)) {
        if (n[field] === null || typeof n[field] === "number") {
          item[field] = n[field];
        }
      }
      if (n.serving_size === null || typeof n.serving_size === "string")
        item.servingSize = n.serving_size;
      if (
        n.servings_per_container === null ||
        typeof n.servings_per_container === "string"
      )
        item.servingsPerContainer = n.servings_per_container;
      for (const field of [
        "upc",
        "ingredients",
        "allergens",
        "category",
        "highlights",
      ]) {
        if (n[field] !== undefined) item[field] = n[field];
      }
      // Preserve the legacy connector's productImageUrl() mapping. These URLs
      // are deterministic from the observed H-E-B product id; they are not
      // scraped or inferred from nutrition content.
      const paddedProductId = n.product_id.padStart(9, "0");
      item.images = {
        thumbnail: `https://images.heb.com/is/image/HEBGrocery/prd-small/${paddedProductId}.jpg`,
        full: `https://images.heb.com/is/image/HEBGrocery/${n.product_id}-1`,
      };
      items[n.product_id] = item;
      if (n.source === "heb_product_page") found++;
      if (n.source === "usda_fdc") foundUSDA++;
      if (n.source === "blocked") blocked++;
    }
    const total = Object.keys(items).length;
    if (total !== orderedProducts.size) {
      return {
        ok: false,
        error: {
          kind: "incomplete_scope",
          scope: "heb.nutrition",
          reason: "nutrition outcomes do not cover every ordered product",
        },
      };
    }
    return {
      ok: true,
      payload: {
        items,
        coverage: {
          total,
          found,
          foundUSDA,
          blocked,
          percentCovered: total
            ? Math.round(((found + foundUSDA) / total) * 100)
            : 0,
        },
      },
    };
  },
};

// Retained legacy H-E-B order projection, unchanged.
// ---------------------------------------------------------------------------

const hebOrders: LegacyScopeBinding = {
  scope: "heb.orders",
  pdppSource: "https://registry.pdpp.dev/connectors/heb",
  pdppStreams: ["orders", "order_items"],
  legacySchemaPath: "heb.orders.json",
  fieldsRead: {
    orders: ["id", "order_date", "total_cents", "item_count", "status"],
    order_items: [
      "order_id",
      "name",
      "product_id",
      "product_url",
      "image_url",
      "quantity",
      "line_total_cents",
    ],
  },
  primaryKey: { orders: ["id"], order_items: ["id"] },
  lossy: [
    "orderUrl and address: the signed profile has no equivalent fields; fulfillment_location is not treated as an address.",
    "status_code, store_name, timeslot_start/end, unfulfilled_count, fulfillment_method, and fetched_at are not represented by the legacy schema.",
    "total and item price: derived from declared integer cents when present; omitted when absent. No currency or decimal text is guessed.",
    "the retained collector emitted only product-linked named lines; a source line without either field cannot be safely counted as complete and fails this scope.",
    "quantity: a declared numeric quantity is converted to its decimal string form to match the legacy connector output type.",
  ],
  provenance: [
    {
      ...hebPublishedEvidence,
      path: "declarations/heb.collection-profile.json#streams[name=orders,order_items]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("heb.orders", options, [
      "orders",
      "order_items",
    ]);
    if (guard) return guard;

    const sourceItems = byStream(records, "order_items");
    const sourceOrderIds = new Set(
      byStream(records, "orders").map((order) => order.id),
    );
    let skippedItems = 0;
    let skippedOrders = 0;
    let orderItemsShortOfDeclaredCount = false;
    const missingFields = new Set<string>();
    if (sourceItems.some((item) => !sourceOrderIds.has(item.order_id))) {
      return {
        ok: false,
        error: {
          kind: "incomplete_scope",
          scope: "heb.orders",
          reason: "order_items.order_id has no matching order",
        },
      };
    }
    const orders = byStream(records, "orders").flatMap((order) => {
      if (!isNonEmptyString(order.id)) {
        skippedOrders += 1;
        missingFields.add("orders.id");
        return [];
      }
      const items = sourceItems
        .filter((item) => item.order_id === order.id)
        .flatMap((item) => {
          if (
            !isNonEmptyString(item.name) ||
            !isNonEmptyString(item.product_id)
          ) {
            skippedItems += 1;
            if (!isNonEmptyString(item.name))
              missingFields.add("order_items.name");
            if (!isNonEmptyString(item.product_id)) {
              missingFields.add("order_items.product_id");
            }
            return [];
          }
          const quantity =
            typeof item.quantity === "number" && Number.isFinite(item.quantity)
              ? String(item.quantity)
              : null;
          const price =
            typeof item.line_total_cents === "number"
              ? item.line_total_cents / 100
              : undefined;
          return [
            {
              name: item.name,
              productId: item.product_id,
              productUrl:
                typeof item.product_url === "string" ? item.product_url : null,
              imageUrl:
                typeof item.image_url === "string" ? item.image_url : null,
              quantity,
              ...(price === undefined ? {} : { price }),
            },
          ];
        });
      if (
        typeof order.item_count === "number" &&
        Number.isInteger(order.item_count) &&
        order.item_count > items.length
      ) {
        orderItemsShortOfDeclaredCount = true;
      }
      return [
        {
          orderId: order.id,
          items,
          orderDate: toLegacyLongDate(order.order_date),
          ...(typeof order.total_cents === "number"
            ? { total: order.total_cents / 100 }
            : {}),
          ...(typeof order.item_count === "number"
            ? { itemCount: order.item_count }
            : {}),
          ...(typeof order.status === "string" || order.status === null
            ? { status: order.status }
            : {}),
        },
      ];
    });

    const diagnostics =
      skippedItems + skippedOrders > 0
        ? [
            {
              kind: "records_skipped" as const,
              scope: "heb.orders",
              count: skippedItems + skippedOrders,
              missingFields: [...missingFields],
            },
          ]
        : undefined;
    if (diagnostics) {
      return {
        ok: false,
        error: {
          kind: "incomplete_scope",
          scope: "heb.orders",
          reason: `Cannot preserve every valid order line: ${[...missingFields].join(", ")}`,
        },
      };
    }
    if (orderItemsShortOfDeclaredCount) {
      return {
        ok: false,
        error: {
          kind: "incomplete_scope",
          scope: "heb.orders",
          reason:
            "order_items are short of the count H-E-B reported for an order",
        },
      };
    }
    return {
      ok: true,
      payload: {
        orders,
        totalOrders: orders.length,
        totalItems: orders.reduce(
          (total, order) => total + order.items.length,
          0,
        ),
      },
      ...(diagnostics ? { diagnostics } : {}),
    };
  },
};

// Whole Foods 0.3.0 is the published, signature-verified OCI artifact.
const wholefoodsSource = "https://registry.pdpp.dev/connectors/wholefoods";
const wholefoodsEvidence: LegacyScopeBindingProvenance = {
  kind: "oci",
  ref: "ghcr.io/pdp-connect/connector/wholefoods:0.3.0",
  digest:
    "sha256:873e287a153673bb9b96cae87dfe64e36730e18b30ea2e5c1731bdcff8d4432c",
  path: "declarations/wholefoods.collection-profile.json",
};

const wholefoodsProfile: LegacyScopeBinding = {
  scope: "wholefoods.profile",
  pdppSource: wholefoodsSource,
  pdppStreams: ["profile"],
  legacySchemaPath: "wholefoods.profile.json",
  fieldsRead: { profile: ["name", "email"] },
  primaryKey: { profile: ["id"] },
  lossy: [
    "The legacy schema has no account id field; the Amazon customer id is not emitted.",
  ],
  provenance: [
    {
      ...wholefoodsEvidence,
      path: "declarations/wholefoods.collection-profile.json#streams[name=profile]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("wholefoods.profile", options, ["profile"]);
    if (guard) return guard;
    const profiles = byStream(records, "profile");
    if (profiles.length === 0)
      return {
        ok: false,
        error: { kind: "empty_singleton", scope: "wholefoods.profile" },
      };
    if (profiles.length !== 1)
      return {
        ok: false,
        error: {
          kind: "incomplete_scope",
          scope: "wholefoods.profile",
          reason: "profile stream did not contain exactly one record",
        },
      };
    const [p] = profiles;
    if (
      (p.name != null && typeof p.name !== "string") ||
      (p.email != null && typeof p.email !== "string")
    ) {
      return {
        ok: false,
        error: {
          kind: "incomplete_scope",
          scope: "wholefoods.profile",
          reason: "profile contains a malformed scalar value",
        },
      };
    }
    return {
      ok: true,
      payload: {
        name: typeof p.name === "string" ? p.name : null,
        email: typeof p.email === "string" ? p.email : null,
      },
    };
  },
};

const wholefoodsOrders: LegacyScopeBinding = {
  scope: "wholefoods.orders",
  pdppSource: wholefoodsSource,
  pdppStreams: ["orders", "order_items"],
  legacySchemaPath: "wholefoods.orders.json",
  fieldsRead: {
    orders: [
      "id",
      "order_date",
      "order_url",
      "status",
      "total_cents",
      "item_count",
    ],
    order_items: [
      "order_id",
      "name",
      "product_id",
      "product_url",
      "image_url",
      "quantity",
      "unit_price_cents",
    ],
  },
  primaryKey: { orders: ["id"], order_items: ["id"] },
  lossy: [
    "The retained collector emitted only product-linked named lines; a source line without either field fails this scope as incomplete.",
    "Product identity is the source Amazon ASIN in product_id.",
  ],
  provenance: [
    {
      ...wholefoodsEvidence,
      path: "declarations/wholefoods.collection-profile.json#streams[name=orders,order_items]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("wholefoods.orders", options, [
      "orders",
      "order_items",
    ]);
    if (guard) return guard;
    const sourceItems = byStream(records, "order_items");
    const sourceOrders = byStream(records, "orders");
    const sourceOrderIds = new Set(sourceOrders.map((order) => order.id));
    if (
      sourceOrderIds.size !== sourceOrders.length ||
      sourceOrders.some((order) => !isNonEmptyString(order.id))
    ) {
      return {
        ok: false,
        error: {
          kind: "incomplete_scope",
          scope: "wholefoods.orders",
          reason: "orders contain a missing or duplicate id",
        },
      };
    }
    const unrepresentableItem = sourceItems.some(
      (item) =>
        !sourceOrderIds.has(item.order_id) ||
        !isNonEmptyString(item.name) ||
        !isNonEmptyString(item.product_id),
    );
    if (unrepresentableItem) {
      return {
        ok: false,
        error: {
          kind: "incomplete_scope",
          scope: "wholefoods.orders",
          reason:
            "Cannot preserve every valid order line: order_items.name or order_items.product_id is missing",
        },
      };
    }
    if (
      sourceOrders.some(
        (order) =>
          typeof order.item_count !== "number" ||
          !Number.isSafeInteger(order.item_count) ||
          order.item_count < 0 ||
          sourceItems.filter((item) => item.order_id === order.id).length !==
            order.item_count,
      )
    ) {
      return {
        ok: false,
        error: {
          kind: "incomplete_scope",
          scope: "wholefoods.orders",
          reason:
            "order item count is missing or does not match the observed lines",
        },
      };
    }
    const orders = byStream(records, "orders").flatMap((o) => {
      if (!isNonEmptyString(o.id)) return [];
      const items = sourceItems
        .filter((i) => i.order_id === o.id)
        .flatMap((i) => {
          if (!isNonEmptyString(i.name) || !isNonEmptyString(i.product_id))
            return [];
          return [
            {
              name: i.name,
              productId: i.product_id,
              ...(typeof i.product_url === "string"
                ? { productUrl: i.product_url }
                : {}),
              ...(typeof i.image_url === "string"
                ? { imageUrl: i.image_url }
                : {}),
              quantity:
                typeof i.quantity === "number" ? String(i.quantity) : null,
              price:
                typeof i.unit_price_cents === "number"
                  ? i.unit_price_cents / 100
                  : null,
            },
          ];
        });
      return [
        {
          orderId: o.id,
          items,
          ...(typeof o.order_url === "string" ? { orderUrl: o.order_url } : {}),
          ...(typeof o.order_date === "string" || o.order_date === null
            ? { orderDate: o.order_date }
            : {}),
          // The legacy Whole Foods collector labeled every observed order Completed;
          // source 0.3.0 correctly reports status as unknown (null).
          ...(o.status === null
            ? { status: "Completed" }
            : typeof o.status === "string"
              ? { status: o.status }
              : {}),
          ...(typeof o.total_cents === "number"
            ? { total: o.total_cents / 100 }
            : {}),
          ...(typeof o.item_count === "number"
            ? { itemCount: o.item_count }
            : {}),
        },
      ];
    });
    return {
      ok: true,
      payload: {
        orders,
        totalOrders: orders.length,
        totalItems: orders.reduce((sum, o) => sum + o.items.length, 0),
      },
    };
  },
};

const wholefoodsNutritionFields = [
  "product_id",
  "name",
  "source",
  "confidence",
  "calories",
  "protein_g",
  "carbs_g",
  "fat_g",
  "sodium_mg",
  "fiber_g",
  "sugar_g",
  "serving_size",
  "servings_per_container",
];
const wholefoodsNutrition: LegacyScopeBinding = {
  scope: "wholefoods.nutrition",
  pdppSource: wholefoodsSource,
  pdppStreams: ["nutrition", "order_items"],
  legacySchemaPath: "wholefoods.nutrition.json",
  fieldsRead: {
    nutrition: wholefoodsNutritionFields,
    order_items: ["product_id", "name", "product_url", "image_url"],
  },
  primaryKey: { nutrition: ["product_id"], order_items: ["id"] },
  lossy: [
    "ingredients and allergens are not collected by the current nutrition stream.",
    "servingsPerContainer is converted from the declared number to the legacy string field.",
  ],
  provenance: [
    {
      ...wholefoodsEvidence,
      path: "declarations/wholefoods.collection-profile.json#streams[name=nutrition]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("wholefoods.nutrition", options, [
      "nutrition",
      "order_items",
    ]);
    if (guard) return guard;
    const items: Record<string, unknown> = Object.create(null);
    const orderedProducts = new Map<
      string,
      { name: string; productUrl?: string; imageUrl?: string }
    >();
    for (const row of byStream(records, "order_items")) {
      if (!isNonEmptyString(row.product_id) || typeof row.name !== "string")
        return {
          ok: false,
          error: {
            kind: "incomplete_scope",
            scope: "wholefoods.nutrition",
            reason: "order item lacks a source ASIN or name",
          },
        };
      orderedProducts.set(row.product_id, {
        name: row.name,
        ...(typeof row.product_url === "string"
          ? { productUrl: row.product_url }
          : {}),
        ...(typeof row.image_url === "string"
          ? { imageUrl: row.image_url }
          : {}),
      });
    }
    let found = 0,
      foundUSDA = 0,
      blocked = 0;
    const seenNutrition = new Set<string>();
    for (const n of byStream(records, "nutrition")) {
      if (
        !isNonEmptyString(n.product_id) ||
        typeof n.source !== "string" ||
        ![
          "wholefoods_product_page",
          "usda_fdc",
          "not_found",
          "error",
          "blocked",
        ].includes(n.source) ||
        !orderedProducts.has(n.product_id) ||
        seenNutrition.has(n.product_id)
      )
        return {
          ok: false,
          error: {
            kind: "incomplete_scope",
            scope: "wholefoods.nutrition",
            reason:
              "nutrition row has an invalid, duplicate, or unordered product outcome",
          },
        };
      seenNutrition.add(n.product_id);
      const ordered = orderedProducts.get(n.product_id);
      const name = typeof n.name === "string" ? n.name : ordered?.name;
      if (typeof name !== "string")
        return {
          ok: false,
          error: {
            kind: "incomplete_scope",
            scope: "wholefoods.nutrition",
            reason: "nutrition product name is unavailable",
          },
        };
      const item: Record<string, unknown> = { name, source: n.source };
      if (ordered?.productUrl !== undefined)
        item.productUrl = ordered.productUrl;
      if (ordered?.imageUrl !== undefined) item.images = ordered.imageUrl;
      if (["high", "medium", "low"].includes(String(n.confidence))) {
        item.confidence = n.confidence;
      }
      for (const field of [
        "calories",
        "protein_g",
        "carbs_g",
        "fat_g",
        "sodium_mg",
        "fiber_g",
        "sugar_g",
      ]) {
        if (n[field] === null || typeof n[field] === "number") {
          item[field] = n[field];
        }
      }
      if (n.serving_size === null || typeof n.serving_size === "string")
        item.servingSize = n.serving_size;
      if (typeof n.servings_per_container === "number")
        item.servingsPerContainer = String(n.servings_per_container);
      else if (n.servings_per_container === null)
        item.servingsPerContainer = null;
      items[n.product_id] = item;
      if (n.source === "wholefoods_product_page") found++;
      if (n.source === "usda_fdc") foundUSDA++;
      if (n.source === "blocked") blocked++;
    }
    const total = orderedProducts.size;
    if (seenNutrition.size !== total)
      return {
        ok: false,
        error: {
          kind: "incomplete_scope",
          scope: "wholefoods.nutrition",
          reason: "nutrition outcomes do not cover every ordered product",
        },
      };
    return {
      ok: true,
      payload: {
        items,
        coverage: {
          total,
          found,
          foundUSDA,
          blocked,
          percentCovered: total
            ? Math.round(((found + foundUSDA) / total) * 100)
            : 0,
        },
      },
    };
  },
};

// amazon.profile is a documented GAP: no `profile` stream exists on the
// amazon collection-profile.json at all (verified: exactly 2 streams,
// orders and order_items) — legacy's `name`/`isPrime` have no PDPP source.

// iCloud Notes is bound to the signed 0.1.0 collection profile. Desktop
// admission and ingest projection are separate gates.
const icloudNoteFolders: LegacyScopeBinding = {
  scope: "icloud_notes.folders",
  pdppSource: "https://registry.pdpp.dev/connectors/icloud-notes",
  pdppStreams: ["folders"],
  legacySchemaPath: "icloud_notes.folders.json",
  fieldsRead: { folders: ["id", "name"] },
  primaryKey: { folders: ["id"] },
  lossy: [],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/icloud-notes:0.1.0",
      digest:
        "sha256:fe5497bb79b0d567c30790cc71b1e591b955fe474725679b996441bd70c09944",
      path: "declarations/icloud-notes.collection-profile.json#streams[name=folders]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("icloud_notes.folders", options, ["folders"]);
    if (guard) return guard;
    const folders = byStream(records, "folders");
    return {
      ok: true,
      payload: {
        folders: folders.map((folder) => ({
          recordName: orEmptyString(folder.id),
          title: orEmptyString(folder.name),
        })),
        total: folders.length,
      },
    };
  },
};

const icloudNotes: LegacyScopeBinding = {
  scope: "icloud_notes.notes",
  pdppSource: "https://registry.pdpp.dev/connectors/icloud-notes",
  pdppStreams: ["notes", "folders"],
  legacySchemaPath: "icloud_notes.notes.json",
  fieldsRead: {
    notes: [
      "id",
      "title",
      "snippet",
      "folder_id",
      "is_pinned",
      "created_at",
      "modified_at",
      "has_attachments",
      "text_content",
    ],
    folders: ["id", "name"],
  },
  primaryKey: { notes: ["id"], folders: ["id"] },
  lossy: [
    "userName is always null because the declaration has no account/profile stream for the legacy fullName source.",
    "folder uses the legacy display-name shape; unresolved folder references fall back to folder_id.",
  ],
  provenance: [
    {
      kind: "oci",
      ref: "ghcr.io/pdp-connect/connector/icloud-notes:0.1.0",
      digest:
        "sha256:fe5497bb79b0d567c30790cc71b1e591b955fe474725679b996441bd70c09944",
      path: "declarations/icloud-notes.collection-profile.json#streams[name=notes,folders]",
    },
  ],
  project(records, options): ProjectionResult {
    const guard = requireStreams("icloud_notes.notes", options, [
      "notes",
      "folders",
    ]);
    if (guard) return guard;

    const folders = new Map<string, string>();
    for (const folder of byStream(records, "folders")) {
      if (
        typeof folder.id !== "string" ||
        folder.id.length === 0 ||
        typeof folder.name !== "string" ||
        folder.name.length === 0
      ) {
        return {
          ok: false,
          error: {
            kind: "invalid_value",
            scope: "icloud_notes.notes",
            reason: "iCloud Notes folder is missing a declared required field",
          },
        };
      }
      folders.set(folder.id, folder.name);
    }
    const notes = byStream(records, "notes").map((note) => {
      if (typeof note.id !== "string" || note.id.length === 0) return undefined;
      const optionalString = (field: string): string | null | undefined => {
        const value = note[field];
        return value == null || typeof value === "string"
          ? (value ?? null)
          : undefined;
      };
      const title = optionalString("title");
      const snippet = optionalString("snippet");
      const folderId = optionalString("folder_id");
      const createdDate = optionalString("created_at");
      const modifiedDate = optionalString("modified_at");
      const textContent = optionalString("text_content");
      if (
        title === undefined ||
        snippet === undefined ||
        folderId === undefined ||
        createdDate === undefined ||
        modifiedDate === undefined ||
        textContent === undefined ||
        typeof note.is_pinned !== "boolean" ||
        typeof note.has_attachments !== "boolean"
      )
        return undefined;
      return {
        recordName: note.id,
        title,
        snippet,
        folder: folderId === null ? null : (folders.get(folderId) ?? folderId),
        isPinned: note.is_pinned,
        createdDate,
        modifiedDate,
        hasAttachments: note.has_attachments,
        textContent,
      };
    });
    if (notes.some((note) => note === undefined)) {
      return {
        ok: false,
        error: {
          kind: "invalid_value",
          scope: "icloud_notes.notes",
          reason:
            "iCloud Notes contains a record that does not match its declared schema",
        },
      };
    }
    return {
      ok: true,
      payload: { notes, total: notes.length, userName: null },
    };
  },
};

export const LEGACY_SCOPE_BINDINGS: ReadonlyMap<string, LegacyScopeBinding> =
  new Map(
    Object.entries({
      "instagram.profile": instagramProfile,
      "instagram.posts": instagramPosts,
      "instagram.following": instagramFollowing,
      "instagram.ads": instagramAds,
      "github.repositories": githubRepositories,
      "github.starred": githubStarred,
      "github.history": githubHistory,
      "github.profile": githubProfile,
      "github.events": githubEvents,
      "github.contributions": githubContributions,
      "chatgpt.memories": chatgptMemories,
      "chatgpt.conversations": chatgptConversations,
      "linkedin.profile": linkedinProfile,
      "linkedin.connections": linkedinConnections,
      "linkedin.experience": linkedinExperience,
      "linkedin.education": linkedinEducation,
      "linkedin.skills": linkedinSkills,
      "linkedin.languages": linkedinLanguages,
      "spotify.profile": spotifyProfile,
      "spotify.savedTracks": spotifySavedTracks,
      "spotify.playlists": spotifyPlaylists,
      "shop.orders": shopOrders,
      "amazon.orders": amazonOrders,
      "heb.orders": hebOrders,
      "heb.profile": hebProfile,
      "heb.nutrition": hebNutrition,
      "wholefoods.profile": wholefoodsProfile,
      "wholefoods.orders": wholefoodsOrders,
      "wholefoods.nutrition": wholefoodsNutrition,
      "oura.activity": ouraActivity,
      "oura.readiness": ouraReadiness,
      "oura.sleep": ouraSleep,
      "icloud_notes.notes": icloudNotes,
      "icloud_notes.folders": icloudNoteFolders,
      "youtube.profile": youtubeProfile,
      "youtube.subscriptions": youtubeSubscriptions,
      "youtube.playlists": youtubePlaylists,
      "youtube.playlistItems": youtubePlaylistItems,
      "youtube.likes": youtubeLikes,
      "youtube.watchLater": youtubeWatchLater,
      "youtube.history": youtubeHistory,
      "claude.conversations": claudeConversations,
      "claude.projects": claudeProjects,
    }),
  );

/** Known legacy contracts checked against signed declarations but not
 * projectable without fabricating fields or changing the retained contract. */
export const LEGACY_SCOPE_GAPS: ReadonlyMap<
  string,
  { reason: string; provenanceChecked: LegacyScopeBindingProvenance[] }
> = new Map([]);
