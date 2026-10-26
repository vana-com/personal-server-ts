/** Stable legacy entity keys reviewed against the vendored scope schemas.
 * A missing object-array path has no proven key and cannot qualify for takeover.
 * Singleton profiles belong to the selected connection; they need no array key.
 * Grocery nutrition already uses source product IDs as object-map keys.
 *
 * LinkedIn connections/experience/education/skills/languages, Instagram ads,
 * H-E-B delivery addresses, GitHub achievements and Spotify artists retain no
 * upstream ID in the legacy body. Keep those lists unkeyed: names/content are
 * not identities. Instagram ads drops source IDs while projecting. LinkedIn
 * profile, Spotify profile, Instagram profile and YouTube profile are single
 * records scoped to their selected connection, so they need no array key.
 * GitHub repository URLs/qualified names, organization logins and LinkedIn
 * profile URLs are reusable aliases, not stable IDs. Their source IDs are
 * omitted from the legacy body, so those lists must also stay unkeyed.
 * Spotify track URIs may identify local files by tags/duration rather than an
 * opaque source ID. The collector does not enforce catalog-only URIs, so keep
 * both playlist track arrays and saved-track arrays unkeyed.
 */
export const LEGACY_SCOPE_ENTITY_KEYS: Readonly<
  Record<string, Readonly<Record<string, readonly string[]>>>
> = {
  "amazon.orders": {
    "$.orders": ["orderId"],
  },
  "chatgpt.conversations": {
    "$.conversations": ["id"],
    "$.conversations[].messages": ["id"],
  },
  "chatgpt.memories": {
    "$.memories": ["id"],
  },
  "claude.conversations": {
    "$.conversations": ["id"],
    "$.conversations[].messages": ["id"],
  },
  "claude.projects": {
    "$.projects": ["id"],
  },
  "github.contributions": {
    "$.yearTotals": ["year"],
    "$.days": ["date"],
    "$.monthlyTotals": ["month"],
  },
  "github.events": {
    "$.events": ["id"],
  },
  "github.history": {
    "$.pullRequests": ["id"],
    "$.issues": ["id"],
  },
  "heb.orders": {
    "$.orders": ["orderId"],
    "$.orders[].items": ["productId"],
  },
  "icloud_notes.folders": {
    "$.folders": ["recordName"],
  },
  "icloud_notes.notes": {
    "$.notes": ["recordName"],
  },
  "instagram.following": {
    "$.accounts": ["pk"],
  },
  "instagram.posts": {
    "$.posts[].who_liked": ["id"],
  },
  "oura.activity": {
    "$.days": ["id"],
  },
  "oura.readiness": {
    "$.days": ["id"],
  },
  "oura.sleep": {
    "$.dailyScores": ["id"],
    "$.sleepPeriods": ["id"],
  },
  "shop.orders": {
    "$.orders": ["id"],
  },
  "spotify.playlists": {
    // Only the opaque playlist ID is stable across upstream metadata edits.
    "$.playlists": ["uri"],
  },
  "strava.activities": {
    "$.activities": ["id"],
  },
  "strava.coverage_diagnostics": {
    "$.coverage_diagnostics": ["id"],
  },
  "wholefoods.orders": {
    "$.orders": ["orderId"],
    "$.orders[].items": ["productId"],
  },
  "youtube.history": {
    "$.history": ["videoId"],
  },
  "youtube.likes": {
    "$.likedVideos": ["videoId"],
  },
  "youtube.playlistItems": {
    "$.playlists": ["playlistId"],
    "$.playlists[].items": ["videoId"],
  },
  "youtube.playlists": {
    "$.playlists": ["playlistId"],
  },
  "youtube.subscriptions": {
    "$.subscriptions": ["channelId"],
  },
  "youtube.watchLater": {
    "$.watchLater": ["videoId"],
  },
};

/** ID-less legacy scopes that can only prove coverage by exact body snapshot. */
export const LEGACY_SCOPE_SNAPSHOT_EQUIVALENCE: Readonly<Record<string, true>> =
  {
    "github.repositories": true,
    // The old starred projection emits updatedAt:null. A non-null old value is
    // deliberately not reproducible and therefore cannot pass exact equality.
    "github.starred": true,
    "instagram.ads": true,
    "linkedin.connections": true,
    "linkedin.education": true,
    "linkedin.experience": true,
    "linkedin.languages": true,
    "linkedin.skills": true,
    "spotify.savedTracks": true,
  };
