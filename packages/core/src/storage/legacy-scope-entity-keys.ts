/** Stable legacy entity keys reviewed against the vendored scope schemas.
 * A missing object-array path has no proven key and cannot qualify for takeover.
 * Singleton profiles belong to the selected connection; they need no array key.
 * Grocery nutrition already uses source product IDs as object-map keys.
 *
 * LinkedIn experience/education/skills/languages, Instagram ads, H-E-B delivery
 * addresses, GitHub achievements and Spotify artists retain no upstream ID in
 * the legacy body. Keep those lists unkeyed: names/content are not identities.
 * GitHub repository URLs/qualified names, organization logins and LinkedIn
 * profile URLs are reusable aliases, not stable IDs. Their source IDs are
 * omitted from the legacy body, so those lists must also stay unkeyed.
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
    // Repeated track URIs are ambiguous and still fail the duplicate-key guard.
    // Nonempty nested artist lists remain unkeyed even with these outer keys.
    "$.playlists": ["uri"],
    "$.playlists[].tracks": ["uri"],
  },
  "spotify.savedTracks": {
    "$.savedTracks": ["uri"],
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
