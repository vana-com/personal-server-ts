/** Stable legacy entity keys reviewed against the vendored scope schemas.
 * A missing object-array path has no proven key and cannot qualify for takeover.
 * Singleton profiles belong to the selected connection; they need no array key.
 * Grocery nutrition already uses source product IDs as object-map keys.
 *
 * LinkedIn experience/education/skills/languages, Instagram ads, H-E-B delivery
 * addresses, GitHub achievements and Spotify artists retain no upstream ID in
 * the legacy body. Keep those lists unkeyed: names/content are not identities.
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
  "github.profile": {
    // Qualified repository names and organization logins are source identifiers.
    // A rename conservatively leaves the saved head uncovered.
    "$.pinnedRepositories": ["fullName"],
    "$.organizations": ["login"],
  },
  "github.repositories": {
    // Both legacy and PDPP projections retain GitHub's repository URL.
    "$.repositories": ["url"],
  },
  "github.starred": {
    "$.starred": ["url"],
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
  "linkedin.connections": {
    // Retained source profile URL, not the connection's display name.
    "$.connections": ["profileUrl"],
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
