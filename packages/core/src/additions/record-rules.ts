/** One collection of a scope whose items are memory records. */
export interface MemoryRecordRule {
  /** Canonical collection name; also the prefix of every record key. Top-level key in a legacy body. */
  collection: string;
  /**
   * Other names the same collection is stored under: PDPP stream names or
   * alternate legacy keys. In the stored PDPP rows form `{ records: [...] }`
   * a scope's rows belong to the rule whose collection or alias is the
   * scope's dataset name (the part after the first dot).
   */
  aliases?: readonly string[];
  /**
   * LEGACY keyed form: fields tried in order for the record's identity.
   * Dotted paths allowed. Empty = the collection is counted but not tracked.
   */
  idFields: readonly string[];
  /**
   * ROWS form (stored PDPP `{ records: [...] }`): fields tried in order for
   * the identity. Each is chosen so the legacy projection binding copies the
   * value unchanged into the matching `idFields` field, so one record has
   * the same key in both forms (proved per binding in
   * `record-rules.parity.test.ts`). Empty = counted but not tracked.
   */
  rowIdFields: readonly string[];
  /** Rows form: keep a row only when this field equals this value (a stream that feeds several collections). */
  streamFilter?: { field: string; equals: string };
  /**
   * The scope is one record (a profile): counted as 1 when its body has any
   * content (legacy form) or once per row (rows form), never tracked.
   */
  singleton?: true;
}

/** A single-record scope (a profile): counted, never tracked. */
const singleton = (): MemoryRecordRule => ({
  collection: "profile",
  idFields: [],
  rowIdFields: [],
  singleton: true,
});

/** A collection counted toward the total but never tracked for additions. */
const untracked = (
  collection: string,
  aliases?: readonly string[],
): MemoryRecordRule => ({
  collection,
  ...(aliases ? { aliases } : {}),
  idFields: [],
  rowIdFields: [],
});

/** Same id field in both forms. */
const sameId = (
  collection: string,
  fields: readonly string[],
  aliases?: readonly string[],
): MemoryRecordRule => ({
  collection,
  ...(aliases ? { aliases } : {}),
  idFields: fields,
  rowIdFields: fields,
});

/**
 * Scope -> its record collections. The server's `total` must agree with what
 * the owner app counts, so a scope the app counts is never given an empty
 * list; where identity is not provably stable it is counted but not tracked.
 * An empty list means the owner app also counts 0 for the scope.
 *
 * Both stored forms of a scope must produce the same keys, so each rule names
 * the id field per form. Where the projection binding keeps no field that is
 * equal in both forms (linkedin.experience, linkedin.education: the legacy
 * body drops the row id), the collection is untracked in both forms and only
 * counts toward the total.
 *
 * Changing a rule's `collection` or id fields re-keys that scope's ledger, so
 * its records would be dated as new until its sidecar is rebuilt.
 */
export const MEMORY_RECORD_RULES: Readonly<
  Record<string, readonly MemoryRecordRule[]>
> = {
  // --- Empty: the owner app counts 0 records for these. -------------------
  "chatgpt.memories": [],
  "chatgpt.messages": [],
  "github.profile": [],
  "instagram.profile": [],

  // --- Tracked: an id that is equal in both stored forms. -----------------
  "chatgpt.conversations": [sameId("conversations", ["id"])],
  // Claude's conversations and projects keep the row id in both forms.
  "claude.conversations": [sameId("conversations", ["id"])],
  "claude.projects": [sameId("projects", ["id"])],
  // The binding projects the row's `html_url` into the legacy `url`.
  "github.repositories": [
    {
      collection: "repositories",
      idFields: ["url"],
      rowIdFields: ["html_url"],
    },
  ],
  "github.starred": [
    { collection: "starred", idFields: ["url"], rowIdFields: ["html_url"] },
  ],
  "github.events": [sameId("events", ["id"])],
  // The PDPP streams behind this legacy scope are stored as their own scopes
  // (`github.issues`, `github.pull_requests`, `github.user`), never as one
  // `github.history` rows scope, so these rules serve the legacy body only.
  "github.history": [
    sameId("issues", ["id"]),
    sameId("pullRequests", ["id"], ["pull_requests"]),
  ],
  "github.issues": [sameId("issues", ["id"])],
  "github.pull_requests": [sameId("pullRequests", ["id"], ["pull_requests"])],
  // The PDPP `contributions` stream's records become the legacy `days` array.
  "github.contributions": [sameId("days", ["date"], ["contributions"])],
  // The binding projects the row `id` into the legacy `recordName`.
  "icloud_notes.notes": [
    { collection: "notes", idFields: ["recordName"], rowIdFields: ["id"] },
  ],
  "icloud_notes.folders": [
    { collection: "folders", idFields: ["recordName"], rowIdFields: ["id"] },
  ],
  // The legacy post has no id; `taken_at` is copied unchanged.
  "instagram.posts": [sameId("posts", ["taken_at"])],
  // The PDPP `following` stream's records become the legacy `accounts` array;
  // the binding projects the row `id` into the legacy `pk`.
  "instagram.following": [
    {
      collection: "accounts",
      aliases: ["following"],
      idFields: ["pk"],
      rowIdFields: ["id"],
    },
  ],
  // The PDPP `ads` stream carries all kinds; `streamFilter` keeps each
  // collection to the rows the projection assigns to it. The owner app counts
  // the category rows too, so they are counted (untracked) here.
  "instagram.ads": [
    {
      ...sameId("ad_topics", ["name"], ["ads"]),
      streamFilter: { field: "kind", equals: "ad_topic" },
    },
    {
      ...sameId("advertisers", ["name"], ["ads"]),
      streamFilter: { field: "kind", equals: "advertiser" },
    },
    {
      ...untracked("categories", ["ads"]),
      streamFilter: { field: "kind", equals: "ad_category" },
    },
  ],
  "discord.servers": [sameId("servers", ["id"])],
  "discord.messages": [sameId("messages", ["id"])],
  "discord.connections": [sameId("connections", ["id"])],
  // These store a PDPP `{ records }` body, whose rows are the collection. The
  // dataset-named alias keeps a keyed body (`{ posts: [...] }`) on the same
  // `records:` keys.
  "x.posts": [sameId("records", ["id"], ["posts"])],
  "x.likes": [sameId("records", ["id"], ["likes"])],
  "x.bookmarks": [sameId("records", ["id"], ["bookmarks"])],
  // The binding projects the row `uri` unchanged.
  "spotify.playlists": [
    sameId("playlists", ["uri"], ["public_playlists", "items"]),
  ],
  "spotify.savedTracks": [
    sameId("savedTracks", ["uri"], ["tracks", "items", "saved_tracks"]),
  ],
  // The PDPP stream is `saved_tracks`, so the rows are stored under this
  // scope; its keys equal the legacy `spotify.savedTracks` keys.
  "spotify.saved_tracks": [
    sameId("savedTracks", ["uri"], ["saved_tracks", "tracks", "items"]),
  ],
  // The legacy body keeps the order number as `orderId`.
  "amazon.orders": [
    { collection: "orders", idFields: ["orderId"], rowIdFields: ["id"] },
  ],
  "shop.orders": [sameId("orders", ["id"])],
  "oura.activity": [sameId("days", ["id"], ["activity"])],
  "oura.readiness": [sameId("days", ["id"], ["readiness"])],
  "youtube.playlists": [sameId("playlists", ["url"])],

  // --- Counted, never tracked: the owner app counts them, but no field is --
  // --- provably equal in both stored forms. They report a total and no -----
  // --- additions, and a null trackedSince. ---------------------------------
  // The legacy body drops the row id.
  "linkedin.experience": [untracked("items", ["experience", "experiences"])],
  "linkedin.education": [untracked("items", ["education"])],
  "linkedin.connections": [untracked("connections")],
  "linkedin.skills": [untracked("skills")],
  "linkedin.languages": [untracked("languages")],
  // One `sleep` stream feeds two legacy arrays, so both are counted.
  "oura.sleep": [
    untracked("sleepPeriods", ["sleep"]),
    untracked("dailyScores"),
  ],
  // No binding fixture proves an id equal in both forms.
  "heb.orders": [untracked("orders")],
  "wholefoods.orders": [untracked("orders")],
  "heb.nutrition": [untracked("nutrition")],
  "wholefoods.nutrition": [untracked("nutrition")],
  "youtube.subscriptions": [untracked("subscriptions")],
  "youtube.likes": [untracked("likedVideos", ["likes"])],
  "youtube.watchLater": [untracked("watchLater")],
  "youtube.watch_later": [untracked("watchLater", ["watch_later"])],
  "youtube.history": [untracked("history")],
  "youtube.watch_history": [untracked("history", ["watch_history"])],
  "youtube.playlistItems": [untracked("playlists", ["playlistItems"])],
  "youtube.playlist_items": [untracked("playlists", ["playlist_items"])],
  // Single-record scopes.
  "linkedin.profile": [singleton()],
  "spotify.profile": [singleton()],
  "youtube.profile": [singleton()],
  "heb.profile": [singleton()],
  "wholefoods.profile": [singleton()],
  // Streams that only join into another scope's legacy body, which the owner
  // app counts when they are stored as their own scopes.
  "amazon.order_items": [untracked("order_items")],
  "heb.order_items": [untracked("order_items")],
  "wholefoods.order_items": [untracked("order_items")],
  "claude.messages": [untracked("messages")],
  "claude.account_profile": [untracked("account_profile")],
  "claude.project_documents": [untracked("project_documents")],
  "github.user": [untracked("user")],
  "github.user_stats": [untracked("user_stats")],
  "github.pinned_repositories": [untracked("pinned_repositories")],
  "github.organizations": [untracked("organizations")],
  "instagram.post_likes": [untracked("post_likes")],
  "spotify.playlist_items": [untracked("playlist_items")],
};

/** The rules for a scope, or null when the scope has no entry (generic default applies). */
export function memoryRecordRulesFor(
  scope: string,
): readonly MemoryRecordRule[] | null {
  if (!Object.prototype.hasOwnProperty.call(MEMORY_RECORD_RULES, scope)) {
    return null;
  }
  return MEMORY_RECORD_RULES[scope] ?? null;
}
