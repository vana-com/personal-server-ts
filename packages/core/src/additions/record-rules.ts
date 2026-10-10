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
}

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
 * Scope -> its record collections. An empty list means the scope holds no
 * memory records (a singleton, or a stream that only joins into another
 * scope's legacy body).
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
  "chatgpt.conversations": [sameId("conversations", ["id"])],
  // Claude's conversations and projects keep the row id in both forms.
  "claude.conversations": [sameId("conversations", ["id"])],
  "claude.projects": [sameId("projects", ["id"])],
  "chatgpt.memories": [],
  "chatgpt.messages": [],
  // The legacy body keeps the order number as `orderId`.
  "amazon.orders": [
    { collection: "orders", idFields: ["orderId"], rowIdFields: ["id"] },
  ],
  "shop.orders": [sameId("orders", ["id"])],
  // No binding fixture proves an id equal in both forms: counted, untracked.
  "heb.orders": [untracked("orders")],
  "wholefoods.orders": [untracked("orders")],
  "heb.nutrition": [],
  "wholefoods.nutrition": [],
  // Singletons.
  "linkedin.profile": [],
  "spotify.profile": [],
  "heb.profile": [],
  "wholefoods.profile": [],
  "youtube.profile": [],
  // The legacy body drops the row id: counted, never tracked.
  "linkedin.connections": [untracked("connections")],
  "linkedin.skills": [untracked("skills")],
  "linkedin.languages": [untracked("languages")],
  // One `sleep` stream feeds two legacy arrays (`dailyScores`, `sleepPeriods`).
  "oura.activity": [sameId("days", ["id"], ["activity"])],
  "oura.readiness": [sameId("days", ["id"], ["readiness"])],
  "oura.sleep": [],
  // No binding fixture proves the other youtube lists: untracked (total 0).
  "youtube.playlists": [sameId("playlists", ["url"])],
  "youtube.subscriptions": [],
  "youtube.playlistItems": [],
  "youtube.playlist_items": [],
  "youtube.likes": [],
  "youtube.watchLater": [],
  "youtube.watch_later": [],
  "youtube.history": [],
  "youtube.watch_history": [],
  // Line items that only join into their order's legacy body.
  "amazon.order_items": [],
  "heb.order_items": [],
  "wholefoods.order_items": [],
  "claude.messages": [],
  "claude.account_profile": [],
  "claude.project_documents": [],
  "github.profile": [],
  "github.user": [],
  "github.user_stats": [],
  "github.pinned_repositories": [],
  "github.organizations": [],
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
  "instagram.profile": [],
  "instagram.post_likes": [],
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
  // collection to the rows the projection assigns to it.
  "instagram.ads": [
    {
      ...sameId("ad_topics", ["name"], ["ads"]),
      streamFilter: { field: "kind", equals: "ad_topic" },
    },
    {
      ...sameId("advertisers", ["name"], ["ads"]),
      streamFilter: { field: "kind", equals: "advertiser" },
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
  // The legacy body drops the row id and keeps no other field that is
  // equal in both forms: counted, never tracked.
  "linkedin.experience": [untracked("items", ["experience", "experiences"])],
  "linkedin.education": [untracked("items", ["education"])],
  // The binding projects the row `uri` unchanged.
  "spotify.playlists": [
    sameId("playlists", ["uri"], ["public_playlists", "items"]),
  ],
  "spotify.playlist_items": [],
  "spotify.savedTracks": [
    sameId("savedTracks", ["uri"], ["tracks", "items", "saved_tracks"]),
  ],
  // The PDPP stream is `saved_tracks`, so the rows are stored under this
  // scope; its keys equal the legacy `spotify.savedTracks` keys.
  "spotify.saved_tracks": [
    sameId("savedTracks", ["uri"], ["saved_tracks", "tracks", "items"]),
  ],
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
