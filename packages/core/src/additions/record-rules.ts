/** One collection of a scope whose items are memory records. */
export interface MemoryRecordRule {
  /** Canonical collection name; also the prefix of every record key. Top-level key in a legacy body. */
  collection: string;
  /** Other names the same collection is stored under: PDPP stream names or alternate legacy keys. */
  aliases?: readonly string[];
  /** Fields tried in order for the record's stable identity. Dotted paths allowed (e.g. "track.id"). */
  idFields: readonly string[];
  /** PDPP only: keep a stream's record only when this field equals this value (a stream that feeds several collections). */
  streamFilter?: { field: string; equals: string };
}

/**
 * Scope -> its record collections. An empty list means the scope holds no
 * memory records.
 *
 * These rules must stay in step with the owner apps' memory list. Changing a
 * rule's `collection` or `idFields` re-keys that scope's ledger, so its
 * records would be dated as new on the next write.
 */
export const MEMORY_RECORD_RULES: Readonly<
  Record<string, readonly MemoryRecordRule[]>
> = {
  "chatgpt.conversations": [{ collection: "conversations", idFields: ["id"] }],
  "chatgpt.memories": [],
  "chatgpt.messages": [],
  "github.profile": [],
  "github.repositories": [
    {
      collection: "repositories",
      idFields: ["url", "fullName", "full_name", "name"],
    },
  ],
  "github.starred": [
    {
      collection: "starred",
      idFields: ["url", "fullName", "full_name", "name"],
    },
  ],
  "github.events": [{ collection: "events", idFields: ["id"] }],
  "github.history": [
    { collection: "issues", idFields: ["id", "number"] },
    {
      collection: "pullRequests",
      aliases: ["pull_requests"],
      idFields: ["id", "number"],
    },
  ],
  // The PDPP `contributions` stream's records become the legacy `days` array.
  "github.contributions": [
    { collection: "days", aliases: ["contributions"], idFields: ["date"] },
  ],
  "icloud_notes.notes": [{ collection: "notes", idFields: ["recordName"] }],
  "icloud_notes.folders": [{ collection: "folders", idFields: ["recordName"] }],
  "instagram.profile": [],
  "instagram.posts": [
    { collection: "posts", idFields: ["id", "shortcode", "taken_at"] },
  ],
  // The PDPP `following` stream's records become the legacy `accounts` array.
  "instagram.following": [
    {
      collection: "accounts",
      aliases: ["following"],
      idFields: ["pk", "username"],
    },
  ],
  // The PDPP `ads` stream carries all kinds; `streamFilter` keeps each
  // collection to the rows the projection assigns to it.
  "instagram.ads": [
    {
      collection: "ad_topics",
      aliases: ["ads"],
      idFields: ["name"],
      streamFilter: { field: "kind", equals: "ad_topic" },
    },
    {
      collection: "advertisers",
      aliases: ["ads"],
      idFields: ["name"],
      streamFilter: { field: "kind", equals: "advertiser" },
    },
  ],
  "discord.servers": [{ collection: "servers", idFields: ["id"] }],
  "discord.messages": [{ collection: "messages", idFields: ["id"] }],
  "discord.connections": [{ collection: "connections", idFields: ["id"] }],
  "x.posts": [{ collection: "records", idFields: ["id"] }],
  "x.likes": [{ collection: "records", idFields: ["id"] }],
  "x.bookmarks": [{ collection: "records", idFields: ["id"] }],
  "linkedin.experience": [
    {
      collection: "items",
      aliases: ["experience", "experiences"],
      idFields: ["id", "experienceGroupId"],
    },
  ],
  "linkedin.education": [
    { collection: "items", aliases: ["education"], idFields: ["id"] },
  ],
  "spotify.playlists": [
    {
      collection: "playlists",
      aliases: ["public_playlists", "items"],
      idFields: ["id", "playlist_id", "playlistId", "uri"],
    },
  ],
  // The PDPP `saved_tracks` stream's records become the legacy `savedTracks` array.
  "spotify.savedTracks": [
    {
      collection: "savedTracks",
      aliases: ["tracks", "items", "saved_tracks"],
      idFields: [
        "track.id",
        "track.track_id",
        "track.trackId",
        "track.uri",
        "id",
        "uri",
      ],
    },
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
