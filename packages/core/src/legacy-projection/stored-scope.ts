import type { PdppRecord } from "@opendatalabs/personal-server-ts-core/legacy-projection";
import { LEGACY_SCOPE_BINDINGS } from "@opendatalabs/personal-server-ts-core/legacy-projection";
import { isGithubBrowserSnapshotFile } from "./github-browser-snapshot.js";
import { projectPdppRecordsToLegacyPayload } from "./index.js";

/**
 * PS-Lite on builds 32+ stores a host-v1 connector run raw: one scope file per
 * PDPP stream, each exactly `{"records":[...plain rows]}` (for example
 * `chatgpt.conversations` and `chatgpt.messages`). Owner-data and Desktop
 * writes store the legacy payload instead; no legacy scope shape has a
 * top-level `records` key, so an array of plain rows under it marks a raw file
 * even if PS-Lite later adds metadata keys beside it. Readers call
 * `projectStoredScopeToLegacyPayload` so both stored shapes read the same.
 */
export function isStoredPdppScopeFile(
  value: unknown,
): value is { records: Record<string, unknown>[] } {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const records = (value as { records?: unknown }).records;
  return (
    Array.isArray(records) &&
    records.every(
      (row) => Boolean(row) && typeof row === "object" && !Array.isArray(row),
    )
  );
}

/**
 * The other stored scopes the projection of `scope` joins, e.g.
 * `chatgpt.conversations` → `["chatgpt.messages"]`. Empty when `scope` has no
 * binding. A reader fetches these only when the scope itself is stored raw.
 */
export function storedScopeJoinScopes(scope: string): string[] {
  const binding = LEGACY_SCOPE_BINDINGS.get(scope);
  const own = ownStream(scope);
  if (!(binding && own && binding.pdppStreams.includes(own))) {
    return [];
  }
  const prefix = scope.slice(0, scope.indexOf("."));
  return binding.pdppStreams
    .filter((stream) => stream !== own)
    .map((stream) => `${prefix}.${stream}`);
}

/**
 * Read a stored scope payload in its legacy shape. A legacy payload passes
 * through unchanged. A raw `{records}` payload is projected with the shared
 * legacy-scope binding, joined with whichever `joinScopes` payloads are also
 * stored raw. When the full projection fails (a join scope is absent, or its
 * rows are incomplete), conversation scopes keep ids, titles and dates
 * without messages. Any other failure returns the payload unchanged.
 */
export function projectStoredScopeToLegacyPayload(
  scope: string,
  data: unknown,
  joinScopes: Readonly<Record<string, unknown>> = {},
): unknown {
  if (!isStoredPdppScopeFile(data)) {
    return data;
  }
  const own = ownStream(scope);
  if (own && isGithubBrowserSnapshotFile(scope, data.records)) {
    return projectGithubBrowserSnapshot(scope, data);
  }
  const binding = LEGACY_SCOPE_BINDINGS.get(scope);
  if (!(binding && own && binding.pdppStreams.includes(own))) {
    return data;
  }
  const prefix = scope.slice(0, scope.indexOf("."));
  const fetchedStreams: string[] = [];
  const records: PdppRecord[] = [];
  for (const stream of binding.pdppStreams) {
    const file = stream === own ? data : joinScopes[`${prefix}.${stream}`];
    if (!isStoredPdppScopeFile(file)) {
      continue;
    }
    fetchedStreams.push(stream);
    for (const row of file.records) {
      records.push({ data: row, stream });
    }
  }
  const projection = projectPdppRecordsToLegacyPayload(scope, records, {
    fetchedStreams,
  });
  // The adapter skips a malformed conversation and reports it rather than
  // failing the scope. Memory still lists that conversation by title, so a
  // drop takes the per-conversation path below like a failure does.
  const dropped =
    projection.ok &&
    scope in TITLES_AND_DATES &&
    projection.diagnostics?.some(
      (d) =>
        (d.kind === "records_skipped" || d.kind === "records_dropped") &&
        d.count > 0,
    );
  if (projection.ok && !dropped) {
    return projection.payload;
  }
  const fallback = TITLES_AND_DATES[scope];
  if (!fallback) {
    return data;
  }
  const perConversation = projectConversationsIndividually(
    scope,
    data.records,
    fetchedStreams,
    records,
    own,
  );
  return perConversation ?? fallback(data.records);
}

/**
 * A github-browser scope file is already the legacy shape's source: one
 * snapshot per stream, no join. It must not reach the GitHub API bindings,
 * which would read the nested snapshot as one malformed row. A snapshot the
 * browser binding rejects stays raw rather than becoming an empty inventory.
 */
function projectGithubBrowserSnapshot(
  scope: string,
  data: { records: Record<string, unknown>[] },
): unknown {
  const validation = projectPdppRecordsToLegacyPayload(
    scope,
    [{ data: data.records[0], stream: ownStream(scope)! }],
    { fetchedStreams: [ownStream(scope)!], profileKey: "github-browser" },
  );
  if (!validation.ok) return data;

  const { id: _id, ...legacyPayload } = data.records[0];
  if (scope === "github.events") {
    // The frozen legacy contract kept the collector's fixed wording.
    return {
      ...legacyPayload,
      windowDescription:
        "Up to 300 most recent public events across all repositories (≈90 days, GitHub API limit)",
    };
  }
  return legacyPayload;
}

/**
 * One incomplete conversation (or message) fails the whole-scope projection.
 * Retry each conversation with only its own messages so the good ones keep
 * their content; a conversation that still fails keeps ids, titles and dates.
 * Null for scopes that are not conversation lists.
 */
function projectConversationsIndividually(
  scope: string,
  rows: Record<string, unknown>[],
  fetchedStreams: string[],
  records: PdppRecord[],
  own: string,
): Record<string, unknown> | null {
  const fallback = TITLES_AND_DATES[scope];
  if (!fallback || own !== "conversations") {
    return null;
  }
  const messagesByConversation = new Map<unknown, PdppRecord[]>();
  const others: PdppRecord[] = [];
  for (const record of records) {
    if (record.stream === own) {
      continue;
    }
    if (record.stream === "messages") {
      const id = record.data.conversation_id;
      messagesByConversation.set(id, [
        ...(messagesByConversation.get(id) ?? []),
        record,
      ]);
    } else {
      others.push(record);
    }
  }
  const conversations = rows.map((row) => {
    const projection = projectPdppRecordsToLegacyPayload(
      scope,
      [
        { data: row, stream: own },
        ...others,
        ...(messagesByConversation.get(row.id) ?? []),
      ],
      { fetchedStreams },
    );
    const projected = projection.ok
      ? (projection.payload as { conversations?: unknown[] }).conversations
      : undefined;
    if (projected?.length === 1) {
      return projected[0];
    }
    return (fallback([row]).conversations as unknown[])[0];
  });
  return { conversations, total: conversations.length };
}

function ownStream(scope: string): string | null {
  const dot = scope.indexOf(".");
  return dot > 0 ? scope.slice(dot + 1) : null;
}

/**
 * Legacy field names per conversation scope, filled from the raw rows only.
 * `messages`, `message_count` and the Claude account profile need join input,
 * so they are absent rather than invented as empty.
 */
const TITLES_AND_DATES: Record<
  string,
  (rows: Record<string, unknown>[]) => Record<string, unknown>
> = {
  "chatgpt.conversations": (rows) => {
    const conversations = rows.map((row) => ({
      id: row.id,
      title: row.title ?? null,
      create_time: row.create_time ?? null,
      update_time: row.update_time ?? null,
    }));
    return { conversations, total: conversations.length };
  },
  "claude.conversations": (rows) => {
    const conversations = rows.map((row) => ({
      id: row.id,
      title: row.title ?? null,
      createdAt: row.create_time ?? null,
      updatedAt: row.update_time ?? null,
    }));
    return { conversations, total: conversations.length };
  },
  "claude.projects": (rows) => {
    const projects = rows.map((row) => ({
      id: row.id,
      title: row.name ?? null,
      createdAt: row.create_time ?? null,
      updatedAt: row.update_time ?? null,
    }));
    return { projects, total: projects.length };
  },
};
