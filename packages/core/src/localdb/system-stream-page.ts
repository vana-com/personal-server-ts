import {
  decodeBase64UrlUtf8,
  encodeBase64UrlUtf8,
} from "../encoding/base64url.js";
import { ProtocolError } from "../errors/catalog.js";
import type { LocalSyncDeps } from "./deps.js";
import { readerOf } from "./driver.js";
import {
  systemStreamIdentity,
  type SystemStreamDescriptor,
} from "./system-stream-descriptor.js";

export interface SystemStreamPageOptions {
  readonly limit?: number;
  readonly offset?: number;
  readonly cursor?: string;
}
type Position = [string, string];
interface Cursor {
  version: 1;
  owner: string;
  connection: string;
  stream: string;
  upper: Position;
  after: Position;
}
const invalid = () =>
  new ProtocolError(400, "INVALID_CURSOR", "Invalid system stream page cursor");
function position(value: unknown): value is Position {
  if (!Array.isArray(value) || value.length !== 2) return false;
  const [at, id] = value;
  return (
    typeof at === "string" &&
    at.length === 24 &&
    Number.isFinite(Date.parse(at)) &&
    new Date(at).toISOString() === at &&
    typeof id === "string" &&
    id.length > 0 &&
    id.length <= 1024
  );
}
function atMost(a: Position, b: Position) {
  return a[0] < b[0] || (a[0] === b[0] && a[1] <= b[1]);
}

/** Indexed owner keyset paging. No record bodies outside the page or totals. */
export function createSystemStreamPager(
  deps: Pick<LocalSyncDeps, "db" | "ownerAddress">,
  descriptor: SystemStreamDescriptor,
) {
  const { connectionId } = systemStreamIdentity(descriptor);
  const db = readerOf(deps.db);
  const owner = deps.ownerAddress.toLowerCase();
  return async (cutoff: string, options: SystemStreamPageOptions = {}) => {
    const limit = Math.min(options.limit ?? 50, 200);
    const offset = options.offset ?? 0;
    if (
      !Number.isSafeInteger(limit) ||
      limit < 1 ||
      !Number.isSafeInteger(offset) ||
      offset < 0 ||
      offset > 100000 ||
      (options.cursor && offset !== 0)
    )
      throw new ProtocolError(
        400,
        "INVALID_QUERY",
        "Invalid system stream page bounds",
      );
    let cursor: Cursor | undefined;
    if (options.cursor !== undefined) {
      try {
        if (
          options.cursor.length > 4096 ||
          !/^[A-Za-z0-9_-]+$/.test(options.cursor)
        )
          throw invalid();
        const value = JSON.parse(decodeBase64UrlUtf8(options.cursor)) as Cursor;
        if (
          value.version !== 1 ||
          value.owner !== owner ||
          value.connection !== connectionId ||
          value.stream !== descriptor.stream ||
          !position(value.upper) ||
          !position(value.after) ||
          !atMost(value.after, value.upper)
        )
          throw invalid();
        cursor = value;
      } catch {
        throw invalid();
      }
    }
    const [head] = cursor
      ? []
      : await db.query<{ sort_at: string; record_id: string }>(
          "SELECT sort_at,record_id FROM system_stream_projection WHERE connection_id=? AND stream=? AND sort_at>=? ORDER BY sort_at DESC,record_id DESC LIMIT 1",
          [connectionId, descriptor.stream, cutoff],
        );
    const upper =
      cursor?.upper ??
      (head ? ([head.sort_at, head.record_id] as Position) : null);
    if (!upper)
      return { bodies: [] as string[], limit, offset, nextCursor: null };
    const after = cursor?.after;
    const rows = await db.query<{
      body: string;
      sort_at: string;
      record_id: string;
    }>(
      `SELECT body,sort_at,record_id FROM system_stream_projection
       WHERE connection_id=? AND stream=? AND sort_at>=? AND (sort_at,record_id)<=(?,?)
       ${after ? "AND (sort_at,record_id)<(?,?)" : ""}
       ORDER BY sort_at DESC,record_id DESC LIMIT ? OFFSET ?`,
      [
        connectionId,
        descriptor.stream,
        cutoff,
        ...upper,
        ...(after ?? []),
        limit + 1,
        offset,
      ],
    );
    const more = rows.length > limit;
    const page = rows.slice(0, limit);
    const last = page[page.length - 1];
    const next: Cursor | null =
      more && last
        ? {
            version: 1,
            owner,
            connection: connectionId,
            stream: descriptor.stream,
            upper,
            after: [last.sort_at, last.record_id],
          }
        : null;
    return {
      bodies: page.map((row) => row.body),
      limit,
      offset,
      nextCursor: next ? encodeBase64UrlUtf8(JSON.stringify(next)) : null,
    };
  };
}
