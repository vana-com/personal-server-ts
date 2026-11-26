import {
  decodeBase64UrlUtf8,
  encodeBase64UrlUtf8,
} from "../../encoding/base64url.js";
/**
 * Opaque cursor encoding shared by both store backends. Cursors are base64url
 * JSON; clients MUST NOT parse or construct them (spec §8), but both
 * implementations need a shared wire format to stay behaviorally identical.
 */

/**
 * Binding of a token to the query and to the replica integrity fences of the
 * connections it reads. A backend without replica fences omits both.
 */
interface IntegrityBinding {
  /** Digest of the connection set and field projection the token was minted for. */
  query?: string;
  /** Integrity epoch of each read connection when page 1 was served. */
  integrity?: Record<string, number>;
  /** Projection epoch seen when the token was minted by replication reads. */
  visibilityEpoch?: string;
}

export interface ListCursorPayload extends IntegrityBinding {
  kind: "list";
  /** Current-view revision. A changed view expires rather than mixes pages. */
  viewRevision?: string;
  view?: "owner" | "grant";
  instanceIds?: string[];
  /** Stream this token was minted for. Absent only on legacy cursors. */
  stream?: string;
  /** Store reset epoch this token was minted in. Absent only on legacy cursors. */
  epoch?: string;
  order: "asc" | "desc";
  sortValue: string | null; // cursor_field value of the last row on the page
  recordKey: string; // primary key tiebreaker
  instance?: string; // final tiebreaker; absent only on legacy cursors
  /**
   * Write clock when page 1 was served. A reset of a read instance after
   * this point expires the cursor (410), so one paginated read never mixes
   * rows from two generations. Absent on cursors minted before the fence.
   */
  horizon?: string;
  /**
   * The list order this position belongs to. `instant` orders emitted time by
   * `timeSortKey`; a cursor without it was minted under timestamp-text order
   * and cannot be resumed under instant order without skipping or repeating
   * rows.
   */
  orderKey?: "instant";
  /**
   * `listSortTag` of the order this position belongs to. `sortValue` is then
   * that order's sort key (`listPosition`). Absent: emitted order.
   */
  sort?: string;
}

export interface ChangesSinceCursorPayload extends IntegrityBinding {
  kind: "changes_since";
  /** Stream this token was minted for. Absent only on legacy cursors. */
  stream?: string;
  /** Store reset epoch this token was minted in. Absent only on legacy cursors. */
  epoch?: string;
  /** The session horizon every page of this session is anchored to. */
  horizon: string;
  /** The previous session's horizon, or null for a first-ever sync. */
  sinceHorizon: string | null;
  /** Pagination offset within the horizon-anchored result set. */
  offset: number;
  /**
   * Page cursors only: the identity order `offset` counts in. `code-point`
   * is `compareRecordIdentity`; a page cursor without it counted a
   * locale-dependent key order, so its offset names a different record.
   * Checkpoints carry no position and need none.
   */
  orderKey?: "code-point";
}

export type CursorPayload = ListCursorPayload | ChangesSinceCursorPayload;

export interface VisibilitySnapshot {
  readonly visibilityEpoch: string;
  readonly reader?: string;
}
export interface ValidCursor {
  readonly kind: "valid";
  readonly payload: CursorPayload;
}
export interface Expired {
  readonly kind: "expired";
}

/** Old enabled-mode tokens expire because their projection boundary is unknown. */
export function validateCursor(
  cursor: string,
  snapshot: VisibilitySnapshot,
): ValidCursor | Expired {
  const payload = decodeCursor(cursor);
  return payload.visibilityEpoch === snapshot.visibilityEpoch
    ? { kind: "valid", payload }
    : { kind: "expired" };
}

export function encodeCursor(payload: CursorPayload): string {
  return encodeBase64UrlUtf8(JSON.stringify(payload));
}

export function decodeCursor(cursor: string): CursorPayload {
  try {
    const json = decodeBase64UrlUtf8(cursor);
    const parsed = JSON.parse(json) as CursorPayload;
    if (parsed && (parsed.kind === "list" || parsed.kind === "changes_since")) {
      return parsed;
    }
    throw new Error("malformed cursor payload");
  } catch {
    throw new InvalidCursorSyntaxError();
  }
}

export class InvalidCursorSyntaxError extends Error {
  constructor() {
    super("Cursor token is malformed or unrecognized");
  }
}
