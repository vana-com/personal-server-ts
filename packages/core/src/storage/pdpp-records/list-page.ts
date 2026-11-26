import {
  decodeCursor,
  encodeCursor,
  type ChangesSinceCursorPayload,
  type ListCursorPayload,
} from "./cursor.js";
import { InvalidCursorError, CursorExpiredError } from "./types.js";
import { parseTime, timeSortKey } from "../../pdpp/time.js";
import type {
  ListRecordsOptions,
  ListRecordsPage,
  ListSort,
  PdppStoredRecord,
} from "./types.js";

/**
 * A legacy position cannot prove complete snapshot continuation, and one
 * minted under another list order names a different place; restart explicitly.
 */
export function decodeListCursor(
  cursor: string,
): ListCursorPayload & { instance: string; horizon: string } {
  const payload = decodeCursor(cursor);
  if (payload.kind !== "list") throw new InvalidCursorError();
  if (
    payload.instance === undefined ||
    payload.horizon === undefined ||
    payload.orderKey !== "instant"
  )
    throw new CursorExpiredError();
  return { ...payload, instance: payload.instance, horizon: payload.horizon };
}

/** The identity of a list order, carried in its page cursor. */
export function listSortTag(sort: ListSort | undefined): string {
  return sort === undefined
    ? "emitted"
    : sort.by === "key"
      ? "key"
      : `field:${sort.field}`;
}

/** A list cursor minted under another order names a different position. */
export function assertListCursorSort(
  payload: ListCursorPayload,
  sort: ListSort | undefined,
): void {
  if ((payload.sort ?? "emitted") !== listSortTag(sort))
    throw new InvalidCursorError();
}

/**
 * The sort key of a `sort_field` value: the exact instant (date-time) or the
 * calendar date (date, as its UTC midnight) its RFC 3339 form denotes, or
 * null when the value is absent, null or not valid RFC 3339 (spec-core §8
 * "Stable sort").
 */
export function fieldSortKey(value: unknown): string | null {
  if (typeof value !== "string") return null;
  if (parseTime(value, "date-time")) return timeSortKey(value);
  if (parseTime(value, "date")) return timeSortKey(`${value}T00:00:00Z`);
  return null;
}

/** The position a list cursor names (see `listSnapshotPage`). */
export function cursorPosition(
  payload: ListCursorPayload & { instance: string },
  sort: ListSort | undefined,
): ListPosition {
  return {
    sortKey:
      sort === undefined
        ? timeSortKey(payload.sortValue ?? "")
        : payload.sortValue,
    instance: payload.instance,
    recordKey: payload.recordKey,
  };
}

/** A row's place in a list order. */
export interface ListPosition {
  /** Emitted order and field order; null sorts after every value. */
  readonly sortKey: string | null;
  readonly instance: string;
  readonly recordKey: string;
}

export function listPosition(
  row: Pick<PdppStoredRecord, "instance" | "recordKey" | "data" | "emittedAt">,
  sort: ListSort | undefined,
): ListPosition {
  return {
    sortKey:
      sort === undefined
        ? timeSortKey(row.emittedAt)
        : sort.by === "field"
          ? fieldSortKey(row.data[sort.field])
          : null,
    instance: row.instance,
    recordKey: row.recordKey,
  };
}

/**
 * Compare two positions in `order`. Emitted order keeps its tie-break on key
 * then instance (the SQLite index order). Key and field order use
 * `(instance_id, canonical key)` by code point, and field order puts an
 * absent, null or invalid value after every valid one in both directions
 * (spec-core §8 "Stable sort"; §9 RS item 33).
 */
export function compareListPositions(
  a: ListPosition,
  b: ListPosition,
  order: "asc" | "desc",
  sort: ListSort | undefined,
): number {
  const dir = order === "desc" ? -1 : 1;
  if (sort === undefined) {
    return (
      dir *
      (compareText(a.sortKey ?? "", b.sortKey ?? "") ||
        compareText(a.recordKey, b.recordKey) ||
        compareText(a.instance, b.instance))
    );
  }
  if (sort.by === "field") {
    const am = a.sortKey === null,
      bm = b.sortKey === null;
    if (am !== bm) return am ? 1 : -1;
    if (!am && a.sortKey !== b.sortKey)
      return dir * compareText(a.sortKey!, b.sortKey!);
  }
  return dir * compareRecordIdentity(a, b);
}

/**
 * A sync page cursor's offset counts records in `compareRecordIdentity`
 * order. One minted under the earlier locale-dependent order names a
 * different record, so it restarts explicitly; checkpoints are unaffected.
 */
export function decodeSyncPageCursor(
  cursor: string,
  order?: "asc" | "desc",
): ChangesSinceCursorPayload {
  const payload = decodeCursor(cursor);
  if (payload.kind !== "changes_since") throw new InvalidCursorError();
  if (payload.orderKey !== "code-point") throw new CursorExpiredError();
  // The offset counts in one direction; a page cursor never changes it.
  if ((payload.order ?? "asc") !== (order ?? "asc"))
    throw new InvalidCursorError();
  return payload;
}

/** Complete identity, in the existing public sort order with instance last. */
export const LIST_ORDER_COLUMNS = [
  "emitted_key",
  "record_key",
  "instance",
] as const;

// SQLite BINARY orders UTF-8 by code point, unlike localeCompare/UTF-16.
function compareText(a: string, b: string): number {
  if (a === b) return 0;
  // UTF-16 and UTF-8 ordering differ only for supplementary characters.
  // Keep the common ASCII/BMP comparison allocation-free.
  if (!/[\uD800-\uDBFF]/.test(a) && !/[\uD800-\uDBFF]/.test(b))
    return a < b ? -1 : 1;
  const left = Array.from(a, (c) => c.codePointAt(0)!);
  const right = Array.from(b, (c) => c.codePointAt(0)!);
  for (let i = 0; i < Math.min(left.length, right.length); i++) {
    if (left[i] !== right[i]) return left[i] < right[i] ? -1 : 1;
  }
  return Math.sign(left.length - right.length);
}

/**
 * Locale-independent complete record identity: `instance_id`, then canonical
 * key, by code point. spec-core §9 RS item 21: "Orders a `changes_since`
 * session by `instance_id` and then canonical key string".
 */
export function compareRecordIdentity(
  a: { recordKey: string; instance: string },
  b: { recordKey: string; instance: string },
): number {
  return (
    compareText(a.instance, b.instance) || compareText(a.recordKey, b.recordKey)
  );
}

/** Emitted list order: emitted instant, then key, then instance. SQLite's `emitted_key` is the same `timeSortKey`. */
export function compareListRows(
  a: PdppStoredRecord,
  b: PdppStoredRecord,
): number {
  return compareListPositions(
    listPosition(a, undefined),
    listPosition(b, undefined),
    "asc",
    undefined,
  );
}

/** Consume a sorted snapshot until one extra visible row proves continuation. */
export function listSnapshotPage(
  rows: Iterable<PdppStoredRecord>,
  options: ListRecordsOptions,
  snapshot: { stream: string; epoch: string; horizon: string },
  wasErased?: (row: PdppStoredRecord) => boolean,
): ListRecordsPage {
  const data: PdppStoredRecord[] = [];
  let hasMore = false;
  for (const row of rows) {
    if (options.isVisible && !options.isVisible(row)) continue;
    // Erasure overrides historical membership for that record only: a list
    // is not a sync session, so withholding it loses nothing a later read
    // could have relied on, and the rest of the snapshot stays readable.
    if (wasErased?.(row)) continue;
    if (data.length === options.limit) {
      hasMore = true;
      break;
    }
    data.push(row);
  }
  const last = data.at(-1);
  const payload: ListCursorPayload | undefined =
    last && hasMore
      ? {
          kind: "list",
          ...snapshot,
          order: options.order,
          // Emitted order keeps the raw emitted time; key and field order
          // carry the position's sort key. The cursor is sealed before it
          // leaves the RS (spec-core §4; RS item 21).
          sortValue:
            options.sort === undefined
              ? last.emittedAt
              : listPosition(last, options.sort).sortKey,
          recordKey: last.recordKey,
          instance: last.instance,
          orderKey: "instant",
          sort: listSortTag(options.sort),
        }
      : undefined;
  return {
    data: data.map((row) =>
      options.fields
        ? {
            ...row,
            data: Object.fromEntries(
              options.fields
                .filter((f) => Object.hasOwn(row.data, f))
                .map((f) => [f, row.data[f]]),
            ),
          }
        : row,
    ),
    hasMore,
    nextCursor: payload ? encodeCursor(payload) : undefined,
    horizon: snapshot.horizon,
  };
}
