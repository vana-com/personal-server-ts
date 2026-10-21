import {
  decodeCursor,
  encodeCursor,
  type ListCursorPayload,
} from "./cursor.js";
import {
  InvalidCursorError,
  CursorExpiredError,
  RecordIdentityConflictError,
} from "./types.js";
import { timeSortKey } from "../../pdpp/time.js";
import type {
  ListRecordsOptions,
  ListRecordsPage,
  PdppRecordRow,
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

/** Locale-independent complete record identity, shared by list and sync. */
export function compareRecordIdentity(
  a: { recordKey: string; instance: string },
  b: { recordKey: string; instance: string },
): number {
  return (
    compareText(a.recordKey, b.recordKey) || compareText(a.instance, b.instance)
  );
}

/** List order: emitted instant, then complete identity. SQLite's `emitted_key` is the same `timeSortKey`. */
export function compareListRows(
  a: PdppStoredRecord,
  b: PdppStoredRecord,
): number {
  return (
    compareText(timeSortKey(a.emittedAt), timeSortKey(b.emittedAt)) ||
    compareRecordIdentity(a, b)
  );
}

/** Consume a sorted snapshot until one extra visible row proves continuation. */
export function listSnapshotPage(
  rows: Iterable<PdppStoredRecord>,
  options: ListRecordsOptions,
  snapshot: { stream: string; epoch: string; horizon: string },
  wasErased?: (row: PdppStoredRecord) => boolean,
  versionAt?: (
    instance: string,
    recordKey: string,
  ) => PdppRecordRow | undefined,
): ListRecordsPage {
  const data: PdppStoredRecord[] = [];
  let hasMore = false;
  const visible = (row: PdppRecordRow | undefined): boolean =>
    row !== undefined &&
    !row.deleted &&
    (!options.isVisible || options.isVisible(row));
  for (const row of rows) {
    if (!visible(row)) continue;
    // Erasure overrides historical membership for that record only: a list
    // is not a sync session, so withholding it loses nothing a later read
    // could have relied on, and the rest of the snapshot stays readable.
    if (wasErased?.(row)) continue;
    if (data.length === options.limit) {
      hasMore = true;
      break;
    }
    // The wire names a record by key alone: never send two records as one.
    if (options.oneRecordPerKey && versionAt) {
      for (const instance of options.instanceIds) {
        if (
          instance !== row.instance &&
          visible(versionAt(instance, row.recordKey))
        ) {
          throw new RecordIdentityConflictError(row.recordKey);
        }
      }
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
          sortValue: last.emittedAt,
          recordKey: last.recordKey,
          instance: last.instance,
          orderKey: "instant",
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
