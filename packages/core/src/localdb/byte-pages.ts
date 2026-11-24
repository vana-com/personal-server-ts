// Reads that hold row bodies are cut by the bytes the rows hold, never by a
// row count or an estimate from rows already read. A caller first reads the
// sizes of the next rows alone (small rows: a key and a number), then fetches
// the longest run of them that fits the budget. A row larger than the budget
// is a page of its own: a body is decoded whole.

/** What one page of bodies holds, at most, when two or more rows fit. */
export const PAGE_BYTES = 2 * 1024 * 1024;
/** Rows whose sizes are read at a time: a bound on a size query, not on a page. */
export const SIZE_ROWS = 2048;
/** What a row costs beyond its body: keys, stamps and the shape of a result. */
const ROW_OVERHEAD = 128;

/**
 * How many leading rows of `sizes` (the byte length of each row's body) fit
 * `budget`: at least one, so a row over the budget is a page of its own, and
 * none for no rows.
 */
export function rowsWithin(
  sizes: readonly number[],
  budget: number = PAGE_BYTES,
): number {
  let take = 0;
  let bytes = 0;
  while (take < sizes.length) {
    const next = sizes[take]! + ROW_OVERHEAD;
    if (take > 0 && bytes + next > budget) break;
    bytes += next;
    take += 1;
  }
  return take;
}
