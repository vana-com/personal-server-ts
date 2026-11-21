import { describe, expect, it } from "vitest";
import { aliasViewCheck } from "../../../core/src/localdb/alias-view.js";
import type { SqlReader, SqlValue } from "../../../core/src/localdb/driver.js";
import type {
  Connection,
  Stream,
} from "../../../core/src/localdb/read-selection.js";
import {
  createRecordQuery,
  type SizedRecord,
} from "../../../core/src/localdb/query.js";

/**
 * SQLite before 3.32 rejects a statement that binds more than 999 parameters
 * (the driver contract targets 3.22). The statements a paged alias read adds
 * carry a view guard of 2 + 7 parameters per installed stream, so the number
 * of sized rows one statement takes must shrink as the guard grows.
 */
const LIMIT = 999;

/** A reader that records the parameters of every statement and returns no rows. */
function recording() {
  const counts: number[] = [];
  const reader: SqlReader = {
    async query<R extends Record<string, SqlValue>>(
      _sql: string,
      params?: readonly SqlValue[],
    ): Promise<R[]> {
      counts.push(params?.length ?? 0);
      return [];
    },
  };
  return { reader, counts };
}

const sized = (count: number): SizedRecord[] =>
  Array.from({ length: count }, (_, i) => ({
    pkHash: `h${i}`,
    sha256: `s${i}`,
    bytes: 10,
  }));

const guardOf = (streams: number) => ({
  sql: "1 = 1",
  params: Array.from({ length: 2 + 7 * streams }, (_, i) => i),
});

describe("recordsByHash stays inside SQLite's bound-parameter limit", () => {
  it("binds at most 999 parameters per statement under a 40-stream guard", async () => {
    const { reader, counts } = recording();
    await createRecordQuery(reader).recordsByHash(
      "c1",
      "messages",
      sized(300),
      guardOf(40),
    );
    expect(counts.length).toBeGreaterThan(1);
    expect(Math.max(...counts)).toBeLessThanOrEqual(LIMIT);
    // Every sized row went into some statement: 3 parameters each.
    const rows = counts.reduce(
      (sum, n) => sum + (n - 2 - guardOf(40).params.length) / 3,
      0,
    );
    expect(rows).toBe(300);
  });

  it("still takes 250 rows a statement under a small guard", async () => {
    const { reader, counts } = recording();
    await createRecordQuery(reader).recordsByHash(
      "c1",
      "messages",
      sized(300),
      guardOf(2),
    );
    expect(counts).toEqual([
      2 + 250 * 3 + guardOf(2).params.length,
      2 + 50 * 3 + guardOf(2).params.length,
    ]);
  });

  it("refuses, rather than send, a guard that alone exceeds the limit", async () => {
    const { reader, counts } = recording();
    await expect(
      createRecordQuery(reader).recordsByHash(
        "c1",
        "messages",
        sized(1),
        guardOf(143),
      ),
    ).rejects.toThrow(/999/);
    expect(counts).toEqual([]);
  });
});

describe("the alias view check stays inside the same limit", () => {
  const stream = (i: number) =>
    ({
      stream: `s${i}`,
      installed_version: 1,
      head_data_hash: "h",
    }) as unknown as Stream;
  const connection = { connection_id: "c1", generation: 1 } as Connection;
  const { reader } = recording();

  it("builds for 142 streams", () => {
    expect(() =>
      aliasViewCheck(
        reader,
        connection,
        Array.from({ length: 142 }, (_, i) => stream(i)),
        new Map(),
      ),
    ).not.toThrow();
  });

  it("refuses 143 streams with a clear error", () => {
    expect(() =>
      aliasViewCheck(
        reader,
        connection,
        Array.from({ length: 143 }, (_, i) => stream(i)),
        new Map(),
      ),
    ).toThrow(/999/);
  });
});
