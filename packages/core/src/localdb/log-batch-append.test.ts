import { describe, expect, it } from "vitest";
import {
  appendAll,
  operationStatements,
  tombstoneStatements,
  type PreparedOperation,
} from "./log-batch.js";

// A full refresh that omits many records sends one tombstone per omission, and
// a tombstone is two statements. A `push(...statements)` throws a RangeError
// once the list passes the engine's argument limit, which a large segment
// does, after the registry has accepted it.
const OMISSIONS = 200_000;

const refresh = (): PreparedOperation[] => [
  {
    kind: "complete",
    stream: "items",
    stampO: 5,
    stampR: "run",
    omitted: Array.from({ length: OMISSIONS }, (_, i) => ({
      pkHash: `pk-${i}`,
      recordKey: `key-${i}`,
    })),
  },
];

describe("appending a large batch of statements", () => {
  it("appendAll takes more items than a spread can pass", () => {
    const items = Array.from({ length: OMISSIONS * 2 }, (_, i) => i);
    // The limit the loop avoids.
    expect(() => [].push(...(items as never[]))).toThrow(RangeError);
    const target: number[] = [-1];
    appendAll(target, items);
    expect(target).toHaveLength(items.length + 1);
    expect(target.slice(0, 3)).toEqual([-1, 0, 1]);
    expect(target.at(-1)).toBe(items.at(-1));
  });

  it("an apply's statements carry the tombstone of every omission of a large refresh", () => {
    const statements = operationStatements("pdpp.fixture~", "op", refresh());
    const inserts = statements.filter((s) =>
      s.sql.includes("INSERT OR IGNORE INTO log_tombstones"),
    );
    expect(inserts).toHaveLength(OMISSIONS);
    // The tombstones come first, as the publish commit writes them.
    expect(statements.slice(0, OMISSIONS * 2)).toEqual(
      tombstoneStatements("pdpp.fixture~", refresh()),
    );
  });
});
