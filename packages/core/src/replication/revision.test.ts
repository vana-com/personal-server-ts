import { describe, expect, it } from "vitest";
import { compareRevisions, nextLamportCounter } from "./revision.js";

describe("persisted replica revisions", () => {
  it("orders by counter, then code-unit writer and operation ids", () => {
    const a = { counter: 4, writerId: "a", operationId: "z" };
    expect(compareRevisions(a, { ...a, counter: 5 })).toBe(-1);
    expect(compareRevisions(a, { ...a, writerId: "b", operationId: "a" })).toBe(
      -1,
    );
    expect(compareRevisions(a, { ...a, operationId: "a" })).toBe(1);
    expect(compareRevisions(a, a)).toBe(0);
    expect(nextLamportCounter(3, [8, 2])).toBe(9);
    expect(() => nextLamportCounter(Number.MAX_SAFE_INTEGER, [])).toThrow();
    expect(() => nextLamportCounter(-1, [])).toThrow();
  });
});
