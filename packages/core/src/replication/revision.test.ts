import { describe, expect, it } from "vitest";
import { compareRevisions, nextLamportCounter } from "./revision.js";

describe("persisted replica revisions", () => {
  it("orders by logical revision, then writer and operation ids", () => {
    const a = { logical: 4, writerId: "a", operationId: "z" };
    expect(compareRevisions(a, { ...a, logical: 5 })).toBe(-1);
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
