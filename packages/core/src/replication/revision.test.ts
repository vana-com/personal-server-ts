import { describe, expect, it } from "vitest";
import { compareRevisions, nextHlc, receiveHlc } from "./revision.js";

describe("persisted replica HLC revisions", () => {
  it("uses logical, writer and operation only for deterministic ties", () => {
    const a = { wallMs: 10, logical: 4, writerId: "a", operationId: "z" };
    expect(compareRevisions(a, { ...a, logical: 5 })).toBe(-1);
    expect(compareRevisions(a, { ...a, writerId: "b", operationId: "a" })).toBe(
      -1,
    );
    expect(compareRevisions(a, { ...a, operationId: "a" })).toBe(1);
    expect(compareRevisions(a, a)).toBe(0);
  });
  it("advances past local and observed clocks and caps received future clocks", () => {
    const local = { wallMs: 8, logical: 2, writerId: "a", operationId: "a" };
    const remote = { wallMs: 12, logical: 4, writerId: "b", operationId: "b" };
    expect(nextHlc(local, [remote], 10)).toEqual({ wallMs: 12, logical: 5 });
    expect(receiveHlc({ ...remote, wallMs: 10_000 }, 10, 300_000)).toEqual({
      revision: { wallMs: 10_000, logical: 4 },
      clockAhead: false,
    });
    expect(receiveHlc({ ...remote, wallMs: 1_000_000 }, 10, 300_000)).toEqual({
      revision: { wallMs: 300_010, logical: 0 },
      clockAhead: true,
    });
  });
});
