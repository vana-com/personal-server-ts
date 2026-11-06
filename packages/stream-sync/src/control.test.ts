import { describe, expect, it } from "vitest";
import { classifyControl, sameControl } from "./control.js";
import { InvalidArgumentError } from "./errors.js";
import { controlHashes } from "./namespace.js";
import { keccak256 } from "./test-support/ports.js";

describe("classifyControl", async () => {
  const mine = await controlHashes(keccak256, "0123456789abcdef");
  const theirs = await controlHashes(keccak256, "fedcba9876543210");
  const row = (dataHash: string, deleted = false, version = 4) => ({
    found: true as const,
    version,
    dataHash,
    metadataHash: mine.activeMetadata,
    deleted,
  });

  it("tells own, foreign and deleted rows apart", () => {
    expect(classifyControl({ found: false }, mine)).toEqual({ kind: "absent" });
    expect(classifyControl(row(mine.activeData), mine)).toEqual({
      kind: "active",
      generation: 4,
    });
    expect(classifyControl(row(theirs.activeData), mine)).toEqual({
      kind: "foreign",
      version: 4,
    });
    expect(classifyControl(row(theirs.activeData, true), mine)).toEqual({
      kind: "deleted",
      version: 4,
    });
  });

  it("rejects a non-positive version", () => {
    expect(() => classifyControl(row(mine.activeData, false, 0), mine)).toThrow(
      InvalidArgumentError,
    );
  });

  it("compares states", () => {
    expect(
      sameControl(
        { kind: "active", generation: 1 },
        { kind: "active", generation: 1 },
      ),
    ).toBe(true);
    expect(
      sameControl(
        { kind: "deleted", version: 1 },
        { kind: "foreign", version: 1 },
      ),
    ).toBe(false);
  });
});
