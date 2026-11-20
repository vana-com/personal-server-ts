import { describe, expect, it } from "vitest";
import { compareSemver } from "./semver.js";

describe("compareSemver", () => {
  it("orders by major, minor and patch as numbers", () => {
    expect(compareSemver("1.10.0", "1.9.9")).toBe(1);
    expect(compareSemver("1.2.3", "1.2.3")).toBe(0);
    expect(compareSemver("0.9.0", "1.0.0")).toBe(-1);
  });

  it("puts a pre-release below its release, and orders pre-release fields", () => {
    expect(compareSemver("1.0.0-alpha", "1.0.0")).toBe(-1);
    const order = [
      "1.0.0-alpha",
      "1.0.0-alpha.1",
      "1.0.0-alpha.beta",
      "1.0.0-beta",
      "1.0.0-beta.2",
      "1.0.0-beta.11",
      "1.0.0-rc.1",
      "1.0.0",
    ];
    for (let i = 1; i < order.length; i += 1)
      expect(compareSemver(order[i - 1]!, order[i]!), order[i]).toBe(-1);
  });

  it("ignores build metadata", () => {
    expect(compareSemver("1.0.0+a", "1.0.0+b")).toBe(0);
  });

  it("cannot order a version that is not semver", () => {
    for (const bad of ["1", "1.0", "v1.0.0", "01.0.0", "1.0.0-", ""])
      expect(compareSemver(bad, "1.0.0"), bad).toBeNull();
    expect(compareSemver("1.0.0", "2024.1")).toBeNull();
  });
});
