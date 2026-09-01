import { describe, expect, it } from "vitest";
import { createRng, deriveSeed } from "./prng.js";

describe("createRng", () => {
  it("is reproducible for a seed", () => {
    const a = createRng(1234);
    const b = createRng(1234);
    const draw = (r: ReturnType<typeof createRng>) =>
      Array.from({ length: 50 }, () => r.next());
    expect(draw(a)).toEqual(draw(b));
  });

  it("diverges for different seeds", () => {
    const a = Array.from({ length: 20 }, createRng(1).next);
    const b = Array.from({ length: 20 }, createRng(2).next);
    expect(a).not.toEqual(b);
  });

  it("stays inside [0, 1)", () => {
    const rng = createRng(7);
    for (let i = 0; i < 5000; i++) {
      const x = rng.next();
      expect(x).toBeGreaterThanOrEqual(0);
      expect(x).toBeLessThan(1);
    }
  });

  it("int(n) stays inside [0, n)", () => {
    const rng = createRng(9);
    for (let i = 0; i < 5000; i++) {
      const x = rng.int(13);
      expect(x).toBeGreaterThanOrEqual(0);
      expect(x).toBeLessThan(13);
      expect(Number.isInteger(x)).toBe(true);
    }
  });

  it("between(min, max) is inclusive at both ends", () => {
    const rng = createRng(11);
    const seen = new Set<number>();
    for (let i = 0; i < 3000; i++) seen.add(rng.between(2, 5));
    expect([...seen].sort()).toEqual([2, 3, 4, 5]);
  });

  it("chance(p) approximates p", () => {
    const rng = createRng(42);
    let hits = 0;
    const n = 20000;
    for (let i = 0; i < n; i++) if (rng.chance(0.25)) hits++;
    expect(hits / n).toBeGreaterThan(0.23);
    expect(hits / n).toBeLessThan(0.27);
  });
});

describe("deriveSeed", () => {
  it("gives each stream an independent seed", () => {
    const root = 20260828;
    const a = deriveSeed(root, "oura.sleep");
    const b = deriveSeed(root, "spotify");
    expect(a).not.toEqual(b);
  });

  it("is stable across calls", () => {
    expect(deriveSeed(5, "chatgpt")).toEqual(deriveSeed(5, "chatgpt"));
  });

  it("changes with the root seed", () => {
    expect(deriveSeed(1, "slack")).not.toEqual(deriveSeed(2, "slack"));
  });
});
