import { describe, expect, it } from "vitest";
import { DEFAULTS, ServerConfigSchema } from "../schemas/server-config.js";

describe("query config block", () => {
  it("defaults match the implementation plan's phase 4a budgets", () => {
    const c = ServerConfigSchema.parse({});
    expect(c.query.cpuMs).toBe(30_000);
    expect(c.query.memoryMb).toBe(512);
    expect(c.query.wallClockMs).toBe(60_000);
    expect(c.query.maxOutputBytes).toBe(1_000_000);
  });

  it("is off by default — the graded set decides when it turns on", () => {
    expect(ServerConfigSchema.parse({}).query.enabled).toBe(false);
  });

  it("accepts an explicit query block", () => {
    const c = ServerConfigSchema.parse({
      query: { enabled: true, memoryMb: 1024 },
    });
    expect(c.query.enabled).toBe(true);
    expect(c.query.memoryMb).toBe(1024);
    // Unspecified keys still fall back to defaults.
    expect(c.query.cpuMs).toBe(DEFAULTS.query.cpuMs);
  });

  it("rejects budgets outside sane bounds rather than coercing them", () => {
    expect(() =>
      ServerConfigSchema.parse({ query: { memoryMb: 8 } }),
    ).toThrow();
    expect(() => ServerConfigSchema.parse({ query: { cpuMs: 10 } })).toThrow();
    expect(() =>
      ServerConfigSchema.parse({ query: { maxOutputBytes: 1 } }),
    ).toThrow();
  });

  it("leaves the rest of the config untouched", () => {
    const c = ServerConfigSchema.parse({});
    expect(c.inference.e2ee).toBe(true);
    expect(c.inference.baseUrl).toBe(DEFAULTS.inference.baseUrl);
  });
});
