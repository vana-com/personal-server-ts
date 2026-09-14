/**
 * Pins the two credential lifetimes. Every other test spends the constants, so
 * only this one would notice a policy change: 1 h bearer, 7 d refresh grant.
 */

import { describe, it, expect } from "vitest";
import { MCP_REFRESH_TTL_MS, MCP_TOKEN_TTL_MS } from "./token-expiry.js";

const ONE_HOUR_MS = 3_600_000;
const SEVEN_DAYS_MS = 604_800_000;

describe("MCP credential lifetimes", () => {
  it("keeps the bearer at one hour and the refresh grant at seven days", () => {
    expect(MCP_TOKEN_TTL_MS).toBe(ONE_HOUR_MS);
    expect(MCP_REFRESH_TTL_MS).toBe(SEVEN_DAYS_MS);
  });
});
