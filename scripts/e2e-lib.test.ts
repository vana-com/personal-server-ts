import { describe, expect, it } from "vitest";
import { isNonTerminalJobResponse } from "./e2e-lib.js";

describe("e2e job response helpers", () => {
  it.each(["queued", "claimed", "running"])(
    "polls a direct %s submission response",
    (state) => {
      expect(isNonTerminalJobResponse({ state, created: true })).toBe(true);
    },
  );

  it("polls the nested job response shape", () => {
    expect(isNonTerminalJobResponse({ job: { state: "claimed" } })).toBe(true);
  });

  it.each(["completed", "failed", "expired", "cancelled"])(
    "does not poll a terminal %s response",
    (state) => {
      expect(isNonTerminalJobResponse({ state })).toBe(false);
    },
  );
});
