import { describe, it, expect } from "vitest";
import { PDPP_VERSION, negotiatePdppVersion } from "./pdpp-version.js";

describe("PDPP-Version negotiation (spec-core §8 API versioning)", () => {
  it("assigns the locked v0.1.0 contract identifier 0.1", () => {
    expect(PDPP_VERSION).toBe("0.1");
  });

  it("selects 0.1 when the field is absent", () => {
    expect(negotiatePdppVersion(undefined)).toEqual({
      ok: true,
      selected: "0.1",
    });
    expect(negotiatePdppVersion(null)).toEqual({ ok: true, selected: "0.1" });
  });

  it("selects 0.1 when sent exactly, ignoring surrounding whitespace", () => {
    expect(negotiatePdppVersion("0.1")).toEqual({ ok: true, selected: "0.1" });
    expect(negotiatePdppVersion(" 0.1 ")).toEqual({
      ok: true,
      selected: "0.1",
    });
    expect(negotiatePdppVersion("\t0.1\t")).toEqual({
      ok: true,
      selected: "0.1",
    });
  });

  it.each(["0.1.0", "v0.1", "2026-04-06", "0.2"])(
    "refuses the non-alias %s as unsupported_version",
    (value) => {
      const result = negotiatePdppVersion(value);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code).toBe("unsupported_version");
    },
  );

  it.each([
    "",
    '"0.1"',
    "0.1, 0.1",
    "0.1,2026-04-06",
    "0 .1",
    "\u00a00.1\u00a0",
  ])("treats %j as an invalid field (invalid_request)", (value) => {
    const result = negotiatePdppVersion(value);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("invalid_request");
  });
});
