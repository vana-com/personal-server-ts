import { describe, expect, it } from "vitest";
import { parseAccountAnswer, parseEvidenceBody } from "./evidence-wire.js";

const OWNER = "0x1111111111111111111111111111111111111111";

describe("parseAccountAnswer: the one reading of the Account's stream-sync answer", () => {
  it.each([
    // [what the host saw, the state it means]
    [{ rawStatus: 200, streamSync: true, generation: 3 }, "on", 3],
    [{ rawStatus: 200, streamSync: false, generation: 0 }, "off", 0],
    [{ rawStatus: 204, streamSync: true, generation: 1 }, "on", 1],
  ])("%j is %s", (seen, state, generation) => {
    expect(parseAccountAnswer(seen)).toEqual({ state, generation });
  });

  it.each([
    ["no response", { rawStatus: null }],
    ["a redirect", { rawStatus: 302, streamSync: true, generation: 1 }],
    ["a 401", { rawStatus: 401, streamSync: true, generation: 1 }],
    ["a 500", { rawStatus: 500, streamSync: false, generation: 1 }],
    ["no switch", { rawStatus: 200, generation: 1 }],
    ["a string switch", { rawStatus: 200, streamSync: "true", generation: 1 }],
    // Account's own failure answer carries no generation.
    ["no generation", { rawStatus: 200, streamSync: false }],
    [
      "a negative generation",
      { rawStatus: 200, streamSync: true, generation: -1 },
    ],
    [
      "a fractional generation",
      { rawStatus: 200, streamSync: true, generation: 1.5 },
    ],
    [
      "a generation past the safe integers",
      {
        rawStatus: 200,
        streamSync: true,
        generation: Number.MAX_SAFE_INTEGER + 1,
      },
    ],
    [
      "a string generation",
      { rawStatus: 200, streamSync: true, generation: "1" },
    ],
  ])("%s is unknown, never off", (_name, seen) => {
    expect(parseAccountAnswer(seen)).toEqual({ state: "unknown" });
  });
});

describe("parseEvidenceBody: a host sends either the state or what it saw", () => {
  it("takes a body that names the state, as every host sent it before", () => {
    expect(
      parseEvidenceBody({ owner: OWNER, state: "on", generation: 2 }),
    ).toEqual({ owner: OWNER, state: "on", generation: 2 });
  });

  it("reads the state from what the host saw when it names none", () => {
    expect(
      parseEvidenceBody({
        owner: OWNER,
        rawStatus: 200,
        streamSync: true,
        generation: 2,
      }),
    ).toEqual({ owner: OWNER, state: "on", generation: 2 });
    expect(parseEvidenceBody({ owner: OWNER, rawStatus: null })).toEqual({
      owner: OWNER,
      state: "unknown",
    });
    expect(
      parseEvidenceBody({ owner: OWNER, rawStatus: 200, streamSync: false }),
    ).toEqual({ owner: OWNER, state: "unknown" });
  });

  it("refuses a body that names neither the state nor what the host saw", () => {
    expect(parseEvidenceBody({ owner: OWNER })).toBeNull();
    expect(parseEvidenceBody({ owner: OWNER, state: "maybe" })).toBeNull();
    expect(parseEvidenceBody({ owner: OWNER, rawStatus: "200" })).toBeNull();
    expect(parseEvidenceBody({ rawStatus: 200 })).toBeNull();
  });

  it("a body that names a state and also what the host saw: the named state wins", () => {
    expect(
      parseEvidenceBody({
        owner: OWNER,
        state: "off",
        generation: 1,
        rawStatus: 200,
        streamSync: true,
      }),
    ).toEqual({ owner: OWNER, state: "off", generation: 1 });
  });
});
