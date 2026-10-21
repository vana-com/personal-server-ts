import { describe, expect, it } from "vitest";
import {
  hasPdppOrigin,
  inputHasPdppOrigin,
  isPdppProducer,
} from "./pdpp-import.js";

describe("hasPdppOrigin producer stamps", () => {
  it.each(["pdpp-projector", "pdpp-import-projection", "pdpp-derivative"])(
    "treats the %s stamp as PDPP origin",
    (producer) => {
      expect(isPdppProducer(producer)).toBe(true);
      expect(hasPdppOrigin({ data: { id: 1 }, producer })).toBe(true);
    },
  );

  it("treats an unstamped legacy envelope and an unknown stamp as legacy", () => {
    expect(hasPdppOrigin({ data: { id: 1 } })).toBe(false);
    expect(hasPdppOrigin({ data: { id: 1 }, producer: "pdpp-other" })).toBe(
      false,
    );
    expect(isPdppProducer("pdpp-other")).toBe(false);
    expect(hasPdppOrigin(undefined)).toBe(false);
  });
});

describe("hasPdppOrigin for derivatives", () => {
  const lineage = { sources: [], writtenAt: "2026-09-01T00:00:00Z" };
  it("treats a derivative with no stated origin as PDPP until it is recomputed", () => {
    expect(hasPdppOrigin({ data: { answer: "x", $lineage: lineage } })).toBe(
      true,
    );
    expect(hasPdppOrigin({ data: { $lineage: "garbage" } })).toBe(true);
  });
  it("treats a derivative stamped legacy by the server as legacy", () => {
    expect(
      hasPdppOrigin({
        data: { answer: "x", $lineage: { ...lineage, origin: "legacy" } },
      }),
    ).toBe(false);
  });
});

describe("a malformed legacy marker fails closed", () => {
  const ok = { sources: [], writtenAt: "2026-09-01T00:00:00Z" };
  it.each([
    ["no sources or writtenAt", { origin: "legacy" }],
    ["bad sources", { ...ok, sources: ["not-an-id"] }],
    ["no writtenAt", { sources: [], origin: "legacy" }],
    ["not an object", "legacy"],
  ])("%s counts as PDPP", (_name, lineage) => {
    const marked =
      typeof lineage === "object" ? { ...lineage, origin: "legacy" } : lineage;
    expect(hasPdppOrigin({ data: { $lineage: marked } })).toBe(true);
  });
});

describe("inputHasPdppOrigin", () => {
  it("is PDPP when the index row or the bytes say so", () => {
    const legacy = { data: { id: 1 } };
    expect(inputHasPdppOrigin({ pdppOrigin: true }, legacy)).toBe(true);
    expect(inputHasPdppOrigin({ pdppOrigin: false }, legacy)).toBe(false);
    expect(
      inputHasPdppOrigin(undefined, { data: {}, producer: "pdpp-derivative" }),
    ).toBe(true);
  });
});
