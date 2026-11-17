import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  decideRunSaved,
  type RunSavedInput,
  type RunSavedVerdict,
} from "./run-saved.js";

const fixture = JSON.parse(
  readFileSync(
    new URL("../../contracts/run-saved.json", import.meta.url),
    "utf8",
  ),
) as {
  cases: { id: string; input: RunSavedInput; expect: RunSavedVerdict }[];
};

describe("run-saved.json", () => {
  it("has unique case ids", () => {
    const ids = fixture.cases.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it.each(fixture.cases)("$id", (c) => {
    expect(decideRunSaved(c.input)).toEqual(c.expect);
  });
});
