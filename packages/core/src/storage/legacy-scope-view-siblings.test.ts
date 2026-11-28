import { describe, expect, it } from "vitest";
import { allBoundScopes, siblingScopesOf } from "./legacy-scope-view.js";

// An unswitched account's per-scope delete of a canonical-owned scope also
// deletes these siblings durably. A sibling outside the scope's source would
// delete another source's data, so the tables must keep every connector
// method on one source prefix.
const prefix = (scope: string) => scope.split(".")[0];

describe("siblingScopesOf over every bound scope", () => {
  const bound = allBoundScopes();

  it("covers the bound tables", () => {
    expect(bound.length).toBeGreaterThan(10);
  });

  it.each(bound)("%s: siblings stay in its source", (scope) => {
    for (const sibling of siblingScopesOf(scope)) {
      expect(prefix(sibling)).toBe(prefix(scope));
    }
    expect(siblingScopesOf(scope)).not.toContain(scope);
  });

  it("names the other Oura scopes and nothing else for oura.activity", () => {
    expect(siblingScopesOf("oura.activity")).toEqual([
      "oura.readiness",
      "oura.sleep",
    ]);
  });

  it("has no siblings for an unbound scope", () => {
    expect(siblingScopesOf("notes.manual")).toEqual([]);
  });
});
