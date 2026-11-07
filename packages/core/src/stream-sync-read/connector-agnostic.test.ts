import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  alternateLegacyBindingsForScope,
  LEGACY_SCOPE_BINDINGS,
} from "../legacy-projection/index.js";

/** Every connector key, source key and profile key the bindings name. */
function knownNames(): Set<string> {
  const names = new Set<string>();
  for (const [scope, binding] of LEGACY_SCOPE_BINDINGS) {
    names.add(scope.slice(0, scope.indexOf(".")));
    names.add(
      binding.pdppSource.slice(binding.pdppSource.lastIndexOf("/") + 1),
    );
    for (const [profileKey, alternate] of alternateLegacyBindingsForScope(
      scope,
    )) {
      names.add(profileKey);
      names.add(
        alternate.pdppSource.slice(alternate.pdppSource.lastIndexOf("/") + 1),
      );
    }
  }
  return names;
}

describe("stream-sync read path", () => {
  // Which connector a requested name reads comes from binding data and,
  // for source aliases, from signed connector data: never from a list of
  // connector ids in this module.
  it("names no connector, source or profile key in its code", () => {
    const dir = import.meta.dirname;
    const names = knownNames();
    expect(names.size).toBeGreaterThan(10);
    const found: string[] = [];
    for (const file of readdirSync(dir)) {
      if (!file.endsWith(".ts") || file.endsWith(".test.ts")) continue;
      if (file === "testing.ts") continue;
      const text = readFileSync(join(dir, file), "utf8");
      for (const literal of text.matchAll(/(["'`])([a-z0-9_-]+)\1/g)) {
        if (names.has(literal[2]!)) found.push(`${file}: ${literal[0]}`);
      }
    }
    expect(found).toEqual([]);
  });
});
