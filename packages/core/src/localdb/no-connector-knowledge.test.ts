import { readFileSync, readdirSync } from "node:fs";
import { expect, it } from "vitest";

it("database path names no connector", () => {
  const directory = new URL("./", import.meta.url);
  const sourceFiles = readdirSync(directory, { withFileTypes: true })
    .filter(
      (entry) =>
        entry.isFile() &&
        /\.[cm]?[jt]sx?$/.test(entry.name) &&
        !/\.(?:test|spec)\.[cm]?[jt]sx?$/.test(entry.name),
    )
    .map((entry) => entry.name)
    .sort();

  expect(sourceFiles.length, "localdb source files must be present").toBeGreaterThan(
    0,
  );

  const forbiddenModules = [
    "legacy-projection",
    "record-rules",
    "oura-collection-requirements",
    "method-transition",
    "legacy-scope-view",
    "pdpp-records-sqlite-store",
  ];
  const violations: string[] = [];

  for (const filename of sourceFiles) {
    const source = readFileSync(new URL(filename, directory), "utf8");

    // Include static imports, re-exports, and literal dynamic imports/requires.
    const specifiers = source.matchAll(
      /\b(?:from|import|require)\s*(?:\(\s*)?(["'`])([^"'`]+)\1/g,
    );
    for (const match of specifiers) {
      const specifier = match[2]!;
      if (forbiddenModules.some((module) => specifier.includes(module))) {
        violations.push(`${filename}: forbidden module "${specifier}"`);
      }
    }

    for (const match of source.matchAll(
      /\b(?:oura|strava|claude|chatgpt|instagram|linkedin|spotify|github|gmail|icloud)\b/gi,
    )) {
      violations.push(`${filename}: connector id "${match[0]}"`);
    }
  }

  expect(violations, "database path names no connector").toEqual([]);
});
