import { readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";

/**
 * Host code that decides which streams a connection has, and the delete that
 * fences it, names no connector. The check
 * for `localdb` is `localdb/no-connector-knowledge.test.ts`; this table adds
 * the rest of the sync path.
 */
const CONNECTOR_IDS =
  /\b(?:oura|strava|claude|chatgpt|instagram|linkedin|spotify|github|gmail|icloud|goodreads|amazon|reddit|netflix)\b/gi;

const TABLE: readonly { name: string; files: () => URL[] }[] = [
  {
    name: "core/stream-sync",
    files: () => sources(new URL("./", import.meta.url)),
  },
  {
    name: "stream-sync package",
    files: () => sources(new URL("../../../stream-sync/src/", import.meta.url)),
  },
  {
    name: "lite sync host",
    files: () => [new URL("../../../lite/src/sync.ts", import.meta.url)],
  },
];

function sources(directory: URL): URL[] {
  return readdirSync(directory, { withFileTypes: true })
    .filter(
      (entry) =>
        entry.isFile() &&
        /\.[cm]?[jt]sx?$/.test(entry.name) &&
        !/\.(?:test|spec|test-helper|test-utils)\.[cm]?[jt]sx?$/.test(
          entry.name,
        ),
    )
    .map((entry) => new URL(entry.name, directory));
}

/** Code with its comments removed: a comment may cite a measurement. */
function code(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/.*$/gm, "$1");
}

describe("host sync code names no connector", () => {
  it.each(TABLE)("$name", ({ files }) => {
    const urls = files();
    expect(urls.length, "source files must be present").toBeGreaterThan(0);
    const violations: string[] = [];
    for (const url of urls)
      for (const match of code(readFileSync(url, "utf8")).matchAll(
        CONNECTOR_IDS,
      ))
        violations.push(`${url.pathname.split("/").pop()}: "${match[0]}"`);
    expect(violations).toEqual([]);
  });
});
