import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

/**
 * Host code that decides which streams a connection has, and fences them on
 * delete, reads a manifest's `streams[]` and names no connector. The check for
 * `localdb` is `localdb/no-connector-knowledge.test.ts`; this one covers the
 * rest of the sync path.
 *
 * Policy. A connector id is a `connector_key` or `connector_id` of a pinned
 * declaration under `legacy-projection/declarations`. A production module
 * names a connector when one of its string literals, or a template literal
 * piece, equals an id (case-insensitive, after escapes are resolved). Comments
 * are not code and a URL that merely contains an id (`https://github.com/x`)
 * is not an id. Identifiers are not compared: the key `meta` is an ordinary
 * word, and a connector reaches host code as data, in a literal.
 */

const DECLARATIONS = new URL(
  "../legacy-projection/declarations/",
  import.meta.url,
);

/** Every `connector_key` and `connector_id` the pinned declarations name. */
function connectorIds(): ReadonlySet<string> {
  const ids = new Set<string>();
  for (const name of readdirSync(DECLARATIONS)) {
    if (!name.endsWith(".json")) continue;
    const declaration = JSON.parse(
      readFileSync(new URL(name, DECLARATIONS), "utf8"),
    ) as Record<string, unknown>;
    for (const field of ["connector_key", "connector_id"])
      if (typeof declaration[field] === "string")
        ids.add(declaration[field].toLowerCase());
  }
  return ids;
}

/** The connector ids a source file's string and template literals equal. */
export function connectorLiterals(
  source: string,
  ids: ReadonlySet<string>,
  fileName = "source.ts",
): string[] {
  const found: string[] = [];
  const file = ts.createSourceFile(
    fileName,
    source,
    ts.ScriptTarget.Latest,
    true,
  );
  const visit = (node: ts.Node) => {
    if (
      ts.isStringLiteral(node) ||
      ts.isNoSubstitutionTemplateLiteral(node) ||
      ts.isTemplateHead(node) ||
      ts.isTemplateMiddle(node) ||
      ts.isTemplateTail(node)
    )
      if (ids.has(node.text.toLowerCase())) found.push(node.text);
    ts.forEachChild(node, visit);
  };
  visit(file);
  return found;
}

const NOT_PRODUCTION =
  /(?:\.(?:test|spec|test-helper|test-utils)\.[cm]?[jt]sx?$)|(?:^|\/)(?:__fixtures__|test-support|bench)\//;

/** Production source files under `directory`, recursively. */
export function productionSources(directory: string): string[] {
  const out: string[] = [];
  const walk = (dir: string, relative: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      const rel = relative === "" ? entry.name : `${relative}/${entry.name}`;
      if (entry.isDirectory()) {
        if (!NOT_PRODUCTION.test(`${rel}/`)) walk(full, rel);
      } else if (
        /\.[cm]?[jt]sx?$/.test(entry.name) &&
        !NOT_PRODUCTION.test(rel)
      )
        out.push(full);
    }
  };
  walk(directory, "");
  return out.sort();
}

function violations(files: readonly string[], ids: ReadonlySet<string>) {
  return files.flatMap((file) =>
    connectorLiterals(readFileSync(file, "utf8"), ids, file).map(
      (literal) => `${file.split("/").slice(-3).join("/")}: "${literal}"`,
    ),
  );
}

const path = (relative: string) =>
  fileURLToPath(new URL(relative, import.meta.url));

/** `entry` and every file it reaches through relative imports and re-exports. */
export function relativeImportClosure(entry: string): string[] {
  const seen = new Set<string>();
  const visit = (file: string) => {
    if (seen.has(file)) return;
    seen.add(file);
    const source = ts.createSourceFile(
      file,
      readFileSync(file, "utf8"),
      ts.ScriptTarget.Latest,
      true,
    );
    for (const statement of source.statements) {
      if (
        (ts.isImportDeclaration(statement) ||
          ts.isExportDeclaration(statement)) &&
        statement.moduleSpecifier !== undefined &&
        ts.isStringLiteral(statement.moduleSpecifier) &&
        statement.moduleSpecifier.text.startsWith(".")
      )
        visit(
          join(dirname(file), statement.moduleSpecifier.text).replace(
            /\.js$/,
            ".ts",
          ),
        );
    }
  };
  visit(entry);
  return [...seen].sort();
}

const TABLE: readonly { name: string; files: () => string[] }[] = [
  {
    name: "core/stream-sync, recursively",
    files: () => productionSources(path("./")),
  },
  {
    name: "stream-sync package, recursively",
    files: () => productionSources(path("../../../stream-sync/src/")),
  },
  {
    name: "lite/src/sync.ts and every file it imports by relative path",
    files: () => relativeImportClosure(path("../../../lite/src/sync.ts")),
  },
];

describe("host sync code names no connector", () => {
  const ids = connectorIds();

  it("reads its ids from the pinned declarations", () => {
    expect(ids.size).toBeGreaterThan(10);
    expect(ids.has("oura")).toBe(true);
    expect(ids.has("https://registry.pdpp.dev/connectors/oura")).toBe(true);
  });

  it.each(TABLE)("$name", ({ files }) => {
    const list = files();
    expect(list.length, "source files must be present").toBeGreaterThan(0);
    expect(violations(list, ids)).toEqual([]);
  });

  describe("the scanner", () => {
    const scan = (source: string) => connectorLiterals(source, ids);

    it("flags an id after a string that holds a comment delimiter", () => {
      expect(scan(`const separator = "//"; const connector = "oura";`)).toEqual(
        ["oura"],
      );
    });
    it("flags an id written with an escape", () => {
      expect(scan(String.raw`const a = "o\u0075ra";`)).toEqual(["oura"]);
      expect(scan(String.raw`const a = 'o\x75ra';`)).toEqual(["oura"]);
    });
    it("flags an id in a template piece, not in a longer string", () => {
      expect(scan("const b = `oura`;")).toEqual(["oura"]);
      expect(scan("const c = `${x}oura`;")).toEqual(["oura"]);
      expect(scan("const d = `oura${x}`;")).toEqual(["oura"]);
      expect(scan("const e = `oura-${x}`;")).toEqual([]);
    });
    it("does not flag an ordinary URL that contains an id", () => {
      expect(scan(`const url = "https://github.com/org/repo";`)).toEqual([]);
    });
    it("does not flag a comment or an identifier", () => {
      expect(scan(`// oura\n/* github */\nconst meta = 1;`)).toEqual([]);
    });
    it("flags a registry connector id", () => {
      expect(scan(`f("https://registry.pdpp.dev/connectors/oura")`)).toEqual([
        "https://registry.pdpp.dev/connectors/oura",
      ]);
    });
  });

  describe("the directory walk", () => {
    it("flags a nested production module and skips tests and fixtures", () => {
      const root = mkdtempSync(join(tmpdir(), "no-connector-"));
      mkdirSync(join(root, "deep", "er"), { recursive: true });
      mkdirSync(join(root, "__fixtures__"));
      writeFileSync(join(root, "ok.ts"), `export const x = 1;\n`);
      writeFileSync(
        join(root, "deep", "er", "named.ts"),
        `export const id = "oura";\n`,
      );
      writeFileSync(
        join(root, "deep", "er", "named.test.ts"),
        `export const id = "oura";\n`,
      );
      writeFileSync(
        join(root, "__fixtures__", "f.ts"),
        `export const id = "oura";\n`,
      );
      const files = productionSources(root);
      expect(files.map((file) => file.slice(root.length))).toEqual([
        "/deep/er/named.ts",
        "/ok.ts",
      ]);
      expect(violations(files, ids)).toEqual(['deep/er/named.ts: "oura"']);
    });
  });
});
