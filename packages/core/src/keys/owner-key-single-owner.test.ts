/**
 * Guard: the owner-key module is the only non-test source that names the owner
 * key primitives, the SDK master-key constant, or the master-key message.
 *
 * What it catches: named uses. An identifier with a primitive's name (a call,
 * an import, a property access), an import or re-export of the SDK's
 * `MASTER_KEY_MESSAGE`, and a string literal that contains the master-key
 * message. Code is read as a TypeScript syntax tree, so comments and string
 * contents never hide or fake a use.
 *
 * What it does not catch: computed property names (`sdk["deriveMasterKey"]`),
 * a hand-rolled hash of the signature, or a copy of the message split across
 * strings. It is a tripwire for the common mistake, not a proof that the key is
 * derived once.
 *
 * Scope: every .ts/.tsx/.mts/.cts/.js/.jsx/.mjs/.cjs file under
 * `packages/*\/src` and `packages/*\/scripts`, except `*.test.*` and
 * `*.spec.*` files.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import * as ts from "typescript";
import { describe, expect, it } from "vitest";

const REPO_ROOT = fileURLToPath(new URL("../../../../", import.meta.url));
const SOURCE_EXT = /\.(ts|tsx|mts|cts|js|jsx|mjs|cjs)$/;
const TEST_FILE = /\.(test|spec)\.[cm]?[jt]sx?$/;
const SKIP_DIRS = new Set(["node_modules", "dist", ".turbo", ".git"]);
const MESSAGE = "vana-master-key-v1";

/** The primitives this guard keeps behind the owner module. */
const PRIMITIVES = [
  "deriveMasterKey",
  "streamMasterKeyFromSignature",
  "recoverServerOwner",
  "buildPersonalServerLiteOwnerBindingMessage",
  "buildPersonalServerLiteOwnerBindingSignature",
  "signPersonalServerLiteOwnerBinding",
] as const;

/** Files allowed to name specific primitives, with the reason. */
const ALLOWED: Record<string, { names: readonly string[]; reason: string }> = {
  "packages/core/src/keys/owner-master-key.ts": {
    names: [...PRIMITIVES, MESSAGE],
    reason: "the owner module itself",
  },
  "packages/stream-sync/src/master-key.ts": {
    names: ["streamMasterKeyFromSignature"],
    reason: "defines the stream-sync primitive in its own package",
  },
  "packages/stream-sync/src/vectors.ts": {
    names: ["streamMasterKeyFromSignature"],
    reason: "conformance vectors for the primitive in its own package",
  },
};

function walk(dir: string, out: string[]): void {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      walk(full, out);
    } else if (SOURCE_EXT.test(entry) && !TEST_FILE.test(entry)) {
      out.push(full);
    }
  }
}

function sourceFiles(): string[] {
  const packagesDir = join(REPO_ROOT, "packages");
  const files: string[] = [];
  for (const pkg of readdirSync(packagesDir)) {
    for (const sub of ["src", "scripts"]) {
      const dir = join(packagesDir, pkg, sub);
      if (statSync(dir, { throwIfNoEntry: false })?.isDirectory()) {
        walk(dir, files);
      }
    }
  }
  return files;
}

/**
 * The named uses of the owner-key surface in one source file, read from its
 * syntax tree. `relPath` picks the file's allowance and sets the parser's
 * script kind from its extension.
 */
function violationsIn(relPath: string, source: string): string[] {
  const allowed = ALLOWED[relPath]?.names ?? [];
  const file = ts.createSourceFile(
    relPath,
    source,
    ts.ScriptTarget.Latest,
    true,
  );
  const found = new Set<string>();

  const visit = (node: ts.Node): void => {
    if (ts.isIdentifier(node)) {
      const name = node.text;
      if (
        (PRIMITIVES as readonly string[]).includes(name) &&
        !allowed.includes(name)
      ) {
        found.add(name);
      }
    } else if (
      (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) &&
      node.text.includes(MESSAGE) &&
      !allowed.includes(MESSAGE)
    ) {
      found.add(`string containing "${MESSAGE}"`);
    }
    // The SDK's master-key constant, imported or re-exported from the SDK. A
    // re-export of the owner module's constant under the same name is allowed.
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier &&
      ts.isStringLiteral(node.moduleSpecifier) &&
      node.moduleSpecifier.text.startsWith("@opendatalabs/vana-sdk") &&
      namedBindings(node).some(
        (spec) => spec.name.text === "MASTER_KEY_MESSAGE",
      )
    ) {
      found.add("MASTER_KEY_MESSAGE (SDK)");
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return [...found];
}

/** The import or export specifiers a declaration names, if any. */
function namedBindings(
  node: ts.ImportDeclaration | ts.ExportDeclaration,
): readonly (ts.ImportSpecifier | ts.ExportSpecifier)[] {
  const bindings = ts.isImportDeclaration(node)
    ? node.importClause?.namedBindings
    : node.exportClause;
  if (
    !bindings ||
    !(ts.isNamedImports(bindings) || ts.isNamedExports(bindings))
  ) {
    return [];
  }
  return bindings.elements;
}

describe("owner key derivation has one owner", () => {
  it("no non-test source outside the owner module names the primitives or the master-key message", () => {
    const files = sourceFiles();
    // Vacuity check: the walk must actually see the monorepo.
    expect(files.length).toBeGreaterThan(200);
    expect(files).toContain(
      join(REPO_ROOT, "packages/core/src/keys/owner-master-key.ts"),
    );

    const violations: string[] = [];
    for (const file of files) {
      const relPath = relative(REPO_ROOT, file).split(sep).join("/");
      for (const name of violationsIn(relPath, readFileSync(file, "utf8"))) {
        violations.push(`${relPath}: ${name}`);
      }
    }

    expect(violations).toEqual([]);
    // This parses every source file in the monorepo. On a loaded CI runner it
    // exceeded the 5 s default and timed out; 60 s is a margin, not a measured
    // duration.
  }, 60_000);

  describe("the detector reads code, not text", () => {
    const other = "packages/server/src/example.ts";

    it("flags a call after a string that contains a block-comment opener", () => {
      const source = `const open = "/*";\nexport const k = deriveMasterKey(sig);\n`;
      expect(violationsIn(other, source)).toEqual(["deriveMasterKey"]);
    });

    it("ignores a primitive named only in a comment", () => {
      const source = `// deriveMasterKey is documented here\n/* recoverServerOwner */\nexport const x = 1;\n`;
      expect(violationsIn(other, source)).toEqual([]);
    });

    it("flags an aliased import of a primitive", () => {
      const source = `import { deriveMasterKey as d } from "x";\nd(sig);\n`;
      expect(violationsIn(other, source)).toEqual(["deriveMasterKey"]);
    });

    it("flags the master-key message in a string literal", () => {
      const source = `const m = "vana-master-key-v1";\n`;
      expect(violationsIn(other, source)).toEqual([
        `string containing "${MESSAGE}"`,
      ]);
    });

    it("flags an SDK re-export of MASTER_KEY_MESSAGE", () => {
      const source = `export { MASTER_KEY_MESSAGE } from "@opendatalabs/vana-sdk/browser";\n`;
      expect(violationsIn(other, source)).toEqual(["MASTER_KEY_MESSAGE (SDK)"]);
    });

    it("reads a .mts file", () => {
      const source = `export const k = recoverServerOwner(sig);\n`;
      expect(violationsIn("packages/server/src/example.mts", source)).toEqual([
        "recoverServerOwner",
      ]);
    });
  });
});
