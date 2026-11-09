/**
 * The shipped entry's static import closure, walked from its source. The entry
 * installs the network guard before any package module loads, which only holds
 * if nothing reached from the entry through a static import is a package module
 * or the SQLite store. Dynamic `import()` is not followed: run.ts runs it inside
 * a function, after the guard installs. A dynamic `import()` outside any
 * function body runs at load, so this file refuses it in every file it reaches.
 * `import x = require()` is not parsed here; tsc rejects it (TS1471), which the
 * lint gate runs. `run-entry-order.test.ts` covers a module that captures
 * `fetch` at load; this file covers which modules can load at all.
 */

import { readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const scripts = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ENTRY = join(scripts, "legacy-retire-dry-run.ts");

/** The local files the entry may reach statically, relative to `scripts/`. */
const ALLOWED_LOCAL = [
  "legacy-retire-dry-run.ts",
  "retire-dry-run/copy-only.ts",
  "retire-dry-run/fingerprint.ts",
  "retire-dry-run/hosts.ts",
  "retire-dry-run/network-guard.ts",
  "retire-dry-run/report.ts",
  "retire-dry-run/run.ts",
  "retire-dry-run/setup-error.ts",
];

/**
 * The module specifiers of the statements that load at run time: value imports,
 * side-effect imports and value re-exports. `import type`, a clause of only
 * inline types, and `export type` are erased, so they are skipped.
 */
function staticSpecifiers(file: string): string[] {
  const source = ts.createSourceFile(
    file,
    readFileSync(file, "utf8"),
    ts.ScriptTarget.Latest,
    true,
  );
  const out: string[] = [];
  for (const statement of source.statements) {
    if (ts.isImportDeclaration(statement)) {
      const clause = statement.importClause;
      if (clause?.isTypeOnly) continue;
      const bindings = clause?.namedBindings;
      if (
        clause &&
        !clause.name &&
        bindings &&
        ts.isNamedImports(bindings) &&
        bindings.elements.length > 0 &&
        bindings.elements.every((e) => e.isTypeOnly)
      ) {
        continue;
      }
      out.push((statement.moduleSpecifier as ts.StringLiteral).text);
    } else if (ts.isExportDeclaration(statement) && statement.moduleSpecifier) {
      if (statement.isTypeOnly) continue;
      const bindings = statement.exportClause;
      if (
        bindings &&
        ts.isNamedExports(bindings) &&
        bindings.elements.length > 0 &&
        bindings.elements.every((e) => e.isTypeOnly)
      ) {
        continue;
      }
      out.push((statement.moduleSpecifier as ts.StringLiteral).text);
    }
  }
  return out;
}

/**
 * Dynamic `import()` calls that are not inside any function body. Those run
 * when the module is evaluated, before any code the entry calls.
 */
function moduleScopeDynamicImports(file: string): number {
  const source = ts.createSourceFile(
    file,
    readFileSync(file, "utf8"),
    ts.ScriptTarget.Latest,
    true,
  );
  let count = 0;
  const visit = (node: ts.Node, inFunction: boolean): void => {
    if (
      !inFunction &&
      ts.isCallExpression(node) &&
      node.expression.kind === ts.SyntaxKind.ImportKeyword
    ) {
      count += 1;
    }
    const nested = inFunction || ts.isFunctionLike(node);
    ts.forEachChild(node, (child) => {
      visit(child, nested);
    });
  };
  visit(source, false);
  return count;
}

describe("the shipped entry's static imports", () => {
  it("statically imports only Node built-ins and the allowlisted local files, and no module-scope dynamic import", () => {
    const reached = new Set<string>();
    const bare = new Set<string>();
    const unlisted = new Set<string>();
    const loadTimeImports = new Set<string>();
    const pending = [ENTRY];
    while (pending.length > 0) {
      const file = pending.pop()!;
      if (reached.has(file)) continue;
      reached.add(file);
      if (moduleScopeDynamicImports(file) > 0) {
        loadTimeImports.add(relative(scripts, file));
      }
      for (const spec of staticSpecifiers(file)) {
        if (spec.startsWith("node:")) continue;
        if (!spec.startsWith(".")) {
          bare.add(spec);
          continue;
        }
        const target = resolve(dirname(file), spec).replace(/\.js$/, ".ts");
        const name = relative(scripts, target);
        if (ALLOWED_LOCAL.includes(name)) pending.push(target);
        else unlisted.add(name);
      }
    }
    expect([...bare]).toEqual([]);
    expect([...unlisted]).toEqual([]);
    expect([...loadTimeImports]).toEqual([]);
    // The allowlist names exactly what the walk reaches.
    expect([...reached].map((f) => relative(scripts, f)).sort()).toEqual(
      [...ALLOWED_LOCAL].sort(),
    );
  });
});
