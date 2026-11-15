import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { expect, it } from "vitest";

// Apply must read the registry itself: its answers reflect reads taken after
// the call began. A caller that wraps the registry and hands apply a listing
// taken earlier breaks that, so no localdb source may define a stream listing
// in an object literal. The check reads the syntax tree, so a quoted,
// computed, shorthand or method form cannot slip past a text match, and a
// comment or call is not mistaken for an override.
function overridesStreamListing(source: string): boolean {
  const file = ts.createSourceFile(
    "source.ts",
    source,
    ts.ScriptTarget.Latest,
    true,
  );
  let found = false;
  const nameOf = (name: ts.PropertyName): string | undefined =>
    ts.isIdentifier(name) ||
    ts.isStringLiteralLike(name) ||
    ts.isNumericLiteral(name)
      ? name.text
      : ts.isComputedPropertyName(name) &&
          ts.isStringLiteralLike(name.expression)
        ? name.expression.text
        : undefined;
  const visit = (node: ts.Node): void => {
    if (
      (ts.isPropertyAssignment(node) ||
        ts.isMethodDeclaration(node) ||
        ts.isGetAccessorDeclaration(node)) &&
      ts.isObjectLiteralExpression(node.parent) &&
      nameOf(node.name) === "listStreamRows"
    )
      found = true;
    if (
      ts.isShorthandPropertyAssignment(node) &&
      node.name.text === "listStreamRows"
    )
      found = true;
    ts.forEachChild(node, visit);
  };
  visit(file);
  return found;
}

it("the check sees every way to define a stream listing and nothing else", () => {
  for (const source of [
    "const r = { ...reg, listStreamRows: () => rows };",
    'const r = { ...reg, "listStreamRows": () => rows };',
    'const r = { ...reg, ["listStreamRows"]: () => rows };',
    "const r = { ...reg, listStreamRows() { return rows; } };",
    "const listStreamRows = () => rows; const r = { ...reg, listStreamRows };",
  ])
    expect(overridesStreamListing(source), source).toBe(true);
  for (const source of [
    "await deps.registry.listStreamRows(connector);",
    "// { listStreamRows: () => rows }",
    "type T = LocalSyncDeps['registry']['listStreamRows'];",
    "interface P { listStreamRows(c: string): Promise<R[]> }",
  ])
    expect(overridesStreamListing(source), source).toBe(false);
});

it("no localdb source overrides the registry's stream listing", () => {
  const dir = dirname(fileURLToPath(import.meta.url));
  const offenders = readdirSync(dir)
    .filter((name) => name.endsWith(".ts") && !name.endsWith(".test.ts"))
    .filter((name) =>
      overridesStreamListing(readFileSync(join(dir, name), "utf8")),
    );
  expect(offenders).toEqual([]);
});
