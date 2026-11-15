import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { expect, it } from "vitest";

// Apply must read the registry itself: its answers reflect reads taken after
// the call began. A caller that wraps the registry and hands apply a listing
// taken earlier breaks that, so no localdb source may define a stream listing
// in an object literal, and no object literal may have a computed name that
// the check cannot resolve. The check reads the syntax tree, so a quoted,
// computed, shorthand or method form cannot slip past a text match, and a
// comment or call is not mistaken for an override.
const WELL_KNOWN_SYMBOLS: ReadonlySet<string> = new Set([
  "asyncIterator",
  "iterator",
  "hasInstance",
  "isConcatSpreadable",
  "match",
  "matchAll",
  "replace",
  "search",
  "species",
  "split",
  "toPrimitive",
  "toStringTag",
  "unscopables",
  "dispose",
  "asyncDispose",
]);
function overridesStreamListing(source: string): boolean {
  const file = ts.createSourceFile(
    "source.ts",
    source,
    ts.ScriptTarget.Latest,
    true,
  );
  let found = false;
  // The global Symbol's well-known symbols can never be "listStreamRows".
  // Any other computed name this check cannot resolve to a string literal
  // might be: it fails closed, so no spelling slips past unseen. A file that
  // declares its own `Symbol` gets no exemption.
  const shadowsSymbol = (() => {
    let shadowed = false;
    const scan = (node: ts.Node): void => {
      if (
        (ts.isVariableDeclaration(node) ||
          ts.isParameter(node) ||
          ts.isBindingElement(node) ||
          ts.isFunctionDeclaration(node) ||
          ts.isClassDeclaration(node) ||
          ts.isEnumDeclaration(node) ||
          ts.isImportSpecifier(node) ||
          ts.isImportClause(node) ||
          ts.isNamespaceImport(node)) &&
        node.name !== undefined &&
        ts.isIdentifier(node.name) &&
        node.name.text === "Symbol"
      )
        shadowed = true;
      ts.forEachChild(node, scan);
    };
    scan(file);
    return shadowed;
  })();
  const isWellKnownSymbol = (expression: ts.Expression): boolean =>
    !shadowsSymbol &&
    ts.isPropertyAccessExpression(expression) &&
    ts.isIdentifier(expression.expression) &&
    expression.expression.text === "Symbol" &&
    WELL_KNOWN_SYMBOLS.has(expression.name.text);
  const isListing = (name: ts.PropertyName): boolean =>
    ts.isComputedPropertyName(name)
      ? ts.isStringLiteralLike(name.expression)
        ? name.expression.text === "listStreamRows"
        : !isWellKnownSymbol(name.expression)
      : name.text === "listStreamRows";
  const visit = (node: ts.Node): void => {
    if (
      (ts.isPropertyAssignment(node) ||
        ts.isMethodDeclaration(node) ||
        ts.isGetAccessorDeclaration(node) ||
        ts.isSetAccessorDeclaration(node)) &&
      ts.isObjectLiteralExpression(node.parent) &&
      isListing(node.name)
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
    // Names the check cannot resolve fail closed.
    "const k = 'listStream' + 'Rows'; const r = { ...reg, [k]: () => rows };",
    "const r = { ...reg, [`listStream${'Rows'}`]: () => rows };",
    // Setters, plain and computed.
    "const r = { ...reg, set listStreamRows(v) {} };",
    "const r = { ...reg, set ['listStreamRows'](v) {} };",
    "const r = { ...reg, set [k](v) {} };",
    // Only the global Symbol's well-known symbols are exempt.
    "const Symbol = { custom: 'listStreamRows' }; const r = { [Symbol.asyncIterator]: () => rows };",
    "function f(Symbol) { return { [Symbol.iterator]: () => rows }; }",
    "import { Symbol } from 'x'; const r = { [Symbol.iterator]: () => rows };",
    "const r = { ...reg, [Symbol.custom]: () => rows };",
    "const r = { ...reg, [Symbol.for('listStreamRows')]: () => rows };",
  ])
    expect(overridesStreamListing(source), source).toBe(true);
  for (const source of [
    "await deps.registry.listStreamRows(connector);",
    "// { listStreamRows: () => rows }",
    "type T = LocalSyncDeps['registry']['listStreamRows'];",
    "interface P { listStreamRows(c: string): Promise<R[]> }",
    // A well-known symbol is never the listing.
    "const it = { async *[Symbol.asyncIterator]() { yield 1; } };",
    "const it = { [Symbol.iterator]() { return xs[Symbol.iterator](); }, get [Symbol.toStringTag]() { return 'x'; } };",
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
