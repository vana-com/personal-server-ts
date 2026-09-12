import { builtinModules } from "node:module";

import ts from "typescript";

const nodeBuiltins = new Set(
  builtinModules.flatMap((name) => [name, `node:${name}`]),
);

export function findUndeclaredRuntimeImports(
  bundle: string,
  runtimeDependencies: ReadonlySet<string>,
): string[] {
  const sourceFile = ts.createSourceFile(
    "enclave-main.mjs",
    bundle,
    ts.ScriptTarget.Latest,
    false,
    ts.ScriptKind.JS,
  );
  const undeclared = new Set<string>();

  for (const statement of sourceFile.statements) {
    if (
      !ts.isImportDeclaration(statement) ||
      !ts.isStringLiteral(statement.moduleSpecifier)
    ) {
      continue;
    }

    const specifier = statement.moduleSpecifier.text;
    if (
      specifier.startsWith(".") ||
      specifier.startsWith("/") ||
      specifier.startsWith("#") ||
      nodeBuiltins.has(specifier)
    ) {
      continue;
    }

    const packageName = getPackageName(specifier);
    if (!runtimeDependencies.has(packageName)) {
      undeclared.add(packageName);
    }
  }

  return [...undeclared].sort();
}

function getPackageName(specifier: string): string {
  const segments = specifier.split("/");
  return specifier.startsWith("@")
    ? segments.slice(0, 2).join("/")
    : segments[0];
}
