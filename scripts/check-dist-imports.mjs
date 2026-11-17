// Check every emitted JS file in published packages against its own manifest.
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { builtinModules } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const builtins = new Set(
  builtinModules.flatMap((name) => [name, `node:${name}`]),
);
const violations = [];
// Repository-relative paths and reasons for computed imports that cannot be made static.
const computedImportAllowlist = new Map();
const computedImports = [];

for (const dir of fs.readdirSync(path.join(root, "packages"))) {
  const pkgDir = path.join(root, "packages", dir);
  const manifestPath = path.join(pkgDir, "package.json");
  if (!fs.existsSync(manifestPath)) continue;
  const pkg = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  if (pkg.private) continue;
  const dist = path.join(pkgDir, "dist");
  if (!fs.existsSync(dist)) {
    violations.push(`${path.relative(root, dist)} is missing`);
    continue;
  }
  const allowed = new Set([
    pkg.name,
    ...Object.keys(pkg.dependencies ?? {}),
    ...Object.keys(pkg.optionalDependencies ?? {}),
    ...Object.keys(pkg.peerDependencies ?? {}),
  ]);
  const packed = JSON.parse(
    execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
      cwd: pkgDir,
      encoding: "utf8",
    }),
  );
  const [{ files }] = Array.isArray(packed) ? packed : Object.values(packed);
  const packedFiles = new Set(files.map(({ path: packedPath }) => packedPath));
  for (const { path: packedPath } of files) {
    if (!/\.(?:c?js|mjs)$/.test(packedPath)) continue;
    const file = path.join(pkgDir, packedPath);
    const source = ts.createSourceFile(
      file,
      fs.readFileSync(file, "utf8"),
      ts.ScriptTarget.Latest,
      true,
      ts.ScriptKind.JS,
    );
    const pending = [source];
    while (pending.length) {
      const node = pending.pop();
      let specifier;
      if (
        (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
        node.moduleSpecifier &&
        ts.isStringLiteral(node.moduleSpecifier)
      ) {
        specifier = node.moduleSpecifier.text;
      } else if (ts.isCallExpression(node)) {
        const isDynamicImport =
          node.expression.kind === ts.SyntaxKind.ImportKeyword;
        const isRequire =
          ts.isIdentifier(node.expression) &&
          node.expression.text === "require";
        const arg = node.arguments[0];
        if (
          (isDynamicImport || (isRequire && node.arguments.length === 1)) &&
          arg &&
          (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg))
        ) {
          specifier = arg.text;
        } else if (isDynamicImport) {
          const location = `${path.relative(root, file)}:${source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1}`;
          const reason = computedImportAllowlist.get(path.relative(root, file));
          computedImports.push(
            `${location}${reason ? ` (allowed: ${reason})` : " (unanalysable)"}`,
          );
          if (!reason)
            violations.push(`${location} has an unanalysable dynamic import`);
        }
      }
      if (specifier?.startsWith(".")) {
        const target = path.posix.normalize(
          path.posix.join(path.posix.dirname(packedPath), specifier),
        );
        if (!packedFiles.has(target))
          violations.push(
            `${path.relative(root, file)} imports unpacked relative target ${specifier}`,
          );
      }
      if (specifier && !specifier.startsWith(".") && !builtins.has(specifier)) {
        const name = specifier.startsWith("@")
          ? specifier.split("/").slice(0, 2).join("/")
          : specifier.split("/")[0];
        if (!allowed.has(name))
          violations.push(`${path.relative(root, file)} imports ${specifier}`);
      }
      ts.forEachChild(node, (child) => {
        pending.push(child);
      });
    }
  }
}
console.log(
  `Computed dynamic imports: ${computedImports.length ? `\n${computedImports.join("\n")}` : "none"}`,
);
if (violations.length) {
  console.error(violations.join("\n"));
  process.exit(1);
}
console.log("ok: published dist imports are declared runtime dependencies");
