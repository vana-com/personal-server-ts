// Fails when a built runtime file (packages/*/dist) imports a package that the
// repo lists only as a devDependency. Test-only modules belong in a separate
// output (see packages/core/tsconfig.test-support.json) or in the tsconfig
// `exclude` list, so consumers never receive them.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const rootPkg = readJson(path.join(root, "package.json"));
const devOnly = (pkg) => {
  const runtime = new Set([
    ...Object.keys(pkg.dependencies ?? {}),
    ...Object.keys(pkg.peerDependencies ?? {}).filter(
      (name) => !pkg.peerDependenciesMeta?.[name]?.optional,
    ),
  ]);
  return new Set(
    Object.keys({ ...rootPkg.devDependencies, ...pkg.devDependencies }).filter(
      (name) => !runtime.has(name),
    ),
  );
};
const packageName = (spec) =>
  spec.startsWith("@")
    ? spec.split("/").slice(0, 2).join("/")
    : spec.split("/")[0];
const importRe =
  /^\s*(?:import|export)\s[^'"]*?from\s+['"]([^'"]+)['"]|^\s*import\s+['"]([^'"]+)['"]|\bimport\(\s*['"]([^'"]+)['"]\s*\)/gm;

const violations = [];
for (const dir of fs.readdirSync(path.join(root, "packages"))) {
  const pkgDir = path.join(root, "packages", dir);
  const dist = path.join(pkgDir, "dist");
  if (!fs.existsSync(dist)) continue;
  const forbidden = devOnly(readJson(path.join(pkgDir, "package.json")));
  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const file = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== "node_modules" && entry.name !== "bundle")
          walk(file);
      } else if (entry.name.endsWith(".js")) {
        // dist/scripts holds build-time tools (e.g. bundle verification), which
        // the runtime consumers already treat as dev-tool users.
        if (path.relative(dist, file).startsWith(`scripts${path.sep}`))
          continue;
        for (const m of fs.readFileSync(file, "utf8").matchAll(importRe)) {
          const spec = m[1] ?? m[2] ?? m[3];
          if (!spec.startsWith(".") && forbidden.has(packageName(spec))) {
            violations.push(`${path.relative(root, file)} imports ${spec}`);
          }
        }
      }
    }
  };
  walk(dist);
}
if (violations.length > 0) {
  console.error(violations.join("\n"));
  process.exit(1);
}
console.log("ok: no packages/*/dist file imports a devDependency");
