import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SOURCE_ROOT = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = dirname(SOURCE_ROOT);
const PACKAGE_JSON = join(PACKAGE_ROOT, "package.json");
const SOURCE_PATTERN = /(?<!\.test)\.ts$/;
const IMPORT_PATTERN = /(?:\bfrom\s+|\bimport\s+)["']([^"']+)["']/g;

type PackageJson = { dependencies?: Record<string, string> };

describe("enclave runtime dependencies", () => {
  it("declares every bare source import in dependencies", () => {
    const manifest = JSON.parse(
      readFileSync(PACKAGE_JSON, "utf8"),
    ) as PackageJson;
    const dependencies = new Set(Object.keys(manifest.dependencies ?? {}));

    for (const specifier of bareImports(SOURCE_ROOT)) {
      const dependency = packageName(specifier);
      expect(
        dependencies.has(dependency),
        `${dependency} must be declared in dependencies`,
      ).toBe(true);
    }
  });
});

function bareImports(directory: string): Set<string> {
  const imports = new Set<string>();

  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      for (const specifier of bareImports(path)) imports.add(specifier);
      continue;
    }
    if (!SOURCE_PATTERN.test(entry.name)) continue;

    const source = readFileSync(path, "utf8");
    for (const match of source.matchAll(IMPORT_PATTERN)) {
      const specifier = match[1];
      if (!specifier.startsWith(".") && !specifier.startsWith("node:")) {
        imports.add(specifier);
      }
    }
  }

  return imports;
}

function packageName(specifier: string): string {
  return specifier.startsWith("@")
    ? specifier.split("/").slice(0, 2).join("/")
    : specifier.split("/")[0];
}
