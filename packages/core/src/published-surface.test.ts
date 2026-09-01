import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

type ExportEntry = { types: string; import: string };
type PackageJson = { files: string[]; exports: Record<string, ExportEntry> };

const packageJson = JSON.parse(
  readFileSync(join(packageRoot, "package.json"), "utf8"),
) as PackageJson;

// `tsconfig.json` is JSONC — the exclude list carries the explanation of why
// each entry is there, so the comments have to come off before JSON.parse.
const tsconfigExclude = (): string[] => {
  const raw = readFileSync(join(packageRoot, "tsconfig.json"), "utf8");
  const stripped = raw
    .split("\n")
    .filter((line) => !line.trim().startsWith("//"))
    .join("\n");
  return (JSON.parse(stripped) as { exclude: string[] }).exclude;
};

// Test scaffolding, not product code. Each subtree is excluded from the build
// and has no `exports` entry, so it never reaches the npm tarball; test files
// and `scripts/` reach it by relative path into `src/` instead.
const testOnlySubtrees = ["src/query/evals", "src/test-utils"];

const sourceForTarget = (target: string): string =>
  join(
    packageRoot,
    target.replace(/^\.\/dist\//, "src/").replace(/\.d\.ts$|\.js$/, ".ts"),
  );

const exportTargets = Object.entries(packageJson.exports).flatMap(
  ([subpath, entry]) => [
    [subpath, entry.types] as const,
    [subpath, entry.import] as const,
  ],
);

describe("published surface", () => {
  it("publishes only the build output", () => {
    // Everything below rests on this: excluding a subtree from the build only
    // keeps it out of the tarball while `dist` is the whole published payload.
    expect(packageJson.files).toEqual(["dist"]);
  });

  it("excludes every test-only subtree from the build", () => {
    const exclude = tsconfigExclude();
    for (const subtree of testOnlySubtrees) {
      expect(exclude).toContain(`${subtree}/**`);
    }
  });

  it("exports no subpath that points into a test-only subtree", () => {
    const distSubtrees = testOnlySubtrees.map(
      (subtree) => `./${subtree.replace(/^src\//, "dist/")}/`,
    );
    for (const [subpath, target] of exportTargets) {
      for (const distSubtree of distSubtrees) {
        expect(
          target.startsWith(distSubtree),
          `${subpath} -> ${target} publishes ${distSubtree}`,
        ).toBe(false);
      }
    }
  });

  it("exports no subpath whose source the build drops", () => {
    // The other direction: an `exports` entry naming a file that never gets
    // emitted would ship a dangling subpath to consumers.
    for (const [subpath, target] of exportTargets) {
      const source = sourceForTarget(target);
      expect(existsSync(source), `${subpath} -> ${target} has no source`).toBe(
        true,
      );
      const relative = source.slice(packageRoot.length + 1);
      for (const subtree of testOnlySubtrees) {
        expect(
          relative.startsWith(`${subtree}/`),
          `${subpath} -> ${target} resolves into excluded ${subtree}`,
        ).toBe(false);
      }
    }
  });

  it.skipIf(!existsSync(join(packageRoot, "dist")))(
    "emits no test-only subtree into dist",
    () => {
      // Only meaningful once the package is built. CI runs `npm run build`
      // before `npm test`, and the rest of the suite needs `dist` anyway
      // because tests import published subpaths by package name.
      for (const subtree of testOnlySubtrees) {
        const emitted = join(packageRoot, subtree.replace(/^src\//, "dist/"));
        expect(existsSync(emitted), `${emitted} was emitted`).toBe(false);
      }
    },
  );
});
