import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    // RSS comparisons must not compete with this repository's other tests.
    // Both projects retain the normal root invocation and focused file filters.
    projects: [
      {
        extends: true,
        test: {
          name: "unit",
          include: ["packages/*/src/**/*.test.ts", "scripts/**/*.test.ts"],
          exclude: [
            ...configDefaults.exclude,
            "packages/server/src/localdb/import-memory.test.ts",
          ],
        },
      },
      {
        extends: true,
        test: {
          name: "import-memory",
          include: ["packages/server/src/localdb/import-memory.test.ts"],
          sequence: { groupOrder: 1 },
        },
      },
    ],
    coverage: {
      provider: "v8",
      include: ["packages/*/src/**/*.ts"],
      exclude: ["packages/*/src/**/*.test.ts"],
    },
  },
});
