import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    // Several tests do CPU-bound work that takes 2-5 s alone (100 concurrent
    // sealed writes, 10 minutes of fake-timer sync cycles, a SQLite import).
    // On a 4-core CI runner with parallel files they pass the 5 s default.
    testTimeout: 20_000,
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
