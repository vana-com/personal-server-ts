import tseslint from "typescript-eslint";
import eslintConfigPrettier from "eslint-config-prettier";

const legacyProjectionImport = {
  group: [
    "**/legacy-projection",
    "**/legacy-projection/**",
    "@opendatalabs/personal-server-ts-core/legacy-projection",
  ],
  message:
    "Stream sync holds no connector-specific knowledge: do not import the legacy projection.",
};

export default tseslint.config(
  {
    ignores: [
      "**/dist/**",
      "**/node_modules/**",
      "**/*.d.ts",
      // Offline parity generator; never built or published.
      "packages/core/parity-oracle/**",
    ],
  },
  ...tseslint.configs.recommended,
  eslintConfigPrettier,
  {
    // Runs in browsers and WebViews: no Node built-ins.
    files: [
      "packages/core/src/legacy-projection/**/*.ts",
      "packages/core/src/additions/**/*.ts",
      "packages/core/src/replication/**/*.ts",
      "packages/core/src/storage/pdpp-records/completion.ts",
      "packages/stream-sync/src/**/*.ts",
    ],
    ignores: [
      "**/*.test.ts",
      "**/test-support/**",
      "**/__fixtures__/**",
      "**/github-browser-parity-fixtures.ts",
    ],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            { group: ["node:*"], message: "Keep this module browser-safe." },
          ],
        },
      ],
    },
  },
  // Stream sync holds no connector-specific knowledge. The legacy projection is
  // a hand-written per-connector map; reaching it from here would bring
  // connector names back into the stream-sync writer, reader or protocol.
  // A later `no-restricted-imports` replaces an earlier one for the same file,
  // so the protocol package repeats the browser-safe pattern from above.
  {
    files: [
      "packages/core/src/stream-sync/**/*.ts",
      "packages/core/src/stream-sync-read/**/*.ts",
    ],
    ignores: [
      "**/*.test.ts",
      "**/test-support/**",
      "**/__fixtures__/**",
      // The two modules that still serve legacy data-set names to readers.
      // Nothing else under these directories may join them.
      "packages/core/src/stream-sync-read/service.ts",
      "packages/core/src/stream-sync-read/projection.ts",
    ],
    rules: {
      "no-restricted-imports": [
        "error",
        { patterns: [legacyProjectionImport] },
      ],
    },
  },
  {
    files: ["packages/stream-sync/src/**/*.ts"],
    ignores: ["**/*.test.ts", "**/test-support/**", "**/__fixtures__/**"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            { group: ["node:*"], message: "Keep this module browser-safe." },
            legacyProjectionImport,
          ],
        },
      ],
    },
  },
  {
    files: ["packages/*/src/**/*.ts"],
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/consistent-type-imports": "error",
    },
  },
  {
    files: ["**/*.test.ts", "**/*.spec.ts", "**/test-utils/**/*.ts"],
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-non-null-assertion": "off",
    },
  },
);
