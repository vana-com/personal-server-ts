import tseslint from "typescript-eslint";
import eslintConfigPrettier from "eslint-config-prettier";

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
      "packages/core/src/storage/pdpp-import-job/**/*.ts",
    ],
    ignores: [
      "**/*.test.ts",
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
  {
    // Import jobs read spools in bounded windows (docs/261028-pdpp-import-job.md).
    files: [
      "packages/core/src/storage/pdpp-import-job/**/*.ts",
      "packages/server/src/storage/pdpp-import-jobs-sqlite.ts",
    ],
    ignores: ["**/*.test.ts"],
    rules: {
      "no-restricted-syntax": [
        "error",
        {
          selector:
            "CallExpression[callee.property.name=/^(readFile|readFileSync|readEnvelope|text|arrayBuffer|blob|json)$/]",
          message:
            "Import jobs never read a whole file; use bounded readSpool windows.",
        },
        {
          selector: "CallExpression[callee.name=/^(readFile|readFileSync)$/]",
          message:
            "Import jobs never read a whole file; use bounded readSpool windows.",
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
