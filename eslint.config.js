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
    files: ["packages/core/src/legacy-projection/**/*.ts"],
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
