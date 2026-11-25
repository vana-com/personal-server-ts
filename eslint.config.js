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

const portableEncodingSelectors = [
  {
    selector: 'CallExpression > Literal.arguments[value="base64url"]',
    message:
      "Use the portable encoding/base64url codec instead of a Buffer encoding.",
  },
  {
    selector:
      'MemberExpression[object.name="Buffer"][property.name="compare"], MemberExpression[object.name="Buffer"][computed=true][property.value="compare"]',
    message:
      "Compare Uint8Array bytes without Buffer.compare for browser compatibility.",
  },
];

// A change-feed cursor is a branded string, and a string allows `<`, `>` and
// `Number(...)`, which the type cannot refuse. The gateway's cursor has no
// order and no number inside; the client compares it with `===` only. ESLint
// has no types here, so this reads names: a value called cursor, position,
// after or since. A cursor under another name is not caught.
const CURSOR_NAME =
  "/^(after|since|.*[cC]ursor.*|.*[pP]osition.*|heldUpTo|startedUnder|inFlightTarget)$/";
const cursorSelectors = [
  {
    selector: `BinaryExpression[operator=/^[<>]=?$/]:has(Identifier[name=${CURSOR_NAME}], MemberExpression > Identifier.property[name=${CURSOR_NAME}])`,
    message:
      "A change-feed cursor has no order: compare it with === only. Do not use <, >, <= or >=.",
  },
  {
    selector: `CallExpression[callee.name=/^(Number|BigInt|parseInt|parseFloat)$/] > Identifier.arguments[name=${CURSOR_NAME}], CallExpression[callee.name=/^(Number|BigInt|parseInt|parseFloat)$/] > MemberExpression.arguments > Identifier.property[name=${CURSOR_NAME}]`,
    message:
      "A change-feed cursor is not a number: do not parse it. Keep it as received.",
  },
];

export default tseslint.config(
  {
    ignores: [
      "**/dist/**",
      "**/node_modules/**",
      "**/*.d.ts",
      // Plain CommonJS the SQLite worker thread loads without a build step.
      "packages/server/src/localdb/*.cjs",
      // Offline parity generator; never built or published.
      "packages/core/parity-oracle/**",
    ],
  },
  ...tseslint.configs.recommended,
  eslintConfigPrettier,
  {
    files: ["packages/core/src/**/*.ts", "packages/lite/src/**/*.ts"],
    ignores: ["**/*.test.ts"],
    rules: {
      "no-restricted-syntax": ["error", ...portableEncodingSelectors],
    },
  },
  {
    // The files that hold or pass a change-feed cursor. Repeats the base
    // selectors: a later `no-restricted-syntax` replaces an earlier one.
    files: [
      "packages/core/src/stream-sync/ports.ts",
      "packages/core/src/stream-sync/registry.ts",
      "packages/core/src/sync/engine/change-push.ts",
      "packages/core/src/sync/engine/sync-manager.ts",
    ],
    rules: {
      "no-restricted-syntax": [
        "error",
        ...portableEncodingSelectors,
        ...cursorSelectors,
      ],
    },
  },
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
