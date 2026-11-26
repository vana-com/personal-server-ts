import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: [],
    typecheck: {
      enabled: true,
      only: true,
      tsconfig: "packages/lite/tsconfig.typecheck.json",
      include: ["packages/lite/src/**/*.types.test.ts"],
    },
  },
});
