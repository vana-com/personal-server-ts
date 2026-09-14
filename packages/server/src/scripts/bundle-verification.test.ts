import { describe, expect, it } from "vitest";

import { findUndeclaredRuntimeImports } from "./bundle-verification.js";

describe("findUndeclaredRuntimeImports", () => {
  it("reports bare imports whose packages are absent from the runtime manifest", () => {
    const bundle = `
      import "./local.js";
      import "node:path";
      import { createRequire } from "module";
      import pino from "pino";
      import transport from "pino/transport";
      import {
        missing
      } from "missing-runtime-package/subpath";
      import scoped from "@example/missing/subpath";
    `;

    expect(findUndeclaredRuntimeImports(bundle, new Set(["pino"]))).toEqual([
      "@example/missing",
      "missing-runtime-package",
    ]);
  });
});
