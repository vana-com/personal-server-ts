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

  it("deduplicates repeated imports and returns package names sorted", () => {
    const bundle = `
      import zeta from "zeta/sub";
      import alpha from "alpha";
      import zetaAgain from "zeta/other";
      import alphaAgain from "alpha/deep/path";
      import beta from "@scope/beta/sub";
      import betaAgain from "@scope/beta";
    `;

    expect(findUndeclaredRuntimeImports(bundle, new Set())).toEqual([
      "@scope/beta",
      "alpha",
      "zeta",
    ]);
  });

  it("reports side-effect-only imports of undeclared packages", () => {
    const bundle = `
      import "side-effect-missing";
      import "declared-side-effect";
    `;

    expect(
      findUndeclaredRuntimeImports(bundle, new Set(["declared-side-effect"])),
    ).toEqual(["side-effect-missing"]);
  });

  it("ignores # subpath imports and absolute paths but reports a bare scoped package", () => {
    const bundle = `
      import "#internal";
      import "/absolute/path.js";
      import scoped from "@scope/only";
    `;

    expect(findUndeclaredRuntimeImports(bundle, new Set())).toEqual([
      "@scope/only",
    ]);
  });

  it("returns an empty list when the bundle has no imports", () => {
    expect(findUndeclaredRuntimeImports("", new Set())).toEqual([]);
    expect(findUndeclaredRuntimeImports("const x = 1;\n", new Set())).toEqual(
      [],
    );
  });
});
