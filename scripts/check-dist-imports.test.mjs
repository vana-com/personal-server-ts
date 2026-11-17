import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("checks the files npm actually packs", async (t) => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "dist-imports-"));
  t.after(() => fs.rmSync(fixture, { recursive: true, force: true }));
  fs.mkdirSync(path.join(fixture, "scripts"));
  const pkg = path.join(fixture, "packages", "example");
  fs.mkdirSync(path.join(pkg, "dist-test"), { recursive: true });
  fs.mkdirSync(path.join(pkg, "dist"));
  fs.copyFileSync(
    path.join(root, "scripts/check-dist-imports.mjs"),
    path.join(fixture, "scripts/check-dist-imports.mjs"),
  );
  fs.symlinkSync(
    path.join(root, "node_modules"),
    path.join(fixture, "node_modules"),
  );
  fs.writeFileSync(
    path.join(pkg, "package.json"),
    JSON.stringify({
      name: "example",
      version: "1.0.0",
      files: ["dist", "dist-test", "!dist-test/excluded.js"],
    }),
  );
  const file = path.join(pkg, "dist-test", "fixture.js");
  const check = (code) => {
    fs.writeFileSync(file, code);
    return spawnSync(
      process.execPath,
      [path.join(fixture, "scripts/check-dist-imports.mjs")],
      { encoding: "utf8" },
    );
  };
  fs.writeFileSync(
    path.join(pkg, "dist-test/excluded.js"),
    'import "missing-excluded";',
  );
  const assertViolation = (code, pattern) => {
    const result = check(code);
    assert.equal(result.status, 1, code);
    assert.match(result.stderr, pattern);
  };
  assertViolation('import "missing-package";', /imports missing-package/);
  assertViolation(
    'import("missing-package", { with: { type: "json" } });',
    /imports missing-package/,
  );
  assertViolation("import(`missing-package`);", /imports missing-package/);
  const computed = check("import(`missing-${name}`);");
  assert.equal(computed.status, 1, "computed imports must fail");
  assert.match(computed.stderr, /unanalysable/i);
  assertViolation('import "./excluded.js";', /unpacked relative target/);
  assertViolation('import "./present.js";', /unpacked relative target/);
  fs.writeFileSync(path.join(pkg, "dist-test/present.js"), "export {};");
  assert.equal(
    check('import "./present.js";').status,
    0,
    "packed relative targets and excluded files are accepted",
  );

  const loaderForms = [
    ["require.resolve", (arg) => `require.resolve(${arg});`],
    ["import.meta.resolve", (arg) => `import.meta.resolve(${arg});`],
    [
      "direct createRequire",
      (arg) =>
        `import { createRequire } from "node:module"; createRequire(import.meta.url)(${arg});`,
    ],
    [
      "renamed createRequire binding",
      (arg) =>
        `import { createRequire } from "node:module"; const load = createRequire(import.meta.url); load(${arg});`,
    ],
    ["module.require", (arg) => `module.require(${arg});`],
    [
      "process.mainModule.require",
      (arg) => `process.mainModule.require(${arg});`,
    ],
    ["aliased require", (arg) => `const load = require; load(${arg});`],
    [
      "aliased require chain",
      (arg) => `const a = require; const b = a; b(${arg});`,
    ],
    [
      "bound require.resolve",
      (arg) => `const load = require; load.resolve(${arg});`,
    ],
    [
      "aliased createRequire import",
      (arg) =>
        `import { createRequire as makeRequire } from "node:module"; const load = makeRequire(import.meta.url); load(${arg});`,
    ],
    [
      "createRequire(...).resolve",
      (arg) =>
        `import { createRequire } from "node:module"; createRequire(import.meta.url).resolve(${arg});`,
    ],
    [
      "bound createRequire result .resolve",
      (arg) =>
        `import { createRequire } from "node:module"; const load = createRequire(import.meta.url); load.resolve(${arg});`,
    ],
    [
      "namespace createRequire",
      (arg) =>
        `import * as m from "node:module"; m.createRequire(import.meta.url)(${arg});`,
    ],
    [
      "aliased createRequire factory",
      (arg) =>
        `import { createRequire } from "node:module"; const make = createRequire; make(import.meta.url)(${arg});`,
    ],
    [
      "module.require through an alias",
      (arg) => `const m = module; m.require(${arg});`,
    ],
  ];
  for (const [name, code] of loaderForms) {
    await t.test(`${name} rejects an undeclared runtime package`, () => {
      assertViolation(
        code('"missing-loader-package"'),
        /imports missing-loader-package/,
      );
    });
    await t.test(`${name} rejects a computed runtime specifier`, () => {
      assertViolation(code("runtimePackage"), /unanalysable/i);
    });
    await t.test(
      `${name} uses the existing packed-relative and builtin rules`,
      () => {
        assertViolation(code('"./excluded.js"'), /unpacked relative target/);
        assert.equal(check(code('"./present.js"')).status, 0);
        assert.equal(check(code('"node:fs"')).status, 0);
        // Extensionless/directory CJS resolution remains deliberately deferred.
        assertViolation(code('"./present"'), /unpacked relative target/);
      },
    );
  }

  await t.test("rejects loader identities used in unrecognised ways", () => {
    for (const code of [
      "const load = require; export default load;",
      "use(require);",
      "const { resolve } = require;",
      "let load; load = require;",
      "const load = module.require; use(load);",
      "const load = process.mainModule.require; use(load);",
      'import { createRequire } from "node:module"; use(createRequire);',
      'import { createRequire as c } from "node:module"; use(c(import.meta.url));',
      'import { createRequire } from "node:module"; export const load = createRequire(import.meta.url);',
      "use(import.meta.resolve);",
      "const r = import.meta.resolve; r('x');",
      "require.main.require(name);",
      'process.mainModule.require.call(null, "x");',
    ])
      assertViolation(code, /unanalysable/i);
  });
  await t.test("accepts proven loader uses", () => {
    for (const code of [
      'import { createRequire } from "node:module"; const require = createRequire(import.meta.url); require("./present.js");',
      'import { createRequire } from "node:module"; const load = createRequire(import.meta.url); load.resolve("node:fs");',
      'if (typeof require !== "undefined") {} module.exports = {}; require.cache;',
      "function f(module) { return module.x; } f({});",
      "const { module } = { module: 1 }; module.require;".replace(
        "module.require;",
        "use(module);",
      ),
    ])
      assert.equal(check(code).status, 0, code);
  });
  await t.test("allows only the listed bundle call site", () => {
    const uiDir = path.join(fixture, "packages", "server", "dist", "ui");
    fs.mkdirSync(uiDir, { recursive: true });
    fs.writeFileSync(
      path.join(fixture, "packages", "server", "package.json"),
      JSON.stringify({ name: "server", version: "1.0.0", files: ["dist"] }),
    );
    fs.rmSync(file);
    fs.rmSync(path.join(pkg, "dist-test"), { recursive: true });
    const bundle = path.join(uiDir, "ps-lite-debug.js");
    const run = (code) => {
      fs.writeFileSync(bundle, code);
      return spawnSync(
        process.execPath,
        [path.join(fixture, "scripts/check-dist-imports.mjs")],
        { encoding: "utf8" },
      );
    };
    assert.equal(
      run('import.meta.resolve("pdfjs-dist/package.json");').status,
      0,
    );
    const other = run('import.meta.resolve("other-package/package.json");');
    assert.equal(other.status, 1);
    assert.match(other.stderr, /imports other-package/);
    const unlisted = path.join(uiDir, "other.js");
    fs.writeFileSync(
      unlisted,
      'import.meta.resolve("pdfjs-dist/package.json");',
    );
    fs.writeFileSync(bundle, "export {};");
    const elsewhere = spawnSync(
      process.execPath,
      [path.join(fixture, "scripts/check-dist-imports.mjs")],
      { encoding: "utf8" },
    );
    assert.equal(elsewhere.status, 1);
    assert.match(elsewhere.stderr, /other\.js imports pdfjs-dist/);
  });
});
