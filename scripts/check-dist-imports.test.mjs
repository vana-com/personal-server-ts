import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("checks the files npm actually packs", (t) => {
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
    assert.equal(result.status, 1);
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
});
