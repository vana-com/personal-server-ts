/**
 * Guard: the owner-key module is the only non-test source that names the owner
 * key primitives, the SDK master-key constant, or the master-key message.
 *
 * A runtime that calls a primitive directly can derive a different key from the
 * same wallet than the other runtimes. Route it through
 * `packages/core/src/keys/owner-master-key.ts` instead.
 *
 * Scope: every .ts/.tsx/.js/.mjs/.cjs file under `packages/*\/src` and
 * `packages/*\/scripts`, except `*.test.*` and `*.spec.*` files. Comments are
 * ignored; code is not.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const REPO_ROOT = fileURLToPath(new URL("../../../../", import.meta.url));
const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;
const TEST_FILE = /\.(test|spec)\.[cm]?[jt]sx?$/;
const SKIP_DIRS = new Set(["node_modules", "dist", ".turbo", ".git"]);

/** The primitives this guard keeps behind the owner module. */
const PRIMITIVES = [
  "deriveMasterKey",
  "streamMasterKeyFromSignature",
  "recoverServerOwner",
  "buildPersonalServerLiteOwnerBindingMessage",
  "buildPersonalServerLiteOwnerBindingSignature",
  "signPersonalServerLiteOwnerBinding",
] as const;

/** Files allowed to name specific primitives, with the reason. */
const ALLOWED: Record<string, { names: readonly string[]; reason: string }> = {
  "packages/core/src/keys/owner-master-key.ts": {
    names: [...PRIMITIVES, "vana-master-key-v1"],
    reason: "the owner module itself",
  },
  "packages/stream-sync/src/master-key.ts": {
    names: ["streamMasterKeyFromSignature"],
    reason: "defines the stream-sync primitive in its own package",
  },
  "packages/stream-sync/src/vectors.ts": {
    names: ["streamMasterKeyFromSignature"],
    reason: "conformance vectors for the primitive in its own package",
  },
};

function walk(dir: string, out: string[]): void {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      walk(full, out);
    } else if (SOURCE_EXT.test(entry) && !TEST_FILE.test(entry)) {
      out.push(full);
    }
  }
}

function sourceFiles(): string[] {
  const packagesDir = join(REPO_ROOT, "packages");
  const files: string[] = [];
  for (const pkg of readdirSync(packagesDir)) {
    for (const sub of ["src", "scripts"]) {
      const dir = join(packagesDir, pkg, sub);
      if (statSync(dir, { throwIfNoEntry: false })?.isDirectory()) {
        walk(dir, files);
      }
    }
  }
  return files;
}

/** Removes block and line comments so the guard reads code only. */
function code(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:"'`\\])\/\/.*$/gm, "$1");
}

function violationsIn(relPath: string, source: string): string[] {
  const allowed = ALLOWED[relPath]?.names ?? [];
  const body = code(source);
  const found: string[] = [];
  for (const name of PRIMITIVES) {
    if (allowed.includes(name)) continue;
    if (new RegExp(`\\b${name}\\b`).test(body)) found.push(name);
  }
  // The SDK master-key constant, imported from the SDK. A re-export of the
  // owner module's constant under the same name is allowed.
  if (
    /import\s+(?:type\s+)?\{[^}]*\bMASTER_KEY_MESSAGE\b[^}]*\}\s*from\s*["']@opendatalabs\/vana-sdk[^"']*["']/.test(
      body,
    )
  ) {
    found.push("MASTER_KEY_MESSAGE (SDK)");
  }
  if (
    !allowed.includes("vana-master-key-v1") &&
    body.includes("vana-master-key-v1")
  ) {
    found.push('literal "vana-master-key-v1"');
  }
  return found;
}

describe("owner key derivation has one owner", () => {
  it("no non-test source outside the owner module names the primitives or the master-key message", () => {
    const files = sourceFiles();
    // Vacuity check: the walk must actually see the monorepo.
    expect(files.length).toBeGreaterThan(200);
    expect(files).toContain(
      join(REPO_ROOT, "packages/core/src/keys/owner-master-key.ts"),
    );

    const violations: string[] = [];
    for (const file of files) {
      const relPath = relative(REPO_ROOT, file).split(sep).join("/");
      for (const name of violationsIn(relPath, readFileSync(file, "utf8"))) {
        violations.push(`${relPath}: ${name}`);
      }
    }

    expect(violations).toEqual([]);
  });
});
