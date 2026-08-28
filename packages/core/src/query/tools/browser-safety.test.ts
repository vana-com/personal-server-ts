import { build } from "esbuild";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

/**
 * The capability layer must stay browser-safe: `packages/core` is imported by
 * `packages/lite`, and plan §5 calls a stray `node:` import here "the single
 * easiest way to break the build in a way tests on Node will not catch".
 *
 * This layer is a stronger test than the types-only port, because it carries
 * real code — an interpreter, a parser dependency and the API — any of which
 * could reach a Node built-in. The control below keeps the check honest.
 */

const here = dirname(fileURLToPath(import.meta.url));
// packages/core/src/query/tools -> repo root is five levels up.
const repoRoot = resolve(here, "../../../../..");
const scratch = mkdtempSync(join(tmpdir(), "tools-browser-safety-"));

afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

async function bundleForBrowser(importPath: string) {
  const entry = join(repoRoot, `.tools-browser-entry-${Date.now()}.js`);
  writeFileSync(
    entry,
    `import * as m from ${JSON.stringify(importPath)};\nglobalThis.__m = m;\n`,
  );
  try {
    const result = await build({
      entryPoints: [entry],
      bundle: true,
      platform: "browser",
      format: "esm",
      write: false,
      logLevel: "silent",
      absWorkingDir: repoRoot,
    });
    return { ok: true as const, text: result.outputFiles[0]!.text };
  } catch (err) {
    return { ok: false as const, message: (err as Error).message };
  } finally {
    rmSync(entry, { force: true });
  }
}

describe("the capability layer stays browser-safe", () => {
  it("bundles for the browser with no Node built-ins", async () => {
    const r = await bundleForBrowser(
      "./packages/core/dist/query/tools/index.js",
    );
    expect(r.ok, r.ok ? "" : r.message).toBe(true);
    if (!r.ok) return;
    expect(r.text).not.toMatch(/from ?["']node:/);
    expect(r.text).not.toMatch(/require\(["']node:/);
  }, 60_000);

  it("control: a Node-only module still fails the same check", async () => {
    // Without this, the test above would pass even if the check were broken.
    const r = await bundleForBrowser(
      "./packages/server/dist/query/node-sandbox.js",
    );
    expect(
      r.ok,
      "the browser-safety check has lost its teeth: a Node-only module bundled cleanly",
    ).toBe(false);
    if (!r.ok) expect(r.message).toMatch(/node:|Could not resolve/);
  }, 60_000);
});
