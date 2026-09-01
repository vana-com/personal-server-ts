import { build } from "esbuild";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

/**
 * `packages/core` is imported by `packages/lite`, which runs in a browser or
 * WebView. Plan §5 calls this "the single easiest way to break the build in a
 * way tests on Node will not catch" — a `node:` import added here compiles
 * fine, passes every Node test, and only fails once Lite loads it.
 *
 * So the check has to be a real browser bundle, not a lint rule: bundling for
 * `platform: "browser"` leaves Node built-ins unresolvable, and any of them
 * reachable from the query port fails the build.
 *
 * The second test is the control. A browser bundle of a *types-only* module
 * is trivially clean, so on its own the first test would pass even if the
 * check were broken. Pointing the same check at the Node sandbox
 * implementation must fail — otherwise the check proves nothing.
 */

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../../..");
const scratch = mkdtempSync(join(tmpdir(), "browser-safety-"));

afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

async function bundleForBrowser(importPath: string) {
  // The entry has to sit inside the workspace for package resolution.
  const entry = join(repoRoot, `.browser-safety-entry-${Date.now()}.js`);
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

describe("packages/core query port stays browser-safe", () => {
  it("bundles for the browser with no Node built-ins", async () => {
    const r = await bundleForBrowser("./packages/core/dist/query/ports.js");
    expect(r.ok, r.ok ? "" : r.message).toBe(true);
    if (!r.ok) return;
    expect(r.text).not.toMatch(/from ?["']node:/);
    expect(r.text).not.toMatch(/require\(["']node:/);
  }, 60_000);

  it("control: the Node sandbox implementation does NOT bundle for the browser", async () => {
    // If this ever passes, the test above has stopped meaning anything.
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
