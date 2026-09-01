import { build } from "esbuild";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

/**
 * The agent loop must stay browser-safe: PS-Lite runs the same loop with a
 * different `Sandbox` and the same fetch-based `InferenceProvider`.
 *
 * This matters more here than for the types-only port, because the loop has
 * real dependencies — the inference provider, the profile loader, the
 * transcript budget — and any one of them could pull in a Node built-in
 * without a single Node test noticing.
 *
 * The second test is the control, same as `ports.browser-safety.test.ts`: if a
 * Node-only module ever bundles cleanly, this check has lost its teeth.
 */

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../../../..");
const scratch = mkdtempSync(join(tmpdir(), "agent-browser-safety-"));

afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

async function bundleForBrowser(importPath: string) {
  const entry = join(repoRoot, `.agent-browser-entry-${Date.now()}.js`);
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

describe("the agent loop stays browser-safe", () => {
  it("bundles for the browser with no Node built-ins", async () => {
    const r = await bundleForBrowser(
      "./packages/core/dist/query/agent/index.js",
    );
    expect(r.ok, r.ok ? "" : r.message).toBe(true);
    if (!r.ok) return;
    expect(r.text).not.toMatch(/from ?["']node:/);
    expect(r.text).not.toMatch(/require\(["']node:/);
    // A types-only module bundles clean trivially. Assert the bundle actually
    // carries the loop's runtime, so this cannot pass on an empty export.
    expect(r.text).toContain("runQueryLoop");
    expect(r.text).toContain("vana:run");
    expect(r.text.length).toBeGreaterThan(10_000);
  }, 60_000);

  it("control: a Node-only module does NOT bundle for the browser", async () => {
    const r = await bundleForBrowser(
      "./packages/server/dist/query/node-sandbox.js",
    );
    expect(
      r.ok,
      "the browser-safety check has lost its teeth: a Node-only module bundled cleanly",
    ).toBe(false);
  }, 60_000);
});
