import { build } from "esbuild";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

/**
 * Mounting the query route must not put the QuickJS engine in every PS-Lite
 * bundle.
 *
 * `quickjs-sandbox.ts` statically imports
 * `@jitl/quickjs-singlefile-browser-release-sync`, which base64-inlines a
 * ~1.1 MB WASM engine. `runtime.ts` mounts `/v1/query/*`, so the temptation is
 * to have it reach `runLiteQuery` directly — and the first version of the route
 * did, with `await import("./lite-query-service.js")`, on the assumption that a
 * dynamic import stays out of the graph.
 *
 * It does not. esbuild's single-file output (`--outfile`, no `--splitting`)
 * INLINES a dynamic import rather than emitting a chunk, and both of this
 * package's real consumers bundle that way: `packages/server`'s `bundle-ui`
 * and the mobile `ps_bundle/build.mjs`. The measured cost on
 * `ps-lite-debug.js` was 6,297,472 → 7,377,258 bytes, and the same blob would
 * land in the mobile bundle, where WASM has never run at all (design §19.18:
 * Android WebView and iOS WKWebView are both UNVERIFIED).
 *
 * So the engine is INJECTED (`options.query.ask`, built by
 * `createLiteQueryAsk`) and this test is what keeps it that way. A future
 * `import { createLiteQueryAsk } from "./query/wire.js"` in `runtime.ts` or
 * `browser-runtime.ts` would be invisible in review and fails here instead.
 *
 * The second test is the control. A bundle that merely lacks a marker proves
 * nothing if the marker is wrong or the engine moved, so the same check is
 * pointed at `query/wire.js`, which MUST contain the engine. If that ever comes
 * back clean, the assertion above has stopped meaning anything.
 */

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../../..");
const scratch = mkdtempSync(join(tmpdir(), "lite-engine-graph-"));

afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

/**
 * Bundle exactly the way the real consumers do: one file, IIFE, browser, no
 * code splitting. That is the configuration under which a dynamic import gets
 * inlined, so it is the only configuration this check may use.
 */
async function bundleSingleFile(importPath: string) {
  const entry = join(repoRoot, `.engine-graph-entry-${Date.now()}.js`);
  writeFileSync(
    entry,
    `import * as m from ${JSON.stringify(importPath)};\nglobalThis.__m = m;\n`,
  );
  try {
    const result = await build({
      entryPoints: [entry],
      bundle: true,
      platform: "browser",
      format: "iife",
      target: "chrome108",
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

/**
 * `__vana_enqueue` is the host function name the QuickJS prelude binds
 * (`quickjs-sandbox.ts`'s `VANA_PRELUDE`). It appears in a bundle if and only
 * if the sandbox module is in the graph, which makes it a better marker than a
 * byte count.
 */
const ENGINE_MARKER = "__vana_enqueue";

describe("the QuickJS engine stays out of the PS-Lite runtime's module graph", () => {
  it("bundling runtime.js does not pull the engine in", async () => {
    const r = await bundleSingleFile("./packages/lite/dist/runtime.js");
    expect(r.ok, r.ok ? "" : r.message).toBe(true);
    if (!r.ok) return;
    expect(
      r.text.includes(ENGINE_MARKER),
      "runtime.ts now reaches the QuickJS sandbox. The route must take its " +
        "runner through `options.query.ask` (see query/wire.ts) — importing " +
        "the engine here adds ~1.1MB to every PS-Lite bundle, mobile included.",
    ).toBe(false);
  }, 120_000);

  it("bundling browser-runtime.js does not pull the engine in either", async () => {
    const r = await bundleSingleFile("./packages/lite/dist/browser-runtime.js");
    expect(r.ok, r.ok ? "" : r.message).toBe(true);
    if (!r.ok) return;
    expect(
      r.text.includes(ENGINE_MARKER),
      "createIndexedDbPsLiteRuntime now reaches the QuickJS sandbox; see the " +
        "message above.",
    ).toBe(false);
  }, 120_000);

  it("control: bundling query/wire.js DOES pull the engine in", async () => {
    // If this ever fails, the marker is wrong and the two tests above are vacuous.
    const r = await bundleSingleFile("./packages/lite/dist/query/wire.js");
    expect(r.ok, r.ok ? "" : r.message).toBe(true);
    if (!r.ok) return;
    expect(
      r.text.includes(ENGINE_MARKER),
      "the engine marker was not found in the module whose whole purpose is to " +
        "import the engine, so this check has lost its teeth",
    ).toBe(true);
  }, 120_000);
});
