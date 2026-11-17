import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { describe, expect, it } from "vitest";

// The pure-JS port is the default so browser hosts run unchanged. A browser
// bundle of the key ports and of the log publisher must resolve with no Node module:
// `platform: "browser"` fails the build on an unresolved `node:` import.
describe("browser bundles of the stream-sync crypto path", () => {
  it.each(["./crypto.ts", "../localdb/log-publish.ts"])(
    "%s bundles for the browser without node:crypto",
    async (entry) => {
      const result = await build({
        entryPoints: [fileURLToPath(new URL(entry, import.meta.url))],
        bundle: true,
        platform: "browser",
        format: "esm",
        target: "es2022",
        write: false,
        logLevel: "silent",
      });
      const text = result.outputFiles.map((file) => file.text).join("\n");
      expect(text).not.toContain("node:crypto");
      expect(text.length).toBeGreaterThan(10_000);
    },
    60_000,
  );
});
