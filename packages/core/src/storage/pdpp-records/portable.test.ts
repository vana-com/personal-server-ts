import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { describe, expect, it } from "vitest";

const packageName = "@opendatalabs/personal-server-ts-core";
const portableEntries = [
  "storage/pdpp-records/portable",
  "storage/pdpp-records/completion",
  "storage/pdpp-records/schema",
  "storage/canonical-legacy-projection",
  "storage/legacy-scope-view",
  "legacy-projection",
  "storage/legacy-projection",
];
const root = fileURLToPath(new URL("../../../../../", import.meta.url));

describe("published portable canonical entry points", () => {
  it.each(portableEntries)(
    "bundles %s without Node or HTTP adapters",
    async (entry) => {
      // Resolve the published export map and compiled files, without aliases or
      // tree shaking that could hide an unsafe unused export.
      const result = await build({
        stdin: {
          contents: `export * from "${packageName}/${entry}";`,
          resolveDir: root,
        },
        bundle: true,
        // The PDF reader the block builder uses. It runs in browsers, but its
        // bundled source names `Buffer` in an error message and in a guarded
        // check, which the scan below would count as Node use.
        external: ["unpdf"],
        platform: "browser",
        format: "esm",
        target: "es2022",
        treeShaking: false,
        minify: true,
        metafile: true,
        write: false,
        logLevel: "silent",
      });
      const inputs = Object.keys(result.metafile.inputs);
      expect(
        inputs.some((path) =>
          /memory-store|better-sqlite3|(?:^|\/)hono(?:\/|$)/.test(path),
        ),
      ).toBe(false);
      for (const input of Object.values(result.metafile.inputs)) {
        expect(input.imports.some(({ path }) => path.startsWith("node:"))).toBe(
          false,
        );
      }
      expect(
        result.outputFiles[0].text.match(/\bBuffer\b|better-sqlite3/g) ?? [],
      ).toEqual([]);
    },
  );

  it("keeps the Node memory store available through both public paths", async () => {
    const original = await import(`${packageName}/storage/pdpp-records`);
    const memory = await import(`${packageName}/storage/pdpp-records/memory`);
    expect(memory.createMemoryRecordStore).toBe(
      original.createMemoryRecordStore,
    );
    expect(memory.createMemoryRecordStore()).toMatchObject({
      ingestBatch: expect.any(Function),
      getRecord: expect.any(Function),
    });
  });
});
