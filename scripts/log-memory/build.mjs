import { build } from "esbuild";
import { readFile } from "node:fs/promises";
import path from "node:path";
const root = process.cwd();
await build({
  entryPoints: ["scripts/log-memory/measure.mjs"],
  outfile: process.argv[2],
  bundle: true,
  platform: "node",
  format: "esm",
  packages: "external",
  alias: {
    "@opendatalabs/personal-server-ts-stream-sync": path.join(
      root,
      "packages/stream-sync/src/index.ts",
    ),
    "@opendatalabs/personal-server-ts-core/sync": path.join(
      root,
      "packages/core/src/sync/index.ts",
    ),
  },
  plugins: [
    {
      name: "measurement-boundaries",
      setup(b) {
        b.onLoad(
          { filter: /log-world\.test-utils\.ts$/ },
          async ({ path: file }) => {
            let s = await readFile(file, "utf8");
            s = s.replace(
              'openBetterSqlite3(":memory:")',
              "globalThis.memoryDriver(deviceId)",
            );
            const start = s.indexOf(
              "  const store = new Map<string, Uint8Array>();",
            );
            const end = s.indexOf("  const trace = options.trace;", start);
            if (start < 0 || end < 0) throw Error("world probe drift");
            s =
              s.slice(0, start) +
              "  const innerBlobs = globalThis.memoryBlobs;\n" +
              s.slice(end);
            s = s.replace(
              /keys: \{[\s\S]*?\n      \},\n      signer:/,
              "keys: globalThis.memoryKeys,\n      signer:",
            );
            return { contents: s, loader: "ts" };
          },
        );
        b.onResolve({ filter: /compaction-eligibility-only$/ }, () => ({
          path: "planner",
          namespace: "measurement",
        }));
        b.onLoad({ filter: /.*/, namespace: "measurement" }, async () => {
          let s = await readFile(
            path.join(root, "packages/core/src/localdb/log-compact.ts"),
            "utf8",
          );
          if (!s.includes("!required &&"))
            throw Error("eligibility probe drift");
          // Only the explicitly invoked planner bypasses eligibility. Publication is unchanged.
          s = s.replace("!required &&", "false && !required &&");
          s = s.replace(
            "const fold = foldLog({ snapshot: parts, segments });",
            "await globalThis.memoryFoldInput(parts,segments); const fold = foldLog({ snapshot: parts, segments });",
          );
          return {
            contents: s,
            loader: "ts",
            resolveDir: path.join(root, "packages/core/src/localdb"),
          };
        });
        b.onLoad(
          { filter: /log-(compact|rebase)\.ts$/ },
          async ({ path: file }) => {
            let s = await readFile(file, "utf8");
            if (file.endsWith("log-compact.ts"))
              s = s.replace(
                "!required &&",
                "!globalThis.memoryForcePublicationCompaction && !required &&",
              );
            s = s.replace(
              "const fold = foldLog({ snapshot: parts, segments });",
              "await globalThis.memoryFoldInput(parts,segments); const fold = foldLog({ snapshot: parts, segments });",
            );
            return { contents: s, loader: "ts" };
          },
        );
        b.onLoad({ filter: /log-publish\.ts$/ }, async ({ path: file }) => {
          let s = await readFile(file, "utf8");
          if (!s.includes("return { ops, untyped };"))
            throw Error("operations probe drift");
          s = s.replace(
            "const scope = logScope(candidate.connector, candidate.ns);",
            "await globalThis.memoryCandidate(candidate); const scope = logScope(candidate.connector, candidate.ns);",
          );
          s = s.replace(
            "return { ops, untyped };",
            "globalThis.memoryOperations(ops); return { ops, untyped };",
          );
          return { contents: s, loader: "ts" };
        });
        b.onLoad({ filter: /log-apply\.ts$/ }, async ({ path: file }) => {
          let s = await readFile(file, "utf8");
          if (
            !s.includes(
              "return { segment, bytes: verified.bytes, cipherBytes: cipher.length };",
            ) ||
            !s.includes(
              "return {\n    ...verified.part,\n    entries: await resolveBodies(deps, scope, verified.part.entries),\n  };",
            )
          )
            throw Error("decoded-result probe drift");
          s = s.replace(
            "return { segment, bytes: verified.bytes, cipherBytes: cipher.length };",
            "globalThis.memoryDecoded(segment); return { segment, bytes: verified.bytes, cipherBytes: cipher.length };",
          );
          s = s.replace(
            "return {\n    ...verified.part,\n    entries: await resolveBodies(deps, scope, verified.part.entries),\n  };",
            "const part = { ...verified.part, entries: await resolveBodies(deps, scope, verified.part.entries) }; globalThis.memoryDecoded(part); return part;",
          );
          return { contents: s, loader: "ts" };
        });
      },
    },
  ],
});
