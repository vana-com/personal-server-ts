import { build } from "esbuild";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { execFileSync } from "node:child_process";
const root = process.cwd();
// Read only the measured product path from a pinned revision; the harness stays current.
const source = async (file) =>
  process.env.MEMORY_SOURCE_REF &&
  /core\/src\/localdb\/log-(apply|compact|rebase|seed)\.ts$/.test(file)
    ? execFileSync(
        "git",
        [
          "show",
          `${process.env.MEMORY_SOURCE_REF}:${path.relative(root, file)}`,
        ],
        { encoding: "utf8" },
      )
    : readFile(file, "utf8");
await build({
  entryPoints: [process.argv[3] ?? "scripts/log-memory/measure.mjs"],
  outfile: process.argv[2],
  bundle: true,
  platform: "node",
  format: "esm",
  packages: "external",
  alias: {
    "@opendatalabs/personal-server-ts-core/stream-sync": path.join(
      root,
      "packages/core/src/stream-sync/index.ts",
    ),
    "@opendatalabs/personal-server-ts-core/localdb": path.join(
      root,
      "packages/core/src/localdb/index.ts",
    ),
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
        b.onResolve({ filter: /log-progressive\.js$/ }, () =>
          process.env.MEMORY_BASE_APPLY
            ? {
                path: process.env.MEMORY_BASE_APPLY.replace(
                  /apply\.ts$/,
                  "progressive.ts",
                ),
              }
            : null,
        );
        b.onLoad(
          { filter: /log-(compact|rebase|seed)\.ts$/ },
          async ({ path: file }) => ({
            contents: await source(file),
            loader: "ts",
          }),
        );
        b.onLoad(
          { filter: /log-world\.test-utils\.ts$/ },
          async ({ path: file }) => {
            let s = await readFile(file, "utf8");
            s = s.replace(
              'openBetterSqlite3(":memory:")',
              "globalThis.memoryDriver(deviceId)",
            );
            s = s.replace(
              'openBetterSqlite3(directory ? join(directory, "db") : ":memory:")',
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
          let s = await source(
            path.join(root, "packages/core/src/localdb/log-compact.ts"),
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
          let s = await readFile(
            process.env.MEMORY_REFERENCE_PUBLISH ?? file,
            "utf8",
          );
          s = s.replace(
            "const scope = logScope(candidate.connector, candidate.ns);",
            "await globalThis.memoryCandidate(candidate); const scope = logScope(candidate.connector, candidate.ns);",
          );
          if (s.includes("return { ops, untyped };"))
            s = s.replace(
              "return { ops, untyped };",
              "globalThis.memoryOperations(ops); return { ops, untyped };",
            );
          else if (
            s.includes("await workspace.prepare(ack, piece, completes);")
          )
            s = s.replace(
              "await workspace.prepare(ack, piece, completes);",
              'globalThis.memoryOperations([...taken,...(replace&&(completes||piece.length>0)?[{kind:"complete",stream,cutoff:replace,omitted:piece}]:[])]); await workspace.prepare(ack, piece, completes);',
            );
          else throw Error("operations probe drift");
          return { contents: s, loader: "ts" };
        });
        b.onLoad({ filter: /log-(apply|input)\.ts$/ }, async ({ path: file }) => {
          let s = file.endsWith("log-apply.ts")
            ? process.env.MEMORY_BASE_APPLY
              ? await readFile(process.env.MEMORY_BASE_APPLY, "utf8")
              : await source(file)
            : await readFile(file, "utf8");
          if (file.endsWith("log-apply.ts") && !s.includes("verifySegment("))
            return { contents: s, loader: "ts" };
          if (s.includes("return verified.part;")) {
            s = s.replace(
              "return verified.part;",
              "globalThis.memoryDecoded(verified.part); return verified.part;",
            );
            s = s.replace(
              /return \{\s*segment: verified.segment,/,
              "globalThis.memoryDecoded(verified.segment); return {segment: verified.segment,",
            );
          } else {
            const segment =
              "return { segment, bytes: verified.bytes, cipherBytes: cipher.length };";
            if (!s.includes(segment)) throw Error("decoded-result probe drift");
            s = s.replace(
              segment,
              "globalThis.memoryDecoded(segment); " + segment,
            );
            s = s.replace(
              "return {\n    ...verified.part,\n    entries: await resolveBodies(deps, scope, verified.part.entries),\n  };",
              "const part = { ...verified.part, entries: await resolveBodies(deps, scope, verified.part.entries) }; globalThis.memoryDecoded(part); return part;",
            );
          }
          return { contents: s, loader: "ts" };
        });
      },
    },
  ],
});
