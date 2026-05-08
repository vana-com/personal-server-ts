import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

const ROOTS = ["packages", "scripts", "tests"];
const FORBIDDEN_ROOT_IMPORT =
  /from\s+["']@opendatalabs\/vana-sdk["']|import\s*\(\s*["']@opendatalabs\/vana-sdk["']\s*\)/;

async function* walk(dir: string): AsyncGenerator<string> {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "dist" || entry.name === "node_modules") {
        continue;
      }
      yield* walk(path);
    } else if (entry.isFile() && /\.(ts|tsx|js|mjs|cjs)$/.test(entry.name)) {
      yield path;
    }
  }
}

const violations: string[] = [];

for (const root of ROOTS) {
  for await (const path of walk(root)) {
    const contents = await readFile(path, "utf8");
    if (FORBIDDEN_ROOT_IMPORT.test(contents)) {
      violations.push(path);
    }
  }
}

if (violations.length > 0) {
  console.error(
    [
      "Root imports from @opendatalabs/vana-sdk are forbidden.",
      "Use @opendatalabs/vana-sdk/node or @opendatalabs/vana-sdk/browser.",
      ...violations.map((path) => `- ${path}`),
    ].join("\n"),
  );
  process.exit(1);
}
