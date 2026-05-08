import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

const ROOTS = ["packages", "scripts", "tests"];
const SDK_PACKAGE = "@opendatalabs/vana-sdk";
const SDK_BRANCH_SPEC =
  "github:vana-com/vana-sdk#volod/encryption-auth-primitives";
const SDK_PR_HEAD = "b9b0a78418dd62852e887091be5f229b672a4032";
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

const corePackage = JSON.parse(
  await readFile("packages/core/package.json", "utf8"),
) as {
  dependencies?: Record<string, string>;
};
const lockfile = JSON.parse(await readFile("package-lock.json", "utf8")) as {
  packages?: Record<
    string,
    {
      name?: string;
      resolved?: string;
    }
  >;
};

if (corePackage.dependencies?.[SDK_PACKAGE] !== SDK_BRANCH_SPEC) {
  violations.push(
    `packages/core/package.json must pin ${SDK_PACKAGE} to ${SDK_BRANCH_SPEC}`,
  );
}

const lockedSdk = lockfile.packages?.[`node_modules/${SDK_PACKAGE}`];
if (!lockedSdk?.resolved?.includes(SDK_PR_HEAD)) {
  violations.push(
    `package-lock.json must resolve ${SDK_PACKAGE} to PR 137 head ${SDK_PR_HEAD}`,
  );
}

if (violations.length > 0) {
  console.error(
    [
      "vana-sdk validation failed.",
      "Root imports from @opendatalabs/vana-sdk are forbidden; use /node or /browser.",
      `${SDK_PACKAGE} must stay pinned to PR 137 until a consumable workspace package is available.`,
      ...violations.map((violation) => `- ${violation}`),
    ].join("\n"),
  );
  process.exit(1);
}
