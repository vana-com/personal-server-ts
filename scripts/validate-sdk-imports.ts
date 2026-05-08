import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const ROOTS = ["packages", "scripts", "tests"];
const SDK_PACKAGE = "@opendatalabs/vana-sdk";
const SDK_LOCAL_SPEC = "file:../../../vana-sdk/packages/vana-sdk";
const FORBIDDEN_ROOT_IMPORT =
  /from\s+["']@opendatalabs\/vana-sdk["']|import\s*\(\s*["']@opendatalabs\/vana-sdk["']\s*\)/;
const execFileAsync = promisify(execFile);

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

function readPackageJson(path: string): Promise<{
  dependencies?: Record<string, string>;
}> {
  return readFile(path, "utf8").then((contents) => JSON.parse(contents));
}

const packagesUsingSdk = [
  "packages/core/package.json",
  "packages/lite/package.json",
];
const lockfile = JSON.parse(await readFile("package-lock.json", "utf8")) as {
  packages?: Record<
    string,
    {
      name?: string;
      resolved?: string;
      link?: boolean;
    }
  >;
};

for (const packagePath of packagesUsingSdk) {
  const packageJson = await readPackageJson(packagePath);
  if (packageJson.dependencies?.[SDK_PACKAGE] !== SDK_LOCAL_SPEC) {
    violations.push(
      `${packagePath} must point ${SDK_PACKAGE} at ${SDK_LOCAL_SPEC}`,
    );
  }
}

const lockedSdk = lockfile.packages?.[`node_modules/${SDK_PACKAGE}`];
if (
  lockedSdk?.resolved !== "../vana-sdk/packages/vana-sdk" ||
  !lockedSdk.link
) {
  violations.push(
    `package-lock.json must link ${SDK_PACKAGE} to ../vana-sdk/packages/vana-sdk`,
  );
}

async function validateImportSmoke(
  specifier: `${typeof SDK_PACKAGE}/${string}`,
) {
  try {
    const expectedExports = [
      "deriveMasterKey",
      "deriveScopeKey",
      "encryptWithPassword",
      "decryptWithPassword",
      "verifyWeb3Signed",
    ];
    const script = `
      const mod = await import(${JSON.stringify(specifier)});
      const missing = ${JSON.stringify(expectedExports)}.filter((name) => typeof mod[name] !== "function");
      if (missing.length > 0) {
        throw new Error("missing exports: " + missing.join(","));
      }
    `;
    await execFileAsync(
      process.execPath,
      ["--input-type=module", "-e", script],
      {
        cwd: "packages/core",
      },
    );
  } catch (err) {
    if (err instanceof Error) {
      violations.push(`${specifier} import smoke failed: ${err.message}`);
    } else {
      violations.push(`${specifier} import smoke failed`);
    }
  }
}

await validateImportSmoke("@opendatalabs/vana-sdk/node");
await validateImportSmoke("@opendatalabs/vana-sdk/browser");

if (violations.length > 0) {
  console.error(
    [
      "vana-sdk validation failed.",
      "Root imports from @opendatalabs/vana-sdk are forbidden; use /node or /browser.",
      `${SDK_PACKAGE} must resolve from the sibling ../vana-sdk checkout while PR 137 is active.`,
      ...violations.map((violation) => `- ${violation}`),
    ].join("\n"),
  );
  process.exit(1);
}
