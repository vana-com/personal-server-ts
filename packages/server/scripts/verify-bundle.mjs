import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = resolve(packageRoot, "../..");

const [bundle, runtimePackage, runtimeLock, rootLock] = await Promise.all([
  readFile(resolve(packageRoot, "dist/bundle/enclave-main.mjs"), "utf8"),
  readJson(resolve(packageRoot, "bundle-runtime/package.json")),
  readJson(resolve(packageRoot, "bundle-runtime/package-lock.json")),
  readJson(resolve(repositoryRoot, "package-lock.json")),
]);

const nativeLoaderPatterns = [
  ["node-gyp-build", /node-gyp-build|require_node_gyp_build/],
  ["bindings", /require_bindings|\bbindings\(/],
  ["native .node lookup", /\\\.node\$|\.node["']/],
];

for (const [label, pattern] of nativeLoaderPatterns) {
  if (pattern.test(bundle)) {
    throw new Error(
      `Bundle contains ${label}; externalize the package that loads the native addon`,
    );
  }
}

const runtimeDependencies = runtimePackage.dependencies ?? {};
const runtimeLockDependencies = runtimeLock.packages?.[""]?.dependencies ?? {};

for (const [name, expectedVersion] of Object.entries(runtimeDependencies)) {
  const rootVersion = rootLock.packages?.[`node_modules/${name}`]?.version;
  const runtimeLockVersion =
    runtimeLock.packages?.[`node_modules/${name}`]?.version;

  if (rootVersion !== expectedVersion) {
    throw new Error(
      `${name} runtime pin ${expectedVersion} does not match root lock ${String(rootVersion)}`,
    );
  }
  if (
    runtimeLockDependencies[name] !== expectedVersion ||
    runtimeLockVersion !== expectedVersion
  ) {
    throw new Error(
      `${name} runtime lock does not resolve the manifest pin ${expectedVersion}`,
    );
  }
}

console.log(
  `Verified bundle native loaders and ${Object.keys(runtimeDependencies).length} runtime dependency pins`,
);

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}
