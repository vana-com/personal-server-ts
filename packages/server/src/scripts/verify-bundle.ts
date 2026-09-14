import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { findUndeclaredRuntimeImports } from "./bundle-verification.js";

interface PackageManifest {
  dependencies?: Record<string, string>;
}

interface PackageLock {
  packages?: Record<string, PackageManifest & { version?: string }>;
}

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const repositoryRoot = resolve(packageRoot, "../..");

const [bundle, runtimePackage, runtimeLock, rootLock] = await Promise.all([
  readFile(resolve(packageRoot, "dist/bundle/enclave-main.mjs"), "utf8"),
  readJson<PackageManifest>(
    resolve(packageRoot, "bundle-runtime/package.json"),
  ),
  readJson<PackageLock>(
    resolve(packageRoot, "bundle-runtime/package-lock.json"),
  ),
  readJson<PackageLock>(resolve(repositoryRoot, "package-lock.json")),
]);

const nativeLoaderPatterns: ReadonlyArray<readonly [string, RegExp]> = [
  ["node-gyp-build", /^\/\/ node_modules\/node-gyp-build(?:\/|$)/m],
  ["bindings", /^\/\/ node_modules\/bindings(?:\/|$)/m],
  ["native .node lookup", /^\s*return \/\\\.node\$\/\.test\(name\);?\s*$/m],
];

for (const [label, pattern] of nativeLoaderPatterns) {
  if (pattern.test(bundle)) {
    throw new Error(
      `Bundle contains ${label}; externalize the package that loads the native addon`,
    );
  }
}

const runtimeDependencies = runtimePackage.dependencies ?? {};
const undeclaredRuntimeImports = findUndeclaredRuntimeImports(
  bundle,
  new Set(Object.keys(runtimeDependencies)),
);

if (undeclaredRuntimeImports.length > 0) {
  throw new Error(
    `Bundle imports packages absent from bundle-runtime: ${undeclaredRuntimeImports.join(", ")}`,
  );
}

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
  `Verified bundle imports, native loaders, and ${Object.keys(runtimeDependencies).length} runtime dependency pins`,
);

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}
