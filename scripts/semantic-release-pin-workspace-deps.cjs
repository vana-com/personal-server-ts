/**
 * semantic-release prepare plugin: rewrite monorepo workspace dependencies
 * (`*` → nextRelease.version) so published packages pin same-version
 * @opendatalabs/personal-server-ts-{core,lite,server}.
 *
 * Mirrors the canary pin step in .github/workflows/prerelease.yml.
 * @semantic-release/npm only bumps each package's own `version` field.
 */
const fs = require("node:fs");
const path = require("node:path");

const PACKAGE_FILES = [
  "packages/core/package.json",
  "packages/lite/package.json",
  "packages/server/package.json",
  "packages/cli/package.json",
];

const INTERNAL_DEP = /^@opendatalabs\/personal-server-ts(-|$)/;

const DEP_FIELDS = ["dependencies", "devDependencies", "peerDependencies"];

function pinInternalDepsInPackage(pkg, version) {
  let changed = false;

  for (const field of DEP_FIELDS) {
    const deps = pkg[field];
    if (!deps) continue;
    for (const name of Object.keys(deps)) {
      if (INTERNAL_DEP.test(name) && deps[name] !== version) {
        deps[name] = version;
        changed = true;
      }
    }
  }

  return changed;
}

function pinWorkspacePackageJsonFiles(version) {
  for (const rel of PACKAGE_FILES) {
    const filePath = path.resolve(process.cwd(), rel);
    const pkg = JSON.parse(fs.readFileSync(filePath, "utf8"));

    if (pinInternalDepsInPackage(pkg, version)) {
      fs.writeFileSync(filePath, `${JSON.stringify(pkg, null, 2)}\n`);
    }
  }
}

function pinPackageLock(version) {
  const lockPath = path.resolve(process.cwd(), "package-lock.json");
  if (!fs.existsSync(lockPath)) return;

  const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
  const packages = lock.packages;
  if (!packages || typeof packages !== "object") return;

  let changed = false;
  for (const rel of PACKAGE_FILES) {
    const workspacePath = path.dirname(rel);
    const pkg = packages[workspacePath];
    if (!pkg) continue;
    changed = pinInternalDepsInPackage(pkg, version) || changed;
  }

  if (changed) {
    fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
  }
}

function pinWorkspaceDeps(version) {
  pinWorkspacePackageJsonFiles(version);
  pinPackageLock(version);
}

module.exports = {
  prepare(_pluginConfig, { nextRelease }) {
    if (!nextRelease?.version) {
      throw new Error(
        "semantic-release-pin-workspace-deps: missing nextRelease.version",
      );
    }
    pinWorkspaceDeps(nextRelease.version);
  },
  _private: {
    pinWorkspaceDeps,
  },
};
