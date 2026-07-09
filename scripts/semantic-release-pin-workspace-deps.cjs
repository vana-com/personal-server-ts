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

function pinWorkspaceDeps(version) {
  for (const rel of PACKAGE_FILES) {
    const filePath = path.resolve(process.cwd(), rel);
    const pkg = JSON.parse(fs.readFileSync(filePath, "utf8"));
    let changed = false;

    for (const field of [
      "dependencies",
      "devDependencies",
      "peerDependencies",
    ]) {
      const deps = pkg[field];
      if (!deps) continue;
      for (const name of Object.keys(deps)) {
        if (INTERNAL_DEP.test(name) && deps[name] !== version) {
          deps[name] = version;
          changed = true;
        }
      }
    }

    if (changed) {
      fs.writeFileSync(filePath, `${JSON.stringify(pkg, null, 2)}\n`);
    }
  }
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
};
