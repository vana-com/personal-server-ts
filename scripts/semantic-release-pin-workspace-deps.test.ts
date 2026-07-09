import { createRequire } from "node:module";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const require = createRequire(import.meta.url);
const releasePlugin = require("./semantic-release-pin-workspace-deps.cjs");

const workspaces = ["core", "lite", "server", "cli"];

describe("semantic release workspace versioning", () => {
  it("updates every workspace and lock entry atomically and idempotently", () => {
    const root = mkdtempSync(join(tmpdir(), "ps-release-"));
    const previousCwd = process.cwd();

    try {
      const lockPackages: Record<string, unknown> = {};

      for (const workspace of workspaces) {
        const directory = join(root, "packages", workspace);
        mkdirSync(directory, { recursive: true });
        const manifest = {
          name: `@opendatalabs/personal-server-ts-${workspace}`,
          version: "0.0.1",
          dependencies: {
            "@opendatalabs/personal-server-ts-core": "*",
            "external-package": "^2.0.0",
          },
        };
        writeFileSync(
          join(directory, "package.json"),
          `${JSON.stringify(manifest, null, 2)}\n`,
        );
        lockPackages[`packages/${workspace}`] = structuredClone(manifest);
      }

      writeFileSync(
        join(root, "package-lock.json"),
        `${JSON.stringify({ packages: lockPackages }, null, 2)}\n`,
      );

      process.chdir(root);
      releasePlugin.prepare({}, { nextRelease: { version: "1.0.1" } });

      const firstResult = workspaces.map((workspace) =>
        readFileSync(join(root, "packages", workspace, "package.json"), "utf8"),
      );
      const lock = JSON.parse(
        readFileSync(join(root, "package-lock.json"), "utf8"),
      );

      for (const [index, workspace] of workspaces.entries()) {
        const manifest = JSON.parse(firstResult[index]);
        expect(manifest.version).toBe("1.0.1");
        expect(
          manifest.dependencies["@opendatalabs/personal-server-ts-core"],
        ).toBe("1.0.1");
        expect(manifest.dependencies["external-package"]).toBe("^2.0.0");

        const lockManifest = lock.packages[`packages/${workspace}`];
        expect(lockManifest.version).toBe("1.0.1");
        expect(
          lockManifest.dependencies["@opendatalabs/personal-server-ts-core"],
        ).toBe("1.0.1");
      }

      releasePlugin.prepare({}, { nextRelease: { version: "1.0.1" } });
      expect(
        workspaces.map((workspace) =>
          readFileSync(
            join(root, "packages", workspace, "package.json"),
            "utf8",
          ),
        ),
      ).toEqual(firstResult);
    } finally {
      process.chdir(previousCwd);
      rmSync(root, { recursive: true, force: true });
    }
  });
});
