import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import {
  existsSync,
  symlinkSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const templates = [
  "docker-compose.fleet-worker.yml",
  "docker-compose.fleet-controller.yml",
  "docker-compose.enclave.yml",
  "docker-compose.enclave.inline.yml",
  "docker-compose.mcp-demo.yml",
];

for (const template of templates) {
  for (const scenario of ["stale checkout", "symlink", "nested mount"]) {
    test(`${template}: ${scenario}`, () => {
      const root = mkdtempSync(join(tmpdir(), "dstack-checkout-"));
      try {
        const origin = join(root, "origin");
        const app = join(root, "app");
        mkdirSync(origin);
        const git = (...args) =>
          execFileSync("git", args, {
            cwd: origin,
            encoding: "utf8",
            stdio: ["ignore", "pipe", "pipe"],
          }).trim();
        git("init", "--quiet");
        writeFileSync(join(origin, "source.txt"), "reviewed source\n");
        git("add", "source.txt");
        git(
          "-c",
          "user.name=Fixture",
          "-c",
          "user.email=fixture@example.invalid",
          "commit",
          "--quiet",
          "-m",
          "fixture",
        );
        const ref = git("rev-parse", "HEAD");
        git("clone", "--quiet", "--depth", "1", `file://${origin}`, app);
        writeFileSync(join(app, ".git", "shallow.lock"), "interrupted fetch\n");
        writeFileSync(join(app, "partial-build.txt"), "interrupted build\n");
        for (const volume of ["mcp-state", "fleet-state"]) {
          mkdirSync(join(root, volume));
          writeFileSync(join(root, volume, "protected"), volume);
        }
        const mountinfo = join(root, "mountinfo");
        writeFileSync(
          mountinfo,
          scenario === "nested mount"
            ? `1 0 0:1 / ${app}/state rw - tmpfs tmpfs rw\n`
            : "",
        );
        if (scenario === "symlink") {
          rmSync(app, { recursive: true, force: true });
          symlinkSync(origin, app);
        }
        const yaml = readFileSync(
          fileURLToPath(new URL(template, import.meta.url)),
          "utf8",
        );
        const command = yaml
          .split("      - |\n")[1]
          .split("\n")
          .filter((line) => line.startsWith("        "))
          .map((line) => line.slice(8))
          .join("\n");
        let checkout = command
          .slice(0, command.indexOf("npm ci "))
          .replaceAll("$$", "$");
        checkout = checkout
          .replace(/^apk add .*$/gm, ":")
          .replace(/^date .*$/gm, ":");
        checkout = checkout
          .replaceAll("REPLACE_WITH_REVIEWED_40_HEX_COMMIT", ref)
          .replaceAll(
            "REPLACE_WITH_REVIEWED_PS_IMAGE_DIGEST",
            `fixture@sha256:${"0".repeat(64)}`,
          );
        checkout = checkout
          .replaceAll(
            "https://github.com/vana-com/personal-server-ts",
            `file://${origin}`,
          )
          .replaceAll("/app", app)
          .replaceAll("/proc/self/mountinfo", mountinfo);
        checkout = `docker() { return 0; }\n${checkout}`;
        const result = spawnSync("sh", ["-ec", checkout], {
          cwd: app,
          encoding: "utf8",
          env: {
            ...process.env,
            GIT_REF: ref,
            PS_IMAGE: `fixture@sha256:${"0".repeat(64)}`,
          },
        });
        if (scenario !== "stale checkout") {
          assert.equal(result.status, 1, result.stderr);
          assert.match(result.stderr, /must be unmounted disposable source/);
          assert.equal(
            readFileSync(join(origin, "source.txt"), "utf8"),
            "reviewed source\n",
          );
          return;
        }
        assert.equal(result.status, 0, result.stderr);
        assert.equal(existsSync(join(app, "partial-build.txt")), false);
        assert.equal(
          execFileSync("git", ["rev-parse", "HEAD"], {
            cwd: app,
            encoding: "utf8",
          }).trim(),
          ref,
        );
        assert.equal(
          readFileSync(join(app, "source.txt"), "utf8"),
          "reviewed source\n",
        );
        for (const volume of ["mcp-state", "fleet-state"]) {
          assert.equal(
            readFileSync(join(root, volume, "protected"), "utf8"),
            volume,
          );
        }
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
    });
  }
}
