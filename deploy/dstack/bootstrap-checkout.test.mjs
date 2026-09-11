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

// The fleet composes run prebuilt images and no longer clone at boot, so only
// the level-B templates still have a checkout bootstrap to harden.
const templates = [
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

// The fleet composes were dropped from the checkout hardening above because
// they no longer clone at boot. This guards that property directly: no
// boot-time fetch or build, and every image pinned by digest (or still a
// reviewed placeholder waiting for one).
const fleetTemplates = [
  "docker-compose.fleet-controller.yml",
  "docker-compose.fleet-worker.yml",
];

const bootBuildSteps = [
  /\bgit\s/,
  /\bnpm\s+(ci|install)\b/,
  /\bapk\s+add\b/,
  /\bcurl\b/,
  /\btsc\b/,
  /^\s*build:/,
];
const imageLine = /^\s*image:\s*"?([^"\s]+)"?\s*$/;
const imageDigest = /^\S+@sha256:[0-9a-f]{64}$/;
const reviewedPlaceholder = /^REPLACE_WITH_REVIEWED_[A-Z0-9_]+$/;

for (const template of fleetTemplates) {
  test(`${template}: prebuilt images, no boot-time build`, () => {
    const yaml = readFileSync(
      fileURLToPath(new URL(template, import.meta.url)),
      "utf8",
    );
    // Comments describe what was removed; only executable lines are checked.
    const lines = yaml
      .split("\n")
      .filter((line) => !line.trimStart().startsWith("#"));

    const images = [];
    for (const line of lines) {
      for (const step of bootBuildSteps) {
        assert.equal(step.test(line), false, `boot-time build step: ${line}`);
      }
      const image = line.match(imageLine)?.[1];
      if (image) images.push(image);
    }

    assert.ok(images.length > 0, "no image: line found");
    for (const image of images) {
      assert.ok(
        imageDigest.test(image) || reviewedPlaceholder.test(image),
        `image must be a digest or a reviewed placeholder: ${image}`,
      );
    }
  });
}

// The worker agent gates on a healthy sandbox-runtime: starting it against a
// half-configured runtime cost every dstack /Info ~15 s on 2026-09-11, over the
// Gateway's 15 s identity budget. That gate is only safe while the runtime's
// healthcheck budget outlasts a slow dockerd, so both halves are pinned here.
const RUNTIME_HEALTH_BUDGET_MS = 5 * 60 * 1000;

test("docker-compose.fleet-worker.yml: agent waits for a converging runtime", () => {
  const yaml = readFileSync(
    fileURLToPath(new URL("docker-compose.fleet-worker.yml", import.meta.url)),
    "utf8",
  );
  const lines = yaml
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("#"));
  const seconds = (key) => {
    const raw = lines.find((line) => line.trim().startsWith(`${key}:`));
    return Number(raw?.split(":")[1]?.trim().replace("s", ""));
  };

  assert.ok(
    lines.some((line) => line.trim() === "condition: service_healthy"),
    "the agent must depend on a healthy sandbox-runtime",
  );
  assert.ok(
    lines.some((line) => line.trim() === "restart: unless-stopped"),
    "the agent must restart on its own after a failed start",
  );

  // Failures inside start_period never consume a retry, so the wait before
  // compose calls the runtime unhealthy is start_period + retries x interval.
  const budget =
    (seconds("start_period") + seconds("retries") * seconds("interval")) * 1000;
  assert.ok(
    budget >= RUNTIME_HEALTH_BUDGET_MS,
    `runtime healthcheck budget ${budget} ms is too short to converge`,
  );
});
