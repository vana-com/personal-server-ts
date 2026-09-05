import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const sha = "a".repeat(40);
const digest = "0".repeat(64);
const temporaryRoots: string[] = [];

function temporaryRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "ps-images-env-"));
  temporaryRoots.push(root);
  return root;
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

describe("TEE image environment loading", () => {
  it("reads only valid image keys without executing the file", () => {
    const root = temporaryRoot();
    const imagesEnv = join(root, "images.env");
    const marker = join(root, "executed");
    const common = join(repositoryRoot, "scripts/tee/common.sh");

    writeFileSync(
      imagesEnv,
      [
        `PS_IMAGE=vanaorg/personal-server@sha256:${digest}`,
        `PS_IMAGE_REF=${sha}`,
        "GIT_REF=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "AGENT_IMAGE=attacker.example/agent:latest",
        "DIND_IMAGE=attacker.example/dind:latest",
        `touch ${marker}`,
        "",
      ].join("\n"),
    );

    const result = spawnSync(
      "bash",
      [
        "-c",
        `set -euo pipefail
source "$1"
GIT_REF=${sha}
AGENT_IMAGE=node@sha256:${digest}
DIND_IMAGE=docker@sha256:${digest}
load_images_env "$2"
printf '%s\\n' "$PS_IMAGE" "$PS_IMAGE_REF" "$GIT_REF" "$AGENT_IMAGE" "$DIND_IMAGE"`,
        "test",
        common,
        imagesEnv,
      ],
      { encoding: "utf8" },
    );

    expect(result.status, result.stderr).toBe(0);
    expect(existsSync(marker)).toBe(false);
    expect(result.stdout.trim().split("\n")).toEqual([
      `vanaorg/personal-server@sha256:${digest}`,
      sha,
      sha,
      `node@sha256:${digest}`,
      `docker@sha256:${digest}`,
    ]);
  });

  it("does not load images.env for provision --inline", () => {
    const root = temporaryRoot();
    const scriptDirectory = join(root, "scripts/tee");
    const deployDirectory = join(root, "deploy/dstack");
    const binDirectory = join(root, "bin");
    mkdirSync(scriptDirectory, { recursive: true });
    mkdirSync(deployDirectory, { recursive: true });
    mkdirSync(binDirectory, { recursive: true });
    copyFileSync(
      join(repositoryRoot, "scripts/tee/common.sh"),
      join(scriptDirectory, "common.sh"),
    );
    copyFileSync(
      join(repositoryRoot, "scripts/tee/provision.sh"),
      join(scriptDirectory, "provision.sh"),
    );
    writeFileSync(
      join(deployDirectory, "docker-compose.enclave.inline.yml"),
      "services: {}\n",
    );
    writeFileSync(
      join(deployDirectory, "images.env"),
      `PS_IMAGE=vanaorg/personal-server@sha256:${digest}\nPS_IMAGE_REF=${sha}\n`,
    );
    const phala = join(binDirectory, "phala");
    writeFileSync(phala, "#!/bin/sh\necho reached-phala-deploy >&2\nexit 77\n");
    chmodSync(phala, 0o755);

    const environment = { ...process.env };
    delete environment.PS_IMAGE;
    delete environment.PS_IMAGE_REF;
    const result = spawnSync(
      "bash",
      [
        join(scriptDirectory, "provision.sh"),
        "inline-test",
        "--inline",
        "--ref",
        sha,
        "--app-id",
        sha,
        "--nonce",
        "0",
      ],
      {
        encoding: "utf8",
        env: {
          ...environment,
          PATH: `${binDirectory}:${process.env.PATH ?? ""}`,
          ENCLAVE_AGENT_SECRET: "test-agent-secret",
          AGENT_IMAGE: `node@sha256:${digest}`,
          DIND_IMAGE: `docker@sha256:${digest}`,
          NODE_SECRET: "test-node-secret",
          NODE_ID: "test-node",
          GATEWAY_URL: "https://gateway.example",
        },
      },
    );

    expect(result.status).toBe(77);
    expect(result.stderr).toContain("reached-phala-deploy");
    expect(result.stderr).not.toContain("PS_IMAGE must be a local image tag");
  });
});
