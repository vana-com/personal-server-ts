import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
const memoryRoot = process.env.TMPDIR ?? join(homedir(), ".tmp");
mkdirSync(memoryRoot, { recursive: true });
const fixture = new URL("./pdpp-replication-memory.fixture.ts", import.meta.url)
  .pathname;
const args = (mode: string, directory: string, size: number) => [
  "--import",
  "tsx",
  fixture,
  mode,
  directory,
  String(size),
];

it("reads an existing 64 MiB legacy SQLite blob without a quadratic substr scan", () => {
  const dir = mkdtempSync(join(memoryRoot, "replica-legacy-"));
  try {
    const size = 64 * 1024 * 1024;
    const seeded = spawnSync(process.execPath, args("seed-legacy", dir, size), {
      encoding: "utf8",
      timeout: 30000,
    });
    expect(seeded.status, seeded.stderr).toBe(0);
    const child = spawnSync(process.execPath, args("legacy-read", dir, size), {
      encoding: "utf8",
      timeout: 15000,
    });
    expect(child.status, child.error?.message ?? child.stderr).toBe(0);
    expect(JSON.parse(child.stdout).size).toBe(size);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}, 40000);

it("rejects a second process while payload staging is active and recovers after the holder dies", async () => {
  const dir = mkdtempSync(join(memoryRoot, "replica-lock-"));
  const seeded = spawnSync(
    process.execPath,
    args("seed", dir, 2 * 1024 * 1024),
    { encoding: "utf8", timeout: 30000 },
  );
  expect(seeded.status, seeded.stderr).toBe(0);
  const child = spawn(process.execPath, args("measure", dir, 2 * 1024 * 1024), {
    env: { ...process.env, REPLICA_PAUSE_DIR: dir },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let errors = "";
  child.stderr.on("data", (chunk) => {
    errors += chunk;
  });
  const closed = new Promise((resolve) => child.once("close", resolve));
  try {
    const deadline = Date.now() + 15000;
    while (
      !existsSync(join(dir, "paused")) &&
      Date.now() < deadline &&
      child.exitCode === null
    )
      await new Promise((resolve) => setTimeout(resolve, 20));
    expect(existsSync(join(dir, "paused")), errors).toBe(true);
    const second = spawnSync(
      process.execPath,
      args("probe", dir, 2 * 1024 * 1024),
      { encoding: "utf8", timeout: 15000 },
    );
    expect(second.status, second.stderr).toBe(2);
    child.kill("SIGKILL");
    await closed;
    const restarted = spawnSync(
      process.execPath,
      args("probe", dir, 2 * 1024 * 1024),
      { encoding: "utf8", timeout: 15000 },
    );
    expect(restarted.status, restarted.stderr).toBe(0);
  } finally {
    if (child.exitCode === null) child.kill("SIGKILL");
    await closed;
    rmSync(dir, { recursive: true, force: true });
  }
}, 60000);
