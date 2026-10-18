import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { initializeDatabase } from "../../packages/server/src/storage/index-schema.js";
import { createIndexManager } from "../../packages/server/src/storage/index-manager.js";
import { createNodeDataStorage } from "../../packages/server/src/storage/node-data-storage.js";

const operation = "a".repeat(64);
const scope = "github.events";

function startImport(root: string, body: unknown, interrupt = false) {
  const script = `
    import fs from "node:fs";
    import { syncBuiltinESMExports } from "node:module";
    import { join } from "node:path";
    import { pino } from "pino";
    const root = process.env.IMPORT_TEST_ROOT;
    if (process.env.IMPORT_TEST_INTERRUPT === "1") {
      const link = fs.linkSync;
      fs.linkSync = (...args) => {
        link(...args);
        fs.writeSync(1, "published:" + args[1] + "\\n");
        process.kill(process.pid, "SIGKILL");
      };
      syncBuiltinESMExports();
    }
    const { initializeDatabase } = await import("./packages/server/dist/storage/index-schema.js");
    const { createIndexManager } = await import("./packages/server/dist/storage/index-manager.js");
    const { dataRoutes } = await import("./packages/server/dist/routes/data.js");
    const index = createIndexManager(initializeDatabase(join(root, "index.db")));
    const app = dataRoutes({ indexManager: index, hierarchyOptions: { dataDir: join(root, "data") }, logger: pino({ level: "silent" }), serverOrigin: "http://localhost:8080", serverOwner: "0x1111111111111111111111111111111111111111", devToken: "test-owner", gateway: {}, accessLogWriter: { write: async () => {} } });
    process.stdout.write("ready\\n");
    for await (const chunk of process.stdin) { if (chunk.length) break; }
    const response = await app.request("/${scope}/imports/${operation}", { method: "PUT", headers: { Authorization: "Bearer test-owner", "Content-Type": "application/json" }, body: process.env.IMPORT_TEST_BODY });
    process.stdout.write(JSON.stringify({ status: response.status, body: await response.json() }) + "\\n");
    index.close();
  `;
  const child = spawn(process.execPath, ["--input-type=module", "-e", script], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      IMPORT_TEST_ROOT: root,
      IMPORT_TEST_BODY: JSON.stringify(body),
      IMPORT_TEST_INTERRUPT: interrupt ? "1" : "0",
    },
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  let readyResolve: () => void;
  const ready = new Promise<void>((resolve) => {
    readyResolve = resolve;
  });
  child.stdout.on("data", (chunk) => {
    stdout += chunk.toString();
    if (stdout.includes("ready\n")) readyResolve();
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });
  const done = new Promise<{
    code: number | null;
    signal: NodeJS.Signals | null;
    stdout: string;
    stderr: string;
  }>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      readyResolve();
      resolve({ code, signal, stdout, stderr });
    });
  });
  return { ready, done, release: () => child.stdin.end("go\n") };
}

function response(output: string): {
  status: number;
  body: { importReceipt: unknown };
} {
  return JSON.parse(output.trim().split("\n").at(-1)!);
}

describe("owner imports with independent processes", () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "owner-import-process-"));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("converges concurrent first-start imports on an empty root and refuses a conflicting retry", async () => {
    const a = startImport(root, { value: "A" });
    const b = startImport(root, { value: "A" });
    await Promise.all([a.ready, b.ready]);
    a.release();
    b.release();
    const results = await Promise.all([a.done, b.done]);
    for (const result of results)
      expect(result, result.stderr).toMatchObject({ code: 0, signal: null });
    const receipts = results.map((result) => response(result.stdout));
    expect(receipts.map((r) => r.status).sort()).toEqual([200, 201]);
    expect(receipts[0].body.importReceipt).toEqual(
      receipts[1].body.importReceipt,
    );
    const conflict = startImport(root, { value: "B" });
    await conflict.ready;
    conflict.release();
    const rejected = await conflict.done;
    expect(rejected.code, rejected.stderr).toBe(0);
    expect(response(rejected.stdout).status).toBe(409);
    const index = createIndexManager(
      initializeDatabase(join(root, "index.db")),
    );
    try {
      expect(index.countByScope(scope)).toBe(1);
    } finally {
      index.close();
    }
  });

  it("recovers the original stamp after process death between file publication and index commit", async () => {
    const interrupted = startImport(root, { value: "A" }, true);
    await interrupted.ready;
    interrupted.release();
    const stopped = await interrupted.done;
    expect(stopped.signal, stopped.stderr).toBe("SIGKILL");
    const path = stopped.stdout
      .split("\n")
      .find((line) => line.startsWith("published:"))!
      .slice("published:".length);
    expect(existsSync(path)).toBe(true);
    const envelope = JSON.parse(await readFile(path, "utf8"));
    const before = createIndexManager(
      initializeDatabase(join(root, "index.db")),
    );
    try {
      expect(before.countByScope(scope)).toBe(0);
    } finally {
      before.close();
    }
    const retry = startImport(root, { value: "A" });
    await retry.ready;
    retry.release();
    const recovered = await retry.done;
    expect(recovered.code, recovered.stderr).toBe(0);
    const accepted = response(recovered.stdout);
    expect(accepted.status).toBe(200);
    expect(accepted.body.importReceipt).toMatchObject({
      operation,
      scope,
      collectedAt: envelope.collectedAt,
    });
    const after = createIndexManager(
      initializeDatabase(join(root, "index.db")),
    );
    try {
      expect(after.countByScope(scope)).toBe(1);
      expect(after.findLatestByScope(scope)?.collectedAt).toBe(
        envelope.collectedAt,
      );
    } finally {
      after.close();
    }
    expect(JSON.parse(await readFile(path, "utf8"))).toEqual(envelope);
  });

  it("cancels an unindexed prepared version before a later process can reconstruct it", async () => {
    const index = createIndexManager(
      initializeDatabase(join(root, "index.db")),
    );
    const storage = createNodeDataStorage({
      indexManager: index,
      hierarchyOptions: { dataDir: join(root, "data") },
    });
    try {
      const interrupted = startImport(root, { value: "A" }, true);
      await interrupted.ready;
      interrupted.release();
      const stopped = await interrupted.done;
      expect(stopped.signal, stopped.stderr).toBe("SIGKILL");
      const path = stopped.stdout
        .split("\n")
        .find((line) => line.startsWith("published:"))!
        .slice("published:".length);
      const envelope = JSON.parse(await readFile(path, "utf8"));
      expect(await storage.deleteVersion(scope, envelope.collectedAt)).toBe(
        false,
      );
      expect(existsSync(path)).toBe(false);
      const retry = startImport(root, { value: "A" });
      await retry.ready;
      retry.release();
      const denied = await retry.done;
      expect(denied.code, denied.stderr).toBe(0);
      expect(response(denied.stdout).status).toBe(410);
      expect(index.countByScope(scope)).toBe(0);
      expect(existsSync(path)).toBe(false);
    } finally {
      index.close();
    }
  });
});
