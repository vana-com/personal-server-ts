import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { expect, it } from "vitest";
import {
  BINARY_CHUNK_BYTES,
  BINARY_CHUNKS_MIGRATION,
  LEGACY_WINDOWS,
  readBinaryChunks,
} from "./pdpp-binary-chunks.js";
const memoryRoot = tmpdir();
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

/**
 * SQLite reaches a BLOB offset by walking its overflow pages, so reading a
 * legacy whole-value row one 64 KiB chunk at a time costs O(size^2): 37 s for
 * 64 MiB. Timing proves nothing on a loaded host, so this checks the read
 * strategy instead: a bounded number of windows, and a total overflow walk
 * (the sum of the window offsets) that is a small multiple of the blob.
 */
it("reads an existing 64 MiB legacy SQLite blob without a quadratic substr scan", () => {
  for (const size of [16 * 1024 * 1024, 64 * 1024 * 1024]) {
    const db = new Database(":memory:");
    try {
      db.exec(BINARY_CHUNKS_MIGRATION);
      db.exec(
        "CREATE TABLE IF NOT EXISTS pdpp_blob_bytes (blob_id TEXT PRIMARY KEY, bytes BLOB NOT NULL)",
      );
      const bytes = Buffer.alloc(size, 31);
      bytes.writeUInt32BE(0xdeadbeef, 0);
      bytes.writeUInt32BE(0xfeedface, size - 4);
      db.prepare("INSERT INTO pdpp_blob_bytes VALUES ('legacy', ?)").run(bytes);
      const starts: number[] = [];
      const traced = new Proxy(db, {
        get(target, property) {
          if (property !== "prepare") {
            const value = Reflect.get(target, property, target);
            return typeof value === "function" ? value.bind(target) : value;
          }
          return (sql: string) => {
            const statement = target.prepare(sql);
            if (!sql.includes("substr(")) return statement;
            return new Proxy(statement, {
              get(inner, member) {
                if (member !== "get") return Reflect.get(inner, member, inner);
                return (...args: unknown[]) => {
                  starts.push(args[0] as number);
                  return inner.get(...args);
                };
              },
            });
          };
        },
      });
      let total = 0;
      let first: Uint8Array | undefined;
      let last: Uint8Array | undefined;
      for (const chunk of readBinaryChunks(traced, "canonical", "legacy")) {
        first ??= chunk;
        last = chunk;
        expect(chunk.length).toBeLessThanOrEqual(BINARY_CHUNK_BYTES);
        total += chunk.length;
      }
      expect(total).toBe(size);
      expect(Buffer.from(first!).readUInt32BE(0)).toBe(0xdeadbeef);
      expect(Buffer.from(last!).readUInt32BE(last!.length - 4)).toBe(
        0xfeedface,
      );
      expect(starts.length).toBeLessThanOrEqual(LEGACY_WINDOWS);
      expect(starts.reduce((sum, start) => sum + start, 0)).toBeLessThan(
        size * 8,
      );
    } finally {
      db.close();
    }
  }
}, 60000);

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
