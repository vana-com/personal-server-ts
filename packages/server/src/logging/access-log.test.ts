import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  mkdtemp,
  rm,
  readdir,
  readFile,
  mkdir,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createAccessLogWriter, type AccessLogEntry } from "./access-log.js";
import { createAccessLogReader } from "./access-reader.js";

function makeEntry(overrides: Partial<AccessLogEntry> = {}): AccessLogEntry {
  return {
    logId: "test-log-id",
    grantId: "test-grant-id",
    builder: "0x1234567890abcdef1234567890abcdef12345678",
    action: "read",
    scope: "instagram.profile",
    timestamp: "2026-01-28T12:00:00Z",
    ipAddress: "127.0.0.1",
    userAgent: "TestAgent/1.0",
    ...overrides,
  };
}

describe("AccessLogWriter", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "access-log-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("write() creates log file in correct directory", async () => {
    const logsDir = join(tempDir, "logs");
    const writer = createAccessLogWriter(logsDir);

    await writer.write(makeEntry());

    const files = await readdir(logsDir);
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(/^access-.*\.log$/);
  });

  it("log file name follows access-{YYYY-MM-DD}.log pattern", async () => {
    const logsDir = join(tempDir, "logs");
    const writer = createAccessLogWriter(logsDir);

    await writer.write(makeEntry({ timestamp: "2026-01-28T12:00:00Z" }));

    const files = await readdir(logsDir);
    expect(files[0]).toBe("access-2026-01-28.log");
  });

  it("file content is valid JSON line", async () => {
    const logsDir = join(tempDir, "logs");
    const writer = createAccessLogWriter(logsDir);

    const entry = makeEntry();
    await writer.write(entry);

    const content = await readFile(
      join(logsDir, "access-2026-01-28.log"),
      "utf-8",
    );
    const lines = content.trim().split("\n");
    expect(lines).toHaveLength(1);

    const parsed = JSON.parse(lines[0]);
    expect(parsed.logId).toBe("test-log-id");
    expect(parsed.grantId).toBe("test-grant-id");
    expect(parsed.builder).toBe("0x1234567890abcdef1234567890abcdef12345678");
    expect(parsed.action).toBe("read");
    expect(parsed.scope).toBe("instagram.profile");
    expect(parsed.timestamp).toBe("2026-01-28T12:00:00Z");
    expect(parsed.ipAddress).toBe("127.0.0.1");
    expect(parsed.userAgent).toBe("TestAgent/1.0");
  });

  it("two writes same day produce same file with 2 lines", async () => {
    const logsDir = join(tempDir, "logs");
    const writer = createAccessLogWriter(logsDir);

    await writer.write(
      makeEntry({ logId: "log-1", timestamp: "2026-01-28T10:00:00Z" }),
    );
    await writer.write(
      makeEntry({ logId: "log-2", timestamp: "2026-01-28T22:00:00Z" }),
    );

    const files = await readdir(logsDir);
    expect(files).toHaveLength(1);
    expect(files[0]).toBe("access-2026-01-28.log");

    const content = await readFile(join(logsDir, files[0]), "utf-8");
    const lines = content.trim().split("\n");
    expect(lines).toHaveLength(2);

    expect(JSON.parse(lines[0]).logId).toBe("log-1");
    expect(JSON.parse(lines[1]).logId).toBe("log-2");
  });

  it("uses the UTC day for a timestamp with a local offset", async () => {
    const writer = createAccessLogWriter(tempDir);
    await writer.write(
      makeEntry({ logId: "offset", timestamp: "2026-01-28T23:30:00-02:00" }),
    );
    await writer.write(
      makeEntry({ logId: "utc", timestamp: "2026-01-29T01:30:00Z" }),
    );

    expect(await readdir(tempDir)).toEqual(["access-2026-01-29.log"]);
    const content = await readFile(
      join(tempDir, "access-2026-01-29.log"),
      "utf-8",
    );
    expect(
      content
        .trimEnd()
        .split("\n")
        .map((line) => JSON.parse(line).logId),
    ).toEqual(["offset", "utc"]);
  });

  it("keeps an embedded newline inside a single JSONL record", async () => {
    const writer = createAccessLogWriter(tempDir);
    const userAgent = "Synthetic client\nsecond line";
    await writer.write(makeEntry({ userAgent }));
    await writer.write(makeEntry({ logId: "next-entry" }));

    const content = await readFile(
      join(tempDir, "access-2026-01-28.log"),
      "utf-8",
    );
    const lines = content.split("\n");
    expect(lines).toHaveLength(3);
    expect(lines[2]).toBe("");
    expect(JSON.parse(lines[0]).userAgent).toBe(userAgent);
    expect(JSON.parse(lines[1]).logId).toBe("next-entry");
  });

  it("writes to different days produce separate files", async () => {
    const logsDir = join(tempDir, "logs");
    const writer = createAccessLogWriter(logsDir);

    await writer.write(
      makeEntry({ logId: "day1", timestamp: "2026-01-28T12:00:00Z" }),
    );
    await writer.write(
      makeEntry({ logId: "day2", timestamp: "2026-01-29T12:00:00Z" }),
    );

    const files = (await readdir(logsDir)).sort();
    expect(files).toHaveLength(2);
    expect(files[0]).toBe("access-2026-01-28.log");
    expect(files[1]).toBe("access-2026-01-29.log");

    const content1 = await readFile(join(logsDir, files[0]), "utf-8");
    expect(JSON.parse(content1.trim()).logId).toBe("day1");

    const content2 = await readFile(join(logsDir, files[1]), "utf-8");
    expect(JSON.parse(content2.trim()).logId).toBe("day2");
  });

  it("buckets an entry by UTC date, not local date", async () => {
    const logsDir = join(tempDir, "logs");
    const writer = createAccessLogWriter(logsDir);

    // 23:30 on Jan 28 in UTC-05:00 is 04:30 on Jan 29 in UTC.
    await writer.write(
      makeEntry({
        logId: "utc-bucket",
        timestamp: "2026-01-28T23:30:00-05:00",
      }),
    );

    const files = await readdir(logsDir);
    expect(files).toHaveLength(1);
    expect(files[0]).toBe("access-2026-01-29.log");
  });
});

describe("AccessLogReader", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "access-log-reader-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("returns an empty result when the logs directory does not exist", async () => {
    const reader = createAccessLogReader(join(tempDir, "logs"));

    const result = await reader.read();

    expect(result).toEqual({ logs: [], total: 0, limit: 50, offset: 0 });
  });

  it("returns entries newest-first across day files with total and defaults", async () => {
    const logsDir = join(tempDir, "logs");
    const writer = createAccessLogWriter(logsDir);

    await writer.write(
      makeEntry({ logId: "old", timestamp: "2026-01-28T10:00:00Z" }),
    );
    await writer.write(
      makeEntry({ logId: "mid", timestamp: "2026-01-28T12:00:00Z" }),
    );
    await writer.write(
      makeEntry({ logId: "new", timestamp: "2026-01-29T09:00:00Z" }),
    );

    const result = await createAccessLogReader(logsDir).read();

    expect(result.total).toBe(3);
    expect(result.limit).toBe(50);
    expect(result.offset).toBe(0);
    expect(result.logs.map((entry) => entry.logId)).toEqual([
      "new",
      "mid",
      "old",
    ]);
  });

  it("round-trips entries written by the writer with all fields intact", async () => {
    const logsDir = join(tempDir, "logs");
    const writer = createAccessLogWriter(logsDir);
    const entry = makeEntry();

    await writer.write(entry);

    const result = await createAccessLogReader(logsDir).read();

    expect(result.total).toBe(1);
    expect(result.logs[0]).toEqual(entry);
  });

  it("paginates with limit and offset", async () => {
    const logsDir = join(tempDir, "logs");
    const writer = createAccessLogWriter(logsDir);

    await writer.write(
      makeEntry({ logId: "old", timestamp: "2026-01-28T10:00:00Z" }),
    );
    await writer.write(
      makeEntry({ logId: "mid", timestamp: "2026-01-28T12:00:00Z" }),
    );
    await writer.write(
      makeEntry({ logId: "new", timestamp: "2026-01-29T09:00:00Z" }),
    );

    const reader = createAccessLogReader(logsDir);

    const page1 = await reader.read({ limit: 2 });
    expect(page1.logs.map((entry) => entry.logId)).toEqual(["new", "mid"]);
    expect(page1.total).toBe(3);
    expect(page1.limit).toBe(2);
    expect(page1.offset).toBe(0);

    const page2 = await reader.read({ limit: 2, offset: 2 });
    expect(page2.logs.map((entry) => entry.logId)).toEqual(["old"]);
    expect(page2.total).toBe(3);

    const beyond = await reader.read({ limit: 2, offset: 3 });
    expect(beyond.logs).toEqual([]);
    expect(beyond.total).toBe(3);
  });

  it("skips malformed lines and ignores non-access files", async () => {
    const logsDir = join(tempDir, "logs");
    await mkdir(logsDir, { recursive: true });

    const good = makeEntry({ logId: "good" });
    const alsoGood = makeEntry({
      logId: "also-good",
      timestamp: "2026-01-28T13:00:00Z",
    });
    await writeFile(
      join(logsDir, "access-2026-01-28.log"),
      `${JSON.stringify(good)}\nnot-json\n${JSON.stringify(alsoGood)}\n`,
    );
    await writeFile(
      join(logsDir, "notes.log"),
      `${JSON.stringify(makeEntry({ logId: "stray-log" }))}\n`,
    );
    await writeFile(
      join(logsDir, "access-2026-01-28.txt"),
      `${JSON.stringify(makeEntry({ logId: "stray-txt" }))}\n`,
    );

    const result = await createAccessLogReader(logsDir).read();

    expect(result.total).toBe(2);
    expect(result.logs.map((entry) => entry.logId).sort()).toEqual([
      "also-good",
      "good",
    ]);
  });
});

describe("AccessLogReader error paths", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "access-reader-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("read() on a missing logs directory returns an empty result", async () => {
    const { createAccessLogReader } = await import("./access-reader.js");
    const reader = createAccessLogReader(join(tempDir, "no-such-logs"));

    await expect(reader.read()).resolves.toEqual({
      logs: [],
      total: 0,
      limit: 50,
      offset: 0,
    });
  });

  it("skips a malformed (partially written) line and still returns the valid entries", async () => {
    const { writeFile, mkdir } = await import("node:fs/promises");
    const { createAccessLogReader } = await import("./access-reader.js");
    const logsDir = join(tempDir, "logs");
    await mkdir(logsDir, { recursive: true });

    const good1 = JSON.stringify(
      makeEntry({ logId: "good-1", timestamp: "2026-01-28T10:00:00Z" }),
    );
    const good2 = JSON.stringify(
      makeEntry({ logId: "good-2", timestamp: "2026-01-28T11:00:00Z" }),
    );
    // Torn final write: a truncated JSON line between two valid entries.
    await writeFile(
      join(logsDir, "access-2026-01-28.log"),
      `${good1}\n{"logId": "torn-\n${good2}\n`,
      "utf-8",
    );

    const reader = createAccessLogReader(logsDir);
    const result = await reader.read();

    expect(result.total).toBe(2);
    expect(result.logs.map((entry) => entry.logId)).toEqual([
      "good-2",
      "good-1",
    ]);
  });

  it("rejects the whole read when one log file cannot be read", async () => {
    const { mkdir } = await import("node:fs/promises");
    const { createAccessLogReader } = await import("./access-reader.js");
    const logsDir = join(tempDir, "logs");
    await mkdir(logsDir, { recursive: true });

    const writer = createAccessLogWriter(logsDir);
    await writer.write(makeEntry({ logId: "good-1" }));
    // A directory sitting where a log file should be: readFile fails (EISDIR).
    await mkdir(join(logsDir, "access-2026-01-29.log"));

    const reader = createAccessLogReader(logsDir);
    await expect(reader.read()).rejects.toThrow(/EISDIR/);
  });
});

describe("AccessLogWriter error paths", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "access-log-error-test-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("write() rejects when the logs path exists as a regular file", async () => {
    const { writeFile } = await import("node:fs/promises");
    const filePath = join(tempDir, "not-a-dir");
    await writeFile(filePath, "not a directory", "utf-8");

    const writer = createAccessLogWriter(filePath);
    await expect(writer.write(makeEntry())).rejects.toThrow();

    // No partial log file was created alongside the failure.
    await expect(readdir(tempDir)).resolves.toEqual(["not-a-dir"]);
  });
});
