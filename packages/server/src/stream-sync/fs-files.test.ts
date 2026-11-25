import {
  chmod,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  stat,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createFsStreamSyncFiles } from "./fs-files.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

describe("createFsStreamSyncFiles appendMany and sync", () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "stream-sync-fs-files-"));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  /** Open file descriptors of this process that point under `root`. */
  async function openUnderRoot(): Promise<number> {
    let n = 0;
    for (const fd of await readdir("/proc/self/fd")) {
      try {
        const { readlink } = await import("node:fs/promises");
        if ((await readlink(`/proc/self/fd/${fd}`)).startsWith(root)) n += 1;
      } catch {
        // The descriptor closed while listing.
      }
    }
    return n;
  }

  it("distinguishes a missing file from an existing zero-byte file", async () => {
    const files = createFsStreamSyncFiles(root);
    expect(await files.read("missing.bin")).toBeNull();
    expect(await files.size("missing.bin")).toBe(0);
    expect(await files.list("absent")).toEqual([]);

    await files.write("empty.bin", new Uint8Array());
    expect(await files.read("empty.bin")).toEqual(new Uint8Array());
    expect(await files.size("empty.bin")).toBe(0);
  });

  it("reports an existing file passed as a listing prefix instead of returning an empty list", async () => {
    const files = createFsStreamSyncFiles(root);
    await files.write("one.bin", enc.encode("fixture"));
    await expect(files.list("one.bin")).rejects.toMatchObject({
      code: "ENOTDIR",
    });
    expect(await files.read("one.bin")).toEqual(enc.encode("fixture"));
  });

  it("keeps appended bytes readable at once, in order, across many files", async () => {
    const files = createFsStreamSyncFiles(root);
    for (let round = 0; round < 3; round += 1) {
      await files.appendMany(
        Array.from({ length: 200 }, (_, i) => ({
          path: `spool/${i.toString(16).padStart(3, "0")}`,
          bytes: enc.encode(`r${round};`),
        })),
      );
    }
    for (const i of [0, 63, 64, 199]) {
      const bytes = await files.read(
        `spool/${i.toString(16).padStart(3, "0")}`,
      );
      expect(dec.decode(bytes!)).toBe("r0;r1;r2;");
    }
    await files.sync("spool");
  });

  it("holds a bounded number of descriptors while appending, none after sync", async () => {
    if (process.platform !== "linux") return;
    const files = createFsStreamSyncFiles(root);
    await files.appendMany(
      Array.from({ length: 256 }, (_, i) => ({
        path: `spool/${i}`,
        bytes: enc.encode("x"),
      })),
    );
    expect(await openUnderRoot()).toBeLessThanOrEqual(64);
    await files.sync("spool");
    expect(await openUnderRoot()).toBe(0);
    expect(await files.list("spool")).toHaveLength(256);
  });

  it("appends after a sync and after an eviction without losing bytes", async () => {
    const files = createFsStreamSyncFiles(root);
    await files.appendMany([{ path: "a/0", bytes: enc.encode("1") }]);
    await files.sync("a");
    await files.appendMany([{ path: "a/0", bytes: enc.encode("2") }]);
    await files.appendMany(
      Array.from({ length: 100 }, (_, i) => ({
        path: `b/${i}`,
        bytes: enc.encode("z"),
      })),
    );
    await files.appendMany([{ path: "a/0", bytes: enc.encode("3") }]);
    await files.sync("a");
    expect(dec.decode((await files.read("a/0"))!)).toBe("123");
  });

  it("distinguishes a written empty file from one that does not exist", async () => {
    const files = createFsStreamSyncFiles(root);
    const existing = "samples/empty.bin";
    const absent = "samples/absent.bin";
    await files.write(existing, Uint8Array.of(0, 255, 128));
    await files.write(existing, new Uint8Array());

    expect(await files.read(existing)).toEqual(new Uint8Array());
    expect(await files.read(absent)).toBeNull();
    expect(await files.size(existing)).toBe(0);
    expect(await files.size(absent)).toBe(0);
    expect(await files.list("samples")).toEqual([existing]);

    const chunks: Uint8Array[] = [];
    for await (const chunk of files.readChunks(existing)) chunks.push(chunk);
    expect(chunks).toEqual([]);
  });

  it("lists nested files in sorted root-relative order", async () => {
    const files = createFsStreamSyncFiles(root);
    const prefix = "sample";
    const nested = ["sample/z/leaf", "sample/a/leaf", "sample/root"];
    for (const path of [...nested, "sample-other/stays-out"]) {
      await files.write(path, enc.encode("sample"));
    }
    await mkdir(join(root, prefix, "empty"));

    expect(await files.list(prefix)).toEqual([...nested].sort());
    expect(await files.list("missing")).toEqual([]);
  });

  it("reads each byte once in order across multiple chunks", async () => {
    const files = createFsStreamSyncFiles(root);
    const path = "samples/chunked.bin";
    const bytes = Uint8Array.from(
      { length: 1024 * 1024 + 31 },
      (_, i) => i % 251,
    );
    await files.write(path, bytes);
    const observed: Buffer[] = [];
    for await (const chunk of files.readChunks(path)) {
      observed.push(Buffer.from(chunk));
    }
    expect(observed.length).toBeGreaterThan(1);
    expect(Buffer.concat(observed).equals(Buffer.from(bytes))).toBe(true);
  });

  it("write replaces a file that has an open append handle", async () => {
    const files = createFsStreamSyncFiles(root);
    await files.appendMany([{ path: "s/0", bytes: enc.encode("old") }]);
    await files.write("s/0", enc.encode("new"));
    await files.appendMany([{ path: "s/0", bytes: enc.encode("+tail") }]);
    await files.sync("s");
    expect(await readFile(join(root, "s/0"), "utf8")).toBe("new+tail");
  });

  it("does not leave a temporary file when replacing a directory fails", async () => {
    const files = createFsStreamSyncFiles(root);
    await mkdir(join(root, "fixture-folder"));
    await expect(
      files.write("fixture-folder", enc.encode("fixture")),
    ).rejects.toThrow();
    expect(await readdir(root)).toEqual(["fixture-folder"]);
  });

  it("remove closes handles under the prefix and the files can be created again", async () => {
    if (process.platform !== "linux") return;
    const files = createFsStreamSyncFiles(root);
    await files.appendMany([{ path: "s/0", bytes: enc.encode("a") }]);
    await files.remove("s");
    expect(await openUnderRoot()).toBe(0);
    await files.appendMany([{ path: "s/0", bytes: enc.encode("b") }]);
    await files.sync("s");
    expect(dec.decode((await files.read("s/0"))!)).toBe("b");
  });

  it("preserves each file's order within an interleaved append batch", async () => {
    const files = createFsStreamSyncFiles(root);
    await files.appendMany([
      { path: "batch/a", bytes: enc.encode("a1") },
      { path: "batch/b", bytes: enc.encode("b1") },
      { path: "batch/a", bytes: enc.encode("a2") },
      { path: "batch/b", bytes: enc.encode("b2") },
    ]);
    await files.sync("batch");
    expect(dec.decode((await files.read("batch/a"))!)).toBe("a1a2");
    expect(dec.decode((await files.read("batch/b"))!)).toBe("b1b2");
  });

  it("removes a selected prefix without removing a neighbouring prefix", async () => {
    const files = createFsStreamSyncFiles(root);
    await files.appendMany([
      { path: "run/entry", bytes: enc.encode("first") },
      { path: "run-extra/entry", bytes: enc.encode("keep") },
    ]);
    await files.remove("run");
    await files.remove("run");
    await files.appendMany([
      { path: "run-extra/entry", bytes: enc.encode(" more") },
    ]);
    await files.sync("run-extra");
    expect(await files.list("run")).toEqual([]);
    expect(dec.decode((await files.read("run-extra/entry"))!)).toBe(
      "keep more",
    );
  });

  it("sync of one prefix leaves other prefixes' handles and bytes alone", async () => {
    const files = createFsStreamSyncFiles(root);
    await files.appendMany([
      { path: "x/0", bytes: enc.encode("x") },
      { path: "y/0", bytes: enc.encode("y") },
    ]);
    await files.sync("x");
    await files.appendMany([{ path: "y/0", bytes: enc.encode("y2") }]);
    await files.sync("y");
    expect(dec.decode((await files.read("y/0"))!)).toBe("yy2");
    expect(dec.decode((await files.read("x/0"))!)).toBe("x");
  });
  it("closes idle handles by itself, and sync still reaches the files", async () => {
    const files = createFsStreamSyncFiles(root);
    await files.appendMany([
      { path: "idle/0", bytes: enc.encode("a") },
      { path: "idle/1", bytes: enc.encode("b") },
    ]);
    expect(await openUnderRoot()).toBeGreaterThan(0);
    const deadline = Date.now() + 5000;
    while ((await openUnderRoot()) > 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 50));
    }
    expect(await openUnderRoot()).toBe(0);
    await files.appendMany([{ path: "idle/0", bytes: enc.encode("c") }]);
    await files.sync("idle");
    expect(dec.decode((await files.read("idle/0"))!)).toBe("ac");
  });
});

describe("createFsStreamSyncFiles with private modes", () => {
  let parent: string;
  let root: string;
  let previousMask: number;
  beforeEach(async () => {
    parent = await mkdtemp(join(tmpdir(), "stream-sync-fs-private-"));
    root = join(parent, "files");
    // A common default: group and others may read what is created.
    previousMask = process.umask(0o022);
  });
  afterEach(async () => {
    process.umask(previousMask);
    await rm(parent, { recursive: true, force: true });
  });

  const modeOf = async (path: string) => (await stat(path)).mode & 0o777;

  it("creates its directories 0700 and its files 0600, whatever the umask", async () => {
    const files = createFsStreamSyncFiles(root, { private: true });
    await files.appendMany([{ path: "a/b/leaf", bytes: enc.encode("x") }]);
    await files.write("a/written", enc.encode("y"));
    await files.sync("");
    expect(await modeOf(root)).toBe(0o700);
    expect(await modeOf(join(root, "a"))).toBe(0o700);
    expect(await modeOf(join(root, "a", "b"))).toBe(0o700);
    expect(await modeOf(join(root, "a", "b", "leaf"))).toBe(0o600);
    expect(await modeOf(join(root, "a", "written"))).toBe(0o600);
  });

  it("tightens a root that exists with wider modes before it writes", async () => {
    await mkdir(root, { mode: 0o755 });
    await chmod(root, 0o755);
    const files = createFsStreamSyncFiles(root, { private: true });
    await files.appendMany([{ path: "leaf", bytes: enc.encode("x") }]);
    expect(await modeOf(root)).toBe(0o700);
  });

  it("keeps the default modes when it is not asked to be private", async () => {
    const files = createFsStreamSyncFiles(root);
    await files.appendMany([{ path: "leaf", bytes: enc.encode("x") }]);
    await files.sync("");
    expect(await modeOf(join(root, "leaf"))).toBe(0o644);
  });
});
