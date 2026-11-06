import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
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

  it("write replaces a file that has an open append handle", async () => {
    const files = createFsStreamSyncFiles(root);
    await files.appendMany([{ path: "s/0", bytes: enc.encode("old") }]);
    await files.write("s/0", enc.encode("new"));
    await files.appendMany([{ path: "s/0", bytes: enc.encode("+tail") }]);
    await files.sync("s");
    expect(await readFile(join(root, "s/0"), "utf8")).toBe("new+tail");
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
});
