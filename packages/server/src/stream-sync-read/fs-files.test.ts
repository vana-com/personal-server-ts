import type * as FsPromises from "node:fs/promises";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, parse } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createFsStreamSyncReadFiles } from "./fs-files.js";

const trace = vi.hoisted(() => ({
  events: [] as string[],
  failNextRename: false,
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof FsPromises>();
  return {
    ...actual,
    open: async (...args: Parameters<typeof actual.open>) => {
      const handle = await actual.open(...args);
      const sync = handle.sync.bind(handle);
      handle.sync = async () => {
        trace.events.push(`sync:${String(args[0])}`);
        return sync();
      };
      return handle;
    },
    rename: async (...args: Parameters<typeof actual.rename>) => {
      trace.events.push(`rename:${String(args[1])}`);
      if (trace.failNextRename) {
        trace.failNextRename = false;
        throw new Error("rename failed");
      }
      return actual.rename(...args);
    },
    rm: async (...args: Parameters<typeof actual.rm>) => {
      trace.events.push(`remove:${String(args[0])}`);
      return actual.rm(...args);
    },
  };
});

describe("filesystem publication durability", () => {
  let root: string;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "stream-sync-files-"));
    trace.events.length = 0;
    trace.failNextRename = false;
  });

  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  /** Events, without syncs of directories above the temp root's parent. */
  function events(): string[] {
    const above = new Set<string>();
    for (let dir = dirname(dirname(root)); ; dir = dirname(dir)) {
      above.add(`sync:${dir}`);
      if (dir === parse(dir).root) break;
    }
    return trace.events
      .filter((event) => !above.has(event))
      .map((event) =>
        event.replace(root, "<root>").replace(/\.tmp-\d+-\d+$/, ".tmp"),
      );
  }

  it("syncs the file before rename, then every directory deepest first through the root's parent", async () => {
    const files = createFsStreamSyncReadFiles(root);
    await files.write("views/stream/parts/chunk", new Uint8Array([1, 2]));

    expect(events()).toEqual([
      "sync:<root>/views/stream/parts/chunk.tmp",
      "rename:<root>/views/stream/parts/chunk",
      "sync:<root>/views/stream/parts",
      "sync:<root>/views/stream",
      "sync:<root>/views",
      "sync:<root>",
      `sync:${dirname(root)}`,
    ]);
    expect(await readFile(join(root, "views/stream/parts/chunk"))).toEqual(
      Buffer.from([1, 2]),
    );
  });

  it("syncs every ancestor through the root's parent even when the directories already exist", async () => {
    await mkdir(join(root, "store/views/stream/parts"), { recursive: true });
    const files = createFsStreamSyncReadFiles(join(root, "store"));
    await files.write("views/stream/parts/chunk", new Uint8Array([3]));

    expect(events()).toEqual([
      "sync:<root>/store/views/stream/parts/chunk.tmp",
      "rename:<root>/store/views/stream/parts/chunk",
      "sync:<root>/store/views/stream/parts",
      "sync:<root>/store/views/stream",
      "sync:<root>/store/views",
      "sync:<root>/store",
      "sync:<root>",
      `sync:${dirname(root)}`,
    ]);
  });

  it("completes the root's entry on a successful retry after a write that failed at rename", async () => {
    const files = createFsStreamSyncReadFiles(join(root, "new-root"));
    trace.failNextRename = true;
    await expect(
      files.write("mirror.json", new Uint8Array([6])),
    ).rejects.toThrow("rename failed");
    trace.events.length = 0;

    await files.write("mirror.json", new Uint8Array([6]));

    expect(events()).toContain("sync:<root>");
    expect(events().slice(-3)).toEqual([
      "sync:<root>/new-root",
      "sync:<root>",
      `sync:${dirname(root)}`,
    ]);
  });

  it("syncs every ancestor up to the filesystem root on the retry after a write that created several missing levels and failed", async () => {
    const storeRoot = join(root, "a", "b", "store");
    const files = createFsStreamSyncReadFiles(storeRoot);
    trace.failNextRename = true;
    await expect(
      files.write("mirror.json", new Uint8Array([7])),
    ).rejects.toThrow("rename failed");
    trace.events.length = 0;

    await files.write("mirror.json", new Uint8Array([7]));

    const synced = trace.events
      .filter((event) => event.startsWith("sync:"))
      .map((event) => event.slice("sync:".length));
    const ancestors: string[] = [];
    for (let dir = storeRoot; ; dir = dirname(dir)) {
      ancestors.push(dir);
      if (dir === parse(storeRoot).root) break;
    }
    expect(synced.slice(-ancestors.length)).toEqual(ancestors);
  });

  it("makes a newly created root durable in its existing parent", async () => {
    const files = createFsStreamSyncReadFiles(join(root, "new-root"));
    await files.write("heads/1.json", new Uint8Array([4]));

    expect(events()).toEqual([
      "sync:<root>/new-root/heads/1.json.tmp",
      "rename:<root>/new-root/heads/1.json",
      "sync:<root>/new-root/heads",
      "sync:<root>/new-root",
      "sync:<root>",
      `sync:${dirname(root)}`,
    ]);
  });

  it("syncs the parent after removing a published file", async () => {
    const files = createFsStreamSyncReadFiles(root);
    await files.write("views/current.json", new Uint8Array([5]));
    trace.events.length = 0;

    await files.remove("views/current.json");

    expect(events()).toEqual([
      "remove:<root>/views/current.json",
      "sync:<root>/views",
    ]);
    expect(await files.read("views/current.json")).toBeNull();
  });

  it("keeps removal idempotent when the parent does not exist", async () => {
    const files = createFsStreamSyncReadFiles(root);
    await expect(files.remove("absent/current.json")).resolves.toBeUndefined();
  });
});
