import type * as FsPromises from "node:fs/promises";
import { chmod, mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
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

  it("syncs the file before rename, then every directory deepest first up to the root", async () => {
    const files = await createFsStreamSyncReadFiles(root);
    trace.events.length = 0;
    await files.write("views/stream/parts/chunk", new Uint8Array([1, 2]));

    expect(events()).toEqual([
      "sync:<root>/views/stream/parts/chunk.tmp",
      "rename:<root>/views/stream/parts/chunk",
      "sync:<root>/views/stream/parts",
      "sync:<root>/views/stream",
      "sync:<root>/views",
      "sync:<root>",
    ]);
    expect(await readFile(join(root, "views/stream/parts/chunk"))).toEqual(
      Buffer.from([1, 2]),
    );
  });

  it("syncs the root and its parent when opened, and no directory above the parent", async () => {
    await createFsStreamSyncReadFiles(join(root, "store"));

    expect(events()).toEqual(["sync:<root>/store", "sync:<root>"]);
  });

  it("makes a root created by an earlier process durable on the next open", async () => {
    await mkdir(join(root, "store"));

    await createFsStreamSyncReadFiles(join(root, "store"));

    expect(events()).toEqual(["sync:<root>/store", "sync:<root>"]);
  });

  it("syncs every directory up to the root even when the directories already exist", async () => {
    await mkdir(join(root, "store/views/stream/parts"), { recursive: true });
    const files = await createFsStreamSyncReadFiles(join(root, "store"));
    trace.events.length = 0;
    await files.write("views/stream/parts/chunk", new Uint8Array([3]));

    expect(events()).toEqual([
      "sync:<root>/store/views/stream/parts/chunk.tmp",
      "rename:<root>/store/views/stream/parts/chunk",
      "sync:<root>/store/views/stream/parts",
      "sync:<root>/store/views/stream",
      "sync:<root>/store/views",
      "sync:<root>/store",
    ]);
  });

  it("syncs the chain up to the root on the retry after a write that failed at rename", async () => {
    const files = await createFsStreamSyncReadFiles(
      join(root, "a", "b", "store"),
    );
    trace.failNextRename = true;
    await expect(
      files.write("deep/mirror.json", new Uint8Array([7])),
    ).rejects.toThrow("rename failed");
    trace.events.length = 0;

    await files.write("deep/mirror.json", new Uint8Array([7]));

    expect(events().slice(-3)).toEqual([
      "rename:<root>/a/b/store/deep/mirror.json",
      "sync:<root>/a/b/store/deep",
      "sync:<root>/a/b/store",
    ]);
  });

  it.skipIf(process.getuid?.() === 0)(
    "writes under a root whose ancestors above its parent are traverse-only",
    async () => {
      const blocked = join(root, "blocked");
      await mkdir(join(blocked, "parent"), { recursive: true });
      await chmod(blocked, 0o111);
      try {
        const files = await createFsStreamSyncReadFiles(
          join(blocked, "parent", "store"),
        );
        await files.write("mirror.json", new Uint8Array([8]));
        expect(await files.read("mirror.json")).toEqual(new Uint8Array([8]));
      } finally {
        await chmod(blocked, 0o755);
      }
    },
  );

  it("syncs the parent after removing a published file", async () => {
    const files = await createFsStreamSyncReadFiles(root);
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
    const files = await createFsStreamSyncReadFiles(root);
    await expect(files.remove("absent/current.json")).resolves.toBeUndefined();
  });
});
