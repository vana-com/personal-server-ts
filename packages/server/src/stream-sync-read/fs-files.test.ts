import type * as FsPromises from "node:fs/promises";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createFsStreamSyncReadFiles } from "./fs-files.js";

const trace = vi.hoisted(() => ({ events: [] as string[] }));

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
  });

  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  function events(): string[] {
    return trace.events.map((event) =>
      event.replace(root, "<root>").replace(/\.tmp-\d+-\d+$/, ".tmp"),
    );
  }

  it("syncs the file before rename, then new directories deepest first through the existing ancestor", async () => {
    const files = createFsStreamSyncReadFiles(root);
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

  it("syncs only the parent when its directories already exist", async () => {
    await mkdir(join(root, "views/stream/parts"), { recursive: true });
    const files = createFsStreamSyncReadFiles(root);
    await files.write("views/stream/parts/chunk", new Uint8Array([3]));

    expect(events()).toEqual([
      "sync:<root>/views/stream/parts/chunk.tmp",
      "rename:<root>/views/stream/parts/chunk",
      "sync:<root>/views/stream/parts",
    ]);
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
