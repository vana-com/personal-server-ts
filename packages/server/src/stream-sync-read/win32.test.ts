import type * as FsPromises from "node:fs/promises";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createFsStreamSyncFiles } from "../stream-sync/fs-files.js";
import { createFsStreamSyncReadFiles } from "./fs-files.js";

const synced = vi.hoisted(() => ({ paths: [] as string[] }));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof FsPromises>();
  return {
    ...actual,
    open: async (...args: Parameters<typeof actual.open>) => {
      const handle = await actual.open(...args);
      const sync = handle.sync.bind(handle);
      handle.sync = async () => {
        synced.paths.push(String(args[0]));
        return sync();
      };
      return handle;
    },
  };
});

describe("directory fsync on Windows", () => {
  let root: string;
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "stream-sync-win32-"));
    synced.paths.length = 0;
    Object.defineProperty(process, "platform", { value: "win32" });
  });

  afterEach(async () => {
    Object.defineProperty(process, "platform", platform);
    await rm(root, { recursive: true, force: true });
  });

  const directorySyncs = () =>
    synced.paths.filter((path) => !/\.tmp-\d+-\d+$/.test(path));

  it("read adapter flushes the file and attempts no directory fsync", async () => {
    const files = await createFsStreamSyncReadFiles(join(root, "store"));
    await files.write("views/current.json", new Uint8Array([1]));

    expect(synced.paths.length).toBeGreaterThan(0);
    expect(directorySyncs()).toEqual([]);
    expect(await readFile(join(root, "store/views/current.json"))).toEqual(
      Buffer.from([1]),
    );
  });

  it("writer flushes the file and attempts no directory fsync", async () => {
    const files = createFsStreamSyncFiles(join(root, "sync"));
    await files.write("heads/1.json", new Uint8Array([2]));

    expect(synced.paths.length).toBeGreaterThan(0);
    expect(directorySyncs()).toEqual([]);
    expect(await readFile(join(root, "sync/heads/1.json"))).toEqual(
      Buffer.from([2]),
    );
  });
});
