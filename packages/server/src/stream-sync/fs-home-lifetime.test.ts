import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { StreamSyncFiles } from "@opendatalabs/personal-server-ts-core/stream-sync";
import { createFsStreamSyncFiles } from "./fs-files.js";
import { openFsStreamSyncHome, type FsStreamSyncHome } from "./fs-home.js";

const A = "0x1C5A77d9FA7eF466951B2F01F724BCa3A5820b63" as const;
const NET = "vana:14800:https://g.test";

let root: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "fs-home-life-"));
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true });
});

/** A real file store whose `write` and `readChunks` stop until released. */
function gatedStore() {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const started: string[] = [];
  const create = (dir: string): StreamSyncFiles => {
    const real = createFsStreamSyncFiles(dir);
    return {
      ...real,
      async write(path, bytes) {
        started.push(`write ${path}`);
        await gate;
        return real.write(path, bytes);
      },
      async *readChunks(path) {
        started.push(`readChunks ${path}`);
        yield* real.readChunks(path);
      },
    };
  };
  return { create, release, started };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function neverSettlesWithin(promise: Promise<unknown>, ms: number) {
  let settled = false;
  void promise.then(
    () => (settled = true),
    () => (settled = true),
  );
  await sleep(ms);
  return !settled;
}

const open = (createFiles?: (dir: string) => StreamSyncFiles) =>
  openFsStreamSyncHome({
    root,
    ownerAddress: A,
    network: NET,
    createFiles,
  });

describe.each([
  ["writer files port", (h: FsStreamSyncHome) => h.home.files],
  ["seed staging files port", (h: FsStreamSyncHome) => h.seedFiles],
] as const)("the home's lock outlives file operations: %s", (_name, port) => {
  it("close waits for a write in flight; a second opener gets null until it ends", async () => {
    const store = gatedStore();
    const first = (await open(store.create))!;
    const files = port(first);
    const write = files.write("state.json", new Uint8Array([1]));
    await sleep(10);
    expect(store.started).toHaveLength(1);

    const closing = first.close();
    expect(await neverSettlesWithin(closing, 80)).toBe(true);
    expect(await open()).toBeNull();

    store.release();
    await write;
    await closing;
    const second = await open();
    expect(second).not.toBeNull();
    // The write finished under A's lock, so B sees it.
    expect(await port(second!).read("state.json")).toEqual(new Uint8Array([1]));
    await second!.close();
  });

  it("rejects an operation that starts after close has begun", async () => {
    const store = gatedStore();
    const first = (await open(store.create))!;
    const files = port(first);
    const inFlight = files.write("a", new Uint8Array([1]));
    await sleep(10);
    const closing = first.close();

    for (const attempt of [
      () => files.write("b", new Uint8Array([2])),
      () => files.read("a"),
      () => files.appendMany([{ path: "c", bytes: new Uint8Array([3]) }]),
      () => files.sync("c"),
      () => files.size("a"),
      () => files.list(""),
      () => files.remove("a"),
      async () => {
        for await (const chunk of files.readChunks("a")) void chunk;
      },
    ]) {
      await expect(attempt()).rejects.toMatchObject({
        name: "StreamSyncHomeClosedError",
      });
    }
    // Only the first write ever reached the store.
    expect(store.started).toEqual(["write a"]);

    store.release();
    await inFlight;
    await closing;
    await expect(files.read("a")).rejects.toMatchObject({
      name: "StreamSyncHomeClosedError",
    });
  });

  it("an open iterator holds close until it is returned", async () => {
    const first = (await open())!;
    const files = port(first);
    // Two 1 MiB chunks.
    await files.write("big", new Uint8Array(1024 * 1024 + 10));
    const iterator = files.readChunks("big")[Symbol.asyncIterator]();
    expect((await iterator.next()).done).toBe(false);

    const closing = first.close();
    expect(await neverSettlesWithin(closing, 80)).toBe(true);
    expect(await open()).toBeNull();

    // A started iterator may finish under the held lock.
    expect((await iterator.next()).done).toBe(false);
    expect((await iterator.next()).done).toBe(true);
    await closing;
    expect(await open()).not.toBeNull();
  });

  it("an iterator abandoned with return() releases close", async () => {
    const first = (await open())!;
    const files = port(first);
    await files.write("big", new Uint8Array(1024 * 1024 + 10));
    const iterator = files.readChunks("big")[Symbol.asyncIterator]();
    await iterator.next();
    const closing = first.close();
    expect(await neverSettlesWithin(closing, 50)).toBe(true);
    await iterator.return!();
    await closing;
  });
});

describe("the two ports share one barrier", () => {
  it("close waits for a seed-port operation while the writer port is idle", async () => {
    const store = gatedStore();
    const first = (await open(store.create))!;
    const write = first.seedFiles.write("x", new Uint8Array([1]));
    await sleep(10);
    const closing = first.close();
    expect(await neverSettlesWithin(closing, 80)).toBe(true);
    await expect(first.home.files.read("x")).rejects.toMatchObject({
      name: "StreamSyncHomeClosedError",
    });
    store.release();
    await write;
    await closing;
  });

  it("close twice is safe, also while draining", async () => {
    const store = gatedStore();
    const first = (await open(store.create))!;
    const write = first.home.files.write("x", new Uint8Array([1]));
    await sleep(10);
    const one = first.close();
    const two = first.close();
    expect(await neverSettlesWithin(two, 50)).toBe(true);
    store.release();
    await write;
    await Promise.all([one, two]);
  });
});
