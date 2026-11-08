import { describe, expect, it, vi } from "vitest";
import {
  controlHashes,
  partBlobName,
  type Line,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { StreamSyncImporter } from "./importer.js";
import { streamSyncReadHashes } from "./keys.js";
import { viewLines } from "./lines.js";
import { masterKey } from "./service-fixture.js";
import { buildTestHead, testOwnerKey } from "./testing.js";
import { ViewStore, type ViewKey } from "./view-store.js";

type ImportOptions = ConstructorParameters<typeof StreamSyncImporter>[0];
type Files = Parameters<typeof ViewStore.open>[0];

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const key: ViewKey = { connector: "fixture", ns: "", stream: "items" };
const records = [{ id: "a" }, { id: "b" }, { id: "c" }];
const timeout = 5_000;

class MemoryFiles implements Files {
  readonly data = new Map<string, Uint8Array>();

  async list(prefix: string): Promise<string[]> {
    return [...this.data.keys()].filter((path) =>
      path.startsWith(prefix + "/"),
    );
  }

  async read(path: string): Promise<Uint8Array | null> {
    return this.data.get(path)?.slice() ?? null;
  }

  async write(path: string, bytes: Uint8Array): Promise<void> {
    this.data.set(path, bytes.slice());
  }

  async remove(path: string): Promise<void> {
    this.data.delete(path);
  }
}

async function fixture() {
  const owner = await testOwnerKey(masterKey(7));
  // Keep the real publisher/codec, but use identity encryption for this cache test.
  const publisher = {
    ...owner,
    encrypt: async (_scope: string, clear: Uint8Array) => clear.slice(),
  };
  const input = {
    ...key,
    key: publisher,
    generation: 1,
    primaryKey: ["id"],
    records,
    observedAt: 1,
  };
  const first = await buildTestHead(input);
  const newer = await buildTestHead({ ...input, profileVersion: "1.0.1" });
  expect(newer.head.parts).toEqual(first.head.parts);
  expect(newer.dataHash).not.toBe(first.dataHash);
  const control = await owner.control();
  let row = {
    version: 1,
    dataHash: first.dataHash,
    metadataHash: first.dataHash,
    deleted: false,
  };
  const mirror = {
    deletionFloor: () => 0,
    rowsFor: () => ({
      controls: new Map([
        ["", { ...control.active, version: 1, deleted: false }],
      ]),
      streams: new Map([["", new Map([[key.stream, row]])]]),
    }),
  } as unknown as ImportOptions["mirror"];
  const storage = new Map([...first.blobs, ...newer.blobs]);
  const get = vi.fn(async (path: string) => storage.get(path)?.slice() ?? null);
  const keys: ImportOptions["keys"] = {
    hashes: streamSyncReadHashes,
    keyCheck: owner.keyCheck,
    decrypt: async (_scope, cipher) => cipher.slice(),
  };
  const files = new MemoryFiles();
  const views = await ViewStore.open(files);
  const importer = new StreamSyncImporter({
    mirror,
    views,
    blobs: { get },
    keys,
    controlHashes: await controlHashes(keys.hashes.keccak256, keys.keyCheck),
    logger: { warn: vi.fn() } as ImportOptions["logger"],
  });
  await importer.run([key.connector]);
  expect(importer.listIssues()).toEqual([]);
  expect(views.get(key)?.version).toBe(1);
  const part = first.head.parts[0]!;
  const path = `views/${key.connector}/_/${key.stream}/parts/${part.hash}`;
  const blob = `${first.scope}/${partBlobName(1, part.hash)}`;
  const clear = (await files.read(path))!;
  expect(clear).not.toBeNull();
  const expected = decoder
    .decode(clear)
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line) as Line);

  return {
    files,
    views,
    importer,
    keys,
    get,
    storage,
    path,
    blob,
    clear,
    expected,
    async importNewer() {
      row = { ...row, version: 2, dataHash: newer.dataHash };
      await importer.run([key.connector]);
    },
  };
}

async function readBounded(
  views: ViewStore,
  keys: ImportOptions["keys"],
): Promise<Line[]> {
  const lease = views.lease(key);
  if (!lease) throw new Error("view unavailable");
  const lines: Line[] = [];
  try {
    for await (const line of viewLines(views, keys, lease, {
      winners: new Map(),
      skipped: 0,
      newestObservedAt: null,
    })) {
      lines.push(line);
      // Bound the old parser's microtask loop; a timer alone cannot stop it.
      if (lines.length > records.length) throw new Error("repeated records");
    }
    return lines;
  } finally {
    lease.release();
  }
}

const corruptions: { name: string; mutate(clear: Uint8Array): Uint8Array }[] = [
  {
    name: "complete trailing records removed",
    mutate: (clear) => clear.slice(0, clear.indexOf(10) + 1),
  },
  {
    name: "different valid JSON line",
    mutate: () =>
      encoder.encode('{"o":1,"r":"test-run","v":{"id":"altered"}}\n'),
  },
  {
    name: "final newline replaced with a space",
    mutate: (clear) => {
      const changed = clear.slice();
      changed[changed.length - 1] = 32;
      return changed;
    },
  },
];

describe("cached part integrity", () => {
  for (const corruption of corruptions) {
    it(
      `repairs ${corruption.name} when a newer head reuses the part`,
      async () => {
        const f = await fixture();
        expect(await readBounded(f.views, f.keys)).toEqual(f.expected);
        await f.files.write(f.path, corruption.mutate(f.clear));
        await f.importNewer();

        expect(f.importer.listIssues()).toEqual([]);
        expect(
          f.get.mock.calls.filter(([path]) => path === f.blob),
        ).toHaveLength(2);
        expect(await f.files.read(f.path)).toEqual(f.clear);
        expect(f.views.get(key)?.version).toBe(2);
        expect(await readBounded(f.views, f.keys)).toEqual(f.expected);
        const reopened = await ViewStore.open(f.files);
        expect(await readBounded(reopened, f.keys)).toEqual(f.expected);
      },
      timeout,
    );

    it(
      `rejects ${corruption.name} after reopening without a new import`,
      async () => {
        const f = await fixture();
        await f.files.write(f.path, corruption.mutate(f.clear));
        const reopened = await ViewStore.open(f.files);
        await expect(readBounded(reopened, f.keys)).rejects.toThrow(
          /corrupt|missing|unavailable/i,
        );
      },
      timeout,
    );
  }

  it(
    "reuses an intact cached part without downloading it again",
    async () => {
      const f = await fixture();
      await f.importNewer();
      expect(f.importer.listIssues()).toEqual([]);
      expect(f.get.mock.calls.filter(([path]) => path === f.blob)).toHaveLength(
        1,
      );
      expect(await readBounded(f.views, f.keys)).toEqual(f.expected);
    },
    timeout,
  );

  it(
    "removes a corrupt cache entry when the replacement blob is unavailable",
    async () => {
      const f = await fixture();
      await f.files.write(f.path, corruptions[0]!.mutate(f.clear));
      f.storage.delete(f.blob);
      await f.importNewer();
      expect(f.importer.listIssues()).toEqual([
        expect.objectContaining({ problem: "blob_missing", version: 2 }),
      ]);
      expect(await f.files.read(f.path)).toBeNull();
      await expect(
        readBounded(await ViewStore.open(f.files), f.keys),
      ).rejects.toThrow(/corrupt|missing|unavailable/i);
    },
    timeout,
  );

  it(
    "rejects a missing final newline before the parser repeats a record",
    async () => {
      const f = await fixture();
      const line = decoder.decode(f.clear).split("\n")[0]!;
      // Isolate the parser guard from the store's independent hash verification.
      const read = vi
        .spyOn(f.views, "readPart")
        .mockResolvedValue(encoder.encode(line + " "));
      const lease = f.views.lease(key)!;
      const iterator = viewLines(f.views, f.keys, lease, {
        winners: new Map(),
        skipped: 0,
        newestObservedAt: null,
      });
      try {
        await expect(iterator.next()).rejects.toThrow(
          /corrupt.*final newline/i,
        );
      } finally {
        await iterator.return(undefined);
        lease.release();
        read.mockRestore();
      }
    },
    timeout,
  );
});
