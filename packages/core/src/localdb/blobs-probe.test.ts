import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type { BlobDescriptor } from "./blobs.js";
import { uploadBlobs } from "./blobs.js";
import type { LocalSyncDeps } from "./deps.js";
import {
  StorageObjectTooLargeError,
  createStorageAccess,
  DEFAULT_STORAGE_ACCESS_POLICY,
} from "../stream-sync/storage-retry.js";

/**
 * A blob store that counts the body bytes it serves. `exists` answers from
 * the stored keys and serves no body, as a HEAD does.
 */
function countingStore(initial: Record<string, Uint8Array>) {
  const bodies = new Map(Object.entries(initial));
  let bytesServed = 0;
  const puts: string[] = [];
  return {
    bytesServed: () => bytesServed,
    puts,
    blobs: {
      get: async (key: string) => {
        const body = bodies.get(key) ?? null;
        bytesServed += body?.length ?? 0;
        return body;
      },
      exists: async (key: string) => bodies.has(key),
      put: async (key: string, bytes: Uint8Array) => {
        puts.push(key);
        bodies.set(key, bytes);
      },
    },
  };
}

function depsWith(blobs: ReturnType<typeof countingStore>["blobs"]) {
  // The size is read first, alone; the bytes only once their memory is held.
  const query = vi.fn(async (sql: string) =>
    /length\(bytes\)/.test(sql) ? [{ size: BYTES.length }] : [{ bytes: BYTES }],
  );
  return {
    db: { query } as unknown as LocalSyncDeps["db"],
    keys: {
      encrypt: async (_scope: string, clear: Uint8Array) => clear,
    } as unknown as LocalSyncDeps["keys"],
    blobs,
    query,
  };
}

const BYTES = new Uint8Array([9, 9, 9]);
const BLOB_ID = createHash("sha256").update(BYTES).digest("hex");
const ATTACHMENT: BlobDescriptor = {
  blobId: BLOB_ID,
  key: `scope/g1-b-${BLOB_ID}`,
  scope: "scope",
};

describe("uploadBlobs existence probe", () => {
  it("an attachment already in storage downloads no body and is not re-sent", async () => {
    const store = countingStore({ [ATTACHMENT.key]: new Uint8Array(4096) });
    const deps = depsWith(store.blobs);
    await uploadBlobs(deps as unknown as LocalSyncDeps, [ATTACHMENT]);
    expect(store.bytesServed()).toBe(0);
    expect(store.puts).toEqual([]);
    expect(deps.query).not.toHaveBeenCalled();
  });

  it("an attachment missing from storage is uploaded", async () => {
    const store = countingStore({});
    const deps = depsWith(store.blobs);
    await uploadBlobs(deps as unknown as LocalSyncDeps, [ATTACHMENT]);
    expect(store.puts).toEqual([ATTACHMENT.key]);
  });
});

describe("uploadBlobs memory reservation", () => {
  /** A store whose governor logs, in order, what happens to the attachment. */
  function governed(reserve: () => Promise<() => void>) {
    const log: string[] = [];
    const store = countingStore({});
    const deps = depsWith({
      ...store.blobs,
      put: async (key: string, bytes: Uint8Array) => {
        log.push("put");
        await store.blobs.put(key, bytes);
      },
      governor: {
        reserve: async (bytes: number, objectBytes?: number) => {
          log.push(`reserve ${bytes} ${objectBytes}`);
          const release = await reserve();
          return () => {
            log.push("release");
            release();
          };
        },
        window: () => ({ end: () => ({}) }),
      },
    } as never);
    const read = deps.query.getMockImplementation()!;
    deps.query.mockImplementation(async (sql: string) => {
      log.push(/length\(bytes\)/.test(sql) ? "size" : "read bytes");
      return read(sql);
    });
    const encrypt = deps.keys.encrypt;
    deps.keys.encrypt = async (scope: string, clear: Uint8Array) => {
      log.push("encrypt");
      return encrypt(scope, clear);
    };
    return { log, deps: deps as unknown as LocalSyncDeps };
  }

  it("holds plain and encrypted size before it reads or encrypts, and releases after the upload", async () => {
    const { log, deps } = governed(async () => () => {});
    await uploadBlobs(deps, [ATTACHMENT]);
    expect(log).toEqual([
      "size",
      `reserve ${2 * BYTES.length} ${BYTES.length}`,
      "read bytes",
      "encrypt",
      "put",
      "release",
    ]);
  });

  it("reads and encrypts nothing while the memory budget is full", async () => {
    const { log, deps } = governed(() => new Promise(() => {}));
    void uploadBlobs(deps, [ATTACHMENT]);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(log).toEqual([
      "size",
      `reserve ${2 * BYTES.length} ${BYTES.length}`,
    ]);
  });

  it("releases the memory when the upload fails", async () => {
    const { log, deps } = governed(async () => () => {});
    deps.keys.encrypt = async () => {
      throw new Error("encrypt failed");
    };
    await expect(uploadBlobs(deps, [ATTACHMENT])).rejects.toThrow(
      "encrypt failed",
    );
    expect(log.at(-1)).toBe("release");
  });

  it("refuses an attachment larger than the store accepts, before reading it", async () => {
    const governor = createStorageAccess({
      ...DEFAULT_STORAGE_ACCESS_POLICY,
      maxObjectBytes: BYTES.length - 1,
    });
    const store = countingStore({});
    const deps = depsWith({ ...store.blobs, governor } as never);
    await expect(
      uploadBlobs(deps as unknown as LocalSyncDeps, [ATTACHMENT]),
    ).rejects.toBeInstanceOf(StorageObjectTooLargeError);
    expect(deps.query).toHaveBeenCalledTimes(1); // the size, never the bytes
    expect(store.puts).toEqual([]);
  });

  it("admits an attachment exactly as large as the store accepts, though its memory is twice that", async () => {
    const governor = createStorageAccess({
      ...DEFAULT_STORAGE_ACCESS_POLICY,
      maxObjectBytes: BYTES.length,
    });
    const store = countingStore({});
    const deps = depsWith({ ...store.blobs, governor } as never);
    await uploadBlobs(deps as unknown as LocalSyncDeps, [ATTACHMENT]);
    expect(store.puts).toEqual([ATTACHMENT.key]);
  });
});
