import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type { BlobDescriptor } from "./blobs.js";
import { uploadBlobs } from "./blobs.js";
import type { LocalSyncDeps } from "./deps.js";

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
  const query = vi.fn(async () => [{ bytes: BYTES }]);
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
