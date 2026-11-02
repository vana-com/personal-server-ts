import { afterEach, expect, it, vi } from "vitest";
import { withCreateOnlyUploads } from "./write-once.js";
import type { StorageAdapter } from "./interface.js";

afterEach(() => vi.unstubAllGlobals());

it.each([404, false, "true"])(
  "never PUTs when storage does not advertise write-once enforcement (%s)",
  async (value) => {
    const upload = vi.fn(async () => "blob");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        value === 404
          ? new Response(null, { status: 404 })
          : Response.json({ blobs: { writeOnce: value } }),
      ),
    );
    const adapter = withCreateOnlyUploads(
      { upload } as unknown as StorageAdapter,
      "https://storage.example",
    );
    await expect(
      adapter.uploadCreateOnly!("scope/1", new Uint8Array([1])),
    ).rejects.toThrow("Atomic create-only storage is unavailable");
    expect(upload).not.toHaveBeenCalled();
  },
);

it("rechecks an unavailable backend and admits uploads after enforcement is advertised", async () => {
  const upload = vi.fn(async () => "blob");
  const fetcher = vi
    .fn()
    .mockResolvedValueOnce(new Response(null, { status: 404 }))
    .mockResolvedValue(Response.json({ blobs: { writeOnce: true } }));
  vi.stubGlobal("fetch", fetcher);
  const adapter = withCreateOnlyUploads(
    { upload } as unknown as StorageAdapter,
    "https://storage.example",
  );
  await expect(
    adapter.uploadCreateOnly!("scope/1", new Uint8Array([1])),
  ).rejects.toThrow();
  await adapter.uploadCreateOnly!("scope/1", new Uint8Array([1]));
  await adapter.uploadCreateOnly!("scope/2", new Uint8Array([2]));
  expect(upload).toHaveBeenCalledTimes(2);
  expect(fetcher).toHaveBeenCalledTimes(2);
});
