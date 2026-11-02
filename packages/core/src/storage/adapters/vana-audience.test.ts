import { afterEach, expect, it, vi } from "vitest";
import { createAudienceVanaAdapter } from "./vana-audience.js";
import { StoredBlobConflictError } from "./interface.js";

afterEach(() => vi.unstubAllGlobals());
it("classifies only PUT 409 as immutable blob conflicts on the audience adapter", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(null, { status: 409 })),
  );
  const adapter = createAudienceVanaAdapter({
    endpoint: "https://preview.example",
    audience: "https://storage.example",
    chainId: 14800,
    owner: `0x${"11".repeat(20)}`,
    signer: { signMessage: async () => "0x1234" },
  });
  await expect(
    adapter.upload("scope/1", new Uint8Array([1])),
  ).rejects.toBeInstanceOf(StoredBlobConflictError);
  await expect(
    adapter.download(adapter.urlForKey("scope/1")),
  ).rejects.not.toBeInstanceOf(StoredBlobConflictError);
  await expect(
    adapter.delete(adapter.urlForKey("scope/1")),
  ).rejects.not.toBeInstanceOf(StoredBlobConflictError);
});
