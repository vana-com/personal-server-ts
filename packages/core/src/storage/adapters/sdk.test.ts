import { describe, expect, it, vi } from "vitest";

import { createSdkStorageAdapter, type SdkStorageProvider } from "./sdk.js";

describe("createSdkStorageAdapter", () => {
  it("delegates upload and download through the SDK storage provider", async () => {
    const provider: SdkStorageProvider = {
      upload: vi.fn().mockResolvedValue({
        url: "https://storage.example/file",
        size: 3,
        contentType: "application/octet-stream",
      }),
      download: vi
        .fn()
        .mockResolvedValue(new Blob([new Uint8Array([4, 5, 6])])),
      delete: vi.fn().mockResolvedValue(true),
    };

    const adapter = createSdkStorageAdapter(provider);
    const url = await adapter.upload(
      "scope/collected-at",
      new Uint8Array([1, 2, 3]),
    );
    const bytes = await adapter.download(url);

    expect(url).toBe("https://storage.example/file");
    expect(bytes).toEqual(new Uint8Array([4, 5, 6]));
    expect(provider.upload).toHaveBeenCalledWith(
      expect.any(Blob),
      "scope/collected-at",
    );
    expect(provider.download).toHaveBeenCalledWith(
      "https://storage.example/file",
    );
  });

  it("lazily constructs SDK storage providers", async () => {
    const provider: SdkStorageProvider = {
      upload: vi.fn().mockResolvedValue({
        url: "https://storage.example/file",
        size: 1,
        contentType: "application/octet-stream",
      }),
      download: vi.fn().mockResolvedValue(new Blob()),
      delete: vi.fn().mockResolvedValue(true),
    };
    const factory = vi.fn(() => provider);
    const adapter = createSdkStorageAdapter(factory);

    expect(factory).not.toHaveBeenCalled();
    await adapter.upload("scope/key", new Uint8Array([1]));
    await adapter.delete("https://storage.example/file");

    expect(factory).toHaveBeenCalledTimes(1);
  });

  describe("exists", () => {
    function adapterWithDownload(download: ReturnType<typeof vi.fn>) {
      return createSdkStorageAdapter({
        upload: vi.fn(),
        download,
        delete: vi.fn(),
      } as unknown as SdkStorageProvider);
    }

    it("returns true when the blob downloads", async () => {
      const adapter = adapterWithDownload(
        vi.fn().mockResolvedValue(new Blob()),
      );
      await expect(adapter.exists("https://s/x")).resolves.toBe(true);
    });

    it("returns false only for a definitive not-found", async () => {
      const adapter = adapterWithDownload(
        vi
          .fn()
          .mockRejectedValue(
            new Error("vana-storage download failed: 404 Not Found"),
          ),
      );
      await expect(adapter.exists("https://s/x")).resolves.toBe(false);
    });

    it("rethrows transient failures instead of reporting absence", async () => {
      // A 5xx or network blip must not read as "blob missing" — the upload
      // worker's blob heal would overwrite a blob that is actually there.
      const adapter = adapterWithDownload(
        vi
          .fn()
          .mockRejectedValue(
            new Error("vana-storage download failed: 503 Service Unavailable"),
          ),
      );
      await expect(adapter.exists("https://s/x")).rejects.toThrow("503");

      const networkAdapter = adapterWithDownload(
        vi
          .fn()
          .mockRejectedValue(
            new Error("vana-storage download network error: fetch failed"),
          ),
      );
      await expect(networkAdapter.exists("https://s/x")).rejects.toThrow(
        "network error",
      );
    });
  });
});
