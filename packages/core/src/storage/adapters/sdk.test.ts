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
});
