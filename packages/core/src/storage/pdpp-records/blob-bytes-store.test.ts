import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { createMemoryRecordStore } from "./memory-store.js";
import { BlobConflictError } from "./types.js";

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

describe("memory record store: blob bytes", () => {
  it("stores bytes and derives blob_id from their content", () => {
    const store = createMemoryRecordStore();
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const meta = store.storeBlobBytes(bytes, "application/octet-stream");
    expect(meta.blobId).toBe(`sha256:${sha256Hex(bytes)}`);
    expect(meta.sizeBytes).toBe(4);
    expect(meta.sha256).toBe(sha256Hex(bytes));
    expect(meta.mimeType).toBe("application/octet-stream");
  });

  it("reads back the exact bytes just stored", () => {
    const store = createMemoryRecordStore();
    const bytes = new Uint8Array([9, 8, 7, 255, 0]);
    const meta = store.storeBlobBytes(bytes, "image/png");
    const readBack = store.getBlobBytes(meta.blobId);
    expect(readBack).toBeDefined();
    expect(Array.from(readBack!)).toEqual(Array.from(bytes));
  });

  it("makes stored metadata visible through getBlobMeta", () => {
    const store = createMemoryRecordStore();
    const meta = store.storeBlobBytes(new Uint8Array([1]), "text/plain");
    expect(store.getBlobMeta(meta.blobId)).toEqual(meta);
  });

  it("re-storing identical bytes with the same mimeType is an idempotent no-op", () => {
    const store = createMemoryRecordStore();
    const bytes = new Uint8Array([1, 2, 3]);
    const first = store.storeBlobBytes(bytes, "image/jpeg");
    const second = store.storeBlobBytes(bytes.slice(), "image/jpeg");
    expect(second).toEqual(first);
    expect(store.getBlobBytes(first.blobId)?.byteLength).toBe(3);
  });

  it("throws BlobConflictError when identical bytes are re-stored with a different mimeType", () => {
    const store = createMemoryRecordStore();
    const bytes = new Uint8Array([1, 2, 3]);
    store.storeBlobBytes(bytes, "image/jpeg");
    expect(() => store.storeBlobBytes(bytes.slice(), "image/png")).toThrow(
      BlobConflictError,
    );
    // The original bytes/metadata are untouched by the rejected attempt.
    const meta = store.getBlobMeta(`sha256:${sha256Hex(bytes)}`);
    expect(meta?.mimeType).toBe("image/jpeg");
  });

  it("different content produces different blob_ids, never colliding or overwriting", () => {
    const store = createMemoryRecordStore();
    const a = store.storeBlobBytes(new Uint8Array([1]), "text/plain");
    const b = store.storeBlobBytes(new Uint8Array([2]), "text/plain");
    expect(a.blobId).not.toBe(b.blobId);
    expect(store.getBlobBytes(a.blobId)?.[0]).toBe(1);
    expect(store.getBlobBytes(b.blobId)?.[0]).toBe(2);
  });

  it("returns undefined for a blob_id with metadata but no stored bytes (legacy/test fixture row)", () => {
    const store = createMemoryRecordStore();
    store.putBlobMeta({
      blobId: "blob_legacy",
      mimeType: "image/jpeg",
      sizeBytes: 10,
      sha256: "deadbeef",
    });
    expect(store.getBlobBytes("blob_legacy")).toBeUndefined();
  });

  it("returns undefined for a completely unknown blob_id", () => {
    const store = createMemoryRecordStore();
    expect(store.getBlobBytes("blob_nonexistent")).toBeUndefined();
  });

  it("fails closed when stored bytes no longer match the recorded metadata (corruption)", () => {
    const store = createMemoryRecordStore();
    const bytes = new Uint8Array([1, 2, 3]);
    const meta = store.storeBlobBytes(bytes, "application/octet-stream");
    // Simulate on-disk corruption: metadata claims a hash/size that the
    // actual stored bytes no longer satisfy.
    store.putBlobMeta({ ...meta, sha256: "0".repeat(64) });
    expect(store.getBlobBytes(meta.blobId)).toBeUndefined();
  });

  it("fails closed when recorded sizeBytes no longer matches the stored payload length", () => {
    const store = createMemoryRecordStore();
    const bytes = new Uint8Array([1, 2, 3]);
    const meta = store.storeBlobBytes(bytes, "application/octet-stream");
    store.putBlobMeta({ ...meta, sizeBytes: 999 });
    expect(store.getBlobBytes(meta.blobId)).toBeUndefined();
  });

  it("supports a genuine zero-byte blob distinctly from an absent one", () => {
    const store = createMemoryRecordStore();
    const meta = store.storeBlobBytes(
      new Uint8Array(0),
      "application/octet-stream",
    );
    const readBack = store.getBlobBytes(meta.blobId);
    expect(readBack).toBeDefined();
    expect(readBack?.byteLength).toBe(0);
  });

  it("clears blob bytes on close", () => {
    const store = createMemoryRecordStore();
    const meta = store.storeBlobBytes(new Uint8Array([1]), "text/plain");
    store.close();
    expect(store.getBlobBytes(meta.blobId)).toBeUndefined();
  });

  it("completes a metadata-only row (matching mimeType, no bytes yet) instead of reporting a false no-op", () => {
    const store = createMemoryRecordStore();
    const bytes = new Uint8Array([1, 2, 3]);
    const blobId = `sha256:${sha256Hex(bytes)}`;
    store.putBlobMeta({
      blobId,
      mimeType: "image/jpeg",
      sizeBytes: bytes.byteLength,
      sha256: sha256Hex(bytes),
    });
    expect(store.getBlobBytes(blobId)).toBeUndefined();

    const meta = store.storeBlobBytes(bytes, "image/jpeg");
    expect(meta.blobId).toBe(blobId);
    const readBack = store.getBlobBytes(blobId);
    expect(readBack).toBeDefined();
    expect(Array.from(readBack!)).toEqual(Array.from(bytes));
  });

  it("does not return a false success when re-storing over existing corrupt bytes", () => {
    const store = createMemoryRecordStore();
    const bytes = new Uint8Array([1, 2, 3]);
    const meta = store.storeBlobBytes(bytes, "application/octet-stream");
    // Corrupt the recorded metadata so it no longer matches the stored bytes.
    store.putBlobMeta({ ...meta, sha256: "0".repeat(64) });
    expect(store.getBlobBytes(meta.blobId)).toBeUndefined();

    // Re-storing the SAME original bytes must not silently report success
    // over content that is now unverifiable -- it's an explicit conflict.
    expect(() =>
      store.storeBlobBytes(bytes.slice(), "application/octet-stream"),
    ).toThrow(BlobConflictError);
  });

  it("rejects mismatched MIME type without changing the persisted content", () => {
    const store = createMemoryRecordStore();
    const bytes = new Uint8Array([1, 2, 3]);
    const original = store.storeBlobBytes(bytes, "image/jpeg");

    expect(() => store.storeBlobBytes(bytes.slice(), "image/png")).toThrow(
      BlobConflictError,
    );

    // Persisted content is untouched by the rejected attempt.
    expect(store.getBlobMeta(original.blobId)).toEqual(original);
    const readBack = store.getBlobBytes(original.blobId);
    expect(Array.from(readBack!)).toEqual(Array.from(bytes));
  });
});

describe("metadata-only completion integrity", () => {
  it.each(["sha256", "sizeBytes"] as const)(
    "rejects incompatible %s before adding bytes",
    (field) => {
      const store = createMemoryRecordStore();
      try {
        const bytes = new Uint8Array([1, 2, 3]);
        const correct = {
          blobId: `sha256:${sha256Hex(bytes)}`,
          sha256: sha256Hex(bytes),
          sizeBytes: bytes.length,
          mimeType: "image/jpeg",
        };
        const invalid = {
          ...correct,
          ...(field === "sha256"
            ? { sha256: "0".repeat(64) }
            : { sizeBytes: 99 }),
        };
        store.putBlobMeta(invalid);
        expect(() => store.storeBlobBytes(bytes, correct.mimeType)).toThrow(
          BlobConflictError,
        );
        expect(store.getBlobMeta(correct.blobId)).toEqual(invalid);
        store.putBlobMeta(correct);
        expect(store.getBlobBytes(correct.blobId)).toBeUndefined();
      } finally {
        store.close();
      }
    },
  );
});
