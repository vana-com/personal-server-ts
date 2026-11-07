import { decodeHead } from "@opendatalabs/personal-server-ts-stream-sync";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createMemoryStreamSyncReadFiles } from "./memory-files.js";
import { ViewStore } from "./view-store.js";

// Isolate restoration completeness from the head wire-format validator.
vi.mock("@opendatalabs/personal-server-ts-stream-sync", () => ({
  decodeHead: vi.fn(),
}));

const key = { connector: "source", ns: "", stream: "records" };
const base = "views/source/_/records";
const hashes = ["a".repeat(64), "b".repeat(64)];
const head = {
  parts: hashes.map((hash) => ({ hash })),
} as unknown as Parameters<ViewStore["commit"]>[4];
const headBytes = new TextEncoder().encode("decoded by the fixture");
const dataHash = "c".repeat(64);

describe("restored view completeness", () => {
  beforeEach(() => {
    vi.mocked(decodeHead).mockReturnValue({ kind: "ok", head });
  });

  async function committed() {
    const files = createMemoryStreamSyncReadFiles();
    const store = await ViewStore.open(files);
    await store.putPart(key, hashes[0]!, new Uint8Array([1]));
    await store.putPart(key, hashes[1]!, new Uint8Array([2]));
    await store.commit(key, 7, dataHash, headBytes, head);
    return files;
  }

  it("does not import a restored head with a missing referenced part", async () => {
    const files = await committed();
    await files.remove(`${base}/parts/${hashes[1]}`);

    const restored = await ViewStore.open(files);

    expect(restored.get(key)).toBeNull();
    expect(restored.lease(key)).toBeNull();
    expect(restored.views()).toEqual([]);
    expect(await files.read(`${base}/current.json`)).toBeNull();
    // Retain surviving parts so an unchanged registry row can reuse them.
    expect(await restored.hasPart(key, hashes[0]!)).toBe(true);
  });

  it("allows reimport of the same registry version after an incomplete restore", async () => {
    const files = await committed();
    await files.remove(`${base}/parts/${hashes[1]}`);
    const restored = await ViewStore.open(files);
    expect(restored.get(key)).toBeNull();

    await restored.putPart(key, hashes[1]!, new Uint8Array([2]));
    await restored.commit(key, 7, dataHash, headBytes, head);

    const reopened = await ViewStore.open(files);
    expect(reopened.get(key)?.version).toBe(7);
    expect(await reopened.readPart(key, hashes[1]!)).toEqual(
      new Uint8Array([2]),
    );
  });

  it("preserves a complete restored view, including an existing empty part", async () => {
    const files = await committed();
    await files.write(`${base}/parts/${hashes[1]}`, new Uint8Array());

    const restored = await ViewStore.open(files);

    expect(restored.get(key)?.version).toBe(7);
    expect(restored.views()).toHaveLength(1);
    expect(await restored.readPart(key, hashes[1]!)).toEqual(new Uint8Array());
  });

  it("drops a pointer whose head is missing", async () => {
    const files = await committed();
    await files.remove(`${base}/heads/7.json`);

    const restored = await ViewStore.open(files);

    expect(restored.get(key)).toBeNull();
    expect(await files.read(`${base}/current.json`)).toBeNull();
  });
});
