import { sha256 } from "@noble/hashes/sha2";
import { decodeHead } from "@opendatalabs/personal-server-ts-stream-sync";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createMemoryStreamSyncReadFiles } from "./memory-files.js";
import { ViewStore, type ImportedVersion } from "./view-store.js";

// Isolate restoration completeness from the head wire-format validator.
vi.mock("@opendatalabs/personal-server-ts-stream-sync", () => ({
  decodeHead: vi.fn(),
}));

const key = { connector: "source", ns: "", stream: "records" };
const base = "views/source/_/records";
const clear = [new Uint8Array([1]), new Uint8Array()];
// A part is stored under the SHA-256 of its clear bytes.
const hashes = clear.map((bytes) =>
  Array.from(sha256(bytes), (b) => b.toString(16).padStart(2, "0")).join(""),
);
const head = {
  parts: hashes.map((hash, i) => ({ hash, bytes: clear[i]!.length })),
} as unknown as ImportedVersion["head"];
const headBytes = new TextEncoder().encode("decoded by the fixture");
const dataHash = "c".repeat(64);

describe("restored view completeness", () => {
  beforeEach(() => {
    vi.mocked(decodeHead).mockReturnValue({ kind: "ok", head });
  });

  /** Import version 7 the way the importer does: parts first, then commit. */
  async function importSeven(store: ViewStore, only?: number) {
    await store.withImport(key, async (tx) => {
      for (const [i, hash] of hashes.entries()) {
        if (only !== undefined && i !== only) continue;
        if (!(await tx.hasPart(hash))) await tx.putPart(hash, clear[i]!);
      }
      await tx.commit(7, dataHash, headBytes, head);
    });
  }

  async function committed() {
    const files = createMemoryStreamSyncReadFiles();
    await importSeven(await ViewStore.open(files));
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
    expect(await files.read(`${base}/parts/${hashes[0]}`)).not.toBeNull();
  });

  it("allows reimport of the same registry version after an incomplete restore", async () => {
    const files = await committed();
    await files.remove(`${base}/parts/${hashes[1]}`);
    const restored = await ViewStore.open(files);
    expect(restored.get(key)).toBeNull();

    await importSeven(restored);

    const reopened = await ViewStore.open(files);
    expect(reopened.get(key)?.version).toBe(7);
    expect(await reopened.readPart(key, hashes[1]!)).toEqual(clear[1]);
  });

  it("preserves a complete restored view, including an existing empty part", async () => {
    const files = await committed();
    await files.write(`${base}/parts/${hashes[1]}`, clear[1]!);

    const restored = await ViewStore.open(files);

    expect(restored.get(key)?.version).toBe(7);
    expect(restored.views()).toHaveLength(1);
    expect(await restored.readPart(key, hashes[1]!)).toEqual(clear[1]);
  });

  it("drops a pointer whose head is missing", async () => {
    const files = await committed();
    await files.remove(`${base}/heads/7.json`);

    const restored = await ViewStore.open(files);

    expect(restored.get(key)).toBeNull();
    expect(await files.read(`${base}/current.json`)).toBeNull();
  });
});
