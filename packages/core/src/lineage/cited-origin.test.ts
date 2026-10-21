import { describe, expect, it } from "vitest";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { ingestDataContract } from "../contracts/data.js";
import { citedSourcesHavePdppOrigin } from "./cited-origin.js";

async function seed(
  storage: ReturnType<typeof createMemoryDataStorage>,
  scope: string,
  body: Record<string, unknown>,
  lineage?: { sources: `0x${string}`[]; writtenAt: string },
) {
  const r = await ingestDataContract({
    storage,
    scopeParam: scope,
    body,
    collectedAt: "2026-09-01T00:00:00Z",
    status: "stored",
    ...(lineage ? { lineage } : {}),
  });
  if (!r.ok) throw new Error("seed failed");
}

describe("citedSourcesHavePdppOrigin", () => {
  it("is false for no sources and for legacy-only sources", async () => {
    const storage = createMemoryDataStorage();
    await seed(storage, "oura.sleep", { score: 1 });
    expect(await citedSourcesHavePdppOrigin(storage, [])).toBe(false);
    expect(await citedSourcesHavePdppOrigin(storage, ["oura.sleep"])).toBe(
      false,
    );
  });

  it("is true when the row says PDPP even if the bytes look legacy", async () => {
    const storage = createMemoryDataStorage();
    await seed(storage, "oura.sleep", { score: 1 });
    storage.findEntry({ scope: "oura.sleep" })!.pdppOrigin = true;
    expect(await citedSourcesHavePdppOrigin(storage, ["oura.sleep"])).toBe(
      true,
    );
  });

  it("is true when the bytes say PDPP even if the row says legacy (pre-upgrade row)", async () => {
    const storage = createMemoryDataStorage();
    // No origin statement: what a derivative written before this change holds.
    await seed(
      storage,
      "archive.answer",
      { answer: "old" },
      { sources: [], writtenAt: "2026-09-01T00:00:00Z" },
    );
    expect(
      await citedSourcesHavePdppOrigin(
        {
          ...storage,
          findEntry: (q) => ({ ...storage.findEntry(q)!, pdppOrigin: false }),
          readEnvelope: storage.readEnvelope.bind(storage),
        },
        ["archive.answer"],
      ),
    ).toBe(true);
  });

  it("is true for a source with no row or that cannot be read", async () => {
    const storage = createMemoryDataStorage();
    expect(await citedSourcesHavePdppOrigin(storage, ["nothing.here"])).toBe(
      true,
    );
    await seed(storage, "oura.sleep", { score: 1 });
    expect(
      await citedSourcesHavePdppOrigin(
        {
          findEntry: storage.findEntry.bind(storage),
          readEnvelope: async () => {
            throw new Error("unreadable");
          },
        },
        ["oura.sleep"],
      ),
    ).toBe(true);
  });
});
