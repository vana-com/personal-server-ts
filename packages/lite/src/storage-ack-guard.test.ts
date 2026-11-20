/**
 * An upload's acknowledgement names the row it uploaded. A path can be
 * replaced by a new row while the upload is in flight; the acknowledgement of
 * the old row must then change nothing.
 */
import { describe, expect, it } from "vitest";

import {
  createMemoryPsLitePersistence,
  createMemoryPsLiteStagedFileStore,
} from "./test-support/memory.js";
import { createOpenPersistentPsLiteStorage } from "./test-support/open-storage.js";

const SCOPE = "notes.entries";
const PATH = `data/${SCOPE}/2026-11-09T00:00:01.000Z.json`;
const row = (sizeBytes: number) => ({
  fileId: null,
  scope: SCOPE,
  collectedAt: "2026-11-09T00:00:01.000Z",
  path: PATH,
  sizeBytes,
});

async function open() {
  return createOpenPersistentPsLiteStorage(
    { kind: "custom" },
    createMemoryPsLitePersistence(),
    createMemoryPsLiteStagedFileStore(),
  );
}

describe("guarded acknowledgement of an upload", () => {
  it("stamps the row it names", async () => {
    const storage = await open();
    const a = await storage.insertEntry(row(1));

    expect(await storage.updateEntryVersion(PATH, 3, a.id)).toBe(true);
    expect(await storage.updateDataPointId(PATH, "0xa", a.id)).toBe(true);
    expect(
      storage.findEntry({ scope: SCOPE, at: a.collectedAt }),
    ).toMatchObject({
      version: 3,
      dataPointId: "0xa",
    });
  });

  it("does not stamp a row that replaced the one it names", async () => {
    const storage = await open();
    const a = await storage.insertEntry(row(1));
    const b = await storage.insertEntry(row(2));
    expect(b.id).not.toBe(a.id);

    expect(await storage.updateEntryVersion(PATH, 3, a.id)).toBe(false);
    expect(await storage.updateDataPointId(PATH, "0xa", a.id)).toBe(false);
    expect(
      storage.findEntry({ scope: SCOPE, at: a.collectedAt }),
    ).toMatchObject({
      id: b.id,
      version: b.version,
      dataPointId: null,
    });
    expect(storage.findUnsynced().map((e) => e.id)).toEqual([b.id]);
  });
});
