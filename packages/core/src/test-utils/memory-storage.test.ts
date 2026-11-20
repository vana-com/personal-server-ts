import { describe, expect, it } from "vitest";
import { createMemoryDataStorage } from "./memory-storage.js";

describe("memory data storage findEntry", () => {
  it("answers another scope's file id as a missing one", async () => {
    const storage = createMemoryDataStorage();
    for (const [scope, fileId] of [
      ["chatgpt.conversations", "file-chatgpt"],
      ["youtube.history", "file-youtube"],
    ] as const) {
      const entry = await storage.insertEntry({
        fileId,
        path: `${scope}/2026-11-01.json`,
        scope,
        collectedAt: "2026-11-01T00:00:00Z",
        sizeBytes: 10,
      });
      expect(entry.fileId).toBe(fileId);
    }
    const own = storage.findEntry({
      scope: "chatgpt.conversations",
      fileId: "file-chatgpt",
    });
    expect(own?.scope).toBe("chatgpt.conversations");
    expect(
      storage.findEntry({
        scope: "chatgpt.conversations",
        fileId: "file-youtube",
      }),
    ).toBeUndefined();
    expect(
      storage.findEntry({ scope: "chatgpt.conversations", fileId: "nope" }),
    ).toBeUndefined();
  });
});
