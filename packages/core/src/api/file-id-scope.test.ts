import { describe, expect, it, vi } from "vitest";
import { handlePersonalServerDataRequest } from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";

/**
 * A file id selects a version inside the requested scope only. A file id of
 * another scope must behave exactly like one that does not exist, and the
 * foreign id must never reach policy.
 */
describe("data API: a wrong-scope file id is a missing file id", () => {
  async function run(fileId: string) {
    const storage = createMemoryDataStorage();
    for (const [scope, id] of [
      ["chatgpt.conversations", "file-chatgpt"],
      ["youtube.history", "file-youtube"],
    ] as const) {
      await storage.insertEntry({
        fileId: id,
        path: `${scope}/2026-11-01.json`,
        scope,
        collectedAt: "2026-11-01T00:00:00Z",
        sizeBytes: 10,
      });
    }
    const authorizeBuilderRead = vi
      .fn()
      .mockResolvedValue({ grantId: "grant-1", builder: "0x2222" });
    const response = await handlePersonalServerDataRequest(
      new Request(
        `https://ps.test/v1/data/chatgpt.conversations?content=raw&grantId=grant-1&fileId=${fileId}`,
      ),
      {
        storage,
        auth: {
          authorizeOwner: vi.fn(),
          authorizeBuilderList: vi.fn(),
          authorizeBuilderRead,
        },
        accessLogWriter: { write: vi.fn() },
        accountStorageMode: { owner: "fixture", read: () => "unswitched" },
      } as never,
      { basePath: "/v1/data" },
    );
    return {
      status: response.status,
      body: await response.text(),
      authorizeBuilderRead,
    };
  }

  it("answers byte-identically and never hands the foreign id to policy", async () => {
    const foreign = await run("file-youtube");
    const missing = await run("file-does-not-exist");
    expect(foreign.status).toBe(missing.status);
    expect(foreign.body).toBe(missing.body);
    expect(foreign.status).toBe(404);
    for (const call of [
      ...foreign.authorizeBuilderRead.mock.calls,
      ...missing.authorizeBuilderRead.mock.calls,
    ]) {
      expect(call[0].fileId).toBeUndefined();
    }
  });
});
