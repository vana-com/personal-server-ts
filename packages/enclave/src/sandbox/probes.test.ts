import { afterEach, describe, expect, it, vi } from "vitest";
import { probeSync, probeSyncStatus } from "./probes.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("sandbox sync probe", () => {
  it("is ready once the requested scope is hydrated during full sync", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            enabled: true,
            running: true,
            syncing: true,
            lastSync: null,
            pendingFiles: 0,
            hydratedScopes: ["chatgpt.conversations"],
            errors: [],
          }),
          { status: 200 },
        ),
      ),
    );

    const result = await probeSyncStatus(
      "http://sandbox",
      "token",
      undefined,
      "chatgpt.conversations",
    );

    expect(result.ready).toBe(true);
  });

  it("uses the full-sync predicate when no requested scope is provided", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            enabled: true,
            running: true,
            syncing: true,
            lastSync: null,
            pendingFiles: 0,
            hydratedScopes: ["chatgpt.conversations"],
            errors: [],
          }),
          { status: 200 },
        ),
      ),
    );

    await expect(probeSyncStatus("http://sandbox", "token")).resolves.toEqual(
      expect.objectContaining({ ready: false }),
    );
  });

  it.each([
    ["unregistered", "Register this Personal Server before syncing."],
    [
      "registration_check_failed",
      "Could not verify server registration before syncing.",
    ],
  ])(
    "fails immediately when sync is blocked by %s",
    async (reason, message) => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(
          new Response(
            JSON.stringify({
              enabled: true,
              running: true,
              syncing: false,
              blocked: { reason, message },
              lastSync: null,
              lastProcessedTimestamp: null,
              pendingFiles: 0,
              errors: [],
            }),
            { status: 200 },
          ),
        ),
      );

      await expect(probeSync("http://sandbox", "token")).rejects.toThrow(
        `Sandbox sync failed: ${reason}: ${message}`,
      );
    },
  );
});
