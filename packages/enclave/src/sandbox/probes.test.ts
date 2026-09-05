import { afterEach, describe, expect, it, vi } from "vitest";
import { probeSync } from "./probes.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("sandbox sync probe", () => {
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
