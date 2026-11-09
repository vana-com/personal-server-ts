import { describe, expect, it } from "vitest";
import {
  legacyWritesRefused,
  refuseLegacyWrite,
  UPDATE_REQUIRED_MESSAGE,
} from "./legacy-write-gate.js";
import type { AccountStorageModeValue } from "./account-storage-mode.js";

const mode = (value: AccountStorageModeValue) => ({ read: () => value });

describe("legacyWritesRefused", () => {
  // UNKNOWN_AS_OFF
  it("refuses when no mode is wired: a missing mode is never permission", () => {
    expect(legacyWritesRefused(undefined)).toBe(true);
  });

  it("refuses unless the account is unswitched", () => {
    expect(legacyWritesRefused(mode("unswitched"))).toBe(false);
    expect(legacyWritesRefused(mode("switched"))).toBe(true);
    expect(legacyWritesRefused(mode("unknown"))).toBe(true);
  });
});

describe("refuseLegacyWrite", () => {
  it("returns null for an unswitched account", () => {
    expect(refuseLegacyWrite(mode("unswitched"))).toBeNull();
  });

  it("returns the 426 update_required body for a switched account", async () => {
    const response = refuseLegacyWrite(mode("switched"));
    expect(response?.status).toBe(426);
    expect(response?.headers.get("upgrade")).toBe("vana-stream-sync");
    const body = await response!.json();
    expect(body.errorCode).toBe("update_required");
    expect(body.error.errorCode).toBe("update_required");
    expect(body.message).toBe(UPDATE_REQUIRED_MESSAGE);
  });

  // UNKNOWN_AS_OFF
  it("returns a retryable 503 ACCOUNT_MODE_UNKNOWN when the mode is unknown", async () => {
    for (const unknown of [mode("unknown"), undefined]) {
      const response = refuseLegacyWrite(unknown);
      expect(response?.status).toBe(503);
      expect(response?.headers.get("retry-after")).toBe("5");
      const body = await response!.json();
      expect(body.error.errorCode).toBe("ACCOUNT_MODE_UNKNOWN");
    }
  });
});
