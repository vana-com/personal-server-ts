import { describe, expect, it } from "vitest";
import {
  LegacyWriteRefusedError,
  legacyWriteRefusedErrorFor,
  refuseLegacyWrite,
  updateRequiredResponse,
  UPDATE_REQUIRED_MESSAGE,
} from "./legacy-write-gate.js";
import type { AccountStorageModeValue } from "./account-storage-mode.js";

const mode = (value: AccountStorageModeValue) => ({ read: () => value });

// The gate decides nothing: it turns the three answers of the mode port into
// the words a legacy client reads.
describe("refuseLegacyWrite, the three answers", () => {
  it("returns null for an unswitched account", () => {
    expect(refuseLegacyWrite(mode("unswitched"))).toBeNull();
  });

  it("returns the 426 update_required body for a switched account", async () => {
    const response = refuseLegacyWrite(mode("switched"));
    expect(response?.status).toBe(426);
    expect(response?.headers.get("upgrade")).toBe("vana-stream-sync");
    expect(response?.headers.get("cache-control")).toBe("no-store");
    const body = await response!.json();
    expect(body.errorCode).toBe("update_required");
    expect(body.error.errorCode).toBe("update_required");
    expect(body.message).toBe(UPDATE_REQUIRED_MESSAGE);
  });

  // UNKNOWN_AS_OFF
  it("returns a retryable 503 ACCOUNT_MODE_UNKNOWN when the mode is unknown", async () => {
    const response = refuseLegacyWrite(mode("unknown"));
    expect(response?.status).toBe(503);
    expect(response?.headers.get("retry-after")).toBe("5");
    const body = await response!.json();
    expect(body.error.errorCode).toBe("ACCOUNT_MODE_UNKNOWN");
  });

  // UNKNOWN_AS_OFF
  it("treats no mode wired as unknown: a missing answer is never permission", async () => {
    const response = refuseLegacyWrite(undefined);
    expect(response?.status).toBe(503);
    expect((await response!.json()).error.errorCode).toBe(
      "ACCOUNT_MODE_UNKNOWN",
    );
  });
});

describe("LegacyWriteRefusedError", () => {
  it("carries the 426 for a switched account and says never retry", async () => {
    const error = legacyWriteRefusedErrorFor("switched");
    expect(error).toBeInstanceOf(LegacyWriteRefusedError);
    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe("LegacyWriteRefusedError");
    expect(error.verdict).toBe("switched");
    expect(error.response.status).toBe(426);
    expect((await error.response.json()).errorCode).toBe("update_required");
  });

  it("carries the retryable 503 for an unknown mode", async () => {
    const error = legacyWriteRefusedErrorFor("unknown");
    expect(error.verdict).toBe("unknown");
    expect(error.response.status).toBe(503);
    expect(error.response.headers.get("retry-after")).toBe("5");
  });

  it("reads its verdict from the response status when none is given", () => {
    expect(new LegacyWriteRefusedError(updateRequiredResponse()).verdict).toBe(
      "switched",
    );
    expect(
      new LegacyWriteRefusedError(new Response(null, { status: 503 })).verdict,
    ).toBe("unknown");
  });
});
