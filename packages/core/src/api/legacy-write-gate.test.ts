import { describe, expect, it, vi } from "vitest";
import { createAccountStorageMode } from "./account-storage-mode.js";
import {
  fenceLegacyCommit,
  LegacyWriteRefusedError,
  legacyWriteVerdict,
  refuseLegacyWrite,
  UPDATE_REQUIRED_MESSAGE,
} from "./legacy-write-gate.js";

const OWNER_A = "0x1111111111111111111111111111111111111111";
const OWNER_B = "0x2222222222222222222222222222222222222222";

/** A switch source whose answer a test can change between writes. */
function source(initial: boolean | "unreachable") {
  const state = { value: initial };
  const read = vi.fn(() => {
    if (state.value === "unreachable") throw new Error("Account unreachable");
    return state.value;
  });
  return { state, read };
}

describe("legacyWriteVerdict", () => {
  it("treats an unwired mode as unknown, never as allow (UNWIRED_ALLOWS)", () => {
    expect(legacyWriteVerdict(undefined)).toBe("unknown");
    expect(refuseLegacyWrite(undefined)?.status).toBe(503);
  });

  it("follows the mode: unswitched allows, switched refuses, unknown refuses", () => {
    expect(
      legacyWriteVerdict(createAccountStorageMode({ source: () => false })),
    ).toBe("allow");
    expect(
      legacyWriteVerdict(createAccountStorageMode({ source: () => true })),
    ).toBe("switched");
    expect(
      legacyWriteVerdict(
        createAccountStorageMode({
          source: () => {
            throw new Error("Account unreachable");
          },
        }),
      ),
    ).toBe("unknown");
  });

  it("answers unknown for an owner the mode is not bound to", () => {
    const mode = createAccountStorageMode({
      owner: OWNER_A,
      source: () => false,
    });
    expect(legacyWriteVerdict(mode, OWNER_A)).toBe("allow");
    expect(legacyWriteVerdict(mode, OWNER_B)).toBe("unknown");
  });
});

describe("refuseLegacyWrite", () => {
  it("returns null for an unswitched account", () => {
    expect(
      refuseLegacyWrite(createAccountStorageMode({ source: () => false })),
    ).toBeNull();
  });

  it("returns the 426 update_required body for a switched account", async () => {
    const response = refuseLegacyWrite(
      createAccountStorageMode({ source: () => true }),
    );
    expect(response?.status).toBe(426);
    expect(response?.headers.get("upgrade")).toBe("vana-stream-sync");
    const body = await response!.json();
    expect(body.errorCode).toBe("update_required");
    expect(body.error.errorCode).toBe("update_required");
    expect(body.message).toBe(UPDATE_REQUIRED_MESSAGE);
  });

  it("returns a retryable 503 ACCOUNT_MODE_UNKNOWN while the mode is unknown", async () => {
    const { read } = source("unreachable");
    const response = refuseLegacyWrite(
      createAccountStorageMode({ source: read }),
    );
    expect(response?.status).toBe(503);
    expect(response?.headers.get("retry-after")).toBe("5");
    expect((await response!.json()).error.errorCode).toBe(
      "ACCOUNT_MODE_UNKNOWN",
    );
  });

  it("stays switched after the source says true, then false, then unreachable", () => {
    const { state, read } = source(true);
    const mode = createAccountStorageMode({ source: read });
    expect(refuseLegacyWrite(mode)?.status).toBe(426);
    state.value = false;
    expect(refuseLegacyWrite(mode)?.status).toBe(426);
    state.value = "unreachable";
    expect(refuseLegacyWrite(mode)?.status).toBe(426);
  });

  it("allows once an unreachable source recovers to false, and refuses once it says true", () => {
    const { state, read } = source("unreachable");
    const mode = createAccountStorageMode({ source: read });
    expect(refuseLegacyWrite(mode)?.status).toBe(503);
    state.value = false;
    expect(refuseLegacyWrite(mode)).toBeNull();
    state.value = true;
    expect(refuseLegacyWrite(mode)?.status).toBe(426);
  });
});

describe("fenceLegacyCommit", () => {
  it("passes while the account is unswitched and re-reads the mode on every call", () => {
    const { state, read } = source(false);
    const mode = createAccountStorageMode({ source: read });
    expect(() => fenceLegacyCommit(mode)).not.toThrow();
    state.value = true;
    expect(() => fenceLegacyCommit(mode)).toThrow(LegacyWriteRefusedError);
  });

  it("carries the 426 response when switched and the 503 when unknown", () => {
    const switched = createAccountStorageMode({ source: () => true });
    try {
      fenceLegacyCommit(switched);
      throw new Error("expected a refusal");
    } catch (error) {
      expect((error as LegacyWriteRefusedError).response.status).toBe(426);
    }
    const unknown = createAccountStorageMode({
      source: () => true,
      owner: OWNER_A,
    });
    try {
      fenceLegacyCommit(unknown, OWNER_B);
      throw new Error("expected a refusal");
    } catch (error) {
      expect((error as LegacyWriteRefusedError).response.status).toBe(503);
    }
  });

  it("leaves the decision to the storage seal when no mode is wired", () => {
    // The route-level check has no opinion without a mode; the seal at the
    // final durable step refuses (unknown), so nothing depends on this.
    expect(() => fenceLegacyCommit(undefined)).not.toThrow();
  });
});
