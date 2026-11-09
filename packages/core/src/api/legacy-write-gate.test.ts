import { describe, expect, it, vi } from "vitest";
import {
  latchLegacyWriteSwitch,
  legacyWritesRefused,
  refuseLegacyWrite,
  UPDATE_REQUIRED_MESSAGE,
} from "./legacy-write-gate.js";

/** A switch source whose answer a test can change between writes. */
function source(initial: boolean | "unreachable") {
  const state = { value: initial };
  const read = vi.fn(() => {
    if (state.value === "unreachable") throw new Error("Account unreachable");
    return state.value;
  });
  return { state, read };
}

describe("legacyWritesRefused", () => {
  it("refuses nothing when no switch is wired", () => {
    expect(legacyWritesRefused(undefined)).toBe(false);
  });

  it("refuses exactly while the switch reads true", () => {
    expect(legacyWritesRefused(() => true)).toBe(true);
    expect(legacyWritesRefused(() => false)).toBe(false);
  });
});

describe("refuseLegacyWrite", () => {
  it("returns null for an unswitched account", () => {
    expect(refuseLegacyWrite(() => false)).toBeNull();
  });

  it("returns the 426 update_required body for a switched account", async () => {
    const response = refuseLegacyWrite(() => true);
    expect(response?.status).toBe(426);
    expect(response?.headers.get("upgrade")).toBe("vana-stream-sync");
    const body = await response!.json();
    expect(body.errorCode).toBe("update_required");
    expect(body.error.errorCode).toBe("update_required");
    expect(body.message).toBe(UPDATE_REQUIRED_MESSAGE);
  });
});

describe("latchLegacyWriteSwitch", () => {
  it("stays switched after the source says true, even when it later says false", () => {
    const { state, read } = source(true);
    const latched = latchLegacyWriteSwitch(read);
    expect(latched()).toBe(true);
    state.value = false;
    expect(latched()).toBe(true);
    expect(latched()).toBe(true);
    // Once latched the source is not consulted again.
    expect(read).toHaveBeenCalledTimes(1);
  });

  it("stays switched after the source becomes unreachable", () => {
    const { state, read } = source(true);
    const latched = latchLegacyWriteSwitch(read);
    expect(latched()).toBe(true);
    state.value = "unreachable";
    expect(latched()).toBe(true);
  });

  it("fails open: an unreachable source before any true answer is not switched", () => {
    const { state, read } = source("unreachable");
    const latched = latchLegacyWriteSwitch(read);
    expect(latched()).toBe(false);
    expect(refuseLegacyWrite(latched)).toBeNull();
    // Once the source is reachable and says true, the latch sets and holds.
    state.value = true;
    expect(latched()).toBe(true);
    state.value = false;
    expect(latched()).toBe(true);
  });

  it("follows a source that has never said true, in both directions", () => {
    const { state, read } = source(false);
    const latched = latchLegacyWriteSwitch(read);
    expect(latched()).toBe(false);
    state.value = true;
    expect(latched()).toBe(true);
  });
});
