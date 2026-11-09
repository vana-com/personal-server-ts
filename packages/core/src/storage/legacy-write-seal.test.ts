import { describe, expect, it } from "vitest";
import { createAccountStorageMode } from "../api/account-storage-mode.js";
import { createLegacyWriteSeal } from "./legacy-write-seal.js";
import { LegacyWriteRefusedError } from "../api/legacy-write-gate.js";

const owner = "0x1111111111111111111111111111111111111111";

function sealWith(state: { value: boolean | "throw" }) {
  const mode = createAccountStorageMode({
    owner,
    source: () => {
      if (state.value === "throw") throw new Error("no evidence");
      return state.value;
    },
  });
  return createLegacyWriteSeal({ mode, owner });
}

describe("legacy write seal", () => {
  it("runs the step when the account is unswitched", () => {
    const seal = sealWith({ value: false });
    expect(seal.commit(() => 7)).toBe(7);
    expect(seal.verdict()).toBe("allow");
  });

  it("refuses a switched account with a 426 and runs nothing", () => {
    const seal = sealWith({ value: true });
    let ran = false;
    try {
      seal.commit(() => {
        ran = true;
      });
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(LegacyWriteRefusedError);
      expect((error as LegacyWriteRefusedError).verdict).toBe("switched");
      expect((error as LegacyWriteRefusedError).response.status).toBe(426);
    }
    expect(ran).toBe(false);
  });

  it("refuses when the mode cannot be known with a retryable 503", () => {
    const seal = sealWith({ value: "throw" });
    try {
      seal.commit(() => undefined);
      expect.unreachable();
    } catch (error) {
      expect((error as LegacyWriteRefusedError).verdict).toBe("unknown");
      expect((error as LegacyWriteRefusedError).response.status).toBe(503);
    }
  });

  it("answers unknown, never allow, until it is bound to a mode", () => {
    const seal = createLegacyWriteSeal();
    expect(seal.verdict()).toBe("unknown");
    expect(() => seal.assertOpen()).toThrow(LegacyWriteRefusedError);
  });

  it("asks the mode in the same tick the step starts", () => {
    const state = { value: false as boolean };
    const seal = sealWith(state);
    const order: string[] = [];
    seal.commit(() => {
      order.push("step");
      // A switch after the step began cannot undo it.
      state.value = true;
    });
    expect(order).toEqual(["step"]);
    expect(() => seal.commit(() => order.push("second"))).toThrow(
      LegacyWriteRefusedError,
    );
    expect(order).toEqual(["step"]);
  });

  it("drain waits for a commit that started before the switch, and not for later ones", async () => {
    const state = { value: false as boolean };
    const seal = sealWith(state);
    let release!: () => void;
    const parked = new Promise<void>((resolve) => (release = resolve));
    const landed: string[] = [];
    const commit = seal.commit(async () => {
      await parked;
      landed.push("first");
    });
    state.value = true;
    let drained = false;
    const draining = seal.drain().then(() => {
      drained = true;
    });
    await Promise.resolve();
    expect(drained).toBe(false);
    expect(() => seal.commit(async () => landed.push("late"))).toThrow(
      LegacyWriteRefusedError,
    );
    release();
    await commit;
    await draining;
    expect(landed).toEqual(["first"]);
  });

  it("drain also settles when the commit fails", async () => {
    const seal = sealWith({ value: false });
    const failing = seal.commit(async () => {
      throw new Error("disk full");
    });
    await expect(failing).rejects.toThrow("disk full");
    await expect(seal.drain()).resolves.toBeUndefined();
  });

  it("binds once: the same mode again is a no-op, another mode throws", () => {
    const seal = createLegacyWriteSeal();
    const mode = createAccountStorageMode({ source: () => false });
    seal.bind({ mode });
    seal.bind({ mode });
    expect(seal.verdict()).toBe("allow");
    expect(() =>
      seal.bind({ mode: createAccountStorageMode({ source: () => false }) }),
    ).toThrow(/already bound/);
  });
});
