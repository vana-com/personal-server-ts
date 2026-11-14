/**
 * The legacy-write seal over a REAL mode authority (not a stub): the seal is
 * the module's own lock, so these tests drive the lock, not a copy of its
 * answer.
 */
import { describe, expect, it } from "vitest";
import { LegacyWriteRefusedError } from "../api/legacy-write-gate.js";
import { authorityHearing } from "../test-utils/account-mode.js";
import {
  createMemoryModeRecordStore,
  createModeAuthority,
} from "../sync/account-mode/index.js";
import { createLegacyWriteSeal } from "./legacy-write-seal.js";

const OWNER = "0x1111111111111111111111111111111111111111";

function gate() {
  let open!: () => void;
  const opened = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { opened, open };
}
const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

async function sealOver(state: "off" | "on") {
  const authority = await authorityHearing(OWNER, state);
  return {
    authority,
    seal: createLegacyWriteSeal({ authority, owner: OWNER }),
  };
}

const evidence = (state: "on" | "off") => ({
  owner: OWNER,
  state,
});

describe("commit", () => {
  it("runs the write for an unswitched account and returns its value", async () => {
    const { seal } = await sealOver("off");
    let ran = 0;
    expect(
      await seal.commit(async () => {
        ran += 1;
        return "stored";
      }),
    ).toBe("stored");
    expect(ran).toBe(1);
  });

  it("refuses a switched account with the 426 and never runs the write", async () => {
    const { seal } = await sealOver("on");
    let ran = 0;
    const refused = await seal
      .commit(() => {
        ran += 1;
      })
      .catch((error: unknown) => error);
    expect(refused).toBeInstanceOf(LegacyWriteRefusedError);
    expect((refused as LegacyWriteRefusedError).verdict).toBe("switched");
    expect((refused as LegacyWriteRefusedError).response.status).toBe(426);
    expect(ran).toBe(0);
  });

  // UNKNOWN_AS_OFF
  it("refuses an unknown mode with the retryable 503", async () => {
    const authority = createModeAuthority({
      store: createMemoryModeRecordStore(),
    });
    await authority.ready;
    const seal = createLegacyWriteSeal({ authority, owner: OWNER });
    let ran = 0;
    const refused = await seal
      .commit(() => {
        ran += 1;
      })
      .catch((error: unknown) => error);
    expect((refused as LegacyWriteRefusedError).verdict).toBe("unknown");
    expect((refused as LegacyWriteRefusedError).response.status).toBe(503);
    expect(ran).toBe(0);
  });

  // UNKNOWN_AS_OFF
  it("answers unknown for a store with no owner, even on an unswitched account", async () => {
    const authority = await authorityHearing(OWNER, "off");
    const seal = createLegacyWriteSeal({ authority, owner: undefined });
    let ran = 0;
    const refused = await seal
      .commit(() => {
        ran += 1;
      })
      .catch((error: unknown) => error);
    expect((refused as LegacyWriteRefusedError).verdict).toBe("unknown");
    expect(ran).toBe(0);
  });

  it("asks for a record other than the one it was built for: the owner is the store's, not the caller's", async () => {
    const authority = await authorityHearing(OWNER, "off");
    const other = createLegacyWriteSeal({
      authority,
      owner: "0x2222222222222222222222222222222222222222",
    });
    await expect(other.commit(() => 1)).rejects.toBeInstanceOf(
      LegacyWriteRefusedError,
    );
  });

  // SEAL_OUTSIDE_LOCK
  it("lets a commit in flight when On is submitted finish before On is answered", async () => {
    const { authority, seal } = await sealOver("off");
    const barrier = gate();
    let landed = false;
    const write = seal.commit(async () => {
      await barrier.opened;
      landed = true;
    });
    await tick();
    let answered = false;
    const on = authority.submitEvidence(evidence("on")).then((decision) => {
      // The write was in flight first, so it has landed by now.
      answered = landed;
      return decision;
    });
    await tick();
    await tick();
    expect(landed).toBe(false);
    expect(answered).toBe(false);
    barrier.open();
    await write;
    expect((await on).kind).toBe("streams");
    expect(answered).toBe(true);
  });

  // SEAL_OUTSIDE_LOCK
  it("refuses a commit queued after On and never runs its write", async () => {
    const { authority, seal } = await sealOver("off");
    const barrier = gate();
    const first = seal.commit(() => barrier.opened);
    await tick();
    const on = authority.submitEvidence(evidence("on"));
    await tick();
    let secondRan = false;
    const second = seal
      .commit(() => {
        secondRan = true;
      })
      .catch((error: unknown) => error);
    await tick();
    await tick();
    barrier.open();
    await first;
    await on;
    const refused = (await second) as LegacyWriteRefusedError;
    expect(refused).toBeInstanceOf(LegacyWriteRefusedError);
    expect(refused.verdict).toBe("switched");
    expect(secondRan).toBe(false);
  });

  it("releases the lock when the write throws, so a later On is not stuck", async () => {
    const { authority, seal } = await sealOver("off");
    await expect(
      seal.commit(() => {
        throw new Error("disk full");
      }),
    ).rejects.toThrow("disk full");
    expect((await authority.submitEvidence(evidence("on"))).kind).toBe(
      "streams",
    );
  });
});

describe("remove", () => {
  it("runs in every mode: unswitched, switched and unknown", async () => {
    for (const state of ["off", "on"] as const) {
      const { seal } = await sealOver(state);
      expect(await seal.remove(async () => state)).toBe(state);
    }
    const authority = createModeAuthority({
      store: createMemoryModeRecordStore(),
    });
    await authority.ready;
    const unknown = createLegacyWriteSeal({ authority, owner: OWNER });
    expect(await unknown.remove(() => "removed")).toBe("removed");
  });

  it("makes an On wait for a removal in flight", async () => {
    const { authority, seal } = await sealOver("off");
    const barrier = gate();
    let removed = false;
    const removal = seal.remove(async () => {
      await barrier.opened;
      removed = true;
    });
    await tick();
    let answered = false;
    const on = authority.submitEvidence(evidence("on")).then((decision) => {
      answered = removed;
      return decision;
    });
    await tick();
    await tick();
    expect(answered).toBe(false);
    barrier.open();
    await removal;
    await on;
    expect(answered).toBe(true);
  });
});

describe("admit", () => {
  it("translates the three answers and takes no lock", async () => {
    const open = (await sealOver("off")).seal.admit();
    expect(open).toBeNull();

    const switched = (await sealOver("on")).seal.admit();
    expect(switched?.status).toBe(426);

    const authority = createModeAuthority({
      store: createMemoryModeRecordStore(),
    });
    await authority.ready;
    const unknown = createLegacyWriteSeal({ authority, owner: OWNER }).admit();
    expect(unknown?.status).toBe(503);
    expect((await unknown!.json()).error.errorCode).toBe(
      "ACCOUNT_MODE_UNKNOWN",
    );
  });

  it("answers while a commit holds the lock: it is only an early courtesy", async () => {
    const { seal } = await sealOver("off");
    const barrier = gate();
    const write = seal.commit(() => barrier.opened);
    await tick();
    expect(seal.admit()).toBeNull();
    barrier.open();
    await write;
  });
});

describe("verdict", () => {
  it("says allow, switched or unknown from the durable record", async () => {
    expect((await sealOver("off")).seal.verdict()).toBe("allow");
    expect((await sealOver("on")).seal.verdict()).toBe("switched");
    const authority = createModeAuthority({
      store: createMemoryModeRecordStore(),
    });
    await authority.ready;
    expect(createLegacyWriteSeal({ authority, owner: OWNER }).verdict()).toBe(
      "unknown",
    );
  });

  it("follows the record, not a copy: it turns switched as soon as On lands", async () => {
    const { authority, seal } = await sealOver("off");
    expect(seal.verdict()).toBe("allow");
    await authority.submitEvidence(evidence("on"));
    expect(seal.verdict()).toBe("switched");
  });
});
