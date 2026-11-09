/**
 * The stateful half of the account-mode module, driven directly. The shared
 * vectors cover the rules as event traces; these tests cover what a trace
 * cannot say: which call waits for which, and what a store sees when.
 */
import { describe, expect, it } from "vitest";
import { createModeAuthority, type ModeAuthority } from "./authority.js";
import { createMemoryModeRecordStore } from "./memory-record-store.js";
import { accountStorageModeOf } from "./port.js";

const A = "0x1111111111111111111111111111111111111111";
const B = "0x2222222222222222222222222222222222222222";

function evidence(
  owner: string,
  state: "on" | "off" | "unknown",
  rawStatus: number | null = 200,
) {
  return {
    owner,
    authOwner: owner,
    state,
    fetchStartedAt: Date.now(),
    rawStatus,
  };
}

async function boot(
  store = createMemoryModeRecordStore(),
  extra: Partial<Parameters<typeof createModeAuthority>[0]> = {},
): Promise<{ authority: ModeAuthority; store: typeof store }> {
  const authority = createModeAuthority({ store, bootId: "boot-1", ...extra });
  await authority.ready;
  return { authority, store };
}

/** A promise a test settles by hand. */
function gate() {
  let open!: () => void;
  const opened = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { opened, open };
}

const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

describe("boot", () => {
  it("answers 503 for an owner it has never heard of", async () => {
    const { authority } = await boot();
    expect(authority.read(A)).toEqual({
      kind: "refuse",
      code: "ACCOUNT_MODE_UNKNOWN",
      status: 503,
    });
  });

  it("refuses every read until the stored records are loaded", async () => {
    const store = createMemoryModeRecordStore([
      [
        A,
        {
          switched: true,
          switchedAt: 1,
          cleanOffAt: null,
          offFetchStartMono: null,
          bootId: null,
        },
      ],
    ]);
    const loading = gate();
    const slow = {
      ...store,
      load: () => loading.opened.then(() => store.load()),
    };
    const authority = createModeAuthority({ store: slow, bootId: "b" });
    expect(authority.read(A).kind).toBe("refuse");
    loading.open();
    await authority.ready;
    expect(authority.read(A).kind).toBe("streams");
  });

  it("fails closed, and retries the load, when the stored records cannot be read", async () => {
    const store = createMemoryModeRecordStore();
    store.failLoads(true);
    const authority = createModeAuthority({ store, bootId: "b" });
    await expect(authority.ready).rejects.toThrow();
    expect(authority.read(A).kind).toBe("refuse");
    store.failLoads(false);
    // The next evidence loads again.
    expect((await authority.submitEvidence(evidence(A, "off"))).kind).toBe(
      "legacy",
    );
  });
});

describe("a read that names no owner", () => {
  // OWNERLESS_READ_ANSWERS
  it("is unknown, even though other owners have answers", async () => {
    const { authority } = await boot();
    await authority.submitEvidence(evidence(A, "off"));
    await authority.submitEvidence(evidence(B, "on"));
    for (const owner of ["", undefined as unknown as string]) {
      expect(authority.read(owner).kind).toBe("refuse");
      expect(authority.admit(owner, "op").kind).toBe("refuse");
    }
    expect(accountStorageModeOf(authority).read("")).toBe("unknown");
  });
});

describe("the commit seal", () => {
  // ADMISSION_ONLY_CHECK
  it("refuses a write that was admitted before the account switched", async () => {
    const { authority } = await boot();
    await authority.submitEvidence(evidence(A, "off"));
    expect(authority.admit(A, "op-1").kind).toBe("legacy");
    await authority.submitEvidence(evidence(A, "on"));
    let wrote = 0;
    const sealed = await authority.commitLegacy(A, "op-1", () => {
      wrote += 1;
    });
    expect(sealed).toEqual({
      ok: false,
      decision: {
        kind: "refuse",
        code: "LEGACY_REFUSED_SWITCHED",
        status: 426,
      },
    });
    expect(wrote).toBe(0);
    expect(authority.commitLegacySync(A, "op-1", () => (wrote += 1)).ok).toBe(
      false,
    );
    expect(wrote).toBe(0);
  });

  // SEAL_OUTSIDE_LOCK
  it("makes an On latch wait for a legacy write in flight, and refuses the write queued behind it", async () => {
    const { authority, store } = await boot();
    await authority.submitEvidence(evidence(A, "off"));

    const inFlight = gate();
    let firstFinished = false;
    const first = authority.commitLegacy(A, "op-1", async () => {
      await inFlight.opened;
      firstFinished = true;
    });
    await tick();

    // The latch is requested while the first write is still running.
    let latched = false;
    const on = authority.submitEvidence(evidence(A, "on")).then((decision) => {
      latched = true;
      return decision;
    });
    await tick();
    // A second write passes its early check (Off is still current) and queues
    // behind the latch request.
    let secondRan = false;
    const second = authority.commitLegacy(A, "op-2", () => {
      secondRan = true;
    });
    await tick();
    await tick();

    // The latch has not been written, and nothing is saved, while the first
    // write runs.
    expect(latched).toBe(false);
    expect(store.durable.get(A)?.switched).toBe(false);
    expect(firstFinished).toBe(false);

    inFlight.open();
    expect((await first).ok).toBe(true);
    expect((await on).kind).toBe("streams");
    // The queued write meets the latch inside the lock and does not run.
    expect(await second).toMatchObject({
      ok: false,
      decision: { code: "LEGACY_REFUSED_SWITCHED", status: 426 },
    });
    expect(secondRan).toBe(false);
  });

  it("lets two legacy writes run together while the account is unswitched", async () => {
    const { authority } = await boot();
    await authority.submitEvidence(evidence(A, "off"));
    const release = gate();
    const running: string[] = [];
    const write = (id: string) =>
      authority.commitLegacy(A, id, async () => {
        running.push(id);
        await release.opened;
      });
    const both = Promise.all([write("a"), write("b")]);
    await tick();
    expect(running).toEqual(["a", "b"]);
    release.open();
    await both;
  });

  it("picks up an On that another runtime saved to the same store", async () => {
    const store = createMemoryModeRecordStore();
    const first = (await boot(store)).authority;
    const second = createModeAuthority({ store, bootId: "boot-2" });
    await second.ready;
    await first.submitEvidence(evidence(A, "off"));
    await second.submitEvidence(evidence(A, "off"));
    // The second runtime latches On; the first has not heard of it.
    await second.submitEvidence(evidence(A, "on"));
    expect(first.read(A).kind).toBe("legacy");
    const sealed = await first.commitLegacy(A, "op", () => {
      throw new Error("a stale runtime must not write legacy data");
    });
    expect(sealed.ok).toBe(false);
  });
});

describe("the durable On record", () => {
  // LATCH_NOT_DURABLE
  it("is in the store before the decision that depends on it is served", async () => {
    const { authority, store } = await boot();
    const decision = await authority.submitEvidence(evidence(A, "on"));
    expect(decision.kind).toBe("streams");
    expect(store.durable.get(A)?.switched).toBe(true);
  });

  // LATCH_NOT_DURABLE
  it("survives a restart that forgets everything but the store", async () => {
    const store = createMemoryModeRecordStore();
    const first = (await boot(store)).authority;
    await first.submitEvidence(evidence(A, "on"));
    const restarted = (await boot(store)).authority;
    expect(restarted.read(A).kind).toBe("streams");
    // A stale Off after the restart does not lower it.
    await restarted.submitEvidence(evidence(A, "off"));
    expect(restarted.read(A).kind).toBe("streams");
  });

  // SAVE_AFTER_USE
  it("blocks legacy work and stream answers until the save settles", async () => {
    const { authority, store } = await boot();
    await authority.submitEvidence(evidence(A, "off"));
    store.pauseSaves();
    const pending = authority.submitEvidence(evidence(A, "on"));
    await tick();
    expect(authority.read(A).kind).toBe("refuse");
    expect(authority.admit(A, "op").kind).toBe("refuse");
    expect(authority.commitLegacySync(A, "op", () => 1).ok).toBe(false);
    store.releaseSaves();
    expect((await pending).kind).toBe("streams");
    expect(authority.read(A).kind).toBe("streams");
  });

  // SAVE_AFTER_USE
  it("keeps refusing after a failed save, and tries again at the next evidence", async () => {
    const { authority, store } = await boot();
    store.failSaves(true);
    expect((await authority.submitEvidence(evidence(A, "on"))).kind).toBe(
      "refuse",
    );
    expect(authority.read(A).kind).toBe("refuse");
    expect(authority.commitLegacySync(A, "op", () => 1).ok).toBe(false);
    store.failSaves(false);
    expect((await authority.submitEvidence(evidence(A, "on"))).kind).toBe(
      "streams",
    );
    expect(store.durable.get(A)?.switched).toBe(true);
  });
});

describe("a new user's first launch", () => {
  it("uses an explicit Off as soon as it is saved, and not before", async () => {
    const { authority, store } = await boot();
    store.pauseSaves();
    const off = authority.submitEvidence(evidence(A, "off"));
    await tick();
    // The save is pending: nothing is answered on the strength of the Off.
    expect(authority.admit(A, "op").kind).toBe("refuse");
    store.releaseSaves();
    expect((await off).kind).toBe("legacy");
    expect(store.durable.get(A)?.switched).toBe(false);
    expect(authority.admit(A, "op").kind).toBe("legacy");
    const sealed = await authority.commitLegacy(A, "op", () => "written");
    expect(sealed).toEqual({ ok: true, value: "written" });
  });

  // OFF_USED_BEFORE_SAVE
  it("treats an Off whose save throws as unknown, until a later Off is saved", async () => {
    const { authority, store } = await boot();
    store.failSaves(true);
    expect(await authority.submitEvidence(evidence(A, "off"))).toEqual({
      kind: "refuse",
      code: "ACCOUNT_MODE_UNKNOWN",
      status: 503,
    });
    expect(authority.admit(A, "op").kind).toBe("refuse");
    expect(authority.read(A).kind).toBe("refuse");
    const refused = await authority.commitLegacy(A, "op", () => "written");
    expect(refused.ok).toBe(false);
    store.failSaves(false);
    expect((await authority.submitEvidence(evidence(A, "off"))).kind).toBe(
      "legacy",
    );
    expect(authority.admit(A, "op").kind).toBe("legacy");
  });

  it("answers the first On after its save, with importRequired false when nothing is legacy", async () => {
    const { authority } = await boot(undefined, {
      hasLegacyFiles: () => false,
    });
    expect(await authority.submitEvidence(evidence(A, "on"))).toEqual({
      kind: "streams",
      importRequired: false,
    });
  });
});

describe("importRequired", () => {
  it("is reported once, at the first On of an owner that has legacy files", async () => {
    const { authority } = await boot(undefined, {
      hasLegacyFiles: (owner) => owner === A,
    });
    await authority.submitEvidence(evidence(A, "off"));
    expect(await authority.submitEvidence(evidence(A, "on"))).toEqual({
      kind: "streams",
      importRequired: true,
    });
    expect(await authority.submitEvidence(evidence(A, "on"))).toEqual({
      kind: "streams",
      importRequired: false,
    });
    expect(await authority.submitEvidence(evidence(B, "on"))).toEqual({
      kind: "streams",
      importRequired: false,
    });
  });

  it("counts a probe that throws as legacy files present", async () => {
    const { authority } = await boot(undefined, {
      hasLegacyFiles: () => {
        throw new Error("probe failed");
      },
      onWarning: () => undefined,
    });
    expect(await authority.submitEvidence(evidence(A, "on"))).toEqual({
      kind: "streams",
      importRequired: true,
    });
  });

  it("is reported again after a failed save, because the first answer never went out", async () => {
    const { authority, store } = await boot(undefined, {
      hasLegacyFiles: () => true,
    });
    store.failSaves(true);
    expect((await authority.submitEvidence(evidence(A, "on"))).kind).toBe(
      "refuse",
    );
    store.failSaves(false);
    expect(await authority.submitEvidence(evidence(A, "on"))).toEqual({
      kind: "streams",
      importRequired: true,
    });
  });
});

describe("evidence from the wrong place", () => {
  it("changes nothing when the authenticated owner differs", async () => {
    const { authority } = await boot();
    const decision = await authority.submitEvidence({
      ...evidence(A, "on"),
      authOwner: B,
    });
    expect(decision.kind).toBe("refuse");
    expect(authority.snapshot().size).toBe(0);
  });

  it("changes nothing for an answer that was not a success", async () => {
    const { authority } = await boot();
    for (const status of [500, 503, 401, null]) {
      const decision = await authority.submitEvidence(
        evidence(A, "off", status),
      );
      // No status at all is not a success either: a host that has no HTTP
      // status must say 200 for the answer it trusts.
      expect(decision.kind).toBe("refuse");
    }
  });
});

describe("answers that are not a usable Off or On", () => {
  it("leave a still-fresh Off in place, because an unreachable Account blocks no one who has not switched", async () => {
    const { authority } = await boot();
    await authority.submitEvidence(evidence(A, "off"));
    for (const [state, status] of [
      ["unknown", null],
      ["unknown", 503],
      ["off", 500],
      ["on", 401],
    ] as const) {
      const decision = await authority.submitEvidence(
        evidence(A, state, status),
      );
      expect(decision.kind).toBe("legacy");
    }
    expect(authority.read(A).kind).toBe("legacy");
  });

  it("do not let an Off older than the window replace or end a fresh one", async () => {
    const { authority } = await boot();
    await authority.submitEvidence(evidence(A, "off"));
    const old = await authority.submitEvidence({
      ...evidence(A, "off"),
      fetchStartedAt: Date.now() - 8 * 24 * 60 * 60 * 1000,
    });
    expect(old.kind).toBe("legacy");
  });
});

describe("owner spelling", () => {
  it("is folded to lower case, so one address is one owner", async () => {
    const { authority } = await boot();
    const mixed = "0xAbCdEf0000000000000000000000000000000001";
    await authority.submitEvidence(evidence(mixed, "off"));
    expect(authority.read(mixed.toLowerCase()).kind).toBe("legacy");
    expect(authority.read(mixed.toUpperCase().replace("0X", "0x")).kind).toBe(
      "legacy",
    );
    expect([...authority.snapshot().keys()]).toEqual([mixed.toLowerCase()]);
  });

  it("is not invented by a read: asking about an owner creates no record", async () => {
    const { authority } = await boot();
    expect(authority.read(B).kind).toBe("refuse");
    expect(authority.admit(B, "w1").kind).toBe("refuse");
    expect(authority.snapshot().size).toBe(0);
  });
});

describe("expiry", () => {
  const WEEK = 7 * 24 * 60 * 60 * 1000;

  function clockAt(now: { mono: number }) {
    return { mono: () => now.mono, wall: () => 1_000_000 + now.mono };
  }

  it("reads a stored Off older than the window as unknown, at the deadline and after", async () => {
    const now = { mono: 0 };
    const { authority } = await boot(undefined, { clock: clockAt(now) });
    await authority.submitEvidence({
      ...evidence(A, "off"),
      fetchStartedAt: 1_000_000,
    });
    now.mono = WEEK - 1;
    expect(authority.read(A).kind).toBe("legacy");
    now.mono = WEEK;
    expect(authority.read(A).kind).toBe("refuse");
    now.mono = WEEK * 3;
    expect(authority.read(A).kind).toBe("refuse");
  });

  it("never clears a saved On latch, however much time passes or how the process restarts", async () => {
    const now = { mono: 0 };
    const store = createMemoryModeRecordStore();
    const { authority } = await boot(store, { clock: clockAt(now) });
    await authority.submitEvidence(evidence(A, "on"));
    now.mono = WEEK * 10;
    expect(authority.read(A).kind).toBe("streams");
    const restarted = createModeAuthority({
      store,
      bootId: "boot-2",
      clockTrusted: false,
      clock: clockAt({ mono: 5 }),
    });
    await restarted.ready;
    expect(restarted.read(A).kind).toBe("streams");
  });
});
