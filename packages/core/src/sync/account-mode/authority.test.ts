/**
 * The stateful half of the account-mode module, driven directly. The shared
 * vectors cover the rules as event traces; these tests cover what a trace
 * cannot say: which call waits for which, and what a store sees when.
 */
import { describe, expect, it } from "vitest";
import {
  createModeAuthority,
  createModeAuthorityWithImporter,
  type ModeAuthority,
  type StreamCommitResult,
} from "./authority.js";
import { OFF_TTL_MS, type ModeDecision } from "./mode-machine.js";
import { createMemoryModeRecordStore } from "./memory-record-store.js";
import { accountStorageModeOf } from "./port.js";

const A = "0x1111111111111111111111111111111111111111";
const B = "0x2222222222222222222222222222222222222222";
const C = "0x3333333333333333333333333333333333333333";
const MIXED = "0xAbCdEf1111111111111111111111111111AbCdEf";

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

/** A stream seal asked for its decision only (the write does nothing). */
async function stream(
  authority: Pick<ModeAuthority, "commitStream">,
  owner: string,
  operationId: string,
): Promise<ModeDecision> {
  const result: StreamCommitResult<undefined> = await authority.commitStream(
    owner,
    operationId,
    () => undefined,
  );
  return result.ok
    ? { kind: "streams", importRequired: result.importRequired }
    : result.decision;
}

/** A promise a test settles by hand. */
function gate() {
  let open!: () => void;
  const opened = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { opened, open };
}

const UNKNOWN_REFUSAL = {
  kind: "refuse",
  code: "ACCOUNT_MODE_UNKNOWN",
  status: 503,
};

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

  it("picks up an On that something other than this runtime saved to the store", async () => {
    const { authority, store } = await boot();
    await authority.submitEvidence(evidence(A, "off"));
    expect(authority.read(A).kind).toBe("legacy");
    // A writer that bypassed the store's ownership latches On on the disk.
    store.durable.set(A, { ...store.durable.get(A)!, switched: true });
    const sealed = await authority.commitLegacy(A, "op", () => {
      throw new Error("a stale view must not write legacy data");
    });
    expect(sealed.ok).toBe(false);
  });

  // ASYNC_CALLBACK_ESCAPES_SYNC_SEAL
  it("has no synchronous commit: every legacy write holds the lock until it settles", async () => {
    const { authority } = await boot();
    expect("commitLegacySync" in authority).toBe(false);
    await authority.submitEvidence(evidence(A, "off"));
    const barrier = gate();
    let landed = false;
    const write = authority.commitLegacy(A, "op", async () => {
      await barrier.opened;
      landed = true;
    });
    await tick();
    let latched = false;
    const on = authority.submitEvidence(evidence(A, "on")).then(() => {
      latched = true;
    });
    await tick();
    await tick();
    expect(latched).toBe(false);
    barrier.open();
    await write;
    await on;
    expect(landed).toBe(true);
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
    store.dropLease(); // the process died, and the lease with it
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
    expect((await authority.commitLegacy(A, "op", () => 1)).ok).toBe(false);
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
    expect((await authority.commitLegacy(A, "op", () => 1)).ok).toBe(false);
    store.failSaves(false);
    expect((await authority.submitEvidence(evidence(A, "on"))).kind).toBe(
      "streams",
    );
    expect(store.durable.get(A)?.switched).toBe(true);
  });
});

describe("an On whose first save is rejected", () => {
  // DROP_PENDING_ON_ON_SAVE_FAILURE
  it("is held in memory, so a store that still serves the old Off never brings legacy back", async () => {
    const { authority, store } = await boot();
    await authority.submitEvidence(evidence(A, "off"));
    expect(authority.read(A).kind).toBe("legacy");
    store.failSaves(true);
    expect((await authority.submitEvidence(evidence(A, "on"))).kind).toBe(
      "refuse",
    );
    // The store still serves reads, and still holds the old, unswitched Off.
    expect(store.durable.get(A)?.switched).toBe(false);
    expect((await store.load()).get(A)?.switched).toBe(false);
    expect(authority.read(A)).toMatchObject({ kind: "refuse", status: 503 });
    expect(authority.admit(A, "op")).toMatchObject({
      kind: "refuse",
      status: 503,
    });
    expect((await authority.commitLegacy(A, "op", () => 1)).ok).toBe(false);
    // The async commit re-reads the store inside its lock; it must not see legacy either.
    const result = await authority.commitLegacy(A, "op-2", () => 1);
    expect(result.ok).toBe(false);
    // An Off that arrives meanwhile does not lower it.
    await authority.submitEvidence(evidence(A, "off"));
    expect(authority.read(A).kind).toBe("refuse");
    // Only a successful On save ends the refusal.
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

describe("the import barrier", () => {
  const withLegacy = (extra: Parameters<typeof boot>[1] = {}) =>
    boot(undefined, { hasLegacyFiles: (owner) => owner === A, ...extra });

  it("saves importPending in the same write as the first On, when the owner has legacy files", async () => {
    const { authority, store } = await withLegacy();
    await authority.submitEvidence(evidence(A, "off"));
    expect(await authority.submitEvidence(evidence(A, "on"))).toEqual({
      kind: "streams",
      importRequired: true,
    });
    // IMPORT_FLAG_NOT_PERSISTED
    expect(store.durable.get(A)).toMatchObject({
      switched: true,
      importPending: true,
    });
    expect(store.durable.get(B)).toBeUndefined();
    expect(await authority.submitEvidence(evidence(B, "on"))).toEqual({
      kind: "streams",
      importRequired: false,
    });
    expect(store.durable.get(B)?.importPending).toBe(false);
  });

  it("counts a probe that throws as legacy files present", async () => {
    const { authority, store } = await boot(undefined, {
      hasLegacyFiles: () => {
        throw new Error("probe failed");
      },
      onWarning: () => undefined,
    });
    expect(await authority.submitEvidence(evidence(A, "on"))).toEqual({
      kind: "streams",
      importRequired: true,
    });
    expect(store.durable.get(A)?.importPending).toBe(true);
  });

  // IMPORT_FLAG_NOT_PERSISTED
  it("survives a crash between the On save and the answer: a restarted host is told again", async () => {
    const store = createMemoryModeRecordStore();
    const first = (await withLegacy({ store })).authority;
    await first.submitEvidence(evidence(A, "on"));
    // The answer never reached the host. The process dies; the lease dies too.
    await first.close();
    const restarted = (await withLegacy({ store })).authority;
    expect(restarted.read(A)).toEqual({
      kind: "streams",
      importRequired: true,
    });
    // The Account's next On answer is not "first" and clears nothing.
    expect(await restarted.submitEvidence(evidence(A, "on"))).toEqual({
      kind: "streams",
      importRequired: true,
    });
  });

  // STREAM_WRITE_BEFORE_IMPORT_DONE
  it("refuses stream commits with 503 IMPORT_PENDING until importDone is saved", async () => {
    const { authority, store } = await withLegacy();
    await authority.submitEvidence(evidence(A, "on"));
    const refused = {
      kind: "refuse",
      code: "IMPORT_PENDING",
      status: 503,
    };
    expect(await stream(authority, A, "op")).toEqual(refused);
    store.pauseSaves();
    const done = authority.importDone(A);
    await tick();
    // Save before use: while the clean record is being written, still closed.
    expect((await stream(authority, A, "op")).kind).toBe("refuse");
    store.releaseSaves();
    expect(await done).toEqual({ kind: "streams", importRequired: false });
    expect(store.durable.get(A)?.importPending).toBe(false);
    expect(await stream(authority, A, "op")).toEqual({
      kind: "streams",
      importRequired: false,
    });
  });

  it("keeps the barrier closed when the importDone save fails, and a restart imports again", async () => {
    const store = createMemoryModeRecordStore();
    const { authority } = await withLegacy({ store });
    await authority.submitEvidence(evidence(A, "on"));
    store.failSaves(true);
    expect((await authority.importDone(A)).kind).toBe("refuse");
    expect((await stream(authority, A, "op")).kind).toBe("refuse");
    expect(store.durable.get(A)?.importPending).toBe(true);
    await authority.close();
    store.failSaves(false);
    const restarted = (await withLegacy({ store })).authority;
    expect(restarted.read(A)).toEqual({
      kind: "streams",
      importRequired: true,
    });
    expect(await restarted.importDone(A)).toEqual({
      kind: "streams",
      importRequired: false,
    });
  });

  // ORDINARY_WRITE_PASSES_WHILE_PENDING, IMPORT_SEED_REFUSED_WHILE_PENDING
  it("admits only the importer's seed publish while the import is pending", async () => {
    const store = createMemoryModeRecordStore();
    const { authority, importSeed } = createModeAuthorityWithImporter({
      store,
      bootId: "boot-1",
      hasLegacyFiles: (owner) => owner === A,
    });
    await authority.ready;
    await authority.submitEvidence(evidence(A, "on"));
    const seed = async (op: string) => {
      const r = await importSeed.commitImportSeed(A, op, () => undefined);
      return r.ok
        ? { kind: "streams", importRequired: r.importRequired }
        : r.decision;
    };
    expect(await stream(authority, A, "client-delivery")).toEqual({
      kind: "refuse",
      code: "IMPORT_PENDING",
      status: 503,
    });
    expect(await seed("seed-1")).toEqual({
      kind: "streams",
      importRequired: true,
    });
    // The seed publish is a re-run after a crash: still admitted, still pending.
    expect(await seed("seed-1")).toEqual({
      kind: "streams",
      importRequired: true,
    });
    expect((await stream(authority, A, "client-delivery")).kind).toBe("refuse");
    expect(await authority.importDone(A)).toEqual({
      kind: "streams",
      importRequired: false,
    });
    expect(await stream(authority, A, "client-delivery")).toEqual({
      kind: "streams",
      importRequired: false,
    });
  });

  it("does not admit a seed publish where no stream write may commit", async () => {
    const store = createMemoryModeRecordStore();
    const { authority, importSeed } = createModeAuthorityWithImporter({
      store,
      bootId: "boot-1",
      hasLegacyFiles: (owner) => owner === A,
    });
    await authority.ready;
    const seed = async (owner: string) =>
      (await importSeed.commitImportSeed(owner, "seed", () => undefined)).ok;
    // Unknown owner.
    expect(await seed(A)).toBe(false);
    // An On whose save has not completed is not served.
    store.pauseSaves();
    const answer = authority.submitEvidence(evidence(A, "on"));
    await tick();
    expect(await seed(A)).toBe(false);
    store.releaseSaves();
    await answer;
    expect(await seed(A)).toBe(true);
    // An unswitched account never takes a seed publish.
    await authority.submitEvidence(evidence(B, "off"));
    expect(await seed(B)).toBe(false);
  });

  it("answers importPending(owner) from the saved record", async () => {
    const { authority } = await withLegacy();
    await authority.submitEvidence(evidence(A, "on"));
    expect(await authority.importPending(A)).toBe(true);
    await authority.importDone(A);
    expect(await authority.importPending(A)).toBe(false);
    // An owner with no legacy files has nothing to import.
    await authority.submitEvidence(evidence(B, "on"));
    expect(await authority.importPending(B)).toBe(false);
    // An unswitched account has nothing to import into streams.
    await authority.submitEvidence(evidence(C, "off"));
    expect(await authority.importPending(C)).toBe(false);
  });

  it("lowercases the owner for importPending and importDone", async () => {
    const { authority } = await withLegacy({
      hasLegacyFiles: (owner) => owner === MIXED.toLowerCase(),
    });
    await authority.submitEvidence(evidence(MIXED, "on"));
    expect(await authority.importPending(MIXED)).toBe(true);
    expect(await authority.importPending(MIXED.toLowerCase())).toBe(true);
    await authority.importDone(MIXED);
    expect(await authority.importPending(MIXED.toLowerCase())).toBe(false);
  });

  it("does not answer importPending for an owner it does not know", async () => {
    const { authority } = await withLegacy();
    await expect(authority.importPending(A)).rejects.toThrow(/unknown/i);
  });

  it("opens nothing for an owner with no pending import", async () => {
    const { authority } = await withLegacy();
    expect((await authority.importDone(A)).kind).toBe("refuse");
    await authority.submitEvidence(evidence(A, "off"));
    expect((await authority.importDone(A)).kind).toBe("legacy");
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
    store.dropLease();
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

describe("one owning runtime per store", () => {
  const owned = {
    kind: "refuse",
    code: "ACCOUNT_MODE_STORE_OWNED",
    status: 503,
  };

  // SECOND_RUNTIME_ADMITTED
  it("refuses a second runtime on the same store, and it never admits a legacy write", async () => {
    const { authority: first, store } = await boot();
    await first.submitEvidence(evidence(A, "off"));
    const second = createModeAuthority({ store, bootId: "boot-2" });
    await expect(second.ready).rejects.toThrow();
    expect(second.read(A)).toEqual(owned);
    expect(second.admit(A, "op")).toEqual(owned);
    expect(await second.submitEvidence(evidence(A, "off"))).toEqual(owned);
    let wrote = 0;
    expect(
      await second.commitLegacy(A, "op", () => {
        wrote += 1;
      }),
    ).toEqual({ ok: false, decision: owned });
    expect(wrote).toBe(0);
    // The owner is untouched.
    expect(first.admit(A, "op").kind).toBe("legacy");
  });

  it("lets a second runtime take over after the owner lets go", async () => {
    const { authority: first, store } = await boot();
    await first.submitEvidence(evidence(A, "off"));
    const second = createModeAuthority({ store, bootId: "boot-2" });
    await second.ready.catch(() => undefined);
    await first.close();
    // The owner's closed authority admits nothing.
    expect(first.admit(A, "op").kind).toBe("refuse");
    // The next evidence retries the claim.
    expect((await second.submitEvidence(evidence(A, "off"))).kind).toBe(
      "legacy",
    );
  });
});

describe("a record write is monotone at the store", () => {
  // BLIND_OFF_OVERWRITES_ON
  it("rejects an Off write over a stored On, and a write based on a stale read", async () => {
    const store = createMemoryModeRecordStore();
    const off = {
      switched: false,
      switchedAt: null,
      cleanOffAt: 1,
      offFetchStartMono: 1,
      bootId: "b",
      importPending: false,
    };
    await store.claim();
    await store.save(A, off, null);
    const on = {
      ...off,
      switched: true,
      switchedAt: 2,
      offFetchStartMono: null,
    };
    await store.save(A, on, off);
    // Lowering On to Off fails even when the writer's read is current.
    await expect(store.save(A, off, on)).rejects.toThrow();
    // A write based on an older read fails.
    await expect(
      store.save(A, { ...on, switchedAt: 3 }, off),
    ).rejects.toThrow();
    // A write over a record that was never read fails.
    await expect(store.save(A, on, null)).rejects.toThrow();
    expect(store.durable.get(A)).toEqual(on);
  });

  it("treats a stale-read Off save as a failed save: the durable On stays and the authority adopts it", async () => {
    const inner = createMemoryModeRecordStore();
    let block: Promise<void> | null = null;
    const entered = gate();
    const store = {
      ...inner,
      claim: () => inner.claim(),
      load: () => inner.load(),
      save: async (
        owner: string,
        next: Parameters<typeof inner.save>[1],
        expected: Parameters<typeof inner.save>[2],
      ) => {
        if (block) {
          entered.open();
          await block;
        }
        return inner.save(owner, next, expected);
      },
    };
    const { authority } = await boot(store as never);
    await authority.submitEvidence(evidence(A, "off"));
    const hold = gate();
    block = hold.opened;
    const later = authority.submitEvidence({
      ...evidence(A, "off"),
      fetchStartedAt: Date.now() + 1,
    });
    await entered.opened;
    // Another writer latches On while the Off save is held up at the store.
    inner.durable.set(A, {
      ...inner.durable.get(A)!,
      switched: true,
      switchedAt: 7,
    });
    block = null;
    hold.open();
    expect((await later).kind).toBe("refuse");
    expect(inner.durable.get(A)?.switched).toBe(true);
    expect(authority.read(A).kind).toBe("streams");
    expect((await authority.commitLegacy(A, "op", () => 1)).ok).toBe(false);
  });
});

describe("the fetch start of an Off", () => {
  const fixedClock = { mono: () => 1_000_000, wall: () => 5_000_000 };

  // FUTURE_FETCH_MINTS_FRESH_OFF
  it("treats an Off whose fetch started more than 60 s in the future as unknown", async () => {
    const { authority, store } = await boot(undefined, { clock: fixedClock });
    const decision = await authority.submitEvidence({
      ...evidence(A, "off"),
      fetchStartedAt: 5_000_000 + 61_000,
    });
    expect(decision).toEqual({
      kind: "refuse",
      code: "ACCOUNT_MODE_UNKNOWN",
      status: 503,
    });
    expect(store.durable.has(A)).toBe(false);
    expect(authority.admit(A, "op").kind).toBe("refuse");
  });

  it("clamps a small skew to age zero, and ages a past fetch normally", async () => {
    const { authority } = await boot(undefined, { clock: fixedClock });
    expect(
      (
        await authority.submitEvidence({
          ...evidence(A, "off"),
          fetchStartedAt: 5_000_000 + 59_000,
        })
      ).kind,
    ).toBe("legacy");
    const old = await authority.submitEvidence({
      ...evidence(B, "off"),
      fetchStartedAt: 5_000_000 - OFF_TTL_MS,
    });
    expect(old.kind).toBe("refuse");
  });
});

describe("a save that never settles", () => {
  // SAVE_TIMEOUT_WEDGES_QUEUE
  it("poisons the authority: later work refuses at once, nothing queues behind the hung save and nothing writes", async () => {
    const { authority, store } = await boot(undefined, { saveTimeoutMs: 25 });
    store.pauseSaves();
    const started = Date.now();
    const first = authority.submitEvidence(evidence(A, "on"));
    const queued = authority.submitEvidence(evidence(B, "off"));
    expect((await first).kind).toBe("refuse");
    expect((await queued).kind).toBe("refuse");
    expect(Date.now() - started).toBeLessThan(2000);
    expect(store.saveCalls).toBe(1);
    // Later evidence, admits and reads refuse promptly, and write nothing.
    const later = Date.now();
    expect((await authority.submitEvidence(evidence(A, "on"))).kind).toBe(
      "refuse",
    );
    expect(Date.now() - later).toBeLessThan(20);
    expect(authority.read(A)).toEqual(UNKNOWN_REFUSAL);
    expect(authority.admit(B, "op")).toEqual(UNKNOWN_REFUSAL);
    expect((await authority.commitLegacy(B, "op", () => 1)).ok).toBe(false);
    expect((await stream(authority, A, "op")).kind).toBe("refuse");
    expect(store.saveCalls).toBe(1);
    // The held write lands late; the authority stays poisoned.
    store.releaseSaves();
    await tick();
    expect(authority.read(A)).toEqual(UNKNOWN_REFUSAL);
    expect((await authority.submitEvidence(evidence(A, "on"))).kind).toBe(
      "refuse",
    );
    // A new authority over the store sees what landed.
    await authority.close();
    const reopened = (await boot(store)).authority;
    expect(reopened.read(A).kind).toBe("streams");
  });

  // UNBOUNDED_PRE_SAVE_AWAIT
  it("does not wait for a legacy-file probe that never settles: the import is owed", async () => {
    const { authority, store } = await boot(undefined, {
      saveTimeoutMs: 25,
      hasLegacyFiles: () => new Promise<boolean>(() => undefined),
      onWarning: () => undefined,
    });
    expect(await authority.submitEvidence(evidence(A, "on"))).toEqual({
      kind: "streams",
      importRequired: true,
    });
    expect(store.durable.get(A)?.importPending).toBe(true);
  });

  it("does not wait for a re-read that never settles, and then refuses everything", async () => {
    const inner = createMemoryModeRecordStore();
    let hang = false;
    const store = {
      claim: () => inner.claim(),
      load: () => (hang ? new Promise<never>(() => undefined) : inner.load()),
      save: inner.save.bind(inner),
    };
    const { authority } = await boot(store as never, {
      saveTimeoutMs: 25,
      onWarning: () => undefined,
    });
    await authority.submitEvidence(evidence(A, "off"));
    hang = true;
    // The commit re-reads the record under the lock: it stalls, so it refuses.
    const started = Date.now();
    expect((await authority.commitLegacy(A, "op", () => 1)).ok).toBe(false);
    expect(Date.now() - started).toBeLessThan(2000);
    // Not held up behind it: later work refuses at once.
    const later = Date.now();
    expect((await authority.submitEvidence(evidence(A, "off"))).kind).toBe(
      "refuse",
    );
    expect((await authority.commitLegacy(A, "op", () => 1)).ok).toBe(false);
    expect(Date.now() - later).toBeLessThan(20);
  });

  it("does not wait for the re-read that follows a failed save, and then refuses everything", async () => {
    const inner = createMemoryModeRecordStore();
    let hang = false;
    const store = {
      claim: () => inner.claim(),
      load: () => (hang ? new Promise<never>(() => undefined) : inner.load()),
      save: inner.save.bind(inner),
    };
    const { authority } = await boot(store as never, {
      saveTimeoutMs: 25,
      onWarning: () => undefined,
    });
    inner.failSaves(true);
    expect((await authority.submitEvidence(evidence(A, "off"))).kind).toBe(
      "refuse",
    );
    inner.failSaves(false);
    hang = true;
    // The owner is stale: this evidence re-reads before it saves, and stalls.
    const started = Date.now();
    expect((await authority.submitEvidence(evidence(A, "off"))).kind).toBe(
      "refuse",
    );
    expect(Date.now() - started).toBeLessThan(2000);
    const saves = inner.saveCalls;
    const later = Date.now();
    expect((await authority.submitEvidence(evidence(A, "off"))).kind).toBe(
      "refuse",
    );
    expect(Date.now() - later).toBeLessThan(20);
    expect(inner.saveCalls).toBe(saves);
  });
});
