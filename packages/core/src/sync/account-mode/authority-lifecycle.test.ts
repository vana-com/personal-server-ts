/**
 * What the authority does around the store's lifetime: draining before it lets
 * go, a store that cannot be read, recovery after a refused claim, and the
 * import-seed capability. The shared vectors cover rules as event traces; these
 * cover which call waits for which, and what a store sees when.
 */
import { describe, expect, it } from "vitest";
import {
  createModeAuthority,
  createModeAuthorityWithImporter,
  type ModeAuthority,
  type ModeAuthorityOptions,
} from "./authority.js";
import {
  createMemoryModeRecordStore,
  type MemoryModeRecordStore,
} from "./memory-record-store.js";
import type { ModeRecordStore } from "./record-store.js";

const A = "0x1111111111111111111111111111111111111111";
const B = "0x2222222222222222222222222222222222222222";

const UNKNOWN = {
  kind: "refuse",
  code: "ACCOUNT_MODE_UNKNOWN",
  status: 503,
};
const OWNED = {
  kind: "refuse",
  code: "ACCOUNT_MODE_STORE_OWNED",
  status: 503,
};

function evidence(owner: string, state: "on" | "off") {
  return {
    owner,
    authOwner: owner,
    state,
    fetchStartedAt: Date.now(),
    rawStatus: 200,
  };
}

function gate() {
  let open!: () => void;
  const opened = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { opened, open };
}

const tick = (ms = 0) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * A view of one memory store as one runtime sees it: it logs when its claim,
 * its saves and its release happen, in one shared log.
 */
function viewOf(
  inner: MemoryModeRecordStore,
  name: string,
  log: string[],
  hooks: { beforeClaim?: Promise<void>; beforeLoad?: Promise<void> } = {},
): ModeRecordStore & { claims: number } {
  const view = {
    claims: 0,
    async claim() {
      view.claims += 1;
      await hooks.beforeClaim;
      const lease = await inner.claim();
      log.push(`${name}:claimed`);
      return {
        async release() {
          await lease.release();
          log.push(`${name}:released`);
        },
      };
    },
    async load() {
      await hooks.beforeLoad;
      return inner.load();
    },
    async save(
      owner: string,
      next: Parameters<ModeRecordStore["save"]>[1],
      expected: Parameters<ModeRecordStore["save"]>[2],
    ) {
      await inner.save(owner, next, expected);
      log.push(`${name}:save-landed`);
    },
  };
  return view;
}

async function boot(
  store: ModeRecordStore,
  bootId: string,
  extra: Partial<ModeAuthorityOptions> = {},
): Promise<ModeAuthority> {
  const authority = createModeAuthority({ store, bootId, ...extra });
  await authority.ready;
  return authority;
}

const before = (log: string[], first: string, second: string) => {
  expect(log, `${first} must be logged`).toContain(first);
  expect(log, `${second} must be logged`).toContain(second);
  expect(log.indexOf(first)).toBeLessThan(log.indexOf(second));
};

describe("close drains before it lets go of the store", () => {
  // CLOSE_BEFORE_DRAIN
  it("keeps the store while an admitted legacy write is in flight, and lands nothing after the next owner has it", async () => {
    const inner = createMemoryModeRecordStore();
    const log: string[] = [];
    const first = await boot(viewOf(inner, "first", log), "boot-1");
    await first.submitEvidence(evidence(A, "off"));
    const started = gate();
    const latch = gate();
    const write = first.commitLegacy(A, "op-1", async () => {
      started.open();
      await latch.opened;
      log.push("first:legacy-write");
    });
    await started.opened;

    let closeDone = false;
    const closing = first.close().then(() => {
      closeDone = true;
    });
    await tick(5);

    // A second runtime is refused while the first still holds the store.
    const second = createModeAuthority({
      store: viewOf(inner, "second", log),
      bootId: "boot-2",
    });
    await expect(second.ready).rejects.toThrow();
    expect(second.read(A)).toEqual(OWNED);
    expect(closeDone).toBe(false);

    // New work is refused as soon as close begins.
    let late = 0;
    expect(
      await first.commitLegacy(A, "op-2", () => {
        late += 1;
      }),
    ).toMatchObject({ ok: false });
    expect(await first.submitEvidence(evidence(A, "on"))).toEqual(UNKNOWN);
    expect(late).toBe(0);

    latch.open();
    expect(await write).toEqual({ ok: true, value: undefined });
    await closing;
    expect(closeDone).toBe(true);

    // Now the next owner takes the store and latches On.
    expect((await second.submitEvidence(evidence(A, "on"))).kind).toBe(
      "streams",
    );
    before(log, "first:legacy-write", "first:released");
    before(log, "first:released", "second:claimed");
    expect(log.filter((e) => e === "first:legacy-write")).toHaveLength(1);
    expect(log.indexOf("first:legacy-write")).toBeLessThan(
      log.indexOf("second:save-landed"),
    );
  });

  it("keeps the store while an evidence save is in flight, and lands nothing after the next owner has it", async () => {
    const inner = createMemoryModeRecordStore();
    const log: string[] = [];
    const first = await boot(viewOf(inner, "first", log), "boot-1");
    inner.pauseSaves();
    const answer = first.submitEvidence(evidence(A, "off"));
    await tick(5);

    const closing = first.close();
    await tick(5);
    const second = createModeAuthority({
      store: viewOf(inner, "second", log),
      bootId: "boot-2",
    });
    await expect(second.ready).rejects.toThrow();
    expect(second.read(A)).toEqual(OWNED);

    inner.releaseSaves();
    await answer;
    await closing;
    expect((await second.submitEvidence(evidence(A, "on"))).kind).toBe(
      "streams",
    );
    before(log, "first:save-landed", "first:released");
    before(log, "first:released", "second:claimed");
    expect(inner.durable.get(A)?.switched).toBe(true);
  });

  // CLOSE_IGNORES_TIMED_OUT_SAVE
  it("also waits for a save the authority already gave up on", async () => {
    const inner = createMemoryModeRecordStore();
    const log: string[] = [];
    const first = await boot(viewOf(inner, "first", log), "boot-1", {
      saveTimeoutMs: 20,
    });
    inner.pauseSaves();
    // The save times out: the authority counts it failed and frees its lock,
    // but the write is still running at the store.
    expect((await first.submitEvidence(evidence(A, "on"))).kind).toBe("refuse");
    let closeDone = false;
    const closing = first.close().then(() => {
      closeDone = true;
    });
    await tick(30);
    expect(closeDone).toBe(false);
    const second = createModeAuthority({
      store: viewOf(inner, "second", log),
      bootId: "boot-2",
    });
    await expect(second.ready).rejects.toThrow();

    inner.releaseSaves();
    await closing;
    before(log, "first:save-landed", "first:released");
    expect(log).not.toContain("second:claimed");
  });

  it("is safe to call twice, and releases the store once", async () => {
    const inner = createMemoryModeRecordStore();
    const log: string[] = [];
    const first = await boot(viewOf(inner, "first", log), "boot-1");
    await Promise.all([first.close(), first.close()]);
    await first.close();
    expect(log.filter((e) => e === "first:released")).toHaveLength(1);
    await boot(viewOf(inner, "second", log), "boot-2");
  });

  // LOAD_AFTER_CLOSE_SERVES
  it("never serves from a load that finishes after close, and gives the store back", async () => {
    const inner = createMemoryModeRecordStore([
      [
        A,
        {
          switched: true,
          switchedAt: 1,
          cleanOffAt: null,
          offFetchStartMono: null,
          bootId: null,
          importPending: false,
        },
      ],
    ]);
    const log: string[] = [];
    const loading = gate();
    const authority = createModeAuthority({
      store: viewOf(inner, "first", log, { beforeLoad: loading.opened }),
      bootId: "boot-1",
    });
    const ready = authority.ready.then(
      () => "served",
      () => "refused",
    );
    await tick(5);
    const closing = authority.close();
    loading.open();
    await closing;
    await tick(5);
    // A load that finishes after close is not a success for whoever waits on it.
    expect(await ready).toBe("refused");
    expect(authority.read(A)).toEqual(UNKNOWN);
    expect(authority.admit(A, "op")).toEqual(UNKNOWN);
    expect(await authority.commitStream(A, "op", () => 1)).toEqual({
      ok: false,
      decision: UNKNOWN,
    });
    expect(authority.snapshot().size).toBe(0);
    // The store is free for the next runtime.
    const next = await boot(viewOf(inner, "second", log), "boot-2");
    expect(next.read(A).kind).toBe("streams");
  });

  it("gives the store back when close lands while the claim is still pending", async () => {
    const inner = createMemoryModeRecordStore();
    const log: string[] = [];
    const claiming = gate();
    const authority = createModeAuthority({
      store: viewOf(inner, "first", log, { beforeClaim: claiming.opened }),
      bootId: "boot-1",
    });
    authority.ready.catch(() => undefined);
    await tick(5);
    const closing = authority.close();
    claiming.open();
    await closing;
    expect(authority.read(A)).toEqual(UNKNOWN);
    await boot(viewOf(inner, "second", log), "boot-2");
  });
});

describe("a store that cannot be claimed", () => {
  function setup() {
    const inner = createMemoryModeRecordStore();
    const log: string[] = [];
    let mono = 0;
    const clock = { mono: () => mono, wall: () => Date.now() };
    return {
      inner,
      log,
      clock,
      at: (ms: number) => {
        mono = ms;
      },
    };
  }

  // READ_NEVER_RETRIES_OWNERSHIP
  it("claims again from an ordinary read once the owner has closed, and serves what is stored", async () => {
    const { inner, log, clock, at } = setup();
    const owner = await boot(viewOf(inner, "owner", log), "boot-1", { clock });
    await owner.submitEvidence(evidence(A, "on"));
    const cli = viewOf(inner, "cli", log);
    const refused = createModeAuthority({
      store: cli,
      bootId: "boot-2",
      clock,
      ownerRetryMs: 1000,
    });
    await expect(refused.ready).rejects.toThrow();
    expect(refused.read(A)).toEqual(OWNED);
    expect(cli.claims).toBe(1);

    // The owner leaves. No file is deleted; the CLI only asks again.
    await owner.close();
    at(1500);
    expect(refused.read(A)).toEqual(OWNED);
    await tick(5);
    expect(refused.read(A)).toEqual({ kind: "streams", importRequired: false });
    expect(refused.admit(A, "op").kind).toBe("streams");
    expect(cli.claims).toBe(2);
  });

  it("asks again at most once per interval, and one ask at a time", async () => {
    const { inner, log, clock, at } = setup();
    await boot(viewOf(inner, "owner", log), "boot-1", { clock });
    const cli = viewOf(inner, "cli", log);
    const refused = createModeAuthority({
      store: cli,
      bootId: "boot-2",
      clock,
      ownerRetryMs: 1000,
    });
    await expect(refused.ready).rejects.toThrow();
    for (let i = 0; i < 5; i += 1) refused.read(A);
    at(999);
    for (let i = 0; i < 5; i += 1) refused.admit(A, "op");
    await tick(5);
    expect(cli.claims).toBe(1);
    at(1000);
    for (let i = 0; i < 5; i += 1) refused.read(A);
    await tick(5);
    expect(cli.claims).toBe(2);
    // The owner still holds the store: still refused, and not asked again yet.
    expect(refused.read(A)).toEqual(OWNED);
    at(1500);
    refused.read(A);
    await tick(5);
    expect(cli.claims).toBe(2);
    at(2000);
    refused.read(A);
    await tick(5);
    expect(cli.claims).toBe(3);
  });

  it("does not ask again once it has been closed", async () => {
    const { inner, log, clock, at } = setup();
    await boot(viewOf(inner, "owner", log), "boot-1", { clock });
    const cli = viewOf(inner, "cli", log);
    const refused = createModeAuthority({
      store: cli,
      bootId: "boot-2",
      clock,
      ownerRetryMs: 1000,
    });
    await expect(refused.ready).rejects.toThrow();
    await refused.close();
    at(5000);
    refused.read(A);
    await tick(5);
    expect(cli.claims).toBe(1);
  });
});

describe("an unreadable record", () => {
  const owedOn = (extra: Partial<ModeAuthorityOptions> = {}) => ({
    hasLegacyFiles: (owner: string) => owner === A,
    ...extra,
  });

  async function onWithImportOwed(inner: MemoryModeRecordStore) {
    const first = await boot(inner, "boot-1", owedOn());
    expect(await first.submitEvidence(evidence(A, "on"))).toEqual({
      kind: "streams",
      importRequired: true,
    });
    await first.close();
  }

  // QUARANTINE_FORGETS_ON
  it("cannot erase a saved On: an Off after the restart is refused and no legacy write lands", async () => {
    const inner = createMemoryModeRecordStore();
    await onWithImportOwed(inner);
    inner.quarantine(A);

    const restarted = await boot(inner, "boot-2", {
      hasLegacyFiles: () => false,
    });
    expect(restarted.read(A)).toEqual(UNKNOWN);
    expect(await restarted.submitEvidence(evidence(A, "off"))).toEqual(UNKNOWN);
    let wrote = 0;
    expect(
      await restarted.commitLegacy(A, "op", () => {
        wrote += 1;
      }),
    ).toEqual({ ok: false, decision: UNKNOWN });
    expect(wrote).toBe(0);
    expect(inner.durable.get(A)).toMatchObject({
      switched: false,
      offFetchStartMono: null,
      historyUnknown: true,
    });
    await expect(restarted.importPending(A)).rejects.toThrow();

    // An On re-establishes the latch with the import owed, even with no
    // legacy files left to find.
    expect(await restarted.submitEvidence(evidence(A, "on"))).toEqual({
      kind: "streams",
      importRequired: true,
    });
    expect(inner.durable.get(A)).toMatchObject({
      switched: true,
      importPending: true,
    });
    expect(inner.durable.get(A)).not.toHaveProperty("historyUnknown");
    expect(await restarted.commitStream(A, "op", () => 1)).toMatchObject({
      ok: false,
      decision: { code: "IMPORT_PENDING" },
    });
  });

  it("stays unknown across more restarts until an On answers", async () => {
    const inner = createMemoryModeRecordStore();
    await onWithImportOwed(inner);
    inner.quarantine(A);
    for (const bootId of ["boot-2", "boot-3", "boot-4"]) {
      const runtime = await boot(inner, bootId);
      expect(runtime.read(A)).toEqual(UNKNOWN);
      expect(await runtime.submitEvidence(evidence(A, "off"))).toEqual(UNKNOWN);
      expect(inner.durable.get(A)).toMatchObject({ historyUnknown: true });
      await runtime.close();
    }
  });

  it("is stable through a second corrupt-then-heal cycle", async () => {
    const inner = createMemoryModeRecordStore();
    await onWithImportOwed(inner);
    for (const bootId of ["boot-2", "boot-3"]) {
      inner.quarantine(A);
      const runtime = await boot(inner, bootId);
      expect(await runtime.submitEvidence(evidence(A, "off"))).toEqual(UNKNOWN);
      expect(await runtime.submitEvidence(evidence(A, "on"))).toEqual({
        kind: "streams",
        importRequired: true,
      });
      // The host imports again (the import is idempotent), then it is done.
      expect((await runtime.importDone(A)).kind).toBe("streams");
      expect(inner.durable.get(A)).toMatchObject({
        switched: true,
        importPending: false,
      });
      expect(inner.durable.get(A)).not.toHaveProperty("historyUnknown");
      await runtime.close();
    }
  });

  it("also wins over a fresh Off held in memory when the record is lost while running", async () => {
    const inner = createMemoryModeRecordStore();
    const runtime = await boot(inner, "boot-1");
    await runtime.submitEvidence(evidence(A, "off"));
    expect(runtime.admit(A, "op").kind).toBe("legacy");
    inner.quarantine(A);
    let wrote = 0;
    expect(
      await runtime.commitLegacy(A, "op", () => {
        wrote += 1;
      }),
    ).toEqual({ ok: false, decision: UNKNOWN });
    expect(wrote).toBe(0);
    expect(runtime.read(A)).toEqual(UNKNOWN);
  });

  it("never lets save write a tombstone over an On, or an Off over a tombstone", async () => {
    const inner = createMemoryModeRecordStore();
    await inner.claim();
    const on = {
      switched: true,
      switchedAt: 1,
      cleanOffAt: null,
      offFetchStartMono: null,
      bootId: "b",
      importPending: false,
    };
    await inner.save(A, on, null);
    const tomb = { ...on, switched: false, switchedAt: null, bootId: null };
    await expect(
      inner.save(A, { ...tomb, historyUnknown: true }, on),
    ).rejects.toThrow();
    // Nor over nothing, nor over an Off: only a store's own quarantine makes one.
    const C = "0x3333333333333333333333333333333333333333";
    await expect(
      inner.save(C, { ...tomb, historyUnknown: true }, null),
    ).rejects.toThrow();
    const settledOff = {
      ...tomb,
      cleanOffAt: 1,
      offFetchStartMono: 1,
      bootId: "b",
    };
    await inner.save(C, settledOff, null);
    await expect(
      inner.save(C, { ...tomb, historyUnknown: true }, settledOff),
    ).rejects.toThrow();
    expect(inner.durable.get(C)).toEqual(settledOff);
    inner.quarantine(B);
    const stored = inner.durable.get(B)!;
    const off = { ...tomb, cleanOffAt: 1, offFetchStartMono: 1, bootId: "b" };
    await expect(inner.save(B, off, stored)).rejects.toThrow();
    await expect(
      inner.save(B, { ...on, importPending: false }, stored),
    ).rejects.toThrow();
    await inner.save(B, { ...on, importPending: true }, stored);
    expect(inner.durable.get(B)).toMatchObject({
      switched: true,
      importPending: true,
    });
  });
});

describe("the import-seed capability", () => {
  const withLegacy = () =>
    createModeAuthorityWithImporter({
      store: createMemoryModeRecordStore(),
      bootId: "boot-1",
      hasLegacyFiles: (owner) => owner === A,
    });

  // SEED_CAPABILITY_PUBLIC
  it("is not a method of the authority a caller is handed", async () => {
    const { authority } = withLegacy();
    await authority.ready;
    await authority.submitEvidence(evidence(A, "on"));
    expect(authority).not.toHaveProperty("commitImportSeed");
    expect(Object.keys(authority)).not.toContain("commitImportSeed");
    expect(
      (authority as unknown as Record<string, unknown>).commitImportSeed,
    ).toBeUndefined();
    // Holding only the public authority, an ordinary stream write is refused
    // while the import is owed.
    let ran = 0;
    expect(
      await authority.commitStream(A, "ordinary-upload", () => {
        ran += 1;
      }),
    ).toMatchObject({ ok: false, decision: { code: "IMPORT_PENDING" } });
    expect(ran).toBe(0);
    const plain = createModeAuthority({
      store: createMemoryModeRecordStore(),
      bootId: "boot-2",
    });
    expect(plain).not.toHaveProperty("commitImportSeed");
  });

  it("goes only to the code that created the authority, and publishes only while the import is owed", async () => {
    const { authority, importSeed } = withLegacy();
    await authority.ready;
    await authority.submitEvidence(evidence(A, "on"));
    expect(
      await importSeed.commitImportSeed(A, "seed-1", () => "seeded"),
    ).toEqual({ ok: true, value: "seeded", importRequired: true });
    // Not for an owner with no On, and not for an Off.
    expect((await importSeed.commitImportSeed(B, "s", () => 1)).ok).toBe(false);
    await authority.submitEvidence(evidence(B, "off"));
    expect((await importSeed.commitImportSeed(B, "s", () => 1)).ok).toBe(false);
    await authority.importDone(A);
    expect(await authority.commitStream(A, "after", () => 1)).toEqual({
      ok: true,
      value: 1,
      importRequired: false,
    });
  });
});

describe("a stream commit is a seal", () => {
  async function onAuthority(
    extra: Partial<ModeAuthorityOptions> = {},
    legacy = false,
  ) {
    const store = createMemoryModeRecordStore();
    const made = createModeAuthorityWithImporter({
      store,
      bootId: "boot-1",
      hasLegacyFiles: () => legacy,
      ...extra,
    });
    await made.authority.ready;
    await made.authority.submitEvidence(evidence(A, "on"));
    return { ...made, store };
  }

  it("refuses to publish after the authority is closed", async () => {
    const { authority, importSeed } = await onAuthority({}, true);
    // The decision was taken while open; the publish comes after close.
    await authority.close();
    let ran = 0;
    expect(
      await importSeed.commitImportSeed(A, "seed", () => {
        ran += 1;
      }),
    ).toMatchObject({ ok: false, decision: UNKNOWN });
    expect(
      await authority.commitStream(A, "op", () => {
        ran += 1;
      }),
    ).toMatchObject({ ok: false, decision: UNKNOWN });
    expect(ran).toBe(0);
  });

  // STREAM_COMMIT_OUTSIDE_LOCK
  it("makes importDone, and a close, wait for a stream callback in flight", async () => {
    const { authority, importSeed } = await onAuthority({}, true);
    const started = gate();
    const latch = gate();
    const seed = importSeed.commitImportSeed(A, "seed", async () => {
      started.open();
      await latch.opened;
      return "published";
    });
    await started.opened;
    let doneAnswered = false;
    const done = authority.importDone(A).then((d) => {
      doneAnswered = true;
      return d;
    });
    let closed = false;
    await tick(10);
    // importDone is exclusive: it waits for the publish.
    expect(doneAnswered).toBe(false);
    latch.open();
    expect(await seed).toMatchObject({ ok: true, value: "published" });
    expect(await done).toEqual({ kind: "streams", importRequired: false });
    const stream = gate();
    const started2 = gate();
    const write = authority.commitStream(A, "op", async () => {
      started2.open();
      await stream.opened;
    });
    await started2.opened;
    const closing = authority.close().then(() => {
      closed = true;
    });
    await tick(10);
    expect(closed).toBe(false);
    stream.open();
    expect(await write).toMatchObject({ ok: true });
    await closing;
    expect(closed).toBe(true);
  });

  it("never runs the callback of a refused commit", async () => {
    const { authority } = await onAuthority({}, true);
    let ran = 0;
    // The import is owed, so an ordinary stream write is refused.
    expect(
      await authority.commitStream(A, "op", () => {
        ran += 1;
      }),
    ).toMatchObject({ ok: false });
    // An owner that is not On is refused too.
    expect(
      await authority.commitStream(B, "op", () => {
        ran += 1;
      }),
    ).toMatchObject({ ok: false });
    expect(ran).toBe(0);
  });
});
