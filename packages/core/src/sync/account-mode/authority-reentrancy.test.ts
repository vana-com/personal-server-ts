/**
 * A seal callback that calls back into the authority that runs it must fail at
 * once, not wait for itself. The shared vectors are event traces; a callback is
 * code, so a vector cannot express this and these tests carry it.
 */
import { describe, expect, it } from "vitest";
import { createModeAuthorityWithImporter } from "./authority.js";
import { createMemoryModeRecordStore } from "./memory-record-store.js";
import {
  ReentrantAuthorityCall,
  callbackGuardAvailable,
  createCallbackGuard,
} from "./reentrancy.js";

const LEGACY_OWNER = "0x1111111111111111111111111111111111111111";
const STREAM_OWNER = "0x2222222222222222222222222222222222222222";

const evidence = (owner: string, state: "on" | "off") => ({
  owner,
  authOwner: owner,
  state,
  fetchStartedAt: Date.now(),
  rawStatus: 200,
});

const tick = (ms = 0) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

function gate() {
  let open!: () => void;
  const opened = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { opened, open };
}

/** What a call settled to, or "hung" if it had not settled after a moment. */
async function outcome(call: Promise<unknown>): Promise<unknown> {
  const hung = Symbol("hung");
  const result = await Promise.race([
    call.then(
      (value) => ({ value }),
      (error: unknown) => ({ error }),
    ),
    tick(250).then(() => hung),
  ]);
  return result === hung ? "hung" : result;
}

async function setup() {
  const { authority, importSeed } = createModeAuthorityWithImporter({
    store: createMemoryModeRecordStore(),
    bootId: "boot",
  });
  await authority.ready;
  await authority.submitEvidence(evidence(LEGACY_OWNER, "off"));
  await authority.submitEvidence(evidence(STREAM_OWNER, "on"));
  return { authority, importSeed };
}

type Fixture = Awaited<ReturnType<typeof setup>>;

/** Each way to run a callback under the lock, with the owner it needs. */
const KINDS: {
  name: string;
  run: (f: Fixture, write: () => Promise<unknown>) => Promise<{ ok: boolean }>;
}[] = [
  {
    name: "commitLegacy",
    run: (f, write) => f.authority.commitLegacy(LEGACY_OWNER, "op", write),
  },
  {
    name: "commitStream",
    run: (f, write) => f.authority.commitStream(STREAM_OWNER, "op", write),
  },
  {
    name: "commitImportSeed",
    run: (f, write) => f.importSeed.commitImportSeed(STREAM_OWNER, "op", write),
  },
];

/** Each call that takes the lock or waits for it. */
const CALLS: { name: string; call: (f: Fixture) => Promise<unknown> }[] = [
  {
    name: "commitLegacy",
    call: (f) => f.authority.commitLegacy(LEGACY_OWNER, "inner", () => 1),
  },
  {
    name: "commitStream",
    call: (f) => f.authority.commitStream(STREAM_OWNER, "inner", () => 1),
  },
  {
    name: "commitImportSeed",
    call: (f) => f.importSeed.commitImportSeed(STREAM_OWNER, "inner", () => 1),
  },
  {
    name: "submitEvidence",
    call: (f) => f.authority.submitEvidence(evidence(STREAM_OWNER, "on")),
  },
  {
    name: "submitEvidenceMono",
    call: (f) =>
      f.authority.submitEvidenceMono({
        owner: STREAM_OWNER,
        authOwner: STREAM_OWNER,
        state: "on",
        rawStatus: 200,
        fetchStartMono: 0,
      }),
  },
  {
    name: "importDone",
    call: (f) => f.authority.importDone(STREAM_OWNER),
  },
  {
    name: "importPending",
    call: (f) => f.authority.importPending(STREAM_OWNER),
  },
  { name: "close", call: (f) => f.authority.close() },
];

describe("a seal callback that calls back into its authority", () => {
  it("runs where the host has AsyncLocalStorage (Node 22.3 and later)", () => {
    expect(callbackGuardAvailable).toBe(true);
  });

  for (const kind of KINDS) {
    for (const inner of CALLS) {
      // REENTRANT_CALL_WAITS
      it(`REENTRANT_CALL_WAITS: ${inner.name} from inside ${kind.name} throws ReentrantAuthorityCall at once, and the outer commit completes`, async () => {
        const f = await setup();
        let seen: unknown;
        const result = await kind.run(f, async () => {
          seen = await outcome(inner.call(f));
          return "done";
        });
        expect(seen).toMatchObject({
          error: expect.any(ReentrantAuthorityCall),
        });
        expect((seen as { error: Error }).error.name).toBe(
          "ReentrantAuthorityCall",
        );
        expect(result).toMatchObject({ ok: true, value: "done" });
        // The lock is free: new work is admitted and the authority closes.
        expect(
          await outcome(
            f.authority.submitEvidence(evidence(STREAM_OWNER, "on")),
          ),
        ).toMatchObject({ value: { kind: "streams" } });
        expect(await outcome(f.authority.close())).toEqual({
          value: undefined,
        });
      });
    }
  }

  it("is also caught after the callback has awaited, however long", async () => {
    const f = await setup();
    let seen: unknown;
    await f.authority.commitStream(STREAM_OWNER, "op", async () => {
      await tick(20);
      await Promise.resolve();
      seen = await outcome(f.authority.importDone(STREAM_OWNER));
    });
    expect(seen).toMatchObject({ error: expect.any(ReentrantAuthorityCall) });
  });

  it("a refused close leaves the authority open", async () => {
    const f = await setup();
    await f.authority.commitStream(STREAM_OWNER, "op", async () => {
      await outcome(f.authority.close());
    });
    expect(f.authority.read(STREAM_OWNER).kind).toBe("streams");
    expect(
      await f.authority.commitStream(STREAM_OWNER, "later", () => 1),
    ).toMatchObject({ ok: true });
  });

  it("still lets the callback read and admit, which take no lock", async () => {
    for (const kind of KINDS) {
      const f = await setup();
      let seen: unknown;
      await kind.run(f, async () => {
        seen = [
          f.authority.read(STREAM_OWNER).kind,
          f.authority.admit(LEGACY_OWNER, "inner").kind,
        ];
      });
      expect(seen, kind.name).toEqual(["streams", "legacy"]);
    }
  });

  it("does not touch a call that is not inside the callback, while it runs", async () => {
    const f = await setup();
    const hold = gate();
    const entered = gate();
    const outer = f.authority.commitLegacy(LEGACY_OWNER, "slow", async () => {
      entered.open();
      await hold.opened;
      return "slow done";
    });
    await entered.opened;
    // Shared-side calls go on beside it; an exclusive call waits, not throws.
    expect(
      await outcome(f.authority.commitLegacy(LEGACY_OWNER, "other", () => 1)),
    ).toMatchObject({ value: { ok: true, value: 1 } });
    expect(await outcome(f.authority.importPending(STREAM_OWNER))).toEqual({
      value: false,
    });
    const waiting = f.authority.submitEvidence(evidence(STREAM_OWNER, "on"));
    expect(await outcome(waiting)).toBe("hung");
    hold.open();
    expect(await outer).toMatchObject({ ok: true, value: "slow done" });
    expect(await waiting).toMatchObject({ kind: "streams" });
  });

  it("does not flag a call made after the callback has settled", async () => {
    const f = await setup();
    let late: Promise<unknown> | undefined;
    await f.authority.commitStream(STREAM_OWNER, "op", () => {
      late = new Promise((resolve) => {
        setTimeout(() => resolve(f.authority.importPending(STREAM_OWNER)), 30);
      });
    });
    expect(await outcome(late as Promise<unknown>)).toEqual({ value: false });
  });

  it("marks only the authority that runs the callback", async () => {
    const one = await setup();
    const two = await setup();
    let seen: unknown;
    await one.authority.commitStream(STREAM_OWNER, "op", async () => {
      seen = await outcome(
        two.authority.commitStream(STREAM_OWNER, "inner", () => 7),
      );
    });
    expect(seen).toMatchObject({ value: { ok: true, value: 7 } });
  });
});

describe("the callback guard where AsyncLocalStorage is missing", () => {
  it("is off: it runs the callback and never throws", async () => {
    const guard = createCallbackGuard(null);
    expect(await guard.run(() => 5)).toBe(5);
    await expect(guard.run(async () => 6)).resolves.toBe(6);
    await guard.run(() => {
      expect(() => guard.assertOutside("close")).not.toThrow();
    });
  });
});
