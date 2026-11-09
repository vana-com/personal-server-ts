import { describe, expect, it } from "vitest";
import {
  applyAnswer,
  createMemoryModeRecordStore,
  createModeAuthority,
  type ModeRecordStore,
} from "./index.js";

const OWNER = "0xAbC";

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

async function authorityWith(store = createMemoryModeRecordStore()) {
  const onOn: string[] = [];
  const authority = createModeAuthority({
    store,
    onOn: (owner) => onOn.push(owner),
  });
  await authority.ready;
  return { authority, store, onOn };
}

describe("the account-mode record", () => {
  it("is unknown before the first answer: reads stay legacy, legacy writes pause", async () => {
    const { authority } = await authorityWith();
    expect(authority.read(OWNER)).toMatchObject({
      kind: "refuse",
      code: "ACCOUNT_MODE_UNKNOWN",
      status: 503,
    });
    const ran = await authority.commitLegacy(OWNER, () => "wrote");
    expect(ran).toMatchObject({ ok: false, decision: { status: 503 } });
  });

  it("answers unknown, not waiting, before the saved records have loaded", () => {
    const never = new Promise<never>(() => {});
    const authority = createModeAuthority({
      store: { load: () => never, save: async () => {} },
    });
    expect(authority.read(OWNER).kind).toBe("refuse");
  });

  it("takes Off then lets legacy writes run, and is never unknown again", async () => {
    const { authority } = await authorityWith();
    await authority.submitEvidence({ owner: OWNER, state: "off" });
    expect(authority.read(OWNER)).toEqual({ kind: "legacy" });
    expect(await authority.commitLegacy(OWNER, () => 7)).toEqual({
      ok: true,
      value: 7,
    });
    await authority.submitEvidence({ owner: OWNER, state: "unknown" });
    expect(authority.read(OWNER)).toEqual({ kind: "legacy" });
  });

  it("latches On: a later Off at the same generation is ignored, and legacy writes get 426", async () => {
    const { authority, onOn } = await authorityWith();
    await authority.submitEvidence({ owner: OWNER, state: "on" });
    await authority.submitEvidence({ owner: OWNER, state: "off" });
    expect(authority.read(OWNER)).toEqual({ kind: "streams" });
    expect(await authority.commitLegacy(OWNER, () => 1)).toMatchObject({
      ok: false,
      decision: { code: "LEGACY_REFUSED_SWITCHED", status: 426 },
    });
    expect(onOn).toEqual(["0xabc", "0xabc"]);
  });

  it("lets a higher generation replace the record, and ignores a lower one", async () => {
    const { authority } = await authorityWith();
    await authority.submitEvidence({
      owner: OWNER,
      state: "on",
      generation: 3,
    });
    await authority.submitEvidence({
      owner: OWNER,
      state: "off",
      generation: 2,
    });
    await authority.submitEvidence({
      owner: OWNER,
      state: "off",
      generation: 3,
    });
    expect(authority.read(OWNER).kind).toBe("streams");
    await authority.submitEvidence({
      owner: OWNER,
      state: "off",
      generation: 4,
    });
    expect(authority.read(OWNER).kind).toBe("legacy");
    await authority.submitEvidence({
      owner: OWNER,
      state: "on",
      generation: 3,
    });
    expect(authority.read(OWNER).kind).toBe("legacy");
  });

  it("has no expiry: the answer outlives any clock and any restart", async () => {
    const store = createMemoryModeRecordStore();
    const first = createModeAuthority({ store, now: () => 1 });
    await first.submitEvidence({ owner: OWNER, state: "off" });
    const later = createModeAuthority({ store, now: () => 10 ** 15 });
    await later.ready;
    expect(later.read(OWNER).kind).toBe("legacy");
    await first.submitEvidence({ owner: OWNER, state: "on" });
    const restarted = createModeAuthority({ store });
    await restarted.ready;
    expect(restarted.read(OWNER).kind).toBe("streams");
  });

  it("keeps owners apart", async () => {
    const { authority } = await authorityWith();
    await authority.submitEvidence({ owner: OWNER, state: "on" });
    expect(authority.read("0xother").kind).toBe("refuse");
  });

  it("changes nothing when the save fails, and throws", async () => {
    const failing: ModeRecordStore = {
      load: async () => new Map(),
      save: async () => {
        throw new Error("disk full");
      },
    };
    const { authority, onOn } = await authorityWith(failing as never);
    await expect(
      authority.submitEvidence({ owner: OWNER, state: "on" }),
    ).rejects.toThrow("disk full");
    expect(authority.read(OWNER).kind).toBe("refuse");
    expect(onOn).toEqual([]);
  });

  it("starts unknown, not crashed, when the saved records cannot be loaded", async () => {
    const warnings: string[] = [];
    const authority = createModeAuthority({
      store: {
        load: async () => {
          throw new Error("unreadable");
        },
        save: async () => {},
      },
      onWarning: (m) => warnings.push(m),
    });
    await authority.ready;
    expect(authority.read(OWNER).kind).toBe("refuse");
    expect(warnings).toHaveLength(1);
  });

  it("applyAnswer never lowers an On at the same generation", () => {
    const on = { answer: "on" as const, generation: 0, receivedAt: 1 };
    expect(applyAnswer(on, "off", 0, 2)).toBe(on);
  });
});

describe("the commit fence", () => {
  it("makes an On wait for a legacy write in flight, and refuses every legacy write after it", async () => {
    const { authority } = await authorityWith();
    await authority.submitEvidence({ owner: OWNER, state: "off" });
    const gate = deferred();
    const events: string[] = [];
    const inFlight = authority.commitLegacy(OWNER, async () => {
      events.push("write-start");
      await gate.promise;
      events.push("write-end");
    });
    await Promise.resolve();
    const latch = authority
      .submitEvidence({ owner: OWNER, state: "on" })
      .then(() => events.push("on"));
    const late = authority
      .commitLegacy(OWNER, async () => {
        events.push("late-write");
      })
      .then((r) => events.push(r.ok ? "late-ran" : "late-refused"));
    await new Promise((r) => setTimeout(r, 10));
    expect(events).toEqual(["write-start"]);
    gate.resolve();
    await Promise.all([inFlight, latch, late]);
    expect(events).toEqual(["write-start", "write-end", "on", "late-refused"]);
  });

  it("lets a removal run in every mode", async () => {
    const { authority } = await authorityWith();
    await authority.submitEvidence({ owner: OWNER, state: "on" });
    expect(await authority.commitRemoval(() => "removed")).toBe("removed");
  });

  it("refuses new legacy writes once closed, after draining the one in flight", async () => {
    const { authority } = await authorityWith();
    await authority.submitEvidence({ owner: OWNER, state: "off" });
    const gate = deferred();
    const running = authority.commitLegacy(OWNER, () => gate.promise);
    await new Promise((r) => setTimeout(r, 0));
    let closed = false;
    const closing = authority.close().then(() => (closed = true));
    await new Promise((r) => setTimeout(r, 10));
    expect(closed).toBe(false);
    gate.resolve();
    await Promise.all([running, closing]);
    expect(await authority.commitLegacy(OWNER, () => 1)).toMatchObject({
      ok: false,
    });
  });
});
