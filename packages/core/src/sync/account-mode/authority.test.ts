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
  it("is unknown before the first answer: reads and legacy writes pause", async () => {
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

  it("takes Off then lets legacy writes run", async () => {
    const { authority } = await authorityWith();
    await authority.submitEvidence({ owner: OWNER, state: "off" });
    expect(authority.read(OWNER)).toEqual({ kind: "legacy" });
    expect(authority.legacyWriteDecision(OWNER)).toEqual({ kind: "legacy" });
    expect(await authority.commitLegacy(OWNER, () => 7)).toEqual({
      ok: true,
      value: 7,
    });
  });

  describe("a failed read of the Account after an Off", () => {
    const UNKNOWN = {
      kind: "refuse",
      code: "ACCOUNT_MODE_UNKNOWN",
      status: 503,
    };

    it("pauses legacy writes, keeps reads on the record, and keeps the record", async () => {
      const { authority, store } = await authorityWith();
      await authority.submitEvidence({
        owner: OWNER,
        state: "off",
        generation: 2,
      });
      const answered = await authority.submitEvidence({
        owner: OWNER,
        state: "unknown",
      });
      expect(answered).toEqual(UNKNOWN);
      expect(authority.legacyWriteDecision(OWNER)).toEqual(UNKNOWN);
      let ran = false;
      expect(
        await authority.commitLegacy(OWNER, () => {
          ran = true;
        }),
      ).toEqual({ ok: false, decision: UNKNOWN });
      expect(ran).toBe(false);
      // Reads are not writes: the person's data stays readable while the
      // Account cannot be reached.
      expect(authority.read(OWNER)).toEqual({ kind: "legacy" });
      // The record, with its generation, is history the failed read cannot erase.
      expect(store.saved.get("0xabc")).toMatchObject({
        answer: "off",
        generation: 2,
      });
    });

    it("ends at the next verified answer at the record's generation or higher", async () => {
      const { authority } = await authorityWith();
      await authority.submitEvidence({
        owner: OWNER,
        state: "off",
        generation: 2,
      });
      await authority.submitEvidence({ owner: OWNER, state: "unknown" });
      expect(
        await authority.submitEvidence({
          owner: OWNER,
          state: "off",
          generation: 2,
        }),
      ).toEqual({ kind: "legacy" });
      expect(await authority.commitLegacy(OWNER, () => 5)).toEqual({
        ok: true,
        value: 5,
      });
    });

    it("lets an On through: a failed read never lowers a switched account", async () => {
      const { authority } = await authorityWith();
      await authority.submitEvidence({ owner: OWNER, state: "off" });
      await authority.submitEvidence({ owner: OWNER, state: "unknown" });
      expect(
        await authority.submitEvidence({ owner: OWNER, state: "on" }),
      ).toEqual({ kind: "streams" });
      await authority.submitEvidence({ owner: OWNER, state: "unknown" });
      expect(authority.legacyWriteDecision(OWNER)).toEqual({
        kind: "streams",
      });
      expect(await authority.commitLegacy(OWNER, () => 1)).toMatchObject({
        ok: false,
        decision: { code: "LEGACY_REFUSED_SWITCHED", status: 426 },
      });
    });

    it("pauses only the owner whose read failed", async () => {
      const { authority } = await authorityWith();
      await authority.submitEvidence({ owner: OWNER, state: "off" });
      await authority.submitEvidence({ owner: "0xOther", state: "off" });
      await authority.submitEvidence({ owner: OWNER, state: "unknown" });
      expect(authority.legacyWriteDecision("0xother")).toEqual({
        kind: "legacy",
      });
    });

    it("does not stop a legacy write that started before the failed read", async () => {
      const { authority } = await authorityWith();
      await authority.submitEvidence({ owner: OWNER, state: "off" });
      const gate = deferred();
      const started = deferred();
      const inFlight = authority.commitLegacy(OWNER, async () => {
        started.resolve();
        await gate.promise;
        return "done";
      });
      await started.promise;
      await authority.submitEvidence({ owner: OWNER, state: "unknown" });
      gate.resolve();
      expect(await inFlight).toEqual({ ok: true, value: "done" });
    });

    it("refuses legacy writes in a restarted process until it has its own verified answer", async () => {
      const store = createMemoryModeRecordStore();
      const first = createModeAuthority({ store });
      await first.submitEvidence({ owner: OWNER, state: "off" });
      await first.submitEvidence({ owner: OWNER, state: "unknown" });
      // Each restart starts with no verified answer, however often it repeats.
      for (let restart = 0; restart < 2; restart += 1) {
        const restarted = createModeAuthority({ store });
        await restarted.ready;
        // The saved Off still serves reads; it cannot authorize a write.
        expect(restarted.read(OWNER)).toEqual({ kind: "legacy" });
        expect(restarted.legacyWriteDecision(OWNER)).toEqual(UNKNOWN);
        let ran = false;
        expect(
          await restarted.commitLegacy(OWNER, () => {
            ran = true;
          }),
        ).toEqual({ ok: false, decision: UNKNOWN });
        expect(ran).toBe(false);
      }
      const third = createModeAuthority({ store });
      await third.ready;
      await third.submitEvidence({ owner: OWNER, state: "off" });
      expect(await third.commitLegacy(OWNER, () => 3)).toEqual({
        ok: true,
        value: 3,
      });
    });

    it("keeps a saved On refusing writes and serving streams after a restart", async () => {
      const store = createMemoryModeRecordStore();
      const first = createModeAuthority({ store });
      await first.submitEvidence({ owner: OWNER, state: "on" });
      const restarted = createModeAuthority({ store });
      await restarted.ready;
      expect(restarted.read(OWNER)).toEqual({ kind: "streams" });
      expect(await restarted.commitLegacy(OWNER, () => 1)).toMatchObject({
        ok: false,
        decision: { code: "LEGACY_REFUSED_SWITCHED", status: 426 },
      });
    });

    it("is not reopened by a verified answer that was already in flight when a failed read arrived", async () => {
      // An Off at a higher generation waits on its save; a failed read is
      // submitted and finishes meanwhile; the save then completes.
      const memory = createMemoryModeRecordStore();
      const saveGate = deferred();
      const saveEntered = deferred();
      let gateSaves = false;
      const store: ModeRecordStore = {
        load: () => memory.load(),
        save: async (owner, record) => {
          if (gateSaves) {
            saveEntered.resolve();
            await saveGate.promise;
          }
          await memory.save(owner, record);
        },
      };
      const { authority } = await authorityWith(store);
      await authority.submitEvidence({
        owner: OWNER,
        state: "off",
        generation: 0,
      });
      gateSaves = true;
      const slowOff = authority.submitEvidence({
        owner: OWNER,
        state: "off",
        generation: 1,
      });
      // The real save has been entered: the answer is in flight.
      await saveEntered.promise;
      expect(
        await authority.submitEvidence({ owner: OWNER, state: "unknown" }),
      ).toEqual(UNKNOWN);
      saveGate.resolve();
      // The slow answer was asked before the failed read, so it cannot say the
      // Account is readable now.
      expect(await slowOff).toEqual(UNKNOWN);
      expect(authority.legacyWriteDecision(OWNER)).toEqual(UNKNOWN);
      expect(await authority.commitLegacy(OWNER, () => 1)).toEqual({
        ok: false,
        decision: UNKNOWN,
      });
      await authority.submitEvidence({
        owner: OWNER,
        state: "off",
        generation: 1,
      });
      expect(await authority.commitLegacy(OWNER, () => 2)).toEqual({
        ok: true,
        value: 2,
      });
    });

    it("refuses legacy writes after an On whose save failed, until a later answer applies", async () => {
      // Off at generation 2 is verified in this process; the On that follows
      // cannot be saved. The latest evidence says switched, so the older Off
      // must not keep authorizing writes.
      const memory = createMemoryModeRecordStore();
      let failSaves = false;
      const store: ModeRecordStore = {
        load: () => memory.load(),
        save: async (owner, record) => {
          if (failSaves) throw new Error("disk full");
          await memory.save(owner, record);
        },
      };
      const { authority } = await authorityWith(store);
      await authority.submitEvidence({
        owner: OWNER,
        state: "off",
        generation: 2,
      });
      expect(await authority.commitLegacy(OWNER, () => 1)).toEqual({
        ok: true,
        value: 1,
      });
      failSaves = true;
      await expect(
        authority.submitEvidence({ owner: OWNER, state: "on", generation: 2 }),
      ).rejects.toThrow("disk full");
      expect(authority.legacyWriteDecision(OWNER)).toEqual(UNKNOWN);
      let ran = false;
      expect(
        await authority.commitLegacy(OWNER, () => {
          ran = true;
        }),
      ).toEqual({ ok: false, decision: UNKNOWN });
      expect(ran).toBe(false);
      // Reads still follow the record that was saved.
      expect(authority.read(OWNER)).toEqual({ kind: "legacy" });
      failSaves = false;
      // A later answer that applies ends it: here the On lands.
      expect(
        await authority.submitEvidence({
          owner: OWNER,
          state: "on",
          generation: 2,
        }),
      ).toEqual({ kind: "streams" });
      expect(await authority.commitLegacy(OWNER, () => 2)).toMatchObject({
        ok: false,
        decision: { code: "LEGACY_REFUSED_SWITCHED", status: 426 },
      });
    });

    it("keeps the pause through an older generation: Off 2, unknown, then a verified answer at 1", async () => {
      const { authority } = await authorityWith();
      await authority.submitEvidence({
        owner: OWNER,
        state: "off",
        generation: 2,
      });
      await authority.submitEvidence({ owner: OWNER, state: "unknown" });
      for (const state of ["off", "on"] as const) {
        expect(
          await authority.submitEvidence({
            owner: OWNER,
            state,
            generation: 1,
          }),
        ).toEqual(UNKNOWN);
        expect(await authority.commitLegacy(OWNER, () => 1)).toEqual({
          ok: false,
          decision: UNKNOWN,
        });
      }
      await authority.submitEvidence({
        owner: OWNER,
        state: "off",
        generation: 2,
      });
      expect(await authority.commitLegacy(OWNER, () => 3)).toEqual({
        ok: true,
        value: 3,
      });
    });

    it("does not reopen on an answer older than the record: a stale Off or a stale On", async () => {
      const store = createMemoryModeRecordStore([
        ["0xabc", { answer: "off", generation: 2, receivedAt: 1 }],
      ]);
      const { authority } = await authorityWith(store);
      // Nothing verified in this process yet, and an older answer is not one.
      for (const state of ["off", "on"] as const) {
        expect(
          await authority.submitEvidence({
            owner: OWNER,
            state,
            generation: 1,
          }),
        ).toEqual(UNKNOWN);
        expect(authority.legacyWriteDecision(OWNER)).toEqual(UNKNOWN);
        expect(authority.read(OWNER)).toEqual({ kind: "legacy" });
      }
      expect(
        await authority.submitEvidence({
          owner: OWNER,
          state: "off",
          generation: 2,
        }),
      ).toEqual({ kind: "legacy" });
    });
  });

  describe("evidence that has arrived but is not applied yet", () => {
    const UNKNOWN = {
      kind: "refuse",
      code: "ACCOUNT_MODE_UNKNOWN",
      status: 503,
    };

    async function verifiedOff(store?: ModeRecordStore) {
      const made = await authorityWith(store);
      await made.authority.submitEvidence({
        owner: OWNER,
        state: "off",
        generation: 2,
      });
      return made;
    }

    it("fences a legacy write that was asked for before the On arrived and has not started", async () => {
      const memory = createMemoryModeRecordStore();
      let failSaves = false;
      const store: ModeRecordStore = {
        load: () => memory.load(),
        save: async (owner, record) => {
          if (failSaves) throw new Error("disk full");
          await memory.save(owner, record);
        },
      };
      const { authority } = await verifiedOff(store);
      failSaves = true;
      let ran = false;
      // Both calls are made before either has awaited anything: the write is
      // asked for first and has not started, then the On arrives.
      const write = authority.commitLegacy(OWNER, () => {
        ran = true;
      });
      const on = authority.submitEvidence({
        owner: OWNER,
        state: "on",
        generation: 2,
      });
      // The early checks refuse as soon as the answer has arrived.
      expect(authority.legacyWriteDecision(OWNER)).toEqual(UNKNOWN);
      const settled = await Promise.allSettled([write, on]);
      expect(ran).toBe(false);
      expect(settled[0]).toEqual({
        status: "fulfilled",
        value: { ok: false, decision: UNKNOWN },
      });
      expect(settled[1].status).toBe("rejected");
    });

    it("fences a legacy write asked for after the On arrived, and refuses it as switched once the On applies", async () => {
      const memory = createMemoryModeRecordStore();
      const saveGate = deferred();
      const saveEntered = deferred();
      const store: ModeRecordStore = {
        load: () => memory.load(),
        save: async (owner, record) => {
          if (record.answer === "on") {
            saveEntered.resolve();
            await saveGate.promise;
          }
          await memory.save(owner, record);
        },
      };
      const { authority } = await verifiedOff(store);
      const on = authority.submitEvidence({
        owner: OWNER,
        state: "on",
        generation: 2,
      });
      await saveEntered.promise;
      expect(authority.legacyWriteDecision(OWNER)).toEqual(UNKNOWN);
      let ran = false;
      const write = authority.commitLegacy(OWNER, () => {
        ran = true;
      });
      saveGate.resolve();
      expect(await on).toEqual({ kind: "streams" });
      expect(await write).toMatchObject({
        ok: false,
        decision: { code: "LEGACY_REFUSED_SWITCHED", status: 426 },
      });
      expect(ran).toBe(false);
    });

    it("lets a write that had already started drain, and the On waits for it", async () => {
      const { authority } = await verifiedOff();
      const entered = deferred();
      const finish = deferred();
      const write = authority.commitLegacy(OWNER, async () => {
        entered.resolve();
        await finish.promise;
        return "wrote";
      });
      await entered.promise;
      const on = authority.submitEvidence({
        owner: OWNER,
        state: "on",
        generation: 2,
      });
      expect(authority.legacyWriteDecision(OWNER)).toEqual(UNKNOWN);
      expect(authority.read(OWNER)).toEqual({ kind: "legacy" });
      finish.resolve();
      expect(await write).toEqual({ ok: true, value: "wrote" });
      expect(await on).toEqual({ kind: "streams" });
    });

    it("does not refuse a write that waits for an answer that applies and is current: an Off poll", async () => {
      const memory = createMemoryModeRecordStore();
      const saveGate = deferred();
      const saveEntered = deferred();
      let gateSaves = false;
      const store: ModeRecordStore = {
        load: () => memory.load(),
        save: async (owner, record) => {
          if (gateSaves) {
            saveEntered.resolve();
            await saveGate.promise;
          }
          await memory.save(owner, record);
        },
      };
      const { authority } = await verifiedOff(store);
      gateSaves = true;
      // A newer generation of Off: it has to be saved, so it is in flight.
      const poll = authority.submitEvidence({
        owner: OWNER,
        state: "off",
        generation: 3,
      });
      await saveEntered.promise;
      const write = authority.commitLegacy(OWNER, () => "wrote");
      saveGate.resolve();
      expect(await poll).toEqual({ kind: "legacy" });
      expect(await write).toEqual({ ok: true, value: "wrote" });
    });

    it("refuses a waiting write once the answers pending at its entry settle, without draining answers that keep arriving", async () => {
      // Off 3 is in flight when the write is asked for. Off 4 arrives before
      // 3 is released, and each later save entry enqueues the next answer
      // before its own is released, so the owner never has zero unsettled
      // answers until the test stops enqueuing.
      const memory = createMemoryModeRecordStore();
      const SAVES = 4;
      const entered = Array.from({ length: SAVES }, deferred);
      const gates = Array.from({ length: SAVES }, deferred);
      const submitted: Array<Promise<unknown>> = [];
      const released = [false, false, false, false];
      let saves = 0;
      let counting = false;
      const holder: {
        authority?: Awaited<ReturnType<typeof authorityWith>>["authority"];
      } = {};
      const store: ModeRecordStore = {
        load: () => memory.load(),
        save: async (owner, record) => {
          if (counting && saves < SAVES) {
            const i = saves++;
            // From the second save on, the next answer arrives before this
            // one is released.
            if (i >= 1 && i + 1 < SAVES) {
              submitted.push(
                holder.authority!.submitEvidence({
                  owner: OWNER,
                  state: "off",
                  generation: 4 + i,
                }),
              );
            }
            entered[i]!.resolve();
            await gates[i]!.promise;
          }
          await memory.save(owner, record);
        },
      };
      const { authority } = await verifiedOff(store);
      holder.authority = authority;
      counting = true;
      submitted.push(
        authority.submitEvidence({ owner: OWNER, state: "off", generation: 3 }),
      );
      await entered[0]!.promise;
      let ran = false;
      const write = authority.commitLegacy(OWNER, () => {
        ran = true;
      });
      // Off 4 arrives after the write was asked for, before Off 3 is released.
      submitted.push(
        authority.submitEvidence({ owner: OWNER, state: "off", generation: 4 }),
      );
      released[0] = true;
      gates[0]!.resolve();
      // Off 3 settles, so the write's cohort has. Off 4 was queued for the
      // lock before the write asked for it, so it saves first, and enqueues
      // Off 5 while it does.
      await entered[1]!.promise;
      released[1] = true;
      gates[1]!.resolve();
      // The write is refused while Off 5 is still unsettled, and Off 5's save
      // is not released: it was not waited for.
      expect(await write).toEqual({ ok: false, decision: UNKNOWN });
      expect(ran).toBe(false);
      expect(released).toEqual([true, true, false, false]);
      for (let i = 2; i < SAVES; i += 1) {
        await entered[i]!.promise;
        released[i] = true;
        gates[i]!.resolve();
      }
      await Promise.all(submitted);
      // Once the evidence has drained, a write is admitted on the last Off.
      expect(await authority.commitLegacy(OWNER, () => "wrote")).toEqual({
        ok: true,
        value: "wrote",
      });
    });

    it("takes back a live permission for an answer older than the record: Off 2, then a stale On 1 or a stale Off 1", async () => {
      for (const state of ["on", "off"] as const) {
        const { authority } = await verifiedOff();
        expect(
          await authority.submitEvidence({
            owner: OWNER,
            state,
            generation: 1,
          }),
        ).toEqual(UNKNOWN);
        expect(authority.legacyWriteDecision(OWNER)).toEqual(UNKNOWN);
        let ran = false;
        expect(
          await authority.commitLegacy(OWNER, () => {
            ran = true;
          }),
        ).toEqual({ ok: false, decision: UNKNOWN });
        expect(ran).toBe(false);
        // The saved record is unchanged and reads still follow it.
        expect(authority.read(OWNER)).toEqual({ kind: "legacy" });
        // A later current answer ends the pause.
        await authority.submitEvidence({
          owner: OWNER,
          state: "off",
          generation: 2,
        });
        expect(await authority.commitLegacy(OWNER, () => 1)).toEqual({
          ok: true,
          value: 1,
        });
      }
    });
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

  it("never saves a stale Off while the load has failed, and recovers from the reload", async () => {
    const saves: Array<{ owner: string; generation: number }> = [];
    const durable = new Map([
      ["0xabc", { answer: "on" as const, generation: 7, receivedAt: 1 }],
    ]);
    let loads = 0;
    const warnings: string[] = [];
    const authority = createModeAuthority({
      store: {
        load: async () => {
          loads += 1;
          if (loads <= 2) throw new Error("unreadable");
          return durable;
        },
        save: async (owner, record) => {
          saves.push({ owner, generation: record.generation });
        },
      },
      onWarning: (m) => warnings.push(m),
    });
    await authority.ready;
    expect(authority.read(OWNER).kind).toBe("refuse");
    expect(loads).toBe(1);
    const first = await authority.submitEvidence({
      owner: OWNER,
      state: "off",
      generation: 6,
    });
    expect(first.kind).toBe("refuse");
    expect(saves).toEqual([]);
    expect(authority.read(OWNER).kind).toBe("refuse");
    expect(await authority.commitLegacy(OWNER, () => 1)).toMatchObject({
      ok: false,
      decision: { status: 503 },
    });
    expect(loads).toBe(2);
    expect(warnings).toHaveLength(2);
    // The next evidence retries the load; the stale Off loses to the durable On.
    const second = await authority.submitEvidence({
      owner: OWNER,
      state: "off",
      generation: 6,
    });
    expect(second).toEqual({ kind: "streams" });
    expect(authority.read(OWNER)).toEqual({ kind: "streams" });
    expect(saves).toEqual([]);
    expect(loads).toBe(3);
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
    const entered = deferred();
    const events: string[] = [];
    const inFlight = authority.commitLegacy(OWNER, async () => {
      events.push("write-start");
      entered.resolve();
      await gate.promise;
      events.push("write-end");
    });
    // The write has started: this is the one the On must wait for.
    await entered.promise;
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
