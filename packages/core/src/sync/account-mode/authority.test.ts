import { describe, expect, it } from "vitest";
import {
  applyAnswer,
  createMemoryModeRecordStore,
  createModeAuthority,
  type AccountModeRecord,
  type ModeAnswer,
  type ModeAuthority,
  type ModeDecision,
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

  describe("the last answer, remembered while the Account cannot be read", () => {
    const UNKNOWN = {
      kind: "refuse",
      code: "ACCOUNT_MODE_UNKNOWN",
      status: 503,
    };

    it("lets legacy writes run on a remembered Off after a restart, with no answer in this process", async () => {
      const store = createMemoryModeRecordStore();
      const first = createModeAuthority({ store });
      await first.submitEvidence({ owner: OWNER, state: "off", generation: 2 });
      // Each restart starts with no answer from the Account, however often it
      // repeats: the saved Off is the last thing the Account said.
      for (let restart = 0; restart < 2; restart += 1) {
        const restarted = createModeAuthority({ store });
        await restarted.ready;
        expect(restarted.read(OWNER)).toEqual({ kind: "legacy" });
        expect(restarted.legacyWriteDecision(OWNER)).toEqual({
          kind: "legacy",
        });
        expect(await restarted.commitLegacy(OWNER, () => restart)).toEqual({
          ok: true,
          value: restart,
        });
      }
    });

    it("keeps legacy writes open through a failed read of the Account, and keeps the record", async () => {
      const { authority, store } = await authorityWith();
      await authority.submitEvidence({
        owner: OWNER,
        state: "off",
        generation: 2,
      });
      // The host could not read the Account: the answer is the remembered Off.
      const answered = await authority.submitEvidence({
        owner: OWNER,
        state: "unknown",
      });
      expect(answered).toEqual({ kind: "legacy" });
      expect(authority.legacyWriteDecision(OWNER)).toEqual({ kind: "legacy" });
      expect(await authority.commitLegacy(OWNER, () => "wrote")).toEqual({
        ok: true,
        value: "wrote",
      });
      expect(authority.read(OWNER)).toEqual({ kind: "legacy" });
      expect(store.saved.get("0xabc")).toMatchObject({
        answer: "off",
        generation: 2,
      });
    });

    it("keeps a remembered On refusing legacy writes through a failed read, in this process and after a restart", async () => {
      const store = createMemoryModeRecordStore();
      const first = createModeAuthority({ store });
      await first.submitEvidence({ owner: OWNER, state: "on" });
      expect(
        await first.submitEvidence({ owner: OWNER, state: "unknown" }),
      ).toEqual({ kind: "streams" });
      const restarted = createModeAuthority({ store });
      await restarted.ready;
      for (const authority of [first, restarted]) {
        expect(authority.read(OWNER)).toEqual({ kind: "streams" });
        expect(await authority.commitLegacy(OWNER, () => 1)).toMatchObject({
          ok: false,
          decision: { code: "LEGACY_REFUSED_SWITCHED", status: 426 },
        });
      }
    });

    it("stays unknown with no remembered answer: a first launch with the Account down", async () => {
      const { authority, store } = await authorityWith();
      expect(
        await authority.submitEvidence({ owner: OWNER, state: "unknown" }),
      ).toEqual(UNKNOWN);
      expect(authority.read(OWNER)).toEqual(UNKNOWN);
      expect(authority.legacyWriteDecision(OWNER)).toEqual(UNKNOWN);
      let ran = false;
      expect(
        await authority.commitLegacy(OWNER, () => {
          ran = true;
        }),
      ).toEqual({ ok: false, decision: UNKNOWN });
      expect(ran).toBe(false);
      expect(store.saved.size).toBe(0);
    });

    it("lets a fresh On replace a remembered Off at once: another device switched", async () => {
      const store = createMemoryModeRecordStore();
      const first = createModeAuthority({ store });
      await first.submitEvidence({ owner: OWNER, state: "off" });
      const restarted = createModeAuthority({ store });
      await restarted.ready;
      expect(await restarted.commitLegacy(OWNER, () => 1)).toEqual({
        ok: true,
        value: 1,
      });
      expect(
        await restarted.submitEvidence({ owner: OWNER, state: "on" }),
      ).toEqual({ kind: "streams" });
      expect(await restarted.commitLegacy(OWNER, () => 2)).toMatchObject({
        ok: false,
        decision: { code: "LEGACY_REFUSED_SWITCHED", status: 426 },
      });
      expect(store.saved.get("0xabc")).toMatchObject({ answer: "on" });
    });

    it("lets a fresh answer replace the remembered one: a higher generation (a reset) wins, On or Off", async () => {
      const store = createMemoryModeRecordStore([
        ["0xabc", { answer: "on", generation: 0, receivedAt: 1 }],
      ]);
      const { authority } = await authorityWith(store);
      // The remembered On refuses legacy writes until the Account says otherwise.
      expect(await authority.commitLegacy(OWNER, () => 1)).toMatchObject({
        ok: false,
        decision: { status: 426 },
      });
      // A reset: the Account answers Off at the next generation.
      expect(
        await authority.submitEvidence({
          owner: OWNER,
          state: "off",
          generation: 1,
        }),
      ).toEqual({ kind: "legacy" });
      expect(store.saved.get("0xabc")).toMatchObject({
        answer: "off",
        generation: 1,
      });
      expect(await authority.commitLegacy(OWNER, () => 2)).toEqual({
        ok: true,
        value: 2,
      });
    });

    it("never reuses one owner's remembered answer for another", async () => {
      const { authority } = await authorityWith();
      await authority.submitEvidence({ owner: OWNER, state: "off" });
      await authority.submitEvidence({ owner: "0xOther", state: "unknown" });
      expect(authority.legacyWriteDecision("0xother")).toEqual(UNKNOWN);
      let ran = false;
      expect(
        await authority.commitLegacy("0xother", () => {
          ran = true;
        }),
      ).toEqual({ ok: false, decision: UNKNOWN });
      expect(ran).toBe(false);
      // The first owner keeps theirs.
      expect(authority.legacyWriteDecision(OWNER)).toEqual({ kind: "legacy" });
    });

    it("does not stop a legacy write that is running when a failed read arrives, or a later one", async () => {
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
      expect(await authority.commitLegacy(OWNER, () => "next")).toEqual({
        ok: true,
        value: "next",
      });
    });

    it("lets an Off answer that was in flight when a failed read arrived take effect", async () => {
      // An Off at a higher generation waits on its save; a failed read is
      // submitted and finishes meanwhile; the save then completes. The failed
      // read says nothing about the Account, so the answer stands.
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
      await saveEntered.promise;
      // While an answer waits to be applied, a legacy write is held back.
      expect(authority.legacyWriteDecision(OWNER)).toEqual(UNKNOWN);
      await authority.submitEvidence({ owner: OWNER, state: "unknown" });
      saveGate.resolve();
      expect(await slowOff).toEqual({ kind: "legacy" });
      expect(await authority.commitLegacy(OWNER, () => 1)).toEqual({
        ok: true,
        value: 1,
      });
      expect(memory.saved.get("0xabc")).toMatchObject({ generation: 1 });
    });

    it("refuses legacy writes after an On whose save failed, until a later answer applies", async () => {
      // Off at generation 2 is remembered; the On that follows cannot be
      // saved. The Account said switched, so the older Off must not keep
      // authorizing writes.
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
      // A failed read after that does not give the permission back.
      await authority.submitEvidence({ owner: OWNER, state: "unknown" });
      expect(authority.legacyWriteDecision(OWNER)).toEqual(UNKNOWN);
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

    it("lets the saved Off authorize again after a restart that follows a failed On save (the withdrawal is in memory only)", async () => {
      // The withdrawal is held in memory: a failed save leaves the store's old
      // record, so a restart restores the saved Off. See `submitEvidence` in
      // authority.ts.
      const memory = createMemoryModeRecordStore();
      let failSaves = false;
      const store: ModeRecordStore = {
        load: () => memory.load(),
        save: async (owner, record) => {
          if (failSaves) throw new Error("disk full");
          await memory.save(owner, record);
        },
      };
      const first = createModeAuthority({ store });
      await first.submitEvidence({ owner: OWNER, state: "off", generation: 2 });
      failSaves = true;
      await expect(
        first.submitEvidence({ owner: OWNER, state: "on", generation: 2 }),
      ).rejects.toThrow("disk full");
      expect(first.legacyWriteDecision(OWNER)).toEqual(UNKNOWN);
      // The record the store kept is still the Off.
      expect([...memory.saved.values()]).toMatchObject([{ answer: "off" }]);

      const restarted = createModeAuthority({ store });
      await restarted.ready;
      // The Account cannot be read: a failed read, no answer.
      await restarted.submitEvidence({ owner: OWNER, state: "unknown" });
      expect(restarted.legacyWriteDecision(OWNER)).toEqual({ kind: "legacy" });
      expect(await restarted.commitLegacy(OWNER, () => 1)).toEqual({
        ok: true,
        value: 1,
      });
      // The first answer the Account gives ends it.
      failSaves = false;
      expect(
        await restarted.submitEvidence({
          owner: OWNER,
          state: "on",
          generation: 2,
        }),
      ).toEqual({ kind: "streams" });
      expect(await restarted.commitLegacy(OWNER, () => 2)).toMatchObject({
        ok: false,
        decision: { code: "LEGACY_REFUSED_SWITCHED", status: 426 },
      });
    });

    it("withdraws the permission for an answer older than the record, and a failed read does not give it back", async () => {
      const store = createMemoryModeRecordStore([
        ["0xabc", { answer: "off", generation: 2, receivedAt: 1 }],
      ]);
      const { authority } = await authorityWith(store);
      // The remembered Off at generation 2 allows writes on its own.
      expect(authority.legacyWriteDecision(OWNER)).toEqual({ kind: "legacy" });
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
        await authority.submitEvidence({ owner: OWNER, state: "unknown" });
        expect(authority.legacyWriteDecision(OWNER)).toEqual(UNKNOWN);
        expect(await authority.commitLegacy(OWNER, () => 1)).toEqual({
          ok: false,
          decision: UNKNOWN,
        });
      }
      expect(
        await authority.submitEvidence({
          owner: OWNER,
          state: "off",
          generation: 2,
        }),
      ).toEqual({ kind: "legacy" });
      expect(await authority.commitLegacy(OWNER, () => 3)).toEqual({
        ok: true,
        value: 3,
      });
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

    it("settles and releases the lock for a backlog larger than a call can take as arguments", async () => {
      // The bookkeeping must not spread the pending set into Math.max or
      // Math.min: a backlog this size throws a RangeError there, and a throw
      // before the release would hold the lock forever.
      const BACKLOG = 150_000;
      const memory = createMemoryModeRecordStore();
      const entered = deferred();
      const gate = deferred();
      let gating = false;
      const store: ModeRecordStore = {
        load: () => memory.load(),
        save: async (owner, record) => {
          if (gating) {
            gating = false;
            entered.resolve();
            await gate.promise;
          }
          await memory.save(owner, record);
        },
      };
      const { authority } = await verifiedOff(store);
      gating = true;
      const submitted = [
        authority.submitEvidence({ owner: OWNER, state: "off", generation: 3 }),
      ];
      await entered.promise;
      for (let i = 0; i < BACKLOG; i += 1) {
        submitted.push(
          authority.submitEvidence({
            owner: OWNER,
            state: "off",
            generation: 3,
          }),
        );
      }
      // A write asked for with the whole backlog pending.
      const write = authority.commitLegacy(OWNER, () => "wrote");
      gate.resolve();
      await Promise.all(submitted);
      // The write's cohort has settled; the backlog's last answer is current.
      expect(await write).toEqual({ ok: true, value: "wrote" });
      expect(await authority.commitLegacy(OWNER, () => "again")).toEqual({
        ok: true,
        value: "again",
      });
    }, 60_000);

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

  it("keeps ready from rejecting and still reloads when the warning sink throws", async () => {
    let loads = 0;
    const authority = createModeAuthority({
      store: {
        load: async () => {
          loads += 1;
          if (loads === 1) throw new Error("unreadable");
          return new Map([
            ["0xabc", { answer: "on" as const, generation: 7, receivedAt: 1 }],
          ]);
        },
        save: async () => {},
      },
      onWarning: () => {
        throw new Error("sink broke");
      },
    });
    await expect(authority.ready).resolves.toBeUndefined();
    expect(authority.read(OWNER).kind).toBe("refuse");
    const next = await authority.submitEvidence({
      owner: OWNER,
      state: "on",
      generation: 8,
    });
    expect(next.kind).not.toBe("refuse");
    expect(loads).toBe(2);
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

  describe("an answer that arrives while the records will not load", () => {
    const UNKNOWN = {
      kind: "refuse",
      code: "ACCOUNT_MODE_UNKNOWN",
      status: 503,
    };

    /** A store that fails its first `failures` loads, then holds a saved Off. */
    function offStoreFailing(failures: number) {
      const durable = new Map([
        ["0xabc", { answer: "off" as const, generation: 0, receivedAt: 1 }],
      ]);
      const saves: unknown[] = [];
      let loads = 0;
      const store: ModeRecordStore = {
        load: async () => {
          loads += 1;
          if (loads <= failures) throw new Error("unreadable");
          return durable;
        },
        save: async (_owner, record) => {
          saves.push(record);
        },
      };
      return { store, saves, loads: () => loads };
    }

    it("lets a later load of the saved Off restore legacy writes when only an Off and a failed read arrived", async () => {
      // Startup load fails, the reload for the Off fails, the reload for the
      // failed read succeeds. No save was attempted, so nothing was lost.
      const { store, saves, loads } = offStoreFailing(2);
      const authority = createModeAuthority({ store, onWarning: () => {} });
      await authority.ready;
      expect(
        (await authority.submitEvidence({ owner: OWNER, state: "off" })).kind,
      ).toBe("refuse");
      expect(loads()).toBe(2);
      expect(await authority.commitLegacy(OWNER, () => 1)).toMatchObject({
        ok: false,
        decision: { status: 503 },
      });

      expect(
        await authority.submitEvidence({ owner: OWNER, state: "unknown" }),
      ).toEqual({ kind: "legacy" });
      expect(loads()).toBe(3);
      expect(authority.legacyWriteDecision(OWNER)).toEqual({ kind: "legacy" });
      expect(await authority.commitLegacy(OWNER, () => 2)).toEqual({
        ok: true,
        value: 2,
      });
      expect(saves).toEqual([]);
    });

    it("applies an On answered while the records would not load once they load: the owner is switched, as with a readable store", async () => {
      const { store, saves } = offStoreFailing(2);
      const onOn: string[] = [];
      const authority = createModeAuthority({
        store,
        onWarning: () => {},
        onOn: (owner) => onOn.push(owner),
      });
      await authority.ready;
      expect(
        (await authority.submitEvidence({ owner: OWNER, state: "on" })).kind,
      ).toBe("refuse");
      expect(authority.legacyWriteDecision(OWNER)).toEqual(UNKNOWN);

      // The saved Off loads; the held On is judged against it and latches.
      expect(
        await authority.submitEvidence({ owner: OWNER, state: "unknown" }),
      ).toEqual({ kind: "streams" });
      expect(authority.read(OWNER)).toEqual({ kind: "streams" });
      expect(saves).toEqual([expect.objectContaining({ answer: "on" })]);
      expect(onOn).toEqual(["0xabc"]);
      expect(await authority.commitLegacy(OWNER, () => 1)).toMatchObject({
        ok: false,
        decision: { status: 426 },
      });

      // On latches: a later Off at the same generation changes nothing.
      expect(
        await authority.submitEvidence({ owner: OWNER, state: "off" }),
      ).toEqual({ kind: "streams" });
      expect(authority.read(OWNER)).toEqual({ kind: "streams" });
    });

    it("judges an Off held after an On against that On, not on its own", async () => {
      const { store } = offStoreFailing(3);
      const authority = createModeAuthority({ store, onWarning: () => {} });
      await authority.ready;
      await authority.submitEvidence({ owner: OWNER, state: "on" });
      await authority.submitEvidence({ owner: OWNER, state: "off" });
      // The third load succeeds here, on a failed read: the On latched.
      await authority.submitEvidence({ owner: OWNER, state: "unknown" });
      expect(authority.read(OWNER)).toEqual({ kind: "streams" });
      expect(authority.legacyWriteDecision(OWNER)).toEqual({
        kind: "streams",
      });
    });
    describe("an Off answered while the records would not load is judged when they do", () => {
      // Invariant: for any sequence of answers and failed loads, the
      // permission once the store is readable again equals the permission the
      // same answers give with the store readable throughout, or is stricter.
      function offAtGenerationTwo(failures: number) {
        const durable = new Map([
          ["0xabc", { answer: "off" as const, generation: 2, receivedAt: 1 }],
        ]);
        const saves: unknown[] = [];
        let loads = 0;
        const store: ModeRecordStore = {
          load: async () => {
            loads += 1;
            if (loads <= failures) throw new Error("unreadable");
            return new Map(durable);
          },
          save: async (_owner, record) => {
            saves.push(record);
            durable.set("0xabc", record as never);
          },
        };
        return { store, saves };
      }

      it("withdraws for a generation 1 Off older than the saved generation 2 Off", async () => {
        const { store, saves } = offAtGenerationTwo(2);
        const authority = createModeAuthority({ store, onWarning: () => {} });
        await authority.ready;
        await authority.submitEvidence({
          owner: OWNER,
          state: "off",
          generation: 1,
        });
        expect(
          await authority.submitEvidence({ owner: OWNER, state: "unknown" }),
        ).toEqual(UNKNOWN);
        expect(authority.legacyWriteDecision(OWNER)).toEqual(UNKNOWN);
        expect(await authority.commitLegacy(OWNER, () => 1)).toMatchObject({
          ok: false,
          decision: { status: 503 },
        });
        expect(saves).toEqual([]);
      });

      it("lifts and saves for a generation 3 Off newer than the saved generation 2 Off", async () => {
        const { store, saves } = offAtGenerationTwo(2);
        const authority = createModeAuthority({ store, onWarning: () => {} });
        await authority.ready;
        await authority.submitEvidence({
          owner: OWNER,
          state: "off",
          generation: 3,
        });
        expect(
          await authority.submitEvidence({ owner: OWNER, state: "unknown" }),
        ).toEqual({ kind: "legacy" });
        expect(saves).toEqual([
          expect.objectContaining({ answer: "off", generation: 3 }),
        ]);
        expect(await authority.commitLegacy(OWNER, () => 2)).toEqual({
          ok: true,
          value: 2,
        });
      });

      it("judges every held Off in order: an older one given while unreadable does not decide, a newer one does", async () => {
        const { store } = offAtGenerationTwo(3);
        const authority = createModeAuthority({ store, onWarning: () => {} });
        await authority.ready;
        await authority.submitEvidence({
          owner: OWNER,
          state: "off",
          generation: 1,
        });
        await authority.submitEvidence({
          owner: OWNER,
          state: "off",
          generation: 3,
        });
        expect(
          await authority.submitEvidence({ owner: OWNER, state: "unknown" }),
        ).toEqual({ kind: "legacy" });
      });

      it("withdraws for the stale Off when the load recovers on the next answer, not a failed read", async () => {
        const { store } = offAtGenerationTwo(2);
        const authority = createModeAuthority({ store, onWarning: () => {} });
        await authority.ready;
        await authority.submitEvidence({
          owner: OWNER,
          state: "off",
          generation: 1,
        });
        // Recovers here; this Off is also older than the record.
        await authority.submitEvidence({
          owner: OWNER,
          state: "off",
          generation: 0,
        });
        expect(authority.legacyWriteDecision(OWNER)).toEqual(UNKNOWN);
      });
    });
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

describe("answers given while the records will not load, against a model of the readable store", () => {
  // The oracle: the answers applied in arrival order with the store readable
  // throughout. `applyAnswer` decides each owner's record. An answer lifts the
  // write permission when it is not older than the record it produced,
  // withdraws it otherwise, and withdraws it when its save fails (the record
  // stays). The permission is a saved Off that is not withdrawn. Each answer
  // is one save attempt: nothing is retried. Nothing else matters: no load, no
  // buffer, no lock.
  //
  // The contract, for every sequence of answers (of several owners, arriving
  // interleaved), failed loads, failed saves (counted over every save the
  // store sees, whichever the owner and whatever the record) and restarts at
  // any step, with backlogs of any length:
  // - The permission is never wider than the oracle's, and equals it when no
  //   save fails and the process has read the store.
  // - A submission returns the decision a legacy write then meets.
  // - An On the process applies, live or replayed after the store loads,
  //   notifies `onOn` for its owner.
  // - A restart loses an answer the process held because the store never
  //   loaded: no process could keep it (the registry refuses legacy writes
  //   once the owner is On, see the header of `authority.ts`). The oracle is
  //   not given an answer that was lost.
  interface Model {
    record: AccountModeRecord | undefined;
    withdrawn: boolean;
    /** The latest answer's save failed: it was rejected, not applied. */
    failed: boolean;
  }
  interface Answer {
    state: ModeAnswer;
    generation: number;
    /** Absent means `OWNER`. */
    owner?: string;
  }
  /** The owners a scenario can use: the store keeps them apart by this key. */
  const OWNERS = [OWNER, "0xDeF", "0x123"];
  const keyOf = (owner: string) => owner.trim().toLowerCase();
  const ownerOf = (a: { owner?: string }) => a.owner ?? OWNER;

  /**
   * Which save attempts fail. Attempts are counted over every save the store
   * sees, from 1: the oracle and the implementation each run the same schedule
   * from the start, so a retry or a replay that makes a different attempt
   * meets a different outcome.
   */
  type Failures =
    | { kind: "none" }
    /** The first `count` attempts fail, then every attempt saves. */
    | { kind: "first"; count: number }
    /** Exactly these attempts fail (numbered from 1). */
    | { kind: "at"; attempts: number[] }
    /** Each of the first 40 attempts fails with chance `rate`. */
    | { kind: "random"; rate: number; salt: number };

  function failsAt(failures: Failures, attempt: number): boolean {
    if (failures.kind === "none") return false;
    if (failures.kind === "first") return attempt <= failures.count;
    if (failures.kind === "at") return failures.attempts.includes(attempt);
    if (attempt > 40) return false;
    return generator(failures.salt * 100 + attempt).next() < failures.rate;
  }

  /** One schedule's counter: each call is the next save attempt. */
  function attemptCounter(failures: Failures) {
    let attempts = 0;
    return (): boolean => failsAt(failures, (attempts += 1));
  }

  function modelAnswer(
    model: Model,
    answer: Answer,
    saveFails: () => boolean,
  ): Model {
    const next = applyAnswer(model.record, answer.state, answer.generation, 0);
    if (next !== model.record && saveFails()) {
      return { record: model.record, withdrawn: true, failed: true };
    }
    return {
      record: next,
      withdrawn: !(answer.generation >= next.generation),
      failed: false,
    };
  }

  type LogEntry =
    { kind: "answer"; answer: Answer; lost: boolean } | { kind: "restart" };

  /** The record saved for `owner` before the scenario starts. */
  function savedFor(scenario: Scenario, owner: string) {
    return keyOf(owner) === keyOf(OWNER)
      ? scenario.saved
      : scenario.savedOthers?.[keyOf(owner)];
  }

  /** The oracle's owners after the first `upTo` log entries: pure, from the start. */
  function readableStore(
    scenario: Scenario,
    log: LogEntry[],
    upTo = log.length,
  ): Map<string, Model> {
    const saveFails = attemptCounter(scenario.failures);
    const models = new Map<string, Model>(
      OWNERS.map((o) => [
        keyOf(o),
        { record: savedFor(scenario, o), withdrawn: false, failed: false },
      ]),
    );
    for (const entry of log.slice(0, upTo)) {
      if (entry.kind === "restart") {
        for (const [o, m] of models) {
          models.set(o, { record: m.record, withdrawn: false, failed: false });
        }
      } else if (!entry.lost) {
        const o = keyOf(ownerOf(entry.answer));
        models.set(o, modelAnswer(models.get(o)!, entry.answer, saveFails));
      }
    }
    return models;
  }

  const modelAllows = (m: Model) => m.record?.answer === "off" && !m.withdrawn;
  const modelRead = (m: Model) =>
    m.record ? (m.record.answer === "on" ? "streams" : "legacy") : "refuse";
  const modelWrite = (m: Model) =>
    m.record?.answer === "on"
      ? "streams"
      : modelAllows(m)
        ? "legacy"
        : "refuse";

  type Step =
    /**
     * `sequential`: one submission after another is awaited, as polls are;
     * otherwise they are all submitted at once.
     */
    | { kind: "answers"; answers: Answer[]; sequential?: boolean }
    | { kind: "unknown"; owner?: string }
    | { kind: "readable"; readable: boolean }
    /**
     * The process restarts, at any step: held, withdrawn or settled. The new
     * process reads the store as it is.
     */
    | { kind: "restart" };

  interface Scenario {
    /** The record saved for `OWNER`. */
    saved: AccountModeRecord | undefined;
    /** The records saved for the other owners, by lower-case owner. */
    savedOthers?: Record<string, AccountModeRecord>;
    readable: boolean;
    failures: Failures;
    steps: Step[];
  }

  const same = (a: unknown, b: unknown) =>
    JSON.stringify(a) === JSON.stringify(b);

  /** Run one scenario; return what went wrong, or null. */
  async function check(scenario: Scenario): Promise<string | null> {
    const noFailures = scenario.failures.kind === "none";
    const saveFails = attemptCounter(scenario.failures);
    const durable = new Map<string, AccountModeRecord>();
    for (const o of OWNERS) {
      const saved = savedFor(scenario, o);
      if (saved) durable.set(keyOf(o), saved);
    }
    let readable = scenario.readable;
    const created: { authority?: ModeAuthority } = {};
    const admittedDuringSave: string[] = [];
    const wakeups = new Map<string, number>();
    const store: ModeRecordStore = {
      load: async () => {
        if (!readable) throw new Error("unreadable");
        return new Map(durable);
      },
      save: async (owner, record) => {
        // A judged answer is not applied until its save settles: nothing may
        // admit a legacy write for its owner meanwhile.
        for (let i = 0; i < 3; i += 1) {
          if (created.authority?.legacyWriteDecision(owner).kind === "legacy") {
            admittedDuringSave.push(
              `${owner}:${record.answer}:${record.generation}`,
            );
          }
          await Promise.resolve();
        }
        if (saveFails()) throw new Error("save failed");
        durable.set(owner, record);
      },
    };
    const boot = async () => {
      const authority = createModeAuthority({
        store,
        onWarning: () => {},
        onOn: (owner) => {
          wakeups.set(keyOf(owner), (wakeups.get(keyOf(owner)) ?? 0) + 1);
        },
      });
      created.authority = authority;
      await authority.ready;
      return authority;
    };
    let authority = await boot();

    const log: LogEntry[] = [];
    /** Whether this process has read the store, and what it holds until then. */
    let loaded = readable;
    let held: Array<Extract<LogEntry, { kind: "answer" }>> = [];
    const names: string[] = [];
    const submit = (a: Answer) =>
      authority.submitEvidence({
        owner: ownerOf(a),
        state: a.state,
        generation: a.generation,
      });
    for (const [index, step] of scenario.steps.entries()) {
      /** What each owner's last submission in this step returned. */
      const returned = new Map<string, ModeDecision>();
      const wakeupsBefore = new Map(wakeups);
      /** Log positions of the answers this step makes the process apply. */
      let replayed: number[] = [];
      const reachStore = (entries: Array<(typeof held)[number]>) => {
        if (loaded) return;
        if (readable) {
          replayed = held.map((entry) => log.indexOf(entry));
          loaded = true;
          held = [];
        } else held.push(...entries);
      };
      if (step.kind === "readable") {
        readable = step.readable;
        names.push(`store ${readable ? "readable" : "unreadable"}`);
        continue;
      }
      if (step.kind === "restart") {
        for (const entry of held) entry.lost = true;
        held = [];
        log.push({ kind: "restart" });
        authority = await boot();
        loaded = readable;
        names.push("restart");
      } else if (step.kind === "unknown") {
        reachStore([]);
        const owner = step.owner ?? OWNER;
        returned.set(
          keyOf(owner),
          await authority.submitEvidence({ owner, state: "unknown" }),
        );
        names.push(`failed read ${keyOf(owner)}`);
      } else {
        const entries = step.answers.map((answer) => ({
          kind: "answer" as const,
          answer,
          lost: false,
        }));
        log.push(...entries);
        reachStore(entries);
        let results: PromiseSettledResult<ModeDecision>[];
        if (step.sequential) {
          results = [];
          for (const a of step.answers) {
            results.push(...(await Promise.allSettled([submit(a)])));
          }
        } else results = await Promise.allSettled(step.answers.map(submit));
        // A save that fails rejects the submission: nothing to wake for.
        for (const [i, result] of results.entries()) {
          const owner = keyOf(ownerOf(step.answers[i]!));
          if (result.status === "fulfilled") returned.set(owner, result.value);
          else returned.delete(owner);
        }
        for (const a of step.answers) {
          names.push(`${keyOf(ownerOf(a))}:${a.state}@${a.generation}`);
        }
      }

      const where = `after step ${index} [${names.length > 40 ? `… ${names.slice(-40).join(" ")}` : names.join(" ")}]`;
      const models = readableStore(scenario, log);
      for (const o of OWNERS) {
        const model = models.get(keyOf(o))!;
        const decision = authority.legacyWriteDecision(o);
        const allowed = decision.kind === "legacy";
        if (allowed && !modelAllows(model)) {
          return `${where}: ${keyOf(o)}: legacy writes allowed, the readable store withdraws`;
        }
        if (noFailures && loaded) {
          if (decision.kind !== modelWrite(model)) {
            return `${where}: ${keyOf(o)}: store loaded, write decision ${decision.kind}, readable store ${modelWrite(model)}`;
          }
          if (authority.read(o).kind !== modelRead(model)) {
            return `${where}: ${keyOf(o)}: store loaded, read ${authority.read(o).kind}, readable store ${modelRead(model)}`;
          }
        }
        const answered = returned.get(keyOf(o));
        if (answered !== undefined && !same(answered, decision)) {
          return `${where}: ${keyOf(o)}: the submission returned ${JSON.stringify(answered)}, a legacy write meets ${JSON.stringify(decision)}`;
        }
        const wrote = await authority.commitLegacy(o, () => "wrote");
        const met = wrote.ok
          ? "legacy"
          : wrote.decision.status === 426
            ? "streams"
            : "refuse";
        if (met !== decision.kind) {
          return `${where}: ${keyOf(o)}: decision ${decision.kind}, the write met ${met}`;
        }
        if (
          answered !== undefined &&
          decision.kind === "streams" &&
          (wakeups.get(keyOf(o)) ?? 0) === (wakeupsBefore.get(keyOf(o)) ?? 0)
        ) {
          return `${where}: ${keyOf(o)} is On and the import was not woken`;
        }
      }
      for (const position of replayed) {
        const entry = log[position] as Extract<LogEntry, { kind: "answer" }>;
        const o = keyOf(ownerOf(entry.answer));
        const afterIt = readableStore(scenario, log, position + 1).get(o)!;
        if (
          afterIt.record?.answer === "on" &&
          !afterIt.failed &&
          (wakeups.get(o) ?? 0) === (wakeupsBefore.get(o) ?? 0)
        ) {
          return `${where}: a replayed On of ${o} did not wake the import`;
        }
      }
      if (admittedDuringSave.length > 0) {
        return `${where}: legacy writes admitted while ${admittedDuringSave[0]} was unsaved`;
      }
    }
    return null;
  }

  async function shrink(scenario: Scenario): Promise<Scenario> {
    let best = scenario;
    const onlyFirstOwner = (s: Scenario): Scenario => ({
      ...s,
      steps: s.steps.map((step) =>
        step.kind === "answers"
          ? {
              ...step,
              answers: step.answers.map(({ owner: _, ...rest }) => rest),
            }
          : step.kind === "unknown"
            ? { kind: "unknown" }
            : step,
      ),
    });
    for (let progress = true; progress;) {
      progress = false;
      const candidates: Scenario[] = [];
      const single = onlyFirstOwner(best);
      // Only a change is progress: a scenario already of one owner is not.
      if (!same(single, best)) candidates.push(single);
      for (let i = 0; i < best.steps.length; i += 1) {
        candidates.push({
          ...best,
          steps: best.steps.filter((_, j) => j !== i),
        });
        const step = best.steps[i]!;
        if (step.kind === "answers" && step.answers.length > 1) {
          const without = (from: number, to: number): Scenario => ({
            ...best,
            steps: best.steps.map((s, j) =>
              j === i
                ? {
                    ...step,
                    answers: step.answers.filter((_, m) => m < from || m >= to),
                  }
                : s,
            ),
          });
          // Chunks first, so a long backlog shrinks in a few rounds.
          for (let chunk = step.answers.length >> 1; chunk > 1; chunk >>= 1) {
            for (let from = 0; from < step.answers.length; from += chunk) {
              candidates.push(without(from, from + chunk));
            }
          }
          for (let k = 0; k < step.answers.length; k += 1) {
            candidates.push(without(k, k + 1));
          }
        }
      }
      if (best.failures.kind === "first" && best.failures.count > 1) {
        candidates.push({
          ...best,
          failures: { kind: "first", count: best.failures.count - 1 },
        });
      }
      if (best.failures.kind === "at" && best.failures.attempts.length > 1) {
        for (let k = 0; k < best.failures.attempts.length; k += 1) {
          candidates.push({
            ...best,
            failures: {
              kind: "at",
              attempts: best.failures.attempts.filter((_, m) => m !== k),
            },
          });
        }
      }
      for (const candidate of candidates) {
        if ((await check(candidate)) !== null) {
          best = candidate;
          progress = true;
          break;
        }
      }
    }
    return best;
  }

  /** A seeded generator (mulberry32): the run is the same every time. */
  function generator(seed: number) {
    let a = seed >>> 0;
    const next = () => {
      a = (a + 0x6d2b79f5) >>> 0;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const int = (n: number) => Math.floor(next() * n);
    return { next, int };
  }

  /**
   * The most different answers in a row the implementation once held per owner
   * before it dropped some. The generator goes past it, whatever the code now
   * does, so a bound that drops answers is caught again.
   */
  const FORMER_BACKLOG_BOUND = 64;

  function scenarioFrom(seed: number): Scenario {
    const { next, int } = generator(seed);
    const owners = OWNERS.slice(0, 1 + int(OWNERS.length));
    const answer = (): Answer => ({
      state: next() < 0.55 ? "off" : "on",
      generation: int(4),
      owner: owners[int(owners.length)],
    });
    let failures: Failures = { kind: "none" };
    const mode = next();
    if (mode >= 0.2 && mode < 0.5) {
      failures = { kind: "first", count: 1 + int(6) };
    } else if (mode >= 0.5 && mode < 0.7) {
      failures = {
        kind: "at",
        attempts: Array.from({ length: 1 + int(3) }, () => 1 + int(8)),
      };
    } else if (mode >= 0.7) {
      failures = {
        kind: "random",
        rate: [0.2, 0.5, 0.8][int(3)]!,
        salt: int(1_000_000),
      };
    }
    const steps: Step[] = [];
    const small = (): Step => {
      const r = next();
      if (r < 0.45) return { kind: "answers", answers: [answer()] };
      if (r < 0.55) {
        return {
          kind: "answers",
          answers: Array.from({ length: 2 + int(2) }, answer),
        };
      }
      if (r < 0.67)
        return { kind: "unknown", owner: owners[int(owners.length)] };
      if (r < 0.82) return { kind: "readable", readable: next() < 0.5 };
      return { kind: "restart" };
    };
    // A third of the scenarios hold a backlog past the former bound: polls
    // that bring a different answer each time while the store will not load,
    // with the small steps (a restart, a failed read, a recovery) between.
    const backlog = next() < 0.33;
    if (backlog) {
      // Generations climb through the backlog, so most answers are save
      // attempts and the failures land on them.
      let climb = 0;
      const burst = (length: number): Step => ({
        kind: "answers",
        sequential: true,
        answers: Array.from({ length }, () => {
          climb += next() < 0.25 ? 1 : 0;
          return {
            state: next() < 0.5 ? "off" : "on",
            generation: climb + int(2),
            owner: owners[int(owners.length)],
          };
        }),
      });
      const total = FORMER_BACKLOG_BOUND + 1 + int(60);
      const parts = 1 + int(3);
      for (let part = 0; part < parts; part += 1) {
        steps.push(burst(Math.ceil(total / parts)));
        if (next() < 0.6) steps.push(small());
      }
      for (let n = int(5); n > 0; n -= 1) steps.push(small());
    } else {
      for (let n = 2 + int(12); n > 0; n -= 1) steps.push(small());
    }
    const savedRecord = (): AccountModeRecord | undefined =>
      next() < 0.3
        ? undefined
        : {
            answer: next() < 0.7 ? "off" : "on",
            generation: int(4),
            receivedAt: 1,
          };
    const saved = savedRecord();
    const savedOthers: Record<string, AccountModeRecord> = {};
    for (const o of OWNERS.slice(1)) {
      const record = savedRecord();
      if (record) savedOthers[keyOf(o)] = record;
    }
    return {
      saved,
      savedOthers,
      readable: backlog ? next() < 0.05 : next() < 0.15,
      failures,
      steps,
    };
  }

  const SEED = Number(process.env.ACCOUNT_MODE_PROPERTY_SEED ?? 20261120);
  const RUNS = Number(process.env.ACCOUNT_MODE_PROPERTY_RUNS ?? 20000);

  it(`never allows more than the readable store, for owners interleaved and backlogs of any length, through failed loads, failed saves and restarts at any step, matches it when no save fails, returns what a write meets, and wakes the import for every On (${RUNS} scenarios, seed ${SEED})`, async () => {
    for (let run = 0; run < RUNS; run += 1) {
      const scenario = scenarioFrom(SEED + run);
      const problem = await check(scenario);
      if (problem !== null) {
        const small = await shrink(scenario);
        throw new Error(
          `seed ${SEED + run}: ${problem}\nsmallest scenario: ${JSON.stringify(small)}\nits failure: ${await check(small)}`,
        );
      }
    }
  }, 3_600_000);

  describe("the sequences Codex found on the merged head (e7dbf40c) and on #845 (93d3aca5)", () => {
    // #845 P1 (replay by owner): A On at 1, B On at 1, then A Off at 2, with
    // the store's third save failing. The readable store keeps A On (its Off
    // is the failed save). Recovery that applied A's answers before B's spent
    // the third save on B's On, saved A's Off, and let A write legacy data.
    it("#845 P1: the store's saves are spent in the order the answers arrived, not owner by owner", async () => {
      expect(
        await check({
          saved: { answer: "off", generation: 0, receivedAt: 1 },
          savedOthers: {
            "0xdef": { answer: "off", generation: 0, receivedAt: 1 },
          },
          readable: false,
          failures: { kind: "at", attempts: [3] },
          steps: [
            {
              kind: "answers",
              sequential: true,
              answers: [
                { state: "on", generation: 1 },
                { state: "on", generation: 1, owner: "0xDeF" },
                { state: "off", generation: 2 },
              ],
            },
            { kind: "readable", readable: true },
            { kind: "unknown" },
            { kind: "unknown", owner: "0xDeF" },
          ],
        }),
      ).toBeNull();
    });

    // #845 P1 (compaction): the first save fails on Off at 1, the second saves
    // On at 1, and more than the former bound of different answers follow. A
    // backlog reduced to the On spent the failed save on it, left the owner
    // Off, and let a fresh Off at 1 write legacy data, or, after a restart,
    // the saved Off do so.
    describe("#845 P1: a backlog past the former bound keeps the save a failed Off absorbed", () => {
      const backlog = (): Step => ({
        kind: "answers",
        sequential: true,
        answers: [
          { state: "off", generation: 1 },
          { state: "on", generation: 1 },
          ...Array.from({ length: FORMER_BACKLOG_BOUND + 6 }, (_, i) => ({
            state: "off" as const,
            generation: i % 2,
          })),
        ],
      });
      const scenario = (after: Step[]): Scenario => ({
        saved: { answer: "off", generation: 0, receivedAt: 1 },
        readable: false,
        failures: { kind: "first", count: 1 },
        steps: [
          backlog(),
          { kind: "readable", readable: true },
          { kind: "unknown" },
          ...after,
        ],
      });
      it("so a fresh Off at the same generation does not lift the On", async () => {
        expect(
          await check(
            scenario([
              { kind: "answers", answers: [{ state: "off", generation: 1 }] },
            ]),
          ),
        ).toBeNull();
      });
      it("so the saved record after a restart is the On the readable store saved", async () => {
        expect(await check(scenario([{ kind: "restart" }]))).toBeNull();
      });
    });

    // P1: saved On at generation 0; the store will not load while On at
    // generation 1 and Off at generation 2 arrive; the first two saves fail.
    // The readable store spends them on the On and the Off and keeps the saved
    // On. A replay that spent both on the On saved both answers on later polls
    // and let legacy writes run without a fresh answer.
    it("P1: the saves the readable store spends on the On and the Off are spent on them at recovery too", async () => {
      expect(
        await check({
          saved: { answer: "on", generation: 0, receivedAt: 1 },
          readable: false,
          failures: { kind: "first", count: 2 },
          steps: [
            { kind: "answers", answers: [{ state: "on", generation: 1 }] },
            { kind: "answers", answers: [{ state: "off", generation: 2 }] },
            { kind: "readable", readable: true },
            { kind: "unknown" },
            { kind: "unknown" },
            { kind: "unknown" },
          ],
        }),
      ).toBeNull();
    });

    // P2: a submission that recovered the store returned `read` before the
    // replay settled: `legacy` while writes met 503, and no `onOn` for an On.
    it("P2: a submission that recovers the store returns the decision writes meet", async () => {
      expect(
        await check({
          saved: { answer: "off", generation: 1, receivedAt: 1 },
          readable: false,
          failures: { kind: "first", count: 1 },
          steps: [
            { kind: "answers", answers: [{ state: "off", generation: 3 }] },
            { kind: "readable", readable: true },
            { kind: "answers", answers: [{ state: "off", generation: 3 }] },
          ],
        }),
      ).toBeNull();
    });

    it("P2: a submission that recovers the store wakes the import for the On it replays", async () => {
      expect(
        await check({
          saved: { answer: "off", generation: 0, receivedAt: 1 },
          readable: false,
          failures: { kind: "none" },
          steps: [
            { kind: "answers", answers: [{ state: "on", generation: 1 }] },
            { kind: "readable", readable: true },
            { kind: "answers", answers: [{ state: "on", generation: 1 }] },
          ],
        }),
      ).toBeNull();
    });
  });

  it("wakes the import for an owner whose On is replayed by another owner's submission", async () => {
    const [A, B] = ["0xaaa", "0xbbb"];
    const durable = new Map<string, AccountModeRecord>([
      [A, { answer: "off", generation: 0, receivedAt: 1 }],
    ]);
    let readable = false;
    const woken: string[] = [];
    const authority = createModeAuthority({
      store: {
        load: async () => {
          if (!readable) throw new Error("unreadable");
          return new Map(durable);
        },
        save: async (owner, record) => {
          durable.set(owner, record);
        },
      },
      onWarning: () => {},
      onOn: (owner) => woken.push(owner),
    });
    await authority.ready;
    await authority.submitEvidence({ owner: A, state: "on", generation: 1 });
    expect(woken).toEqual([]);
    readable = true;
    await authority.submitEvidence({ owner: B, state: "unknown" });
    expect(woken).toEqual([A]);
    expect(authority.legacyWriteDecision(A)).toEqual({ kind: "streams" });
  });

  describe("the held answers are runs, however many polls arrive", () => {
    const saveKey = (state: ModeAnswer, generation: number) =>
      `${state}:${generation}`;
    function unreadableThenReadable(
      saved: AccountModeRecord = {
        answer: "off",
        generation: 0,
        receivedAt: 1,
      },
    ) {
      const durable = new Map([["0xabc", saved]]);
      let readable = false;
      const failFirst = new Map<string, number>();
      const attempts = new Map<string, number>();
      const store: ModeRecordStore = {
        load: async () => {
          if (!readable) throw new Error("unreadable");
          return new Map(durable);
        },
        save: async (owner, record) => {
          const key = saveKey(record.answer, record.generation);
          const n = (attempts.get(key) ?? 0) + 1;
          attempts.set(key, n);
          if (n <= (failFirst.get(key) ?? 0)) throw new Error("save failed");
          durable.set(owner, record);
        },
      };
      return {
        store,
        durable,
        failFirst: (state: ModeAnswer, generation: number, times: number) =>
          failFirst.set(saveKey(state, generation), times),
        recover: () => {
          readable = true;
        },
      };
    }

    it("holds no backlog for a poll that repeats, and keeps the permission", async () => {
      const { store, recover } = unreadableThenReadable();
      const authority = createModeAuthority({ store, onWarning: () => {} });
      await authority.ready;
      for (let i = 0; i < 5000; i += 1) {
        await authority.submitEvidence({ owner: OWNER, state: "off" });
      }
      recover();
      expect(
        await authority.submitEvidence({ owner: OWNER, state: "unknown" }),
      ).toEqual({ kind: "legacy" });
    });

    it("applies many different answers in arrival order, as the readable store would: the highest generation's Off wins", async () => {
      const { store, durable, recover } = unreadableThenReadable();
      const authority = createModeAuthority({ store, onWarning: () => {} });
      await authority.ready;
      for (let i = 0; i < 40; i += 1) {
        await authority.submitEvidence({
          owner: OWNER,
          state: "off",
          generation: 1 + (i % 2),
        });
      }
      recover();
      expect(
        await authority.submitEvidence({ owner: OWNER, state: "unknown" }),
      ).toEqual({ kind: "legacy" });
      expect(durable.get("0xabc")).toMatchObject({
        answer: "off",
        generation: 2,
      });
    });

    it("applies a backlog of any length in arrival order, as the readable store would", async () => {
      const { store, durable, recover } = unreadableThenReadable();
      const authority = createModeAuthority({ store, onWarning: () => {} });
      await authority.ready;
      for (let i = 0; i < 1100; i += 1) {
        await authority.submitEvidence({
          owner: OWNER,
          state: "off",
          generation: 1 + (i % 2),
        });
      }
      recover();
      // Every answer is applied: the Off at generation 2 stands.
      expect(
        await authority.submitEvidence({ owner: OWNER, state: "unknown" }),
      ).toEqual({ kind: "legacy" });
      expect(durable.get("0xabc")).toMatchObject({
        answer: "off",
        generation: 2,
      });
    });

    // Codex round 5, P1: coalescing dropped the second On. The readable store
    // spends one save attempt on each answer: the first On fails, the second
    // saves, the Off changes nothing.
    it("spends each held answer's save attempt as the readable store does (On, On, Off at one generation)", async () => {
      const { store, durable, failFirst, recover } = unreadableThenReadable({
        answer: "off",
        generation: 1,
        receivedAt: 1,
      });
      failFirst("on", 1, 1);
      const authority = createModeAuthority({ store, onWarning: () => {} });
      await authority.ready;
      for (const state of ["on", "on", "off"] as const) {
        await authority.submitEvidence({ owner: OWNER, state, generation: 1 });
      }
      recover();
      // One poll applies all three: the Off cannot lift past the On.
      expect(
        await authority.submitEvidence({ owner: OWNER, state: "unknown" }),
      ).toEqual({ kind: "streams" });
      expect(durable.get("0xabc")).toMatchObject({
        answer: "on",
        generation: 1,
      });
      expect(await authority.commitLegacy(OWNER, () => 1)).toMatchObject({
        ok: false,
        decision: { status: 426 },
      });
    });

    // Codex round 5, P2: the bound evicted the only On.
    it("keeps the only On however many answers follow it, and it still holds after a restart", async () => {
      const { store, durable, recover } = unreadableThenReadable({
        answer: "off",
        generation: 5,
        receivedAt: 1,
      });
      const authority = createModeAuthority({ store, onWarning: () => {} });
      await authority.ready;
      await authority.submitEvidence({
        owner: OWNER,
        state: "on",
        generation: 5,
      });
      for (let i = 0; i < 1100; i += 1) {
        await authority.submitEvidence({
          owner: OWNER,
          state: "off",
          generation: 1 + (i % 2),
        });
      }
      await authority.submitEvidence({
        owner: OWNER,
        state: "off",
        generation: 5,
      });
      recover();
      await authority.submitEvidence({ owner: OWNER, state: "unknown" });
      expect(authority.read(OWNER)).toEqual({ kind: "streams" });
      expect(authority.legacyWriteDecision(OWNER).kind).toBe("streams");
      const restarted = createModeAuthority({ store, onWarning: () => {} });
      await restarted.ready;
      expect(durable.get("0xabc")).toMatchObject({
        answer: "on",
        generation: 5,
      });
      expect(restarted.legacyWriteDecision(OWNER).kind).toBe("streams");
    });
  });

  // The two counterexamples the review found, fixed in place.
  it("withdraws for an Off at generation 2 after an Off at generation 3 while the store would not load", async () => {
    const saved = { answer: "off" as const, generation: 1, receivedAt: 1 };
    const scenario: Scenario = {
      saved,
      readable: false,
      failures: { kind: "none" },
      steps: [
        { kind: "answers", answers: [{ state: "off", generation: 3 }] },
        { kind: "answers", answers: [{ state: "off", generation: 2 }] },
        { kind: "readable", readable: true },
        { kind: "unknown" },
      ],
    };
    expect(await check(scenario)).toBeNull();
  });

  it("keeps the owner unadmitted while a remembered answer's save is pending, and after it fails", async () => {
    const durable = new Map([
      ["0xabc", { answer: "off" as const, generation: 1, receivedAt: 1 }],
    ]);
    let readable = false;
    const gate = deferred();
    const store: ModeRecordStore = {
      load: async () => {
        if (!readable) throw new Error("unreadable");
        return new Map(durable);
      },
      save: async () => {
        await gate.promise;
        throw new Error("save failed");
      },
    };
    const authority = createModeAuthority({ store, onWarning: () => {} });
    await authority.ready;
    await authority.submitEvidence({
      owner: OWNER,
      state: "off",
      generation: 3,
    });
    readable = true;
    const recovery = authority.submitEvidence({
      owner: OWNER,
      state: "unknown",
    });
    await new Promise((r) => setTimeout(r, 10));
    // The Off at generation 3 is judged and its save is blocked.
    expect(authority.legacyWriteDecision(OWNER).kind).toBe("refuse");
    gate.resolve();
    await recovery;
    expect(authority.legacyWriteDecision(OWNER).kind).toBe("refuse");
    expect(await authority.commitLegacy(OWNER, () => 1)).toMatchObject({
      ok: false,
      decision: { status: 503 },
    });
  });
});
