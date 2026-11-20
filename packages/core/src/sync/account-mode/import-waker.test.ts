import { describe, expect, it } from "vitest";
import { createModeAuthority } from "./authority.js";
import { createImportWaker, type ImportRunner } from "./import-waker.js";
import { createMemoryModeRecordStore, type ModeRecordStore } from "./record.js";

const OWNER = "0xabc";

function recorder(behaviour?: (signal: AbortSignal) => Promise<void>) {
  const signals: AbortSignal[] = [];
  const importer: ImportRunner = {
    run: async (signal) => {
      signals.push(signal);
      await behaviour?.(signal);
    },
  };
  return { importer, signals };
}

function aborted(signal: AbortSignal): Promise<void> {
  return new Promise((resolve) =>
    signal.addEventListener("abort", () => resolve()),
  );
}

async function authorityWith(answer?: "on" | "off") {
  const authority = createModeAuthority({
    store: createMemoryModeRecordStore(),
  });
  await authority.ready;
  if (answer) await authority.submitEvidence({ owner: OWNER, state: answer });
  return authority;
}

describe("the import waker", () => {
  it("runs the importer only for a switched owner", async () => {
    for (const answer of [undefined, "off"] as const) {
      const { importer, signals } = recorder();
      const waker = createImportWaker({
        authority: await authorityWith(answer),
        owner: OWNER,
        importer,
      });
      await waker.wake();
      expect(signals).toHaveLength(0);
    }
    const { importer, signals } = recorder();
    const waker = createImportWaker({
      authority: await authorityWith("on"),
      owner: OWNER,
      importer,
    });
    await waker.wake();
    expect(signals).toHaveLength(1);
  });

  it("joins a run in flight, and runs again at a later wake", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const { importer, signals } = recorder(() => gate);
    const waker = createImportWaker({
      authority: await authorityWith("on"),
      owner: OWNER,
      importer,
    });
    const first = waker.wake();
    const second = waker.wake();
    release();
    await Promise.all([first, second]);
    expect(signals).toHaveLength(1);
    await waker.wake();
    expect(signals).toHaveLength(2);
  });

  it("logs a failed run, and the next wake tries again", async () => {
    const warnings: string[] = [];
    let calls = 0;
    const { importer } = recorder(async () => {
      calls += 1;
      if (calls === 1) throw new Error("disk full");
    });
    const waker = createImportWaker({
      authority: await authorityWith("on"),
      owner: OWNER,
      importer,
      onWarning: (message) => warnings.push(message),
    });
    await expect(waker.wake()).resolves.toBeUndefined();
    expect(warnings).toHaveLength(1);
    await waker.wake();
    expect(calls).toBe(2);
  });

  it("stop aborts the run in flight and waits for it", async () => {
    const { importer, signals } = recorder(aborted);
    const waker = createImportWaker({
      authority: await authorityWith("on"),
      owner: OWNER,
      importer,
    });
    const run = waker.wake();
    await Promise.resolve();
    await Promise.resolve();
    expect(signals[0]?.aborted).toBe(false);
    await waker.stop();
    expect(signals[0]?.aborted).toBe(true);
    await run;
  });

  it("stop before the records load starts no run, and a later wake does nothing", async () => {
    let finishLoad!: () => void;
    const loading = new Promise<void>((resolve) => (finishLoad = resolve));
    const memory = createMemoryModeRecordStore();
    await memory.save(OWNER, { answer: "on", generation: 0, receivedAt: 1 });
    const slow: ModeRecordStore = {
      load: async () => {
        await loading;
        return memory.load();
      },
      save: (owner, record) => memory.save(owner, record),
    };
    const authority = createModeAuthority({ store: slow });
    const { importer, signals } = recorder();
    const waker = createImportWaker({ authority, owner: OWNER, importer });
    const waiting = waker.wake();
    await waker.stop();
    finishLoad();
    await waiting;
    expect(signals).toHaveLength(0);
    await waker.wake();
    expect(signals).toHaveLength(0);
  });

  it("is woken by the authority when an answer leaves the owner On", async () => {
    const { importer, signals } = recorder();
    const woken: { waker?: ReturnType<typeof createImportWaker> } = {};
    const authority = createModeAuthority({
      store: createMemoryModeRecordStore(),
      onOn: () => void woken.waker?.wake(),
    });
    woken.waker = createImportWaker({ authority, owner: OWNER, importer });
    await authority.ready;
    await authority.submitEvidence({ owner: OWNER, state: "off" });
    await Promise.resolve();
    expect(signals).toHaveLength(0);
    await authority.submitEvidence({ owner: OWNER, state: "on" });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(signals).toHaveLength(1);
  });
});
