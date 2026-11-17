// A change delta as the manager uses it.
//
// The held request's answer can carry what changed after the position the
// manager holds (`since`). When the manager's last clean pass started under
// exactly that position, applying the delta is the whole pass: no server row,
// no listing or control row read. Every other case runs the full
// cycle it ran before. Each test names the mutation of `deltaPass` it pins.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Logger } from "../../logger/index.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { UploadWorkerDeps } from "../workers/upload.js";
import type {
  DeltaApplyResult,
  RegistryChangeDelta,
} from "../../stream-sync/ports.js";
import {
  createSyncManager,
  type ChangePush,
  type SyncManagerOptions,
} from "./sync-manager.js";

const logger = {
  info: vi.fn(),
  error: vi.fn(),
  warn: vi.fn(),
  debug: vi.fn(),
  trace: vi.fn(),
  fatal: vi.fn(),
} as unknown as Logger;

type Handlers = Parameters<ChangePush["subscribe"]>[0];

const APPLIED: DeltaApplyResult = {
  outcome: "applied",
  connections: 1,
  deleted: 0,
  blobGets: 1,
  blobMs: 0,
  applyMs: 0,
};

function delta(
  since: string,
  seq: string,
  extra: Partial<Extract<RegistryChangeDelta, { reset: false }>> = {},
): RegistryChangeDelta {
  return {
    since,
    seq,
    reset: false,
    rows: [],
    gone: [],
    serversChanged: false,
    ...extra,
  };
}

function setup(
  opts: {
    applyDelta?: (d: RegistryChangeDelta) => Promise<DeltaApplyResult>;
    mode?: () => string;
  } = {},
) {
  let handlers: Handlers | null = null;
  const push: ChangePush = {
    subscribe(h) {
      handlers = h;
      return () => {};
    },
  };
  const cycle = vi.fn<() => Promise<unknown>>(async () => {});
  const applyDelta = vi.fn(opts.applyDelta ?? (async () => APPLIED));
  const canSync = vi.fn(async () => ({ ok: true as const }));
  const manager = createSyncManager(
    {
      logger,
      serverOwner: "0x1111111111111111111111111111111111111111",
      storage: { findUnsynced: () => [] },
    } as unknown as UploadWorkerDeps,
    { logger } as unknown as DownloadWorkerDeps,
    {
      accountStorageMode: {
        read: (opts.mode ?? (() => "switched")) as () => "switched",
      },
      pollInterval: 60_000,
      localSync: { cycle, applyDelta },
      changeProbe: { read: async () => "m1", intervalMs: 5_000, push },
      canSync,
    } as SyncManagerOptions,
  );
  return {
    manager,
    cycle,
    applyDelta,
    canSync,
    handlers: () => handlers!,
  };
}

type T = ReturnType<typeof setup>;

/** Start and let one timer cycle settle under `position`. */
async function settled(t: T, position = "7") {
  t.manager.start();
  await vi.advanceTimersByTimeAsync(0);
  t.handlers().onHealth(true);
  t.handlers().onPosition(position);
  await vi.advanceTimersByTimeAsync(60_000);
  t.cycle.mockClear();
  t.canSync.mockClear();
}

/** One answer of the held request: its position, then the change. */
async function answer(t: T, d: RegistryChangeDelta | undefined, seq: string) {
  t.handlers().onPosition(seq);
  t.handlers().onChange(d);
  await vi.advanceTimersByTimeAsync(0);
}

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("a change delta", () => {
  it("the held request asks from the position the last clean pass started under (mutation: since from the push cursor)", async () => {
    const t = setup();
    t.manager.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(t.handlers().since?.()).toBeUndefined(); // nothing settled yet
    t.handlers().onHealth(true);
    t.handlers().onPosition("7");
    await vi.advanceTimersByTimeAsync(60_000);
    expect(t.handlers().since?.()).toBe("7");
    t.handlers().onPosition("9"); // the push moved; the device did not
    expect(t.handlers().since?.()).toBe("7");
    await t.manager.stop();
  });

  it("from the held position is the whole pass: no cycle, no server read, settled at its seq (mutation: delta ignored)", async () => {
    const t = setup();
    await settled(t);
    const d = delta("7", "8");
    await answer(t, d, "8");
    expect(t.applyDelta).toHaveBeenCalledWith(d);
    expect(t.cycle).not.toHaveBeenCalled();
    expect(t.canSync).not.toHaveBeenCalled();
    // Settled at 8: the next answer's delta starts there, and the timer has
    // nothing to repeat.
    expect(t.handlers().since?.()).toBe("8");
    await vi.advanceTimersByTimeAsync(60 * 60_000);
    expect(t.cycle).not.toHaveBeenCalled();
    await t.manager.stop();
  });

  it("from another position runs the cycle (mutation: no since check)", async () => {
    const t = setup();
    await settled(t);
    await answer(t, delta("6", "8"), "8");
    expect(t.applyDelta).not.toHaveBeenCalled();
    expect(t.cycle).toHaveBeenCalledTimes(1);
    await t.manager.stop();
  });

  it("read at a seq other than the pushed position runs the cycle (mutation: no seq check)", async () => {
    const t = setup();
    await settled(t);
    await answer(t, delta("7", "8"), "9");
    expect(t.applyDelta).not.toHaveBeenCalled();
    expect(t.cycle).toHaveBeenCalledTimes(1);
    await t.manager.stop();
  });

  it("before any clean pass runs the cycle", async () => {
    const t = setup();
    t.manager.start();
    await vi.advanceTimersByTimeAsync(0);
    t.cycle.mockClear();
    t.handlers().onHealth(true);
    await answer(t, { since: "7", seq: "8", reset: true }, "8");
    expect(t.applyDelta).not.toHaveBeenCalled();
    expect(t.cycle).toHaveBeenCalledTimes(1);
    await t.manager.stop();
  });

  it("a reset runs the cycle (mutation: reset applied)", async () => {
    const t = setup();
    await settled(t);
    await answer(t, { since: "7", seq: "8", reset: true }, "8");
    expect(t.applyDelta).not.toHaveBeenCalled();
    expect(t.cycle).toHaveBeenCalledTimes(1);
    await t.manager.stop();
  });

  it("a local apply that hands back runs the cycle in the same pass, and settles from it", async () => {
    const t = setup({
      applyDelta: async () => ({ outcome: "cycle", reason: "a control row" }),
    });
    await settled(t);
    await answer(t, delta("7", "8"), "8");
    expect(t.applyDelta).toHaveBeenCalledTimes(1);
    expect(t.cycle).toHaveBeenCalledTimes(1);
    expect(t.canSync).toHaveBeenCalledTimes(1);
    expect(t.handlers().since?.()).toBe("8");
    await t.manager.stop();
  });

  it("a local apply that throws runs the cycle (mutation: error ends the pass)", async () => {
    const t = setup({
      applyDelta: async () => {
        throw new Error("segment fetch failed");
      },
    });
    await settled(t);
    await answer(t, delta("7", "8"), "8");
    expect(t.cycle).toHaveBeenCalledTimes(1);
    await t.manager.stop();
  });

  it("outside the switched mode runs the cycle (mutation: no mode check)", async () => {
    let mode = "switched";
    const t = setup({ mode: () => mode });
    await settled(t);
    mode = "unknown";
    await answer(t, delta("7", "8"), "8");
    expect(t.applyDelta).not.toHaveBeenCalled();
    await t.manager.stop();
  });

  it("while a cycle runs, the delta is dropped and a full follow-up runs", async () => {
    const t = setup();
    await settled(t);
    let release!: () => void;
    t.cycle.mockImplementationOnce(
      () => new Promise<void>((resolve) => (release = resolve)),
    );
    await answer(t, delta("6", "8"), "8"); // a full cycle, held open
    await answer(t, delta("7", "9"), "9"); // arrives while it runs
    release();
    await vi.advanceTimersByTimeAsync(0);
    expect(t.applyDelta).not.toHaveBeenCalled();
    expect(t.cycle).toHaveBeenCalledTimes(2);
    await t.manager.stop();
  });

  it("a request without a delta that arrives during a cycle makes the follow-up a full pass, whatever delta comes after it (mutation: queued delta kept)", async () => {
    const t = setup();
    await settled(t);
    let release!: () => void;
    t.cycle.mockImplementationOnce(
      () => new Promise<void>((resolve) => (release = resolve)),
    );
    await answer(t, delta("6", "8"), "8"); // a full cycle, held open
    await answer(t, undefined, "9"); // a poke with no delta
    await answer(t, delta("8", "10"), "10"); // would apply on its own
    release();
    await vi.advanceTimersByTimeAsync(0);
    expect(t.applyDelta).not.toHaveBeenCalled();
    expect(t.cycle).toHaveBeenCalledTimes(2);
    await t.manager.stop();
  });

  it("a poke without a delta (the first answer after a failure) runs the cycle", async () => {
    const t = setup();
    await settled(t);
    await answer(t, undefined, "8");
    expect(t.applyDelta).not.toHaveBeenCalled();
    expect(t.cycle).toHaveBeenCalledTimes(1);
    await t.manager.stop();
  });

  it("a reset waits for the full listing's persisted completion before advancing since (mutation: full cycle not awaited)", async () => {
    const t = setup();
    await settled(t);
    let persist!: () => void;
    t.cycle.mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          persist = resolve;
        }),
    );
    await answer(t, { since: "7", seq: "8", reset: true }, "8");
    expect(t.applyDelta).not.toHaveBeenCalled();
    expect(t.cycle).toHaveBeenCalledTimes(1);
    // The held request asks from the position the listing settles at, so a
    // change that lands meanwhile comes back as a delta; nothing is settled
    // yet, and a listing that fails leaves no position (next test).
    expect(t.handlers().since?.()).toBe("8");
    persist();
    await vi.advanceTimersByTimeAsync(0);
    expect(t.handlers().since?.()).toBe("8");
    await t.manager.stop();
  });

  it("a reset whose listing fails settles nothing: the delta that follows it runs the cycle (mutation: the asked-from position settled at the pass's start)", async () => {
    const t = setup();
    await settled(t);
    let fail!: (error: Error) => void;
    t.cycle.mockImplementationOnce(
      () => new Promise<void>((_resolve, reject) => (fail = reject)),
    );
    await answer(t, { since: "7", seq: "8", reset: true }, "8");
    expect(t.handlers().since?.()).toBe("8");
    fail(new Error("listing failed"));
    await vi.advanceTimersByTimeAsync(0);
    expect(t.handlers().since?.()).toBeUndefined();
    t.cycle.mockClear();
    await answer(t, delta("8", "9"), "9");
    expect(t.applyDelta).not.toHaveBeenCalled();
    expect(t.cycle).toHaveBeenCalledTimes(1);
    await t.manager.stop();
  });

  it("a missing link falls back to a full cycle without applying across the gap", async () => {
    const t = setup();
    await settled(t);
    let release!: () => void;
    t.applyDelta.mockImplementationOnce(
      () =>
        new Promise<DeltaApplyResult>((resolve) => {
          release = () => resolve(APPLIED);
        }),
    );
    await answer(t, delta("7", "8"), "8");
    await answer(t, delta("8", "9"), "9");
    await answer(t, delta("10", "11"), "11");
    release();
    await vi.advanceTimersByTimeAsync(0);
    expect(t.cycle).toHaveBeenCalledTimes(1);
    expect(t.applyDelta.mock.calls.map(([d]) => d.seq)).not.toContain("11");
    await t.manager.stop();
  });

  it("overlapping answers serialize through persistence and a late older answer cannot settle (mutation: concurrent cycles or regressing position)", async () => {
    const t = setup();
    await settled(t);
    let persist!: () => void;
    t.applyDelta.mockImplementationOnce(
      () =>
        new Promise<DeltaApplyResult>((resolve) => {
          persist = () => resolve(APPLIED);
        }),
    );
    await answer(t, delta("7", "8"), "8");
    await answer(t, delta("7", "9"), "9");
    expect(t.applyDelta).toHaveBeenCalledTimes(1);
    expect(t.cycle).not.toHaveBeenCalled();
    // The second answer waits behind the first pass; the request that follows
    // it asks from the position the follow-up pass will start under.
    expect(t.handlers().since?.()).toBe("9");
    persist();
    await vi.advanceTimersByTimeAsync(0);
    expect(t.cycle).toHaveBeenCalledTimes(1);
    expect(t.handlers().since?.()).toBe("9");
    // The older request can also arrive after the newer pass finished.
    await answer(t, delta("7", "8"), "8");
    await vi.advanceTimersByTimeAsync(60_000);
    expect(t.handlers().since?.()).toBe("9");
    expect(t.applyDelta).toHaveBeenCalledTimes(1);
    expect(t.cycle).toHaveBeenCalledTimes(1);
    await t.manager.stop();
  });

  it.each(["delta", "cycle"])(
    "steady idle with healthy push runs no work with the %s path",
    async (path) => {
      const t = setup({
        applyDelta: async () =>
          path === "delta" ? APPLIED : { outcome: "cycle", reason: "disabled" },
      });
      await settled(t);
      await vi.advanceTimersByTimeAsync(60 * 60_000);
      expect(t.applyDelta).not.toHaveBeenCalled();
      expect(t.cycle).not.toHaveBeenCalled();
      expect(t.canSync).not.toHaveBeenCalled();
      await t.manager.stop();
    },
  );

  it("a lower reset lists again without settling an older answer", async () => {
    const t = setup();
    await settled(t, "9");
    await answer(t, { since: "9", seq: "3", reset: true }, "3");
    expect(t.cycle).toHaveBeenCalledTimes(1);
    expect(t.handlers().since?.()).toBeUndefined();
    t.handlers().onPosition("3");
    await vi.advanceTimersByTimeAsync(60_000);
    expect(t.handlers().since?.()).toBe("3");
    await t.manager.stop();
  });

  it("a reset whose listing cannot finish a connection never offers an applied cursor", async () => {
    const t = setup();
    await settled(t);
    t.cycle.mockResolvedValueOnce({
      connections: [
        {
          connectionId: "c",
          error: "unreadable log",
          status: "update_required",
        },
      ],
    });
    await answer(t, { since: "7", seq: "8", reset: true }, "8");
    expect(t.handlers().since?.()).toBeUndefined();
    expect(t.manager.getStatus().blocked?.reason).toBe("update_required");
    // Keep the existing policy: an unsupported format does not poll forever.
    await vi.advanceTimersByTimeAsync(60_000);
    expect(t.cycle).toHaveBeenCalledTimes(1);
    await t.manager.stop();
  });
});
