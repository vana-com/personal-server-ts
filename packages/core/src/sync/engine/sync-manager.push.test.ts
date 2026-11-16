// The registry change push as the manager uses it.
//
// A poke is only a request to pull (`requestPull`); the pull still compares the
// registry's change marker and runs the cycle, so a poke can be lost, doubled
// or late without a wrong result. While the subscription is healthy the timed
// probe stretches to a minute; when it is not, the short probe returns, so the
// push can only ever make the system faster than it was.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Logger } from "../../logger/index.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { UploadWorkerDeps } from "../workers/upload.js";
import type { StreamSyncRegistry } from "../../stream-sync/ports.js";
import { createRegistryChangePush } from "./change-push.js";
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

function build(
  options: Partial<SyncManagerOptions>,
  storage: object = { findUnsynced: () => [] },
) {
  return createSyncManager(
    {
      logger,
      serverOwner: "0x1111111111111111111111111111111111111111",
      storage,
    } as unknown as UploadWorkerDeps,
    { logger } as unknown as DownloadWorkerDeps,
    {
      accountStorageMode: { read: () => "switched" },
      pollInterval: 60_000,
      ...options,
    },
  );
}

/** A push the test drives by hand. */
function fakePush() {
  const state = {
    subscribed: 0,
    stopped: 0,
    handlers: null as null | {
      onChange(): void;
      onHealth(healthy: boolean): void;
      onPosition(position: string): void;
    },
  };
  const push: ChangePush = {
    subscribe(handlers) {
      state.subscribed += 1;
      state.handlers = handlers;
      return () => {
        state.stopped += 1;
      };
    },
  };
  return { push, state };
}

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("a poke", () => {
  it("pulls: a moved marker runs a cycle at once, long before the 5 s probe or the 60 s timer", async () => {
    const { push, state } = fakePush();
    let marker = "m1";
    const cycle = vi.fn(async () => {});
    const read = vi.fn(async () => marker);
    const manager = build({
      localSync: { cycle },
      changeProbe: { read, intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    state.handlers!.onChange(); // first poke: nothing applied yet
    await vi.advanceTimersByTimeAsync(0);
    cycle.mockClear();

    marker = "m2";
    state.handlers!.onChange();
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(1);
    await manager.stop();
  });

  it("a plain probe poke (focus, online) still skips a marker that did not move", async () => {
    const { push } = fakePush();
    const cycle = vi.fn(async () => {});
    const manager = build({
      localSync: { cycle },
      changeProbe: { read: async () => "m1", intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    await manager.requestPull(); // applies m1
    cycle.mockClear();
    await manager.requestPull();
    await manager.requestPull();
    expect(cycle).not.toHaveBeenCalled();
    await manager.stop();
  });

  it("a push answer that says the sequence moved cycles even when the probe marker is equal", async () => {
    // The marker fingerprints one row: a second row stamped in the same
    // millisecond leaves it unchanged. The gateway's sequence is exact, so a
    // verified change must not be judged by the lossy marker.
    const { push, state } = fakePush();
    const cycle = vi.fn(async () => {});
    const manager = build({
      localSync: { cycle },
      changeProbe: { read: async () => "m1", intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    await manager.requestPull(); // m1 is applied
    cycle.mockClear();

    state.handlers!.onChange();
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(1);
    await manager.stop();
  });

  it("still cycles when the marker probe itself fails: a verified change does not need it", async () => {
    const { push, state } = fakePush();
    const cycle = vi.fn(async () => {});
    const manager = build({
      localSync: { cycle },
      changeProbe: {
        read: async () => {
          throw new Error("probe down");
        },
        intervalMs: 5_000,
        push,
      },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    cycle.mockClear();
    state.handlers!.onChange();
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(1);
    await manager.stop();
  });

  it("does not stop a failing cycle from being reported, and never throws into the subscription", async () => {
    const { push, state } = fakePush();
    let marker = "m1";
    const manager = build({
      localSync: {
        cycle: async () => {
          throw new Error("cycle failed");
        },
      },
      changeProbe: { read: async () => marker, intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    marker = "m2";
    expect(() => state.handlers!.onChange()).not.toThrow();
    await vi.advanceTimersByTimeAsync(0);
    await manager.stop();
  });
});

describe("a pushed change does not wait for the optional probe", () => {
  const never = () => new Promise<string>(() => {});

  /** A probe whose reads answer "m1" until the test makes them hang. */
  function hangingProbe() {
    let hang = false;
    const read = vi.fn(async () => (hang ? never() : "m1"));
    return { read, hang: () => (hang = true) };
  }

  it("starts a cycle at once although the probe read never settles", async () => {
    const { push, state } = fakePush();
    const cycle = vi.fn(async () => {});
    const probe = hangingProbe();
    const manager = build({
      localSync: { cycle },
      changeProbe: { read: probe.read, intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    await manager.requestPull(); // the marker is established
    cycle.mockClear();
    probe.hang();

    state.handlers!.onChange();
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(1); // long before the next 60 s tick
    await manager.stop();
  });

  it("does not join a timed probe read that is already pending", async () => {
    const { push, state } = fakePush();
    const cycle = vi.fn(async () => {});
    const probe = hangingProbe();
    const manager = build({
      localSync: { cycle },
      changeProbe: { read: probe.read, intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    await manager.requestPull();
    cycle.mockClear();
    probe.hang();
    probe.read.mockClear();
    await vi.advanceTimersByTimeAsync(5_000); // the timed probe starts and hangs
    expect(probe.read).toHaveBeenCalledTimes(1);
    expect(cycle).not.toHaveBeenCalled();

    state.handlers!.onChange();
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(1);
    await manager.stop();
  });

  it("keeps cycles one at a time: a forced request during a running cycle waits for a follow-up", async () => {
    const { push, state } = fakePush();
    let running = 0;
    let overlap = 0;
    let release: () => void = () => {};
    const cycle = vi.fn(async () => {
      running += 1;
      overlap = Math.max(overlap, running);
      await new Promise<void>((r) => (release = r));
      running -= 1;
    });
    const probe = hangingProbe();
    const manager = build({
      localSync: { cycle },
      changeProbe: { read: probe.read, intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    probe.hang();
    state.handlers!.onChange();
    await vi.advanceTimersByTimeAsync(0);
    state.handlers!.onChange(); // arrives while the first cycle runs
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(1);
    release();
    await vi.advanceTimersByTimeAsync(0);
    release();
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(2);
    expect(overlap).toBe(1);
    await manager.stop();
  });

  describe("a failing cycle", () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    // Each attempt holds until the test rejects it. Back-off jitter is fixed at
    // its middle (x1.0), so the cooldowns are 1 s, 2 s, 4 s, ...
    function failingCycles() {
      vi.spyOn(Math, "random").mockReturnValue(0.5);
      const rejects: Array<(e: Error) => void> = [];
      let running = 0;
      let overlap = 0;
      const cycle = vi.fn(async () => {
        running += 1;
        overlap = Math.max(overlap, running);
        try {
          await new Promise<void>((_, reject) => rejects.push(reject));
        } finally {
          running -= 1;
        }
      });
      return { cycle, rejects, overlap: () => overlap };
    }

    function quietProbe(push: ChangePush) {
      return { read: async () => "m1", intervalMs: 3_600_000, push };
    }

    it("runs the follow-up a queued request is owed after a cooldown, not at once", async () => {
      const { push, state } = fakePush();
      const { cycle, rejects, overlap } = failingCycles();
      const manager = build({
        localSync: { cycle },
        changeProbe: quietProbe(push),
      });
      manager.start();
      await vi.advanceTimersByTimeAsync(0);
      expect(cycle).toHaveBeenCalledTimes(1); // the startup cycle, held
      state.handlers!.onChange(); // accepted while it runs
      rejects[0]!(new Error("storage unreachable"));
      await vi.advanceTimersByTimeAsync(0);
      expect(cycle).toHaveBeenCalledTimes(1); // no immediate retry
      await vi.advanceTimersByTimeAsync(999);
      expect(cycle).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(1); // the first back-off step
      expect(cycle).toHaveBeenCalledTimes(2); // the owed follow-up, exactly one
      expect(overlap()).toBe(1);
      rejects[1]!(new Error("storage unreachable")); // let stop() drain it
      await manager.stop().catch(() => {});
    });

    it("retries nothing when no follow-up was requested", async () => {
      const { push } = fakePush();
      const { cycle, rejects } = failingCycles();
      const manager = build({
        localSync: { cycle },
        changeProbe: quietProbe(push),
      });
      manager.start();
      await vi.advanceTimersByTimeAsync(0);
      rejects[0]!(new Error("storage unreachable"));
      await vi.advanceTimersByTimeAsync(30_000);
      expect(cycle).toHaveBeenCalledTimes(1);
      await manager.stop();
    });

    it("under pushes during every failing attempt: finite immediate attempts, backed-off retries, queued work progresses, first error delivered", async () => {
      const { push, state } = fakePush();
      const { cycle, rejects, overlap } = failingCycles();
      const deleted = vi.fn(async () => 1);
      const manager = build(
        { localSync: { cycle }, changeProbe: quietProbe(push) },
        {
          findUnsynced: () => [],
          deleteScope: deleted,
          listVersions: () => [],
        },
      );
      manager.start();
      await vi.advanceTimersByTimeAsync(0);
      expect(cycle).toHaveBeenCalledTimes(1);

      state.handlers!.onChange(); // during attempt 1
      const waiter = manager.trigger().then(
        () => "resolved",
        (e: Error) => e.message,
      ); // a caller waiting on attempt 1
      const queued = manager.deleteScope("instagram.profile");
      await vi.advanceTimersByTimeAsync(0);
      expect(deleted).not.toHaveBeenCalled(); // behind the running attempt

      rejects[0]!(new Error("first failure"));
      await vi.advanceTimersByTimeAsync(0);
      expect(await waiter).toBe("first failure"); // not held back by retries
      await queued; // the slot was released: the delete ran between attempts
      expect(deleted).toHaveBeenCalledTimes(1);
      expect(cycle).toHaveBeenCalledTimes(1); // finite: one attempt, then cooldown

      // Pushes keep arriving, including during the cooldown; none shortens it.
      state.handlers!.onChange();
      await vi.advanceTimersByTimeAsync(500);
      state.handlers!.onChange();
      await vi.advanceTimersByTimeAsync(499);
      expect(cycle).toHaveBeenCalledTimes(1); // 999 ms in
      await vi.advanceTimersByTimeAsync(1);
      expect(cycle).toHaveBeenCalledTimes(2); // 1 s: attempt 2

      state.handlers!.onChange(); // during attempt 2
      rejects[1]!(new Error("second failure"));
      await vi.advanceTimersByTimeAsync(1_999);
      expect(cycle).toHaveBeenCalledTimes(2); // the step doubled: 2 s
      await vi.advanceTimersByTimeAsync(1);
      expect(cycle).toHaveBeenCalledTimes(3);

      state.handlers!.onChange(); // during attempt 3
      rejects[2]!(new Error("third failure"));
      await vi.advanceTimersByTimeAsync(3_999);
      expect(cycle).toHaveBeenCalledTimes(3); // 4 s
      expect(overlap()).toBe(1);

      // Stopping ends the obligation: no retry fires after stop.
      await manager.stop();
      await vi.advanceTimersByTimeAsync(120_000);
      expect(cycle).toHaveBeenCalledTimes(3);
    });

    it("keeps the dirty request while cooling down and runs it once the cooldown ends", async () => {
      const { push, state } = fakePush();
      const { cycle, rejects } = failingCycles();
      const manager = build({
        localSync: { cycle },
        changeProbe: quietProbe(push),
      });
      manager.start();
      await vi.advanceTimersByTimeAsync(0);
      state.handlers!.onChange();
      rejects[0]!(new Error("down"));
      await vi.advanceTimersByTimeAsync(1_000);
      expect(cycle).toHaveBeenCalledTimes(2);
      rejects[1]!(new Error("down")); // no push during this attempt: nothing owed
      await vi.advanceTimersByTimeAsync(30_000);
      expect(cycle).toHaveBeenCalledTimes(2);
      await manager.stop();
    });

    it("starts the back-off over after a cycle succeeds, even when its dirty flag runs the next pass at once", async () => {
      // A fails (1 s), retry B succeeds and its own push starts pass C in the
      // same cycle, C fails: the cooldown is the first step again, not the second.
      vi.spyOn(Math, "random").mockReturnValue(0.5);
      const { push, state } = fakePush();
      const held: Array<{ ok: () => void; fail: (e: Error) => void }> = [];
      const cycle = vi.fn(
        () =>
          new Promise<void>((resolve, reject) =>
            held.push({ ok: resolve, fail: reject }),
          ),
      );
      const manager = build({
        localSync: { cycle },
        changeProbe: quietProbe(push),
      });
      manager.start();
      await vi.advanceTimersByTimeAsync(0);
      state.handlers!.onChange(); // during A
      held[0]!.fail(new Error("A fails"));
      await vi.advanceTimersByTimeAsync(1_000);
      expect(cycle).toHaveBeenCalledTimes(2); // retry B
      state.handlers!.onChange(); // during B: its pass repeats
      held[1]!.ok();
      await vi.advanceTimersByTimeAsync(0);
      expect(cycle).toHaveBeenCalledTimes(3); // C, straight after B
      state.handlers!.onChange(); // during C
      held[2]!.fail(new Error("C fails"));
      await vi.advanceTimersByTimeAsync(999);
      expect(cycle).toHaveBeenCalledTimes(3);
      await vi.advanceTimersByTimeAsync(1); // 1 s after C: B's success reset the step
      expect(cycle).toHaveBeenCalledTimes(4);
      held[3]!.fail(new Error("D fails")); // let stop() drain it
      await manager.stop().catch(() => {});
    });

    it("still reports the failure to the caller that asked for the failed cycle", async () => {
      const { push, state } = fakePush();
      const { cycle, rejects } = failingCycles();
      const manager = build({
        localSync: { cycle },
        changeProbe: quietProbe(push),
      });
      manager.start();
      await vi.advanceTimersByTimeAsync(0);
      const asked = manager.requestPull().then(
        () => "resolved",
        (e: Error) => e.message,
      );
      state.handlers!.onChange();
      rejects[0]!(new Error("storage unreachable"));
      await vi.advanceTimersByTimeAsync(0);
      expect(await asked).toBe("storage unreachable");
      await vi.advanceTimersByTimeAsync(1_000);
      expect(cycle).toHaveBeenCalledTimes(2);
      rejects[1]!(new Error("storage unreachable")); // let stop() drain it
      await manager.stop().catch(() => {});
    });
  });

  it("publishes no marker of its own: the next probe runs one conservative follow-up, then settles", async () => {
    const { push, state } = fakePush();
    let marker = "m1";
    const cycle = vi.fn(async () => {});
    const manager = build({
      localSync: { cycle },
      changeProbe: { read: async () => marker, intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    await manager.requestPull();
    cycle.mockClear();

    marker = "m2";
    state.handlers!.onChange();
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(1);
    await manager.requestPull(); // the probe's own read of m2, then its cycle
    expect(cycle).toHaveBeenCalledTimes(2);
    await manager.requestPull(); // m2 is now applied by a cycle that followed its read
    expect(cycle).toHaveBeenCalledTimes(2);
    await manager.stop();
  });

  it("does not mark a change applied that the forced cycle never read", async () => {
    // pulledMarker only holds a marker that was read BEFORE the cycle that
    // applied it started. A marker answered while a forced cycle is running may
    // describe a commit made after the cycle's registry snapshot.
    const { push, state } = fakePush();
    const answers: Array<(m: string) => void> = [];
    let immediate = true;
    const read = vi.fn(() =>
      immediate
        ? Promise.resolve("m1")
        : new Promise<string>((resolve) => answers.push(resolve)),
    );
    let snapshot = "";
    let registry = "m1";
    let release: () => void = () => {};
    let hold = false;
    const cycle = vi.fn(async () => {
      snapshot = registry; // the cycle's registry read
      if (hold) await new Promise<void>((resolve) => (release = resolve)); // applying it
    });
    const manager = build({
      localSync: { cycle },
      changeProbe: { read, intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    await manager.requestPull(); // m1 is applied
    cycle.mockClear();
    immediate = false;
    hold = true;

    state.handlers!.onChange(); // the forced cycle starts and takes its snapshot
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(1);
    expect(snapshot).toBe("m1");
    registry = "m2"; // a later commit, after the snapshot
    answers.splice(0).forEach((answer) => answer("m2")); // a probe read sees it
    await vi.advanceTimersByTimeAsync(0);
    release(); // the forced cycle finishes with snapshot m1
    await vi.advanceTimersByTimeAsync(0);

    const next = manager.requestPull();
    await vi.advanceTimersByTimeAsync(0);
    answers.splice(0).forEach((answer) => answer("m2"));
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(2); // m2 was never applied: a follow-up runs
    expect(snapshot).toBe("m2");
    release();
    await next;
    await manager.stop();
  });
});

describe("the push position", () => {
  // Every answer of the held request, an empty one at the end of its wait
  // included, carries the registry's current sequence. A cycle reads the
  // registry after the position it started under, so when the push is healthy
  // and the position is the one the last clean cycle started under, that cycle
  // already holds everything the registry has: the timer cycle and the probe
  // add requests and no news. A wake that was lost on the way is found by the
  // next answer, which says it changed. Nothing else is owed.

  /** A manager whose push the test drives by hand. */
  function setup(opts: { cycle?: () => Promise<void> } = {}) {
    const { push, state } = fakePush();
    const cycle = vi.fn(async () => {
      await opts.cycle?.();
    });
    const read = vi.fn(async () => "m1");
    const manager = build({
      localSync: { cycle },
      changeProbe: { read, intervalMs: 5_000, push },
    });
    return { manager, state, cycle, read };
  }

  /**
   * Start, answer the first position, and let one timer cycle settle on it.
   * The start cycle began before any position was known: it proves nothing.
   * The first timer cycle starts under the position and settles on it.
   */
  async function settled(t: ReturnType<typeof setup>, position = "7") {
    t.manager.start();
    await vi.advanceTimersByTimeAsync(0);
    t.state.handlers!.onHealth(true);
    t.state.handlers!.onPosition(position);
    await vi.advanceTimersByTimeAsync(60_000);
    t.cycle.mockClear();
    t.read.mockClear();
  }

  it("runs no timer cycle and no probe while the push is healthy and the position has not moved", async () => {
    const t = setup();
    await settled(t);
    await vi.advanceTimersByTimeAsync(24 * 60 * 60_000);
    expect(t.cycle).not.toHaveBeenCalled();
    expect(t.read).not.toHaveBeenCalled();
    await t.manager.stop();
  });

  it("issues no probe read in an idle minute while the push is healthy, even when the last pass left work owed", async () => {
    // A pass that leaves work (a connection error, a deferred publish) settles
    // nothing, so the timer cycle keeps its clock. The held request still
    // announces every change, so the marker probe has nothing to add.
    const { push, state } = fakePush();
    const cycle = vi.fn(async () => ({
      connections: [{ error: "owed", published: [] }],
    }));
    const read = vi.fn(async () => "m1");
    const manager = build({
      localSync: { cycle },
      changeProbe: { read, intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    state.handlers!.onHealth(true);
    state.handlers!.onPosition("7");
    read.mockClear();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(read).not.toHaveBeenCalled();
    await manager.stop();
  });

  it("a renewal that answers with an unmoved position owes nothing", async () => {
    const t = setup();
    await settled(t);
    for (let i = 0; i < 100; i++) {
      t.state.handlers!.onPosition("7"); // an empty answer at the end of the wait
      await vi.advanceTimersByTimeAsync(25_000);
    }
    expect(t.cycle).not.toHaveBeenCalled();
    expect(t.read).not.toHaveBeenCalled();
    await t.manager.stop();
  });

  it("a renewal that answers moved runs a cycle at once: the position, then the change", async () => {
    const t = setup();
    await settled(t);
    // The poke never arrived; the renewal's answer carries the position and
    // says it changed.
    t.state.handlers!.onPosition("8");
    t.state.handlers!.onChange();
    await vi.advanceTimersByTimeAsync(0);
    expect(t.cycle).toHaveBeenCalledTimes(1);
    // That cycle started under "8": quiet again.
    t.cycle.mockClear();
    await vi.advanceTimersByTimeAsync(60 * 60_000);
    expect(t.cycle).not.toHaveBeenCalled();
    await t.manager.stop();
  });

  it("a position that moved without a change callback ends the skip: the timer repairs it, not an immediate cycle", async () => {
    const t = setup();
    await settled(t);
    t.state.handlers!.onPosition("8");
    await vi.advanceTimersByTimeAsync(60_000);
    expect(t.cycle).toHaveBeenCalledTimes(1);
    // That cycle started under "8" and settled on it: quiet again.
    t.cycle.mockClear();
    await vi.advanceTimersByTimeAsync(5 * 60_000);
    expect(t.cycle).not.toHaveBeenCalled();
    await t.manager.stop();
  });

  it("a position that moves during a cycle owes another cycle", async () => {
    let release!: () => void;
    const hold = new Promise<void>((resolve) => (release = resolve));
    let block = false;
    const t = setup({ cycle: () => (block ? hold : Promise.resolve()) });
    await settled(t);
    block = true;
    t.state.handlers!.onPosition("8");
    t.state.handlers!.onChange(); // cycle starts under "8"
    await vi.advanceTimersByTimeAsync(0);
    t.state.handlers!.onPosition("9"); // moves while that cycle runs
    block = false;
    release();
    await vi.advanceTimersByTimeAsync(0);
    t.cycle.mockClear();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(t.cycle).toHaveBeenCalledTimes(1); // "9" was never read
    await t.manager.stop();
  });

  it("runs one cycle at once when the push turns from healthy to not healthy: while it was silent its position could not vouch for the registry", async () => {
    const t = setup();
    await settled(t);
    t.state.handlers!.onHealth(false);
    await vi.advanceTimersByTimeAsync(0);
    expect(t.cycle).toHaveBeenCalledTimes(1);
    // A push that was never healthy has no silence to answer for.
    t.cycle.mockClear();
    t.state.handlers!.onHealth(false);
    await vi.advanceTimersByTimeAsync(0);
    expect(t.cycle).not.toHaveBeenCalled();
    await t.manager.stop();
  });

  it("falls back to the 60 s timer and the 5 s probe as soon as the push is not healthy", async () => {
    const t = setup();
    await settled(t);
    t.state.handlers!.onHealth(false);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(t.cycle.mock.calls.length).toBeGreaterThanOrEqual(2); // the turn, then the timer
    expect(t.read.mock.calls.length).toBeGreaterThanOrEqual(10);
    await t.manager.stop();
  });

  it("never skips while no position is known (a gateway or push that sends none)", async () => {
    const { push, state } = fakePush();
    const cycle = vi.fn(async () => {});
    const read = vi.fn(async () => "m1");
    const manager = build({
      localSync: { cycle },
      changeProbe: { read, intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    state.handlers!.onHealth(true);
    cycle.mockClear();
    await vi.advanceTimersByTimeAsync(120_000);
    expect(cycle.mock.calls.length).toBeGreaterThanOrEqual(2);
    expect(read.mock.calls.length).toBeGreaterThanOrEqual(10);
    await manager.stop();
  });

  it("a cycle that failed under the current position settles nothing: the next timer tick cycles again", async () => {
    let fail = false;
    const t = setup({
      cycle: async () => {
        if (fail) throw new Error("boom");
      },
    });
    await settled(t);
    fail = true;
    t.state.handlers!.onChange(); // a poke at the same position: the cycle fails
    await vi.advanceTimersByTimeAsync(0);
    expect(t.cycle).toHaveBeenCalledTimes(1);
    fail = false;
    t.cycle.mockClear();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(t.cycle).toHaveBeenCalledTimes(1);
    await t.manager.stop();
  });

  it("a blocked cycle settles nothing", async () => {
    const { push, state } = fakePush();
    let ok = true;
    const cycle = vi.fn(async () => {});
    const manager = build({
      localSync: { cycle },
      canSync: () =>
        ok ? { ok: true } : { ok: false, reason: "paused", message: "m" },
      changeProbe: {
        read: async () => "m1",
        intervalMs: 5_000,
        push,
      },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    state.handlers!.onHealth(true);
    state.handlers!.onPosition("7");
    ok = false;
    await vi.advanceTimersByTimeAsync(60_000); // blocked under "7"
    ok = true;
    cycle.mockClear();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(cycle).toHaveBeenCalledTimes(1);
    await manager.stop();
  });

  describe("a cycle that finished but left work no position announces", () => {
    // The stream-sync cycle reports per connection instead of throwing. A
    // connection that failed, or whose publish backs off or waits on a
    // condition, retries only when another cycle runs; the registry does not
    // move for it. Such a cycle settles nothing, so the timer keeps running.
    const report = (
      ...streams: Array<{ error?: string; outcomes?: string[] }>
    ) => ({
      connections: streams.map((s, i) => ({
        connectionId: `c${i}`,
        applied: [],
        published: (s.outcomes ?? ["noop"]).map((outcome) => ({
          stream: "s",
          outcome,
          watermark: null,
        })),
        error: s.error ?? null,
      })),
    });

    // A settled device at position "7", poked at that position into a cycle
    // whose report is `result`. The report stays the same from then on, so the
    // work it names is never resolved: the device must retry it on the clock
    // and must not retry it in a loop.
    async function pokedInto(result: unknown, passMs = 0) {
      const { push, state } = fakePush();
      let next: unknown = report({});
      const passes = { starts: [] as number[], ends: [] as number[] };
      let running = 0;
      let maxRunning = 0;
      let slow = false; // only the passes after the poke take `passMs`
      const cycle = vi.fn(async () => {
        passes.starts.push(Date.now());
        running += 1;
        maxRunning = Math.max(maxRunning, running);
        if (slow && passMs > 0) {
          await new Promise((resolve) => setTimeout(resolve, passMs));
        }
        running -= 1;
        passes.ends.push(Date.now());
        return next;
      });
      const manager = build({
        localSync: { cycle },
        changeProbe: { read: async () => "m1", intervalMs: 5_000, push },
      });
      manager.start();
      await vi.advanceTimersByTimeAsync(0);
      state.handlers!.onHealth(true);
      state.handlers!.onPosition("7");
      await vi.advanceTimersByTimeAsync(60_000); // settles on "7"
      cycle.mockClear();
      passes.starts.length = 0;
      passes.ends.length = 0;
      next = result;
      slow = true;
      state.handlers!.onChange(); // a poke at the same position runs the cycle
      await vi.advanceTimersByTimeAsync(0);
      return { manager, cycle, passes, maxRunning: () => maxRunning };
    }

    const unresolved = [
      ["a connection that failed", report({ error: "boom" })],
      ["a stream whose publish backs off", report({ outcomes: ["backoff"] })],
      [
        "a stream deferred on a condition",
        report({ outcomes: ["noop", "deferred"] }),
      ],
    ] as const;

    it.each(unresolved)(
      "%s: one retry per poll interval, none sooner, none after stop",
      async (_name, result) => {
        const { manager, cycle } = await pokedInto(result);
        expect(cycle).toHaveBeenCalledTimes(1); // the poke

        await vi.advanceTimersByTimeAsync(59_999);
        expect(cycle).toHaveBeenCalledTimes(1); // no rerun of its own
        await vi.advanceTimersByTimeAsync(1);
        expect(cycle).toHaveBeenCalledTimes(2);
        // The same report every time: one cycle each interval over five more.
        for (let interval = 3; interval <= 6; interval++) {
          await vi.advanceTimersByTimeAsync(60_000);
          expect(cycle).toHaveBeenCalledTimes(interval);
        }

        await manager.stop();
        expect(vi.getTimerCount()).toBe(0);
        await vi.advanceTimersByTimeAsync(10 * 60_000);
        expect(cycle).toHaveBeenCalledTimes(6);
      },
    );

    it.each(unresolved)(
      "%s: when a pass outlasts the timer ticks, passes follow one at a time and never start faster than they end",
      async (_name, result) => {
        const passMs = 150_000; // two and a half poll intervals
        const { manager, cycle, passes, maxRunning } = await pokedInto(
          result,
          passMs,
        );
        await vi.advanceTimersByTimeAsync(10 * 60_000);
        // Stop waits for the pass under way; let it end.
        const stopping = manager.stop();
        await vi.advanceTimersByTimeAsync(passMs);
        await stopping;
        const startedAtStop = cycle.mock.calls.length;
        await vi.advanceTimersByTimeAsync(10 * 60_000);
        expect(cycle.mock.calls.length).toBe(startedAtStop);
        expect(vi.getTimerCount()).toBe(0);

        expect(maxRunning()).toBe(1);
        // Each pass starts only after the one before it ended: a tick during a
        // pass costs one follow-up, not one per tick.
        for (let i = 1; i < passes.starts.length; i++) {
          expect(passes.starts[i]).toBeGreaterThanOrEqual(passes.ends[i - 1]!);
        }
        // Ticks in the window: ten. Ten minutes of 150 s passes: at most
        // four finished, plus the one under way when the window closed.
        expect(cycle.mock.calls.length).toBeLessThanOrEqual(5);
        expect(cycle.mock.calls.length).toBeGreaterThanOrEqual(2);
      },
    );

    describe("a connection whose log this build cannot read", () => {
      // The real report shape: the cycle sets both the error text and
      // `status: "update_required"` for it. No later cycle of this build
      // changes that outcome, so it owes no retry; the block stays shown.
      const refused = (id: string) => ({
        connectionId: id,
        applied: [],
        published: [],
        error: "apply: invalid log segment 3 (unsupported_format)",
        status: "update_required" as const,
      });
      const ordinary = (error: string | null, outcome = "noop") => ({
        connectionId: "other",
        applied: [],
        published: [{ stream: "s", outcome, watermark: null }],
        error,
      });

      it("alone: settles under a healthy push, keeps the block, stays quiet on timer and probe ticks, and a poke still cycles", async () => {
        const { manager, cycle } = await pokedInto({
          connections: [refused("c")],
        });
        expect(cycle).toHaveBeenCalledTimes(1); // the poke
        expect(manager.getStatus().blocked?.reason).toBe("update_required");
        await vi.advanceTimersByTimeAsync(10 * 60_000);
        expect(cycle).toHaveBeenCalledTimes(1); // no timer cycle, no probe
        expect(manager.getStatus().blocked?.reason).toBe("update_required");
        await manager.stop();
      });

      it("a poke at the same position still runs a cycle after it settled", async () => {
        const { push, state } = fakePush();
        const cycle = vi.fn(async () => ({ connections: [refused("c")] }));
        const manager = build({
          localSync: { cycle },
          changeProbe: { read: async () => "m1", intervalMs: 5_000, push },
        });
        manager.start();
        await vi.advanceTimersByTimeAsync(0);
        state.handlers!.onHealth(true);
        state.handlers!.onPosition("7");
        await vi.advanceTimersByTimeAsync(60_000);
        cycle.mockClear();
        state.handlers!.onChange();
        await vi.advanceTimersByTimeAsync(0);
        expect(cycle).toHaveBeenCalledTimes(1);
        await manager.stop();
      });

      it.each([
        ["an ordinary error", ordinary("boom")],
        ["a publish that backs off", ordinary(null, "backoff")],
        ["a stream deferred on a condition", ordinary(null, "deferred")],
      ] as const)(
        "beside %s on another connection: not settled, one retry per interval",
        async (_name, other) => {
          const { manager, cycle } = await pokedInto({
            connections: [refused("c"), other],
          });
          expect(cycle).toHaveBeenCalledTimes(1);
          await vi.advanceTimersByTimeAsync(60_000);
          expect(cycle).toHaveBeenCalledTimes(2);
          await vi.advanceTimersByTimeAsync(60_000);
          expect(cycle).toHaveBeenCalledTimes(3);
          expect(manager.getStatus().blocked?.reason).toBe("update_required");
          await manager.stop();
        },
      );
    });

    it("every connection done: quiet again", async () => {
      const { manager, cycle } = await pokedInto(
        report({ outcomes: ["published", "noop", "refused", "purged"] }),
      );
      cycle.mockClear();
      await vi.advanceTimersByTimeAsync(5 * 60_000);
      expect(cycle).not.toHaveBeenCalled();
      await manager.stop();
    });
  });

  it("a registration revoked with no data write is found when the gateway moves the position, and not before", async () => {
    // The sync gate (`canSync`) reads server registration, which is not a data
    // write. The gateway raises the owner's position for it; the manager's
    // part is to run the gate on the cycle that position starts.
    const { push, state } = fakePush();
    let registered = true;
    const canSync = vi.fn(() =>
      registered
        ? { ok: true as const }
        : {
            ok: false as const,
            reason: "unregistered" as const,
            message: "Register this Personal Server before syncing.",
          },
    );
    const cycle = vi.fn(async () => ({ connections: [] }));
    const manager = build({
      localSync: { cycle },
      canSync,
      changeProbe: { read: async () => "m1", intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    state.handlers!.onHealth(true);
    state.handlers!.onPosition("7");
    await vi.advanceTimersByTimeAsync(60_000); // settled on "7"
    canSync.mockClear();
    cycle.mockClear();

    registered = false; // revoked: no data point written
    await vi.advanceTimersByTimeAsync(60 * 60_000);
    expect(canSync).not.toHaveBeenCalled(); // nothing announced it yet

    state.handlers!.onPosition("8"); // the gateway raised the position
    state.handlers!.onChange();
    await vi.advanceTimersByTimeAsync(0);
    expect(canSync).toHaveBeenCalledTimes(1);
    expect(cycle).not.toHaveBeenCalled(); // blocked: nothing transferred
    expect(manager.getStatus().blocked?.reason).toBe("unregistered");

    // A blocked device is never quiet: it finds the registration by timer.
    registered = true;
    await vi.advanceTimersByTimeAsync(60_000);
    expect(cycle).toHaveBeenCalledTimes(1);
    expect(manager.getStatus().blocked).toBeNull();
    await manager.stop();
  });

  it("forgets the position when stopped and restarted", async () => {
    const t = setup();
    await settled(t);
    await t.manager.stop();
    t.manager.start();
    await vi.advanceTimersByTimeAsync(0);
    t.cycle.mockClear();
    // New subscription, nothing known yet: the timer cycle runs.
    await vi.advanceTimersByTimeAsync(60_000);
    expect(t.cycle.mock.calls.length).toBeGreaterThanOrEqual(1);
    await t.manager.stop();
  });
});

describe("the subscription's lifecycle", () => {
  it("subscribes on start, ends on stop, and resubscribes on a restart", async () => {
    const { push, state } = fakePush();
    const manager = build({
      localSync: { cycle: async () => {} },
      changeProbe: { read: async () => "m1", intervalMs: 5_000, push },
    });
    expect(state.subscribed).toBe(0);
    manager.start();
    manager.start(); // idempotent
    expect(state.subscribed).toBe(1);
    await manager.stop();
    expect(state.stopped).toBe(1);
    manager.start();
    expect(state.subscribed).toBe(2);
    await manager.stop();
  });

  it("ignores a poke or health report from a subscription that already ended", async () => {
    const { push, state } = fakePush();
    const cycle = vi.fn(async () => {});
    const read = vi.fn(async () => "m1");
    const manager = build({
      localSync: { cycle },
      changeProbe: { read, intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    const old = state.handlers!;
    await manager.stop();
    read.mockClear();
    old.onChange();
    old.onHealth(true);
    await vi.advanceTimersByTimeAsync(0);
    expect(read).not.toHaveBeenCalled();
  });

  it("changes nothing for a probe without a push", async () => {
    const read = vi.fn(async () => "m1");
    const manager = build({
      localSync: { cycle: async () => {} },
      changeProbe: { read, intervalMs: 5_000 },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    read.mockClear();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(read.mock.calls.length).toBe(12);
    await manager.stop();
  });
});

describe("the real subscription driving the manager", () => {
  /** A registry whose held requests the test answers or fails by hand. */
  function heldRegistry() {
    const pending: Array<{
      after: string | undefined;
      answer: (a: { seq: string; changed: boolean }) => void;
      fail: (e: Error) => void;
    }> = [];
    const registry = {
      waitForChange: (
        after: string | undefined,
        _waitMs: number,
        signal: AbortSignal,
      ) =>
        new Promise<{ seq: string; changed: boolean }>((resolve, reject) => {
          pending.push({ after, answer: resolve, fail: reject });
          signal.addEventListener("abort", () => reject(signal.reason), {
            once: true,
          });
        }),
    } as unknown as StreamSyncRegistry;
    return { registry, pending };
  }

  async function started() {
    const { registry, pending } = heldRegistry();
    const push = createRegistryChangePush(registry)!;
    const cycle = vi.fn(async () => {});
    // The probe marker never moves: every cycle that follows is the push's doing.
    const manager = build({
      localSync: { cycle },
      changeProbe: { read: async () => "m1", intervalMs: 5_000, push },
    });
    manager.start();
    await vi.advanceTimersByTimeAsync(0);
    pending[0].answer({ seq: "1", changed: true }); // learns the cursor
    await vi.advanceTimersByTimeAsync(0);
    await manager.requestPull(); // m1 applied
    cycle.mockClear();
    return { manager, pending, cycle };
  }

  it("a changed sequence cycles although the probe marker is unchanged", async () => {
    const { manager, pending, cycle } = await started();
    pending[1].answer({ seq: "2", changed: true });
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(1);
    await manager.stop();
  });

  it("a failed or timed-out attempt starts one cycle, when the push turns unhealthy: the reconnects that follow start none, and the timer applies the rest", async () => {
    const { manager, pending, cycle } = await started();
    // Fail every held request the subscription sends, for a minute.
    let failed = 1;
    for (let waited = 0; waited < 55_000; waited += 1_000) {
      while (failed < pending.length) pending[failed++].fail(new Error("lost"));
      await vi.advanceTimersByTimeAsync(1_000);
    }
    expect(failed).toBeGreaterThanOrEqual(3); // it did reconnect, repeatedly
    // The push turning unhealthy read once; no reconnect after it read again.
    expect(cycle).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(5_000); // the 60 s timer
    expect(cycle).toHaveBeenCalledTimes(2);
    await manager.stop();
  });

  it("the first answer after a failure cycles although neither the sequence nor the marker moved", async () => {
    const { manager, pending, cycle } = await started();
    pending[1].fail(new Error("socket reset"));
    await vi.advanceTimersByTimeAsync(2_000); // back-off, then the next request
    expect(pending.length).toBeGreaterThanOrEqual(3);
    const atFailure = cycle.mock.calls.length; // the push turning unhealthy read
    pending[2].answer({ seq: "1", changed: false });
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(atFailure + 1);
    // Later empty answers do not cycle.
    pending[3].answer({ seq: "1", changed: false });
    await vi.advanceTimersByTimeAsync(0);
    expect(cycle).toHaveBeenCalledTimes(atFailure + 1);
    await manager.stop();
  });
});
