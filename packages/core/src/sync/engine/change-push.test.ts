// The subscription behind the registry change push.
//
// One held request at a time asks the gateway "has the registry moved since
// sequence S?". An answer with `changed` is a poke; the manager pulls. The
// poke is lossy by design (a lost answer, a dropped socket, a restart), so the
// loop repairs itself by comparing sequences when it reconnects, and says when
// it is NOT healthy so the manager can fall back to its short timed probe.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { StreamSyncRegistry } from "../../stream-sync/ports.js";
import {
  CHANGE_PUSH_WAIT_MS,
  ChangeFeedAbsentError,
  createRegistryChangePush,
} from "./change-push.js";

type Wait = NonNullable<StreamSyncRegistry["waitForChange"]>;
type Answer = { seq: string; changed: boolean };

/** A registry whose held request the test answers, fails or leaves hanging. */
function scripted() {
  const calls: Array<{
    after: string | undefined;
    waitMs: number;
    signal: AbortSignal;
    answer: (a: Answer) => void;
    fail: (e: Error) => void;
  }> = [];
  const waitForChange: Wait = (after, waitMs, signal) =>
    new Promise<Answer>((resolve, reject) => {
      const call = {
        after,
        waitMs,
        signal,
        answer: resolve,
        fail: reject,
      };
      calls.push(call);
      signal.addEventListener("abort", () => reject(signal.reason), {
        once: true,
      });
    });
  return {
    registry: { waitForChange } as unknown as StreamSyncRegistry,
    calls,
  };
}

function subscribed(
  options: Parameters<typeof createRegistryChangePush>[1] = {},
) {
  const s = scripted();
  const push = createRegistryChangePush(s.registry, options)!;
  const pokes = vi.fn();
  const health: boolean[] = [];
  const stop = push.subscribe({
    onChange: pokes,
    onHealth: (h) => health.push(h),
  });
  return { ...s, push, pokes, health, stop };
}

const flush = () => vi.advanceTimersByTimeAsync(0);

beforeEach(() => {
  vi.useFakeTimers();
  vi.spyOn(Math, "random").mockReturnValue(0.5);
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("createRegistryChangePush", () => {
  it("is absent when the registry cannot wait for a change", () => {
    expect(createRegistryChangePush({} as StreamSyncRegistry)).toBeUndefined();
  });

  it("is absent when switched off", () => {
    const s = scripted();
    expect(
      createRegistryChangePush(s.registry, { enabled: false }),
    ).toBeUndefined();
  });

  it("carries the healthy probe period", () => {
    const s = scripted();
    expect(
      createRegistryChangePush(s.registry, { healthyProbeMs: 90_000 })!
        .healthyProbeMs,
    ).toBe(90_000);
    expect(createRegistryChangePush(s.registry)!.healthyProbeMs).toBe(60_000);
  });
});

describe("a subscription", () => {
  it("asks with no cursor first, and a first answer is a poke that makes it healthy", async () => {
    const t = subscribed();
    await flush();
    expect(t.calls).toHaveLength(1);
    expect(t.calls[0]!.after).toBeUndefined();
    expect(t.calls[0]!.waitMs).toBe(CHANGE_PUSH_WAIT_MS);
    t.calls[0]!.answer({ seq: "7", changed: true });
    await flush();
    expect(t.pokes).toHaveBeenCalledTimes(1);
    expect(t.health).toEqual([true]);
    t.stop();
  });

  it("holds the next request with the last sequence it saw", async () => {
    const t = subscribed();
    await flush();
    t.calls[0]!.answer({ seq: "7", changed: true });
    await flush();
    expect(t.calls).toHaveLength(2);
    expect(t.calls[1]!.after).toBe("7");
    t.stop();
  });

  it("does not poke when the wait ran out with nothing changed, and asks again at once", async () => {
    const t = subscribed();
    await flush();
    t.calls[0]!.answer({ seq: "7", changed: true });
    await flush();
    t.calls[1]!.answer({ seq: "7", changed: false });
    await flush();
    expect(t.pokes).toHaveBeenCalledTimes(1);
    expect(t.calls).toHaveLength(3);
    expect(t.calls[2]!.after).toBe("7");
    t.stop();
  });

  it("pokes on every change, however far the sequence jumped", async () => {
    const t = subscribed();
    await flush();
    t.calls[0]!.answer({ seq: "7", changed: true });
    await flush();
    t.calls[1]!.answer({ seq: "19", changed: true }); // a gap of twelve writes
    await flush();
    expect(t.pokes).toHaveBeenCalledTimes(2);
    expect(t.calls[2]!.after).toBe("19");
    t.stop();
  });
});

describe("a poke that never arrives", () => {
  it("is declared dead after the wait plus a grace period, and the subscription says so", async () => {
    const t = subscribed();
    await flush();
    t.calls[0]!.answer({ seq: "7", changed: true });
    await flush();
    expect(t.health).toEqual([true]);
    // The held request hangs: no answer, no error (a half-open socket).
    await vi.advanceTimersByTimeAsync(CHANGE_PUSH_WAIT_MS + 10_000 + 1);
    expect(t.calls[1]!.signal.aborted).toBe(true);
    expect(t.health).toEqual([true, false]);
    t.stop();
  });

  it("is repaired on reconnect: the cursor shows the registry moved, so it pokes once", async () => {
    const t = subscribed();
    await flush();
    t.calls[0]!.answer({ seq: "7", changed: true });
    await flush();
    t.pokes.mockClear();
    await vi.advanceTimersByTimeAsync(CHANGE_PUSH_WAIT_MS + 10_001); // lost
    await vi.advanceTimersByTimeAsync(1_000); // first back-off
    expect(t.calls).toHaveLength(3);
    expect(t.calls[2]!.after).toBe("7");
    t.calls[2]!.answer({ seq: "9", changed: true });
    await flush();
    expect(t.pokes).toHaveBeenCalledTimes(1);
    expect(t.health).toEqual([true, false, true]);
    t.stop();
  });

  it("pokes once on reconnect even when the sequence did not move, since a poke may have been lost on the way", async () => {
    const t = subscribed();
    await flush();
    t.calls[0]!.answer({ seq: "7", changed: true });
    await flush();
    t.pokes.mockClear();
    t.calls[1]!.fail(new Error("socket closed"));
    await flush();
    await vi.advanceTimersByTimeAsync(1_000);
    t.calls[2]!.answer({ seq: "7", changed: false });
    await flush();
    expect(t.pokes).toHaveBeenCalledTimes(1);
    // ...and only once: the next unchanged answer is a plain timeout.
    t.calls[3]!.answer({ seq: "7", changed: false });
    await flush();
    expect(t.pokes).toHaveBeenCalledTimes(1);
    t.stop();
  });
});

describe("a failing gateway", () => {
  it("backs off 1 s, 2 s, 4 s ... up to 30 s and resets after an answer", async () => {
    const t = subscribed();
    await flush();
    const gaps: number[] = [];
    let at = Date.now();
    for (let i = 0; i < 7; i++) {
      t.calls[t.calls.length - 1]!.fail(new Error("503"));
      await flush();
      const before = t.calls.length;
      let waited = 0;
      while (t.calls.length === before && waited < 40_000) {
        await vi.advanceTimersByTimeAsync(500);
        waited += 500;
      }
      gaps.push(waited);
      at = Date.now();
    }
    expect(gaps).toEqual([1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000]);
    expect(t.health.every((h) => h === false)).toBe(true);
    t.calls[t.calls.length - 1]!.answer({ seq: "1", changed: true });
    await flush();
    expect(t.health.at(-1)).toBe(true);
    t.calls[t.calls.length - 1]!.fail(new Error("503"));
    await flush();
    const n = t.calls.length;
    await vi.advanceTimersByTimeAsync(1_000);
    expect(t.calls.length).toBe(n + 1); // back to a 1 s first back-off
    expect(at).toBeGreaterThan(0);
    t.stop();
  });

  it("gives up and stays unhealthy when the gateway has no change route", async () => {
    const t = subscribed();
    await flush();
    t.calls[0]!.fail(new ChangeFeedAbsentError("no route"));
    await flush();
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    expect(t.calls).toHaveLength(1);
    expect(t.pokes).not.toHaveBeenCalled();
    expect(t.health.at(-1) ?? false).toBe(false);
    t.stop();
  });
});

describe("stopping and parking", () => {
  it("aborts the held request, ignores a late answer and asks for nothing more", async () => {
    const t = subscribed();
    await flush();
    t.stop();
    expect(t.calls[0]!.signal.aborted).toBe(true);
    t.calls[0]!.answer({ seq: "7", changed: true });
    await vi.advanceTimersByTimeAsync(60_000);
    expect(t.pokes).not.toHaveBeenCalled();
    expect(t.calls).toHaveLength(1);
  });

  it("holds no request while the host says nobody is looking, and resumes when they are", async () => {
    let active = false;
    const t = subscribed({ active: () => active });
    await vi.advanceTimersByTimeAsync(10_000);
    expect(t.calls).toHaveLength(0);
    active = true;
    await vi.advanceTimersByTimeAsync(2_000);
    expect(t.calls).toHaveLength(1);
    t.stop();
  });
});
