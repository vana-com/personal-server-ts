// The subscription behind the registry change push.
//
// One held request at a time asks the gateway "has the registry moved since
// cursor S?". An answer with `changed` is a poke; the manager pulls. The
// poke is lossy by design (a lost answer, a dropped socket, a restart), so the
// loop repairs itself by comparing cursors when it reconnects, and says when
// it is NOT healthy so the manager can fall back to its short timed probe.
import { getEventListeners } from "node:events";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { StreamSyncRegistry } from "../../stream-sync/ports.js";
import {
  CHANGE_PUSH_WAIT_MS,
  ChangeFeedAbsentError,
  createRegistryChangePush,
} from "./change-push.js";

type Wait = NonNullable<StreamSyncRegistry["waitForChange"]>;
type Answer = { cursor: string; changed: boolean };

/** A registry whose held request the test answers, fails or leaves hanging. */
function scripted() {
  const calls: Array<{
    after: string | undefined;
    since: string | undefined;
    waitMs: number;
    signal: AbortSignal;
    answer: (a: Answer) => void;
    fail: (e: Error) => void;
  }> = [];
  const waitForChange: Wait = (after, waitMs, signal, since) =>
    new Promise<Answer>((resolve, reject) => {
      const call = {
        after,
        since,
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
  const positions: string[] = [];
  const order: string[] = [];
  const stop = push.subscribe({
    onChange: () => {
      order.push("change");
      pokes();
    },
    onHealth: (h) => health.push(h),
    onPosition: (p) => {
      order.push(`position:${p}`);
      positions.push(p);
    },
    since: () => undefined,
  });
  return { ...s, push, pokes, health, positions, order, stop };
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
});

describe("a subscription", () => {
  it("asks with no cursor first, and a first answer is a poke that makes it healthy", async () => {
    const t = subscribed();
    await flush();
    expect(t.calls).toHaveLength(1);
    expect(t.calls[0]!.after).toBeUndefined();
    expect(t.calls[0]!.waitMs).toBe(CHANGE_PUSH_WAIT_MS);
    t.calls[0]!.answer({ cursor: "7", changed: true });
    await flush();
    expect(t.pokes).toHaveBeenCalledTimes(1);
    expect(t.health).toEqual([true]);
    t.stop();
  });

  it("reports each answer's cursor as the position, before it pokes", async () => {
    // The manager compares this position with the one its last clean cycle
    // read at, so the position must be set before the cycle the poke starts.
    const t = subscribed();
    await flush();
    t.calls[0]!.answer({ cursor: "7", changed: true });
    await flush();
    t.calls[1]!.answer({ cursor: "7", changed: false });
    await flush();
    t.calls[2]!.answer({ cursor: "9", changed: true });
    await flush();
    expect(t.positions).toEqual(["7", "7", "9"]);
    expect(t.order).toEqual([
      "position:7",
      "change",
      "position:7",
      "position:9",
      "change",
    ]);
    t.stop();
  });

  it("holds the next request with the last cursor it saw", async () => {
    const t = subscribed();
    await flush();
    t.calls[0]!.answer({ cursor: "7", changed: true });
    await flush();
    expect(t.calls).toHaveLength(2);
    expect(t.calls[1]!.after).toBe("7");
    t.stop();
  });

  it("does not poke when the wait ran out with nothing changed, and asks again at once", async () => {
    const t = subscribed();
    await flush();
    t.calls[0]!.answer({ cursor: "7", changed: true });
    await flush();
    t.calls[1]!.answer({ cursor: "7", changed: false });
    await flush();
    expect(t.pokes).toHaveBeenCalledTimes(1);
    expect(t.calls).toHaveLength(3);
    expect(t.calls[2]!.after).toBe("7");
    t.stop();
  });

  it("pokes on every change, however far the cursor jumped", async () => {
    const t = subscribed();
    await flush();
    t.calls[0]!.answer({ cursor: "7", changed: true });
    await flush();
    t.calls[1]!.answer({ cursor: "19", changed: true }); // a gap of twelve writes
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
    t.calls[0]!.answer({ cursor: "7", changed: true });
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
    t.calls[0]!.answer({ cursor: "7", changed: true });
    await flush();
    t.pokes.mockClear();
    await vi.advanceTimersByTimeAsync(CHANGE_PUSH_WAIT_MS + 10_001); // lost
    await vi.advanceTimersByTimeAsync(1_000); // first back-off
    expect(t.calls).toHaveLength(3);
    expect(t.calls[2]!.after).toBe("7");
    t.calls[2]!.answer({ cursor: "9", changed: true });
    await flush();
    expect(t.pokes).toHaveBeenCalledTimes(1);
    expect(t.health).toEqual([true, false, true]);
    t.stop();
  });

  it("pokes once on reconnect even when the cursor did not move, since a poke may have been lost on the way", async () => {
    const t = subscribed();
    await flush();
    t.calls[0]!.answer({ cursor: "7", changed: true });
    await flush();
    t.pokes.mockClear();
    t.calls[1]!.fail(new Error("socket closed"));
    await flush();
    await vi.advanceTimersByTimeAsync(1_000);
    t.calls[2]!.answer({ cursor: "7", changed: false });
    await flush();
    expect(t.pokes).toHaveBeenCalledTimes(1);
    // ...and only once: the next unchanged answer is a plain timeout.
    t.calls[3]!.answer({ cursor: "7", changed: false });
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
    t.calls[t.calls.length - 1]!.answer({ cursor: "1", changed: true });
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

  it("stays unhealthy without a route and asks again after one held period, not sooner", async () => {
    const t = subscribed();
    await flush();
    t.calls[0]!.fail(new ChangeFeedAbsentError("no route"));
    await flush();
    expect(t.health.at(-1) ?? false).toBe(false);
    await vi.advanceTimersByTimeAsync(CHANGE_PUSH_WAIT_MS - 1);
    expect(t.calls).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(t.calls).toHaveLength(2);
    t.calls[1]!.fail(new ChangeFeedAbsentError("no route"));
    await flush();
    // One request per held period, the most a present route would cost.
    await vi.advanceTimersByTimeAsync(CHANGE_PUSH_WAIT_MS - 1);
    expect(t.calls).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(t.calls).toHaveLength(3);
    expect(t.pokes).not.toHaveBeenCalled();
    t.stop();
  });

  it("picks up a route the gateway gains later: the first answer is healthy and pokes", async () => {
    const t = subscribed();
    await flush();
    t.calls[0]!.fail(new ChangeFeedAbsentError("no route"));
    await flush();
    await vi.advanceTimersByTimeAsync(CHANGE_PUSH_WAIT_MS);
    t.calls[1]!.answer({ cursor: "3", changed: true });
    await flush();
    expect(t.health.at(-1)).toBe(true);
    expect(t.pokes).toHaveBeenCalledTimes(1);
    t.stop();
  });
});

describe("the held period", () => {
  it.each([NaN, Infinity, -Infinity, 0, -5])(
    "uses the default when the host gives %s",
    async (waitMs) => {
      const t = subscribed({ waitMs });
      await flush();
      expect(t.calls[0]!.waitMs).toBe(CHANGE_PUSH_WAIT_MS);
      t.stop();
    },
  );

  it("keeps a finite positive period the host gives", async () => {
    const t = subscribed({ waitMs: 9_000 });
    await flush();
    expect(t.calls[0]!.waitMs).toBe(9_000);
    t.stop();
  });
});

describe("stopping and parking", () => {
  it("aborts the held request, ignores a late answer and asks for nothing more", async () => {
    const t = subscribed();
    await flush();
    t.stop();
    expect(t.calls[0]!.signal.aborted).toBe(true);
    t.calls[0]!.answer({ cursor: "7", changed: true });
    await vi.advanceTimersByTimeAsync(60_000);
    expect(t.pokes).not.toHaveBeenCalled();
    expect(t.calls).toHaveLength(1);
  });
});

describe("a request the registry never cancels", () => {
  /** A registry that ignores the signal: only `answer` ends the request. */
  function deaf() {
    const answers: Array<(a: Answer) => void> = [];
    const waitForChange: Wait = () =>
      new Promise<Answer>((resolve) => answers.push(resolve));
    return {
      registry: { waitForChange } as unknown as StreamSyncRegistry,
      answers,
    };
  }

  it("unsubscribing clears the request deadline at once, and a late answer does nothing", async () => {
    const d = deaf();
    const push = createRegistryChangePush(d.registry)!;
    const pokes = vi.fn();
    const health: boolean[] = [];
    const stop = push.subscribe({
      onChange: pokes,
      onHealth: (h) => health.push(h),
      onPosition: () => {},
      since: () => undefined,
    });
    await flush();
    expect(vi.getTimerCount()).toBe(1); // the request's deadline
    stop();
    expect(vi.getTimerCount()).toBe(0); // gone before any time passes
    d.answers[0]!({ cursor: "9", changed: true }); // the registry answers late
    await vi.advanceTimersByTimeAsync(CHANGE_PUSH_WAIT_MS * 3);
    expect(pokes).not.toHaveBeenCalled();
    expect(health).toEqual([]);
    expect(d.answers).toHaveLength(1); // and asks for nothing more
  });

  it("an answer that arrives after its request's deadline is dropped: answers reach the manager in the order the gateway gave them", async () => {
    // Cursors have no order, so nothing downstream can tell a late answer from
    // a new one. The push alone guarantees it: one request at a time, and the
    // answer of one it gave up on is never delivered.
    const d = deaf();
    const push = createRegistryChangePush(d.registry)!;
    const positions: string[] = [];
    const pokes = vi.fn();
    const stop = push.subscribe({
      onChange: pokes,
      onHealth: () => {},
      onPosition: (p) => positions.push(p as unknown as string),
      since: () => undefined,
    });
    await flush();
    d.answers[0]!({ cursor: "c9", changed: true });
    await flush();
    expect(positions).toEqual(["c9"]);
    await vi.advanceTimersByTimeAsync(CHANGE_PUSH_WAIT_MS + 10_001); // gave up
    await vi.advanceTimersByTimeAsync(1_000); // the back-off, then a new request
    expect(d.answers).toHaveLength(3);
    d.answers[1]!({ cursor: "c10", changed: true }); // the abandoned request answers late
    await flush();
    expect(positions).toEqual(["c9"]);
    expect(pokes).toHaveBeenCalledTimes(1);
    d.answers[2]!({ cursor: "c11", changed: true });
    await flush();
    expect(positions).toEqual(["c9", "c11"]);
    stop();
  });
});

describe("listeners on the subscription's lifetime signal", () => {
  /** The subscription's own AbortController: the first one it creates. */
  function captureLifetime() {
    const created: AbortController[] = [];
    const Real = globalThis.AbortController;
    vi.stubGlobal(
      "AbortController",
      class extends Real {
        constructor() {
          super();
          created.push(this);
        }
      },
    );
    return created;
  }
  const abortListeners = (c: AbortController) =>
    getEventListeners(c.signal, "abort").length;

  it("a gateway outage that backs off repeatedly keeps one listener, not one per back-off", async () => {
    const created = captureLifetime();
    const { calls, stop } = subscribed();
    await flush();
    const lifetime = created[0];
    for (let i = 0; i < 12; i++) {
      calls[calls.length - 1].fail(new Error("down"));
      await vi.advanceTimersByTimeAsync(40_000); // past the longest back-off
    }
    expect(abortListeners(lifetime)).toBeLessThanOrEqual(2);
    stop();
    expect(abortListeners(lifetime)).toBe(0);
    vi.unstubAllGlobals();
  });
});

describe("the delta", () => {
  it("each held request after the first carries the manager's since, read as it is sent (mutation: since never sent)", async () => {
    const s = scripted();
    const sent: Array<string | undefined> = [];
    const wait = s.registry.waitForChange!;
    (s.registry as { waitForChange: Wait }).waitForChange = (
      after,
      waitMs,
      signal,
      since,
    ) => {
      sent.push(since);
      return wait(after, waitMs, signal, undefined);
    };
    let held: string | undefined = "4";
    const push = createRegistryChangePush(s.registry)!;
    const stop = push.subscribe({
      onChange: () => {},
      onHealth: () => {},
      onPosition: () => {},
      since: () => held,
    });
    await flush();
    s.calls[0].answer({ cursor: "4", changed: true });
    await flush();
    held = "5";
    s.calls[1].answer({ cursor: "5", changed: true });
    await flush();
    // The first request has no cursor and so no delta to ask for.
    expect(sent).toEqual([undefined, "4", "5"]);
    stop();
  });

  it("a changed answer hands its delta to onChange; the poke after a failure has none (mutation: delta on every poke)", async () => {
    const s = scripted();
    const push = createRegistryChangePush(s.registry)!;
    const deltas: unknown[] = [];
    const stop = push.subscribe({
      onChange: (d) => deltas.push(d),
      onHealth: () => {},
      onPosition: () => {},
      since: () => "4",
    });
    await flush();
    s.calls[0].answer({ cursor: "4", changed: true });
    await flush();
    const delta = {
      since: "4",
      cursor: "5",
      reset: true as const,
    };
    (s.calls[1].answer as (a: unknown) => void)({
      cursor: "5",
      changed: true,
      delta,
    });
    await flush();
    s.calls[2].fail(new Error("down"));
    await vi.advanceTimersByTimeAsync(5_000);
    (s.calls[3].answer as (a: unknown) => void)({
      cursor: "5",
      changed: false,
      delta,
    });
    await flush();
    expect(deltas).toEqual([undefined, delta, undefined]);
    stop();
  });
});

// The gateway's database has a generation, carried inside every cursor. The
// push does not read it: when the database is replaced the gateway answers a
// held request at once with `changed` and a reset delta, and the push passes
// that on like any other answer. The same behaviour against a gateway that
// mints real cursors is in change-feed-cursor.test.ts.
describe("a replaced database", () => {
  it("the gateway's reset is handed on once, not doubled, and the next request holds the new cursor", async () => {
    const s = scripted();
    const push = createRegistryChangePush(s.registry)!;
    const changes: unknown[] = [];
    const positions: string[] = [];
    const stop = push.subscribe({
      onChange: (d) => changes.push(d),
      onHealth: () => {},
      onPosition: (p) => positions.push(p as unknown as string),
      since: () => "old:4" as never,
    });
    await flush();
    s.calls[0].answer({ cursor: "old:40", changed: true });
    await flush();
    const delta = { since: "old:4", cursor: "new:3", reset: true as const };
    (s.calls[1].answer as (a: unknown) => void)({
      cursor: "new:3",
      changed: true,
      delta,
    });
    await flush();
    expect(changes).toEqual([undefined, delta]);
    // The position is reported before the change, and is the new cursor as is.
    expect(positions).toEqual(["old:40", "new:3"]);
    expect(s.calls[2].after).toBe("new:3");
    stop();
  });
});
