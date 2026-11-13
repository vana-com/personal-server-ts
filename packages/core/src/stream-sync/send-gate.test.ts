import { describe, expect, it } from "vitest";
import {
  DEFAULT_SEND_GATE_POLICY,
  createByteBudget,
  createSendGate,
  type GateTicket,
  type SendGate,
} from "./send-gate.js";
import { fakeClock, type FakeClock } from "./fake-clock.test-helper.js";

function gateOn(clock: FakeClock, overrides = {}): SendGate {
  return createSendGate({ now: clock.now, after: clock.after, ...overrides });
}

/** The next request out of the gate, however long the gate makes it wait. */
async function next(gate: SendGate, clock: FakeClock): Promise<GateTicket> {
  return clock.drive(gate.admit());
}

/** Admit `n` requests one after another and report each as a success. */
async function succeed(gate: SendGate, clock: FakeClock, n: number) {
  for (let i = 0; i < n; i++) (await next(gate, clock)).success();
}

/** Opens the window to `to` by successes alone. */
async function openTo(gate: SendGate, clock: FakeClock, to: number) {
  for (let size = 1; size < to; size++) await succeed(gate, clock, size);
}

describe("the in-flight window", () => {
  it("starts at 1: a second request waits for the first to settle", async () => {
    const clock = fakeClock();
    const gate = gateOn(clock, { maxWindow: 8 });
    const first = await next(gate, clock);
    let secondOut = false;
    void gate.admit().then(() => (secondOut = true));
    await clock.advance(5_000);
    expect(secondOut).toBe(false);
    first.abandon();
    await clock.advance(0);
    expect(secondOut).toBe(true);
  });

  it("grows by one after a window's worth of successes, up to its cap", async () => {
    const clock = fakeClock();
    const gate = gateOn(clock, { maxWindow: 3 });
    expect(gate.stats().window).toBe(1);
    await succeed(gate, clock, 1); // 1 success fills a window of 1
    expect(gate.stats().window).toBe(2);
    await succeed(gate, clock, 1);
    expect(gate.stats().window).toBe(2); // 1 of 2
    await succeed(gate, clock, 1);
    expect(gate.stats().window).toBe(3);
    await succeed(gate, clock, 9);
    expect(gate.stats().window).toBe(3); // the cap
  });

  it("halves on a 503, never below 1", async () => {
    const clock = fakeClock();
    const gate = gateOn(clock, { maxWindow: 8 });
    await openTo(gate, clock, 8);
    expect(gate.stats().window).toBe(8);
    (await next(gate, clock)).congested();
    expect(gate.stats().window).toBe(4);
    (await next(gate, clock)).congested();
    (await next(gate, clock)).congested();
    (await next(gate, clock)).congested();
    expect(gate.stats().window).toBe(1);
  });

  it("halves once for the 503s of requests sent before the first halving", async () => {
    const clock = fakeClock();
    const gate = gateOn(clock, { maxWindow: 8 });
    await openTo(gate, clock, 8);
    const sent = await Promise.all(
      Array.from({ length: 8 }, () => gate.admit()),
    );
    for (const ticket of sent) ticket.congested();
    expect(gate.stats().window).toBe(4);
    expect(gate.stats().throttles).toBe(8);
  });

  it("does not shrink on a 429: only the wait changes", async () => {
    const clock = fakeClock();
    const gate = gateOn(clock, { maxWindow: 8 });
    await openTo(gate, clock, 4);
    expect(gate.stats().window).toBe(4);
    (await next(gate, clock)).quotaExceeded(60_000);
    expect(gate.stats().window).toBe(4);
    expect(gate.stats().throttles).toBe(1);
  });

  it("lets only the current epoch's requests count toward growth", async () => {
    const clock = fakeClock();
    const gate = gateOn(clock, { maxWindow: 16 });
    await openTo(gate, clock, 8);
    const first = await next(gate, clock);
    const staleA = await next(gate, clock);
    const staleB = await next(gate, clock);
    first.congested(); // halves to 4: a new epoch begins; two old requests are still out
    expect(gate.stats().window).toBe(4);
    (await next(gate, clock)).success(); // 1 of the 4 successes the new window needs
    staleA.congested(); // an old answer: it must not halve again, nor reset that count
    expect(gate.stats().window).toBe(4);
    staleB.success(); // nor may an old success count toward growth
    await succeed(gate, clock, 2); // 3 of 4
    expect(gate.stats().window).toBe(4);
    await succeed(gate, clock, 1); // 4 of 4
    expect(gate.stats().window).toBe(5);
  });

  it("holds every caller for no longer than its bound, whatever the server asked", async () => {
    const clock = fakeClock();
    const gate = gateOn(clock, { maxHoldMs: 10_000 });
    (await next(gate, clock)).quotaExceeded(7 * 24 * 60 * 60 * 1000);
    const left: number[] = [];
    void gate.admit().then(() => left.push(clock.now()));
    await clock.advance(9_999);
    expect(left).toEqual([]);
    await clock.advance(2);
    expect(left).toEqual([10_000]);
    expect(gate.stats().retryAfterWaitMs).toBe(10_000);
  });

  it("ignores a wait that is not a finite number", async () => {
    const clock = fakeClock();
    const gate = gateOn(clock);
    (await next(gate, clock)).quotaExceeded(Number.POSITIVE_INFINITY);
    (await next(gate, clock)).congested(Number.NaN);
    const left: number[] = [];
    void gate.admit().then(() => left.push(clock.now()));
    await clock.advance(0);
    expect(left).toEqual([0]);
  });
});

describe("a caller that stops waiting", () => {
  it("leaves the queue when its signal aborts, and never takes a slot", async () => {
    const clock = fakeClock();
    const gate = gateOn(clock, { maxWindow: 4 });
    const first = await next(gate, clock);
    const stop = new AbortController();
    const abandoned = gate.admit(stop.signal);
    const abandonedResult = abandoned.then(
      () => "admitted",
      (reason: unknown) => reason,
    );
    let thirdOut = false;
    void gate.admit().then(() => (thirdOut = true));
    await clock.advance(1_000);
    stop.abort("gave up");
    expect(await abandonedResult).toBe("gave up");
    first.abandon();
    await clock.advance(0);
    // The aborted request took no slot: the one behind it leaves.
    expect(thirdOut).toBe(true);
    expect(gate.stats().requests).toBe(2);
  });

  it("rejects at once when its signal is already aborted", async () => {
    const gate = createSendGate();
    const stop = new AbortController();
    stop.abort("already");
    await expect(gate.admit(stop.signal)).rejects.toBe("already");
    expect(gate.stats().requests).toBe(0);
  });

  it("leaves a wait for a spent quota too, with no timer left behind", async () => {
    const clock = fakeClock();
    const gate = gateOn(clock);
    gate.setQuota({ limit: 1, windowMs: 3_600_000 });
    (await next(gate, clock)).success();
    const stop = new AbortController();
    const waiting = gate.admit(stop.signal).catch((e: unknown) => e);
    await clock.advance(1_000);
    stop.abort("deadline");
    expect(await waiting).toBe("deadline");
    // The gate's own wait is woken and ended with the last waiter.
    await clock.advance(0);
    expect(clock.pending()).toBe(0);
  });
});

describe("the quota tokens", () => {
  const perSecond = { limit: 1, windowMs: 1_000 };

  it("paces to a published quota and never exceeds it", async () => {
    const clock = fakeClock();
    // 10 requests per 10 s; a wide window, so only the tokens limit it.
    const gate = gateOn(clock, { maxWindow: 16 });
    gate.setQuota({ limit: 10, windowMs: 10_000 });
    await openTo(gate, clock, 16);
    const left: number[] = [];
    for (let i = 0; i < 40; i++) {
      void gate.admit().then((t) => {
        left.push(clock.now());
        t.success();
      });
    }
    await clock.advance(60_000);
    expect(left.length).toBe(40);
    for (const start of left) {
      const inWindow = left.filter((t) => t >= start && t < start + 10_000);
      expect(inWindow.length).toBeLessThanOrEqual(10);
    }
  });

  it("paces nothing when the service publishes no quota", async () => {
    const clock = fakeClock();
    const gate = gateOn(clock, { maxWindow: 4 });
    await openTo(gate, clock, 4);
    const left: number[] = [];
    for (let i = 0; i < 4; i++) {
      void gate.admit().then(() => left.push(clock.now()));
    }
    await clock.advance(0);
    expect(left).toEqual([0, 0, 0, 0]);
    expect(gate.stats().quotaPerSec).toBeUndefined();
  });

  it("spends a token when a request leaves, and a reply gives none back", async () => {
    const clock = fakeClock();
    const gate = gateOn(clock, { maxWindow: 4 });
    gate.setQuota(perSecond);
    const first = await next(gate, clock);
    expect(clock.now()).toBe(0);
    // The reply comes back early; the next token is still a second after the send.
    await clock.advance(100);
    first.success();
    const second: number[] = [];
    void gate.admit().then(() => second.push(clock.now()));
    await clock.advance(2_000);
    expect(second).toEqual([1_000]);
  });

  it("holds every caller for a 429's Retry-After, then paces them again", async () => {
    const clock = fakeClock();
    const gate = gateOn(clock, { maxWindow: 4 });
    gate.setQuota({ limit: 4, windowMs: 1_000 });
    (await next(gate, clock)).quotaExceeded(60_000);
    const left: number[] = [];
    for (let i = 0; i < 3; i++) {
      void gate.admit().then((t) => {
        left.push(clock.now());
        t.success();
      });
    }
    await clock.advance(59_999);
    expect(left).toEqual([]);
    await clock.advance(2_000);
    expect(left).toEqual([60_000, 60_250, 60_500]);
    expect(gate.stats().retryAfterWaitMs).toBe(60_000);
  });

  it("follows a quota that changes, and a waiter sleeping on the old one wakes", async () => {
    const clock = fakeClock();
    const gate = gateOn(clock, { maxWindow: 4 });
    gate.setQuota({ limit: 1, windowMs: 86_400_000 });
    expect(gate.stats().quotaPerSec).toBeCloseTo(1 / 86_400);
    (await next(gate, clock)).success();
    const left: number[] = [];
    void gate.admit().then(() => left.push(clock.now()));
    await clock.advance(1_000);
    expect(left).toEqual([]); // a day away
    gate.setQuota({ limit: 1, windowMs: 1_000 });
    expect(gate.stats().quotaPerSec).toBe(1);
    await clock.advance(1_000);
    expect(left.length).toBe(1);
    gate.setQuota(undefined);
    expect(gate.stats().quotaPerSec).toBeUndefined();
  });
});

describe("one place to wait", () => {
  it("a request leaves only when the window, the resume time and a token all allow it", async () => {
    const clock = fakeClock();
    const gate = gateOn(clock, { maxWindow: 4 });
    gate.setQuota({ limit: 1, windowMs: 1_000 });
    const first = await next(gate, clock); // takes the window's one slot and the token
    gate.holdFor(5_000);
    const left: number[] = [];
    void gate.admit().then(() => left.push(clock.now()));
    await clock.advance(1_500); // token back, resume time not passed, slot taken
    expect(left).toEqual([]);
    first.success(); // slot free (and the window is now 2)
    await clock.advance(1_000); // slot free, token back, resume time not passed
    expect(left).toEqual([]);
    await clock.advance(3_000);
    expect(left).toEqual([5_000]);
  });
});

describe("createSendGate parameters", () => {
  it("refuses parameters that would stall or run away", () => {
    expect(() => createSendGate({ maxWindow: 0 })).toThrow(RangeError);
    expect(() => createSendGate({ maxWindow: 1.5 })).toThrow(RangeError);
    expect(() => createSendGate({ maxHoldMs: Number.NaN })).toThrow(RangeError);
  });

  it("caps the default window at the 64 MiB budget over 4 MiB parts", () => {
    expect(DEFAULT_SEND_GATE_POLICY.maxWindow).toBe(
      (64 * 1024 * 1024) / (4 * 1024 * 1024),
    );
  });
});

describe("createByteBudget", () => {
  const flush = async () => {
    for (let i = 0; i < 20; i++) await Promise.resolve();
  };

  it("holds the bytes in use under the limit with 50 streams asking at once", async () => {
    let peak = 0;
    const budget = createByteBudget(16, (inUse) => {
      peak = Math.max(peak, inUse);
    });
    let finished = 0;
    const stream = async () => {
      // Each stream reserves one part of 4 units and holds it while it "uploads".
      for (let part = 0; part < 3; part++) {
        const release = await budget.reserve(4);
        await new Promise((resolve) => setTimeout(resolve, 1));
        release();
      }
      finished += 1;
    };
    await Promise.all(Array.from({ length: 50 }, stream));
    expect(finished).toBe(50);
    expect(peak).toBeLessThanOrEqual(16);
    expect(peak).toBe(16);
    expect(budget.inUse()).toBe(0);
  });

  it("lets one part larger than the whole budget through, alone", async () => {
    const budget = createByteBudget(10);
    const small = await budget.reserve(4);
    let bigHeld = false;
    const big = budget.reserve(25).then((release) => {
      bigHeld = true;
      return release;
    });
    await flush();
    // It waits for the small hold to end: nothing else may be held beside it.
    expect(bigHeld).toBe(false);
    small();
    const releaseBig = await big;
    expect(bigHeld).toBe(true);
    expect(budget.inUse()).toBe(25);
    let smallAgain = false;
    void budget.reserve(1).then(() => (smallAgain = true));
    await flush();
    expect(smallAgain).toBe(false);
    releaseBig();
    await flush();
    expect(smallAgain).toBe(true);
  });

  it("proceeds at once with an oversized part when nothing is held", async () => {
    const budget = createByteBudget(10);
    const release = await budget.reserve(1_000);
    expect(budget.inUse()).toBe(1_000);
    release();
    expect(budget.inUse()).toBe(0);
  });

  it("serves waiters in order and ignores a second release", async () => {
    const budget = createByteBudget(10);
    const first = await budget.reserve(10);
    const order: string[] = [];
    const a = budget.reserve(6).then((r) => (order.push("a"), r));
    const b = budget.reserve(6).then((r) => (order.push("b"), r));
    first();
    first();
    expect(budget.inUse()).toBe(6);
    const releaseA = await a;
    await flush();
    expect(order).toEqual(["a"]);
    releaseA();
    await b;
    expect(order).toEqual(["a", "b"]);
  });
});
