/**
 * A clock the test steps. `advance(ms)` moves time forward, firing each timer
 * at its own moment and letting every settled promise run before it goes on.
 */
export function fakeClock() {
  let time = 0;
  const timers: { until: number; fn: () => void }[] = [];
  const flush = async () => {
    for (let i = 0; i < 30; i++) await Promise.resolve();
  };
  const clock = {
    now: () => time,
    /** Runs `fn` after `ms`; the returned function cancels it. */
    after(ms: number, fn: () => void): () => void {
      const timer = { until: time + ms, fn };
      timers.push(timer);
      return () => {
        const at = timers.indexOf(timer);
        if (at >= 0) timers.splice(at, 1);
      };
    },
    /** Timers still waiting to fire. */
    pending: () => timers.length,
    flush,
    async advance(ms: number): Promise<void> {
      const target = time + ms;
      for (;;) {
        await flush();
        const due = timers
          .filter((t) => t.until <= target)
          .sort((a, b) => a.until - b.until)[0];
        if (!due) break;
        timers.splice(timers.indexOf(due), 1);
        time = Math.max(time, due.until);
        due.fn();
      }
      time = target;
      await flush();
    },
    /** Steps time until `work` settles, and returns what it returned or throws what it threw. */
    async drive<T>(work: Promise<T>, stepMs = 100, limitMs = 3_600_000) {
      let outcome: { ok: T } | { error: unknown } | undefined;
      work.then(
        (ok) => (outcome = { ok }),
        (error: unknown) => (outcome = { error }),
      );
      await flush();
      for (let spent = 0; !outcome && spent < limitMs; spent += stepMs) {
        await clock.advance(stepMs);
      }
      if (!outcome) throw new Error("fake clock: work still pending");
      if ("error" in outcome) throw outcome.error;
      return outcome.ok;
    },
  };
  return clock;
}
export type FakeClock = ReturnType<typeof fakeClock>;
