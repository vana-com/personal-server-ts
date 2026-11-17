/**
 * Where one apply job's wall time goes, for its one log line. It counts what
 * waits on another machine or on the database, and how many of each were in
 * flight together at the peak: a peak of 1 over several fetches means they ran
 * one after another.
 */
export type ApplyWait = "registry" | "fetch" | "decrypt" | "write";

interface Tally {
  n: number;
  /** Sum of the durations; above the job's wall time when they overlapped. */
  ms: number;
  live: number;
  peak: number;
}

export interface ApplyMeter {
  time<T>(kind: ApplyWait, work: () => Promise<T>): Promise<T>;
  /** The line to log, or null when the job waited on nothing. */
  report(
    wallMs: number,
  ): Record<string, number | Record<string, number>> | null;
}

export function createApplyMeter(
  clock: () => number = () => performance.now(),
): ApplyMeter {
  const tallies = new Map<ApplyWait, Tally>();
  return {
    async time(kind, work) {
      const tally = tallies.get(kind) ?? { n: 0, ms: 0, live: 0, peak: 0 };
      tallies.set(kind, tally);
      tally.n++;
      tally.live++;
      tally.peak = Math.max(tally.peak, tally.live);
      const began = clock();
      try {
        return await work();
      } finally {
        tally.ms += clock() - began;
        tally.live--;
      }
    },
    report(wallMs) {
      if (tallies.size === 0) return null;
      const out: Record<string, number | Record<string, number>> = {
        wallMs: Math.round(wallMs),
      };
      for (const [kind, t] of tallies)
        out[kind] = { n: t.n, ms: Math.round(t.ms), peak: t.peak };
      return out;
    },
  };
}
