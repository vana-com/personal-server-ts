import type { LocalSyncDeps } from "./deps.js";

/**
 * One interval of a log publish: when it began (from the start of the publish)
 * and how long it took. Phases may overlap, so their `ms` need not add up to the
 * publish's total, and `atMs` shows which ones ran side by side.
 */
export interface PublishPhase {
  readonly name: string;
  readonly atMs: number;
  readonly ms: number;
}

/** The phases of one `publishLog` call, in the order they finished. */
export interface PhaseClock {
  readonly phases: readonly PublishPhase[];
  /** A moment to pass to `record` later. */
  now(): number;
  record(name: string, from: number): void;
  /** Run `work` as one phase, also when it throws. */
  time<T>(name: string, work: () => Promise<T>): Promise<T>;
  /** Whether a phase of this name ran. */
  ran(name: string): boolean;
  totalMs(): number;
}

export function openPhases(deps: Pick<LocalSyncDeps, "now">): PhaseClock {
  const startedAt = deps.now();
  const phases: PublishPhase[] = [];
  const record = (name: string, from: number) => {
    phases.push({ name, atMs: from - startedAt, ms: deps.now() - from });
  };
  return {
    phases,
    now: () => deps.now(),
    record,
    async time(name, work) {
      const from = deps.now();
      try {
        return await work();
      } finally {
        record(name, from);
      }
    },
    ran: (name) => phases.some((phase) => phase.name === name),
    totalMs: () => deps.now() - startedAt,
  };
}

/**
 * The one info line a log publish that put something on the wire ends with, so a
 * journey reads where the time went. A publish with nothing to send (a quiet
 * poll) logs nothing: it would add a line per connection every cycle.
 */
export function logPublishPhases(
  deps: Pick<LocalSyncDeps, "logger">,
  connectionId: string,
  clock: PhaseClock,
): void {
  if (
    !clock.ran("segment-put") &&
    !clock.ran("attachments") &&
    !clock.ran("registry-commit")
  )
    return;
  deps.logger.info(
    {
      connectionId,
      totalMs: clock.totalMs(),
      phases: clock.phases.map((p) => `${p.name}@${p.atMs}+${p.ms}`),
    },
    "stream sync: log publish timings",
  );
}
