/**
 * Bounded re-submission of a user's delete whose gateway tombstone failed.
 *
 * A tombstone the gateway queued can fail to settle. The gateway then rolls
 * the head back and reports the scope live again, though the user asked to
 * delete it. The retry pass re-submits the delete through the ordinary delete
 * path; this tracker bounds how often. Attempt n waits
 * `baseDelayMs * 2^(n-2)` after attempt n-1 (the first runs at once), and
 * after `maxAttempts` failed re-submissions the scope is reported as failed
 * and left alone until the user deletes it again.
 *
 * In memory per sync manager: a restart starts the count again, so the bound
 * is per boot.
 */
export interface TombstoneResubmitState {
  scope: string;
  /** Re-submissions made so far (the user's own delete is not counted). */
  attempts: number;
  /** The failed tombstone version last seen for the scope. */
  tombstoneVersion: string;
  /** ISO time of the last re-submission. */
  lastAttemptAt: string;
}

export interface TombstoneResubmitSnapshot {
  /** Scopes with a re-submission in progress or due. */
  retrying: TombstoneResubmitState[];
  /** Scopes whose delete did not complete after the last allowed attempt. */
  failed: Array<TombstoneResubmitState & { failedAt: string }>;
}

export interface TombstoneResubmitTracker {
  /** Whether another re-submission is allowed now. */
  due(scope: string): boolean;
  /** True once the scope has used every attempt and been reported. */
  exhausted(scope: string): boolean;
  /** True when the scope has used every attempt but is not reported yet. */
  outOfAttempts(scope: string): boolean;
  /** Count one re-submission; returns the attempt number. */
  recordAttempt(scope: string, tombstoneVersion: string): number;
  /** Report the scope as failed (after the last attempt also failed). */
  giveUp(scope: string, tombstoneVersion: string): TombstoneResubmitState;
  /** Forget the scope: the delete converged, or the user deleted it again. */
  reset(scope: string): void;
  snapshot(): TombstoneResubmitSnapshot;
}

export const DEFAULT_TOMBSTONE_RESUBMIT_MAX_ATTEMPTS = 5;
export const DEFAULT_TOMBSTONE_RESUBMIT_BASE_DELAY_MS = 60_000;

export function createTombstoneResubmitTracker(
  options: {
    maxAttempts?: number;
    baseDelayMs?: number;
    now?: () => number;
  } = {},
): TombstoneResubmitTracker {
  const maxAttempts =
    options.maxAttempts ?? DEFAULT_TOMBSTONE_RESUBMIT_MAX_ATTEMPTS;
  const baseDelayMs =
    options.baseDelayMs ?? DEFAULT_TOMBSTONE_RESUBMIT_BASE_DELAY_MS;
  const now = options.now ?? Date.now;
  const states = new Map<
    string,
    {
      attempts: number;
      tombstoneVersion: string;
      lastAttemptMs: number;
      failedAtMs: number | null;
    }
  >();

  const view = (scope: string): TombstoneResubmitState | null => {
    const state = states.get(scope);
    return state
      ? {
          scope,
          attempts: state.attempts,
          tombstoneVersion: state.tombstoneVersion,
          lastAttemptAt: new Date(state.lastAttemptMs).toISOString(),
        }
      : null;
  };

  return {
    due(scope) {
      const state = states.get(scope);
      if (!state) return true;
      if (state.failedAtMs !== null || state.attempts >= maxAttempts)
        return false;
      const wait = baseDelayMs * 2 ** (state.attempts - 1);
      return now() - state.lastAttemptMs >= wait;
    },
    exhausted(scope) {
      return states.get(scope)?.failedAtMs != null;
    },
    outOfAttempts(scope) {
      const state = states.get(scope);
      return (
        state !== undefined &&
        state.failedAtMs === null &&
        state.attempts >= maxAttempts
      );
    },
    recordAttempt(scope, tombstoneVersion) {
      const state = states.get(scope);
      const attempts = (state?.attempts ?? 0) + 1;
      states.set(scope, {
        attempts,
        tombstoneVersion,
        lastAttemptMs: now(),
        failedAtMs: null,
      });
      return attempts;
    },
    giveUp(scope, tombstoneVersion) {
      const state = states.get(scope) ?? {
        attempts: 0,
        tombstoneVersion,
        lastAttemptMs: now(),
        failedAtMs: null,
      };
      states.set(scope, { ...state, tombstoneVersion, failedAtMs: now() });
      return view(scope)!;
    },
    reset(scope) {
      states.delete(scope);
    },
    snapshot() {
      const retrying: TombstoneResubmitState[] = [];
      const failed: TombstoneResubmitSnapshot["failed"] = [];
      for (const [scope, state] of states) {
        const entry = view(scope)!;
        if (state.failedAtMs === null) retrying.push(entry);
        else
          failed.push({
            ...entry,
            failedAt: new Date(state.failedAtMs).toISOString(),
          });
      }
      return { retrying, failed };
    },
  };
}
