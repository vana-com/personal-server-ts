import type { PlanHead } from "../stream-sync/publish-plan.js";

/** What `planStreamStep` reads of one run stream and its local stream state. */
export type StreamPlanRow = {
  readonly primary_key: string | null;
  readonly profile_key: string | null;
  readonly profile_version: string | null;
  readonly local_primary_key: string;
  readonly local_profile_key: string | null;
  readonly local_profile_version: string | null;
  readonly complete: number;
  readonly head_version: number;
  readonly head_generation: number | null;
  readonly floor_version: string | null;
  readonly floor_o: number | null;
};

/**
 * The run's key and profile, and the local head the run meets. Run end and
 * batch admission both ask `planStreamStep` and must give it the same facts.
 */
export function planInputs(
  stream: StreamPlanRow,
  run: {
    readonly generation: number | null;
    readonly artifact_version: string;
  },
  connector: string,
): {
  readonly primaryKey: string[];
  readonly profile: { key: string; version: string };
  readonly head: PlanHead | null;
} {
  const primaryKey = JSON.parse(
    stream.primary_key ?? stream.local_primary_key,
  ) as string[];
  const profile = {
    key: stream.profile_key ?? connector,
    version: stream.profile_version ?? run.artifact_version,
  };
  const head: PlanHead | null =
    stream.head_version > 0 || stream.floor_o !== null
      ? {
          generation: stream.head_generation ?? run.generation,
          primaryKey: JSON.parse(stream.local_primary_key) as string[],
          profile: {
            key: stream.local_profile_key ?? connector,
            version:
              stream.local_profile_version ??
              stream.floor_version ??
              run.artifact_version,
          },
          complete: stream.complete === 1,
        }
      : null;
  return { primaryKey, profile, head };
}
