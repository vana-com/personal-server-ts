/**
 * PS-Lite's replication runtime (host contract §4.4): the trigger and status
 * surface a phone host drives. It decides nothing about retries or phase
 * order; the engine's coordinator does. It turns the door, the host's boot
 * configuration and the app lifecycle into one driver that steps the engine.
 *
 * Foreground only (§4.4): `resume` on foreground, `pause` on `inactive`,
 * `paused` or `hidden`. A pause aborts the running step and stops scheduling.
 */
import type {
  ReplicationDoorStatus,
  ReplicationRefusal,
} from "@opendatalabs/personal-server-ts-core/replication/door";
import {
  createReplicationDriver,
  type ReplicationDriver,
  type ReplicationDriverStatus,
  type ReplicationTimers,
} from "@opendatalabs/personal-server-ts-core/replication/host-driver";
import type { ProgressReport } from "@opendatalabs/personal-server-ts-core/replication/coordinator";
import {
  replicationBootConfigProblem,
  type LiteReplicationEngine,
  type LiteReplicationTrigger,
  type ReplicationBootConfig,
} from "./replication-ports.js";

/** How long a pause waits for an aborted step before reporting it stuck. */
export const LITE_REPLICATION_PAUSE_GRACE_MS = 2_000;

export type LiteReplicationStatus =
  /** Off by the host's opt-in, or the door was never opened. */
  | { state: "off" }
  /** Turned off once; it stays off on this device (§5.2). */
  | { state: "refused"; refusal: ReplicationRefusal }
  /** On, but this boot cannot run it. */
  | {
      state: "blocked";
      reason:
        | "no_engine"
        | "invalid_owner"
        | "invalid_environment"
        | "invalid_limits";
    }
  | ({ state: "on" | "paused" } & Omit<ReplicationDriverStatus, "state">);

export interface LiteReplicationRuntime {
  status(): LiteReplicationStatus;
  /**
   * Ask for a step now. Single-flight; while paused, off or blocked it does
   * nothing and resolves `undefined`.
   */
  trigger(reason: LiteReplicationTrigger): Promise<ProgressReport | undefined>;
  /** A host-observed dependency change, e.g. `mapping:<connection>`. */
  wake(dependency: string): void;
  /** Foreground: start stepping (steps once now). Idempotent. */
  resume(): void;
  /** Background: abort the running step and stop scheduling. */
  pause(): Promise<void>;
  /** Teardown: like `pause`, with the caller's grace. True when settled. */
  stop(graceMs: number): Promise<boolean>;
}

/**
 * Build the runtime for one boot. With the door anything but `on`, or no
 * boot config or `enabled: false`, it is inert: no engine runs and `status`
 * says why.
 */
export function createLiteReplicationRuntime(input: {
  door: ReplicationDoorStatus;
  config?: ReplicationBootConfig;
  engine?: LiteReplicationEngine;
  timers?: ReplicationTimers;
  onReport?: (report: ProgressReport) => void;
  onError?: (error: unknown) => void;
}): LiteReplicationRuntime {
  const inert = (status: LiteReplicationStatus): LiteReplicationRuntime => ({
    status: () => status,
    trigger: async () => undefined,
    wake: () => {},
    resume: () => {},
    pause: async () => {},
    stop: async () => true,
  });
  if (input.door.state === "refused")
    return inert({ state: "refused", refusal: input.door.refusal });
  if (input.door.state !== "on" || !input.config?.enabled)
    return inert({ state: "off" });
  const problem = replicationBootConfigProblem(input.config);
  if (problem) return inert({ state: "blocked", reason: problem });
  if (!input.engine) return inert({ state: "blocked", reason: "no_engine" });
  const { step } = input.config.limits;
  const driver: ReplicationDriver = createReplicationDriver({
    stepper: input.engine,
    budget: { units: step.units, bytes: step.bytes },
    deadlineMs: step.deadlineMs,
    timers: input.timers,
    onReport: input.onReport,
    onError: input.onError,
  });
  let pausing: Promise<boolean> | undefined;
  return {
    status() {
      const { state, ...rest } = driver.status();
      return { state: state === "running" ? "on" : "paused", ...rest };
    },
    trigger: () => driver.trigger(),
    wake: (dependency) => driver.wake(dependency),
    resume() {
      // A resume during a pause waits for it, so the old step settles first.
      if (pausing) void pausing.then(() => driver.start());
      else driver.start();
    },
    async pause() {
      await this.stop(LITE_REPLICATION_PAUSE_GRACE_MS);
    },
    async stop(graceMs) {
      const stopping = driver.stop(graceMs);
      pausing = stopping;
      try {
        return await stopping;
      } finally {
        if (pausing === stopping) pausing = undefined;
      }
    },
  };
}
