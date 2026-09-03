import type { SandboxRegistry } from "../sandbox/registry.js";
import type { GatewayClient } from "./gateway-client.js";
import { CLAIM_POLL_FLOOR_MS, type ClaimResponse } from "./types.js";

const BACKOFF_MS = 5_000;
const CLAIM_FAILURE_MESSAGE = "Gateway claim loop unavailable";
const CLAIM_RECOVERY_MESSAGE = "Gateway claim loop recovered";
const JOB_RUN_FAILURE_MESSAGE = "Claimed job run failed";
const UNKNOWN_ERROR = "unknown";

export interface JobLogger {
  info(context: Record<string, unknown>, message: string): void;
  warn(context: Record<string, unknown>, message: string): void;
}

export interface ClaimLoopOptions {
  gateway: GatewayClient;
  run(
    job: ClaimResponse["job"],
    identity: ClaimResponse["identity"],
  ): Promise<void>;
  registry: SandboxRegistry;
  leaseSeconds: number;
  wait: number;
  capacity: number;
  logger: JobLogger;
  sleep?: (milliseconds: number) => Promise<void>;
}

export interface ClaimLoop {
  drain(): Promise<void>;
  running(): number;
  draining(): boolean;
}

export function startClaimLoop(options: ClaimLoopOptions): ClaimLoop {
  const sleep = options.sleep ?? delay;
  const inFlight = new Set<Promise<void>>();
  let isDraining = false;
  let unavailable = false;
  let drainPromise: Promise<void> | undefined;

  const loopPromise = claimUntilDrain();

  async function claimUntilDrain(): Promise<void> {
    while (!isDraining) {
      if (inFlight.size >= options.capacity) {
        await Promise.race(inFlight);
        continue;
      }

      let claim: ClaimResponse | null;
      const claimStartedAt = Date.now();
      try {
        claim = await options.gateway.claim(options.wait, {
          leaseSeconds: options.leaseSeconds,
          capacity: options.capacity - inFlight.size,
        });
        if (unavailable) {
          unavailable = false;
          options.logger.info({}, CLAIM_RECOVERY_MESSAGE);
        }
      } catch (error) {
        if (!unavailable) {
          unavailable = true;
          options.logger.warn(
            { error: error instanceof Error ? error.name : "unknown" },
            CLAIM_FAILURE_MESSAGE,
          );
        }
        if (!isDraining) {
          await sleep(BACKOFF_MS);
        }
        continue;
      }

      if (!claim) {
        const remaining = CLAIM_POLL_FLOOR_MS - (Date.now() - claimStartedAt);
        if (!isDraining && remaining > 0) {
          await sleep(remaining);
        }
        continue;
      }
      if (isDraining) {
        continue;
      }

      startRun(claim);
    }

    await Promise.all(inFlight);
  }

  function startRun(claim: ClaimResponse): void {
    const runPromise = runClaim(claim);
    inFlight.add(runPromise);
    void runPromise.then(() => inFlight.delete(runPromise));
  }

  async function runClaim(claim: ClaimResponse): Promise<void> {
    try {
      await options.run(claim.job, claim.identity);
    } catch (error) {
      options.logger.warn(
        { jobId: claim.job.jobId, error: errorSummary(error) },
        JOB_RUN_FAILURE_MESSAGE,
      );
    }
  }

  return {
    drain(): Promise<void> {
      isDraining = true;
      drainPromise ??= loopPromise.then(() => options.registry.drain());

      return drainPromise;
    },
    running(): number {
      return inFlight.size;
    },
    draining(): boolean {
      return isDraining;
    },
  };
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function errorSummary(error: unknown): string {
  if (!(error instanceof Error)) {
    return UNKNOWN_ERROR;
  }

  return `${error.name}: ${error.message}`;
}
