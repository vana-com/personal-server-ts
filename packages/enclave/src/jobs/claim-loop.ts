import type { SandboxRegistry } from "../sandbox/registry.js";
import type { GatewayClient } from "./gateway-client.js";
import type { ClaimResponse } from "./types.js";

const BACKOFF_MS = 5_000;
const CLAIM_FAILURE_MESSAGE = "Gateway claim loop unavailable";
const CLAIM_RECOVERY_MESSAGE = "Gateway claim loop recovered";

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
  let isDraining = false;
  let running = 0;
  let unavailable = false;
  let drainPromise: Promise<void> | undefined;

  const loopPromise = claimUntilDrain();

  async function claimUntilDrain(): Promise<void> {
    while (!isDraining) {
      let claim: ClaimResponse | null;
      try {
        claim = await options.gateway.claim(options.wait, {
          leaseSeconds: options.leaseSeconds,
          capacity: options.capacity,
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

      if (isDraining || !claim) {
        continue;
      }

      running = 1;
      try {
        await options.run(claim.job, claim.identity);
      } finally {
        running = 0;
      }
    }
  }

  return {
    drain(): Promise<void> {
      isDraining = true;
      drainPromise ??= loopPromise.then(() => options.registry.drain());

      return drainPromise;
    },
    running(): number {
      return running;
    },
    draining(): boolean {
      return isDraining;
    },
  };
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
