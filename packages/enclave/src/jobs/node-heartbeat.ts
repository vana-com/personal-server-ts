import type { DstackClient } from "../dstack/client.js";
import type { SandboxRegistry } from "../sandbox/registry.js";
import type { Hex } from "viem";
import type { GatewayClient } from "./gateway-client.js";
import type { JobLogger } from "./claim-loop.js";

export const NODE_HEARTBEAT_INTERVAL_MS = 20_000;

const HEARTBEAT_FAILURE_MESSAGE = "Node heartbeat unavailable";
const HEARTBEAT_RECOVERY_MESSAGE = "Node heartbeat recovered";
const HEX_PREFIX = "0x";

export interface NodeHeartbeatOptions {
  gateway: GatewayClient;
  nodeId: string;
  client: DstackClient;
  registry: SandboxRegistry;
  capacity: number;
  intervalMs?: number;
  logger: JobLogger;
  setTimer?: typeof setInterval;
}

export interface NodeHeartbeat {
  stop(): Promise<void>;
}

export function startNodeHeartbeat(
  options: NodeHeartbeatOptions,
): NodeHeartbeat {
  let stopped = false;
  let unavailable = false;
  let pending = sendHeartbeat();
  const setTimer = options.setTimer ?? setInterval;
  const timer = setTimer(() => {
    if (stopped) {
      return;
    }

    pending = pending.then(sendHeartbeat);
  }, options.intervalMs ?? NODE_HEARTBEAT_INTERVAL_MS);
  timer.unref();

  async function sendHeartbeat(): Promise<void> {
    try {
      const info = await options.client.info();
      await options.gateway.nodeHeartbeat(options.nodeId, {
        composeHash: hexValue(info.composeHash),
        instanceId: info.instanceId,
        activeSandboxes: options.registry.activeCount(),
        capacity: options.capacity,
      });
      if (unavailable) {
        unavailable = false;
        options.logger.info({}, HEARTBEAT_RECOVERY_MESSAGE);
      }
    } catch (error) {
      if (!unavailable) {
        unavailable = true;
        options.logger.warn(
          { error: error instanceof Error ? error.name : "unknown" },
          HEARTBEAT_FAILURE_MESSAGE,
        );
      }
    }
  }

  return {
    async stop(): Promise<void> {
      stopped = true;
      clearInterval(timer);
      await pending;
    },
  };
}

function hexValue(value: string): Hex {
  return (
    value.startsWith(HEX_PREFIX) ? value : `${HEX_PREFIX}${value}`
  ) as Hex;
}
