import type { DstackClient } from "../dstack/client.js";
import { createFakeDstackClient } from "../dstack/fake.js";
import { createRealDstackClient } from "../dstack/real.js";

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 8787;
const DEFAULT_FAKE_APP_ID = "0000000000000000000000000000000000000001";
const FAKE_DSTACK_ENABLED = "1";
const MIN_PORT = 1;
const MAX_PORT = 65_535;

export interface AgentConfig {
  host: string;
  port: number;
  secret: string;
  client: DstackClient;
}

export function agentConfigFromEnv(env: NodeJS.ProcessEnv): AgentConfig {
  const secret = env.ENCLAVE_AGENT_SECRET;
  if (!secret) {
    throw new Error("ENCLAVE_AGENT_SECRET is required");
  }

  return {
    host: env.ENCLAVE_AGENT_HOST ?? DEFAULT_HOST,
    port: readPort(env.ENCLAVE_AGENT_PORT),
    secret,
    client:
      env.DSTACK_FAKE === FAKE_DSTACK_ENABLED
        ? createFakeDstackClient({
            appId: env.DSTACK_FAKE_APP_ID ?? DEFAULT_FAKE_APP_ID,
          })
        : createRealDstackClient(),
  };
}

function readPort(value: string | undefined): number {
  if (value === undefined) {
    return DEFAULT_PORT;
  }

  const port = Number(value);
  if (!Number.isInteger(port) || port < MIN_PORT || port > MAX_PORT) {
    throw new Error("ENCLAVE_AGENT_PORT must be an integer from 1 to 65535");
  }

  return port;
}
