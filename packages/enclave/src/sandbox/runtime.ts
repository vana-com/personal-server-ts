import type { Hex } from "viem";

/**
 * Sandbox boundary (promoted from spike/sandbox launcher.ts):
 *
 * agent -> SandboxRuntime port -> docker CLI -> sandbox-runtime container
 *                                                     |
 *                                                     v
 *                                              gVisor sandbox
 */

export const SANDBOX_ENV_KEYS = [
  "CLOUD_MODE",
  "DEV_UI_ENABLED",
  "TUNNEL_ENABLED",
  "ENCLAVE_MODE",
  "PERSONAL_SERVER_ROOT_PATH",
  "SERVER_ORIGIN",
  "SYNC_ENABLED",
  "VANA_MASTER_KEY_SIGNATURE",
  "PS_ACCESS_TOKEN",
  "PS_SERVER_ADDRESS",
  "PS_SERVER_PUBLIC_KEY",
  "GATEWAY_URL",
  "CHAIN_ID",
  "DATA_REGISTRY_CONTRACT",
  "DATA_PORTABILITY_SERVER_CONTRACT",
  "DATA_PORTABILITY_GRANTEES_CONTRACT",
  "DATA_PORTABILITY_PERMISSIONS_CONTRACT",
  "STORAGE_API_URL",
  "VERCEL_PROTECTION_BYPASS",
] as const;

export const SECRET_ENV_KEYS = [
  "VANA_MASTER_KEY_SIGNATURE",
  "PS_ACCESS_TOKEN",
  "VERCEL_PROTECTION_BYPASS",
] as const;

export type SandboxEnvKey = (typeof SANDBOX_ENV_KEYS)[number];

export interface SandboxSpec {
  userPsId: Hex;
  epoch: number;
  image: string;
  env: Record<string, string>;
}

export interface SandboxHandle {
  id: string;
  origin: string;
}

export interface SandboxRuntime {
  reconcile(): Promise<void>;
  start(spec: SandboxSpec): Promise<SandboxHandle>;
  stop(id: string): Promise<void>;
  inspect(id: string): Promise<{ running: boolean }>;
}

const SANDBOX_ENV_KEY_SET = new Set<string>(SANDBOX_ENV_KEYS);

export function assertSandboxEnv(env: Record<string, string>): void {
  const unknownKey = Object.keys(env).find(
    (key) => !SANDBOX_ENV_KEY_SET.has(key),
  );
  if (unknownKey) {
    throw new Error(`Unknown sandbox environment key: ${unknownKey}`);
  }
}
