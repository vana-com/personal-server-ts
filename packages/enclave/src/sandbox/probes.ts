import { abortError } from "./abort.js";

const HEALTH_PATH = "/health";
const SYNC_STATUS_PATH = "/v1/sync/status";
const HEALTH_REQUEST_TIMEOUT_MS = 1_000;
const SYNC_REQUEST_TIMEOUT_MS = 2_000;
const OK = 200;
const AUTHORIZATION_HEADER = "authorization";
const BEARER_PREFIX = "Bearer ";
const SYNC_ERROR_PREFIX = "Sandbox sync failed: ";

export interface SyncStatus {
  syncing?: boolean;
  lastSync?: string | null;
  pendingFiles?: number;
  errors?: Array<{ message?: string }>;
  blocked?: SyncBlockedReason | null;
}

export interface SyncBlockedReason {
  reason: string;
  message: string;
}

export class SandboxSyncBlockedError extends Error {
  constructor(
    public readonly reason: string,
    message: string,
  ) {
    super(`${SYNC_ERROR_PREFIX}${reason}: ${message}`);
    this.name = "SandboxSyncBlockedError";
  }
}

export type HealthProbe = (
  origin: string,
  signal?: AbortSignal,
) => Promise<boolean>;
export type SyncProbe = (
  origin: string,
  accessToken: string,
  signal?: AbortSignal,
) => Promise<boolean>;
export interface SyncProbeResult {
  ready: boolean;
  status?: SyncStatus;
}
export type SyncStatusProbe = (
  origin: string,
  accessToken: string,
  signal?: AbortSignal,
) => Promise<SyncProbeResult>;

export async function probeHealth(
  origin: string,
  signal?: AbortSignal,
): Promise<boolean> {
  try {
    const response = await fetch(`${origin}${HEALTH_PATH}`, {
      signal: requestSignal(signal, HEALTH_REQUEST_TIMEOUT_MS),
    });

    return response.status === OK;
  } catch {
    if (signal?.aborted) {
      throw abortError();
    }
    return false;
  }
}

export async function probeSync(
  origin: string,
  accessToken: string,
  signal?: AbortSignal,
): Promise<boolean> {
  return (await probeSyncStatus(origin, accessToken, signal)).ready;
}

export async function probeSyncStatus(
  origin: string,
  accessToken: string,
  signal?: AbortSignal,
): Promise<SyncProbeResult> {
  try {
    const response = await fetch(`${origin}${SYNC_STATUS_PATH}`, {
      headers: { [AUTHORIZATION_HEADER]: `${BEARER_PREFIX}${accessToken}` },
      signal: requestSignal(signal, SYNC_REQUEST_TIMEOUT_MS),
    });
    if (!response.ok) {
      return { ready: false };
    }

    const status = (await response.json()) as SyncStatus;
    if (status.blocked) {
      throw new SandboxSyncBlockedError(
        status.blocked.reason,
        status.blocked.message,
      );
    }
    if (status.errors?.length) {
      const messages = status.errors.map(
        (error) => error.message ?? "unknown error",
      );

      throw new Error(`${SYNC_ERROR_PREFIX}${messages.join("; ")}`);
    }

    return {
      ready:
        !status.syncing &&
        Boolean(status.lastSync) &&
        status.pendingFiles === 0,
      status,
    };
  } catch (error) {
    if (signal?.aborted) {
      throw abortError();
    }
    if (error instanceof Error && error.message.startsWith(SYNC_ERROR_PREFIX)) {
      throw error;
    }

    return { ready: false };
  }
}

function requestSignal(
  signal: AbortSignal | undefined,
  timeoutMs: number,
): AbortSignal {
  const timeout = AbortSignal.timeout(timeoutMs);

  return signal ? AbortSignal.any([signal, timeout]) : timeout;
}
