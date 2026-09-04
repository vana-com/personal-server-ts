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
}

export type HealthProbe = (origin: string) => Promise<boolean>;
export type SyncProbe = (
  origin: string,
  accessToken: string,
) => Promise<boolean>;
export interface SyncProbeResult {
  ready: boolean;
  status?: SyncStatus;
}
export type SyncStatusProbe = (
  origin: string,
  accessToken: string,
) => Promise<SyncProbeResult>;

export async function probeHealth(origin: string): Promise<boolean> {
  try {
    const response = await fetch(`${origin}${HEALTH_PATH}`, {
      signal: AbortSignal.timeout(HEALTH_REQUEST_TIMEOUT_MS),
    });

    return response.status === OK;
  } catch {
    return false;
  }
}

export async function probeSync(
  origin: string,
  accessToken: string,
): Promise<boolean> {
  return (await probeSyncStatus(origin, accessToken)).ready;
}

export async function probeSyncStatus(
  origin: string,
  accessToken: string,
): Promise<SyncProbeResult> {
  try {
    const response = await fetch(`${origin}${SYNC_STATUS_PATH}`, {
      headers: { [AUTHORIZATION_HEADER]: `${BEARER_PREFIX}${accessToken}` },
      signal: AbortSignal.timeout(SYNC_REQUEST_TIMEOUT_MS),
    });
    if (!response.ok) {
      return { ready: false };
    }

    const status = (await response.json()) as SyncStatus;
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
    if (error instanceof Error && error.message.startsWith(SYNC_ERROR_PREFIX)) {
      throw error;
    }

    return { ready: false };
  }
}
