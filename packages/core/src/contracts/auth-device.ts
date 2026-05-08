export const DEVICE_SESSION_TTL_MS = 5 * 60 * 1000;
export const DEVICE_POLL_INTERVAL_MS = 5 * 1000;
export const CLI_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;

export interface DeviceTokenStorePort {
  isValid(token: string): Promise<boolean>;
  addToken(
    token: string,
    options?: { expiresAt?: string | Date | null },
  ): Promise<void>;
  removeToken(token: string): Promise<void>;
}

export interface DeviceSession {
  sessionId: string;
  pollToken: string;
  requestedServerOrigin: string;
  status: "pending" | "approved";
  accessToken?: string;
  accessTokenExpiresAt?: string;
  createdAt: number;
  lastPollAt: number;
}

export interface DeviceSessionStore {
  create(input: {
    requestedServerOrigin: string;
    sessionId: string;
    pollToken: string;
    now: number;
  }): DeviceSession;
  get(sessionId: string): DeviceSession | undefined;
  findByPollToken(pollToken: string): DeviceSession | undefined;
  delete(sessionId: string): void;
  purgeExpired(now: number): void;
}

export function createMemoryDeviceSessionStore(): DeviceSessionStore {
  const sessions = new Map<string, DeviceSession>();
  return {
    create(input) {
      const session: DeviceSession = {
        sessionId: input.sessionId,
        pollToken: input.pollToken,
        requestedServerOrigin: input.requestedServerOrigin,
        status: "pending",
        createdAt: input.now,
        lastPollAt: 0,
      };
      sessions.set(input.sessionId, session);
      return session;
    },
    get(sessionId) {
      return sessions.get(sessionId);
    },
    findByPollToken(pollToken) {
      for (const session of sessions.values()) {
        if (session.pollToken === pollToken) return session;
      }
      return undefined;
    },
    delete(sessionId) {
      sessions.delete(sessionId);
    },
    purgeExpired(now) {
      for (const [sessionId, session] of sessions.entries()) {
        if (now - session.createdAt > DEVICE_SESSION_TTL_MS) {
          sessions.delete(sessionId);
        }
      }
    },
  };
}

export type DeviceContractResult = {
  status: number;
  body: unknown;
};

function jsonError(status: number, message: string): DeviceContractResult {
  return {
    status,
    body: { error: { code: status, message } },
  };
}

function serverNotConfigured(): DeviceContractResult {
  return {
    status: 500,
    body: {
      error: {
        code: 500,
        errorCode: "SERVER_NOT_CONFIGURED",
        message:
          "Server owner address not configured. Set VANA_MASTER_KEY_SIGNATURE environment variable.",
      },
    },
  };
}

export function initiateDeviceSessionContract(input: {
  sessionStore: DeviceSessionStore;
  serverOwner?: `0x${string}`;
  requestOrigin: string;
  approvalOrigin: string;
  sessionId: string;
  pollToken: string;
  now: number;
}): DeviceContractResult {
  if (!input.serverOwner) return serverNotConfigured();
  input.sessionStore.purgeExpired(input.now);
  input.sessionStore.create({
    requestedServerOrigin: input.requestOrigin,
    sessionId: input.sessionId,
    pollToken: input.pollToken,
    now: input.now,
  });
  return {
    status: 200,
    body: {
      login: `${input.approvalOrigin}/auth/device/approve?session=${input.sessionId}`,
      poll: {
        endpoint: "/auth/device/poll",
        token: input.pollToken,
      },
    },
  };
}

export function pollDeviceSessionContract(input: {
  sessionStore: DeviceSessionStore;
  pollToken: string | null;
  serverOwner?: `0x${string}`;
  now: number;
}): DeviceContractResult {
  input.sessionStore.purgeExpired(input.now);
  if (!input.pollToken) return jsonError(400, "Missing token parameter");

  const session = input.sessionStore.findByPollToken(input.pollToken);
  if (!session) return { status: 404, body: { status: "expired" } };

  if (input.now - session.lastPollAt < DEVICE_POLL_INTERVAL_MS) {
    return jsonError(
      429,
      `Too many requests. Poll every ${DEVICE_POLL_INTERVAL_MS / 1000} seconds.`,
    );
  }
  session.lastPollAt = input.now;

  if (session.status === "pending") {
    return { status: 404, body: { status: "pending" } };
  }
  if (!input.serverOwner) {
    input.sessionStore.delete(session.sessionId);
    return serverNotConfigured();
  }
  if (session.status === "approved" && session.accessToken) {
    const body = {
      status: "authorized",
      server: session.requestedServerOrigin,
      address: input.serverOwner,
      access_token: session.accessToken,
      expires_at: session.accessTokenExpiresAt,
    };
    input.sessionStore.delete(session.sessionId);
    return { status: 200, body };
  }
  return { status: 404, body: { status: "pending" } };
}

export async function approveDeviceSessionContract(input: {
  sessionStore: DeviceSessionStore;
  tokenStore: DeviceTokenStorePort;
  sessionId: string | null;
  serverOwner?: `0x${string}`;
  accessToken: string;
  now: number;
}): Promise<DeviceContractResult> {
  input.sessionStore.purgeExpired(input.now);
  if (!input.sessionId) return jsonError(400, "Missing session parameter");

  const session = input.sessionStore.get(input.sessionId);
  if (!session) return jsonError(404, "Session expired or invalid");
  if (session.status === "approved") {
    return { status: 200, body: { status: "already_approved" } };
  }
  if (!input.serverOwner) return serverNotConfigured();

  const expiresAt = new Date(input.now + CLI_TOKEN_TTL_MS).toISOString();
  await input.tokenStore.addToken(input.accessToken, { expiresAt });
  session.status = "approved";
  session.accessToken = input.accessToken;
  session.accessTokenExpiresAt = expiresAt;
  return { status: 200, body: { status: "approved" } };
}

export async function provisionDeviceTokenContract(input: {
  tokenStore: DeviceTokenStorePort;
  body: unknown;
  now: number;
}): Promise<DeviceContractResult> {
  if (input.body === null || typeof input.body !== "object") {
    return jsonError(400, "Request body must be valid JSON");
  }
  const body = input.body as { token?: unknown; expires_at?: unknown };
  if (!body.token || typeof body.token !== "string") {
    return jsonError(400, "Missing token");
  }

  let expiresAt: string | null = null;
  if (body.expires_at !== undefined && body.expires_at !== null) {
    if (typeof body.expires_at !== "string") {
      return jsonError(400, "Invalid expires_at");
    }
    const parsed = new Date(body.expires_at);
    if (Number.isNaN(parsed.getTime())) {
      return jsonError(400, "Invalid expires_at");
    }
    if (parsed.getTime() <= input.now) {
      return jsonError(400, "expires_at must be in the future");
    }
    expiresAt = parsed.toISOString();
  }

  await input.tokenStore.addToken(body.token, { expiresAt });
  return { status: 201, body: { status: "created" } };
}

export async function revokeDeviceTokenContract(input: {
  tokenStore: DeviceTokenStorePort;
  bearerToken: string | null;
}): Promise<DeviceContractResult> {
  if (!input.bearerToken) return jsonError(401, "Missing Bearer token");
  if (await input.tokenStore.isValid(input.bearerToken)) {
    await input.tokenStore.removeToken(input.bearerToken);
  }
  return { status: 200, body: { status: "revoked" } };
}
