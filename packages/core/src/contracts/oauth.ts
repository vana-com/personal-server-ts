export const OAUTH_DEVICE_CODE_GRANT =
  "urn:ietf:params:oauth:grant-type:device_code";

export const OAUTH_ACCESS_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;

export interface OAuthTokenStorePort {
  addToken(
    token: string,
    options?: { expiresAt?: string | Date | null },
  ): Promise<void>;
}

export interface OAuthDeviceSession {
  status: "pending" | "approved" | "expired";
  accessToken?: string;
  accessTokenExpiresAt?: string;
  sessionId: string;
}

export interface OAuthDeviceSessionLookup {
  findByDeviceCode(deviceCode: string): OAuthDeviceSession | null;
  consume(sessionId: string): void;
}

export type OAuthTokenResult = {
  status: 200 | 400 | 401;
  body: Record<string, unknown>;
  headers: Record<string, string>;
};

export interface OAuthTokenContractInput {
  body: URLSearchParams;
  authorizationHeader?: string | null;
  tokenStore: OAuthTokenStorePort;
  controlPlaneSecret?: string;
  deviceSessions?: OAuthDeviceSessionLookup;
  randomToken: () => string;
  now?: () => Date;
  safeCompare?: (left: string, right: string) => boolean;
}

type OAuthError =
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "unauthorized_client"
  | "unsupported_grant_type"
  | "authorization_pending"
  | "expired_token";

const NO_STORE_HEADERS = {
  "Cache-Control": "no-store",
  Pragma: "no-cache",
};

function oauthError(
  error: OAuthError,
  description: string,
  status: 400 | 401 = 400,
): OAuthTokenResult {
  return {
    status,
    body: {
      error,
      error_description: description,
    },
    headers: NO_STORE_HEADERS,
  };
}

function defaultSafeCompare(left: string, right: string): boolean {
  const leftBytes = new TextEncoder().encode(left);
  const rightBytes = new TextEncoder().encode(right);
  const length = Math.max(leftBytes.length, rightBytes.length);
  let diff = leftBytes.length ^ rightBytes.length;
  for (let index = 0; index < length; index += 1) {
    diff |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
  }
  return diff === 0;
}

function decodeBase64(input: string): string {
  if (typeof atob === "function") {
    return atob(input);
  }
  throw new Error("Base64 decoding is not available in this runtime");
}

export function parseOAuthBasicAuth(
  headerValue: string | null | undefined,
): { clientId: string; clientSecret: string } | null {
  if (!headerValue?.startsWith("Basic ")) return null;
  const decoded = decodeBase64(headerValue.slice(6));
  const separatorIndex = decoded.indexOf(":");
  if (separatorIndex === -1) return null;
  try {
    return {
      clientId: decodeURIComponent(decoded.slice(0, separatorIndex)),
      clientSecret: decodeURIComponent(decoded.slice(separatorIndex + 1)),
    };
  } catch {
    return null;
  }
}

function asNonEmpty(value: string | null): string | null {
  return value && value.length > 0 ? value : null;
}

export async function oauthTokenContract(
  input: OAuthTokenContractInput,
): Promise<OAuthTokenResult> {
  const grantType = asNonEmpty(input.body.get("grant_type"));
  if (!grantType) {
    return oauthError("invalid_request", "Missing grant_type");
  }

  if (grantType === "client_credentials") {
    return handleClientCredentials(input);
  }
  if (grantType === OAUTH_DEVICE_CODE_GRANT) {
    return handleDeviceCode(input);
  }
  return oauthError(
    "unsupported_grant_type",
    `Grant type '${grantType}' is not supported`,
  );
}

async function handleClientCredentials(
  input: OAuthTokenContractInput,
): Promise<OAuthTokenResult> {
  if (!input.controlPlaneSecret) {
    return oauthError(
      "unauthorized_client",
      "Server is not configured for client_credentials",
      401,
    );
  }

  const fromHeader = parseOAuthBasicAuth(input.authorizationHeader);
  const clientId =
    fromHeader?.clientId ?? asNonEmpty(input.body.get("client_id"));
  const clientSecret =
    fromHeader?.clientSecret ?? asNonEmpty(input.body.get("client_secret"));

  if (!clientId || !clientSecret) {
    return oauthError("invalid_client", "Missing client credentials", 401);
  }
  if (clientId !== "control-plane") {
    return oauthError("invalid_client", `Unknown client_id '${clientId}'`, 401);
  }
  if (
    !(input.safeCompare ?? defaultSafeCompare)(
      clientSecret,
      input.controlPlaneSecret,
    )
  ) {
    return oauthError("invalid_client", "Invalid client_secret", 401);
  }

  const accessToken = input.randomToken();
  const expiresAt = new Date(
    (input.now ?? (() => new Date()))().getTime() +
      OAUTH_ACCESS_TOKEN_TTL_SECONDS * 1000,
  ).toISOString();

  await input.tokenStore.addToken(accessToken, { expiresAt });
  return {
    status: 200,
    body: {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: OAUTH_ACCESS_TOKEN_TTL_SECONDS,
    },
    headers: NO_STORE_HEADERS,
  };
}

async function handleDeviceCode(
  input: OAuthTokenContractInput,
): Promise<OAuthTokenResult> {
  if (!input.deviceSessions) {
    return oauthError(
      "unsupported_grant_type",
      "Device flow is not configured on this server",
    );
  }

  const deviceCode = asNonEmpty(input.body.get("device_code"));
  if (!deviceCode) {
    return oauthError("invalid_request", "Missing device_code");
  }

  const session = input.deviceSessions.findByDeviceCode(deviceCode);
  if (!session) {
    return oauthError("expired_token", "Device code is expired or unknown");
  }
  if (session.status === "expired") {
    return oauthError("expired_token", "Device code is expired");
  }
  if (session.status === "pending" || !session.accessToken) {
    return oauthError(
      "authorization_pending",
      "User has not yet approved the device",
    );
  }

  const expiresInSeconds = session.accessTokenExpiresAt
    ? Math.max(
        1,
        Math.floor(
          (Date.parse(session.accessTokenExpiresAt) -
            (input.now ?? (() => new Date()))().getTime()) /
            1000,
        ),
      )
    : OAUTH_ACCESS_TOKEN_TTL_SECONDS;

  input.deviceSessions.consume(session.sessionId);
  return {
    status: 200,
    body: {
      access_token: session.accessToken,
      token_type: "Bearer",
      expires_in: expiresInSeconds,
    },
    headers: NO_STORE_HEADERS,
  };
}
