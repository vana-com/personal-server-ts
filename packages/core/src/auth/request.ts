import {
  ExpiredTokenError as SdkExpiredTokenError,
  InvalidSignatureError as SdkInvalidSignatureError,
  MissingAuthError as SdkMissingAuthError,
  verifyWeb3Signed,
  type Web3SignedPayload,
} from "@opendatalabs/vana-sdk/browser";
import {
  ExpiredTokenError,
  InvalidSignatureError,
  MissingAuthError,
  ProtocolError,
} from "../errors/catalog.js";

export type AuthMechanism =
  | "web3-signed"
  | "dev-token"
  | "control-plane-token"
  | "cli-session-token";

export interface RequestAuth {
  signer: `0x${string}`;
  payload: Partial<Web3SignedPayload>;
}

export interface SessionTokenVerifierPort {
  isValid(token: string): Promise<boolean>;
}

export interface AuthenticateRequestInput {
  request: Request;
  serverOrigin: string | (() => string);
  devToken?: string;
  accessToken?: string;
  sessionTokenVerifier?: SessionTokenVerifierPort;
  serverOwner?: `0x${string}`;
  now?: () => number;
}

export interface AuthenticatedRequest {
  auth: RequestAuth;
  mechanism: AuthMechanism;
  isPolicyBypass: boolean;
  devBypass: boolean;
}

function resolveOrigin(origin: string | (() => string)): string {
  return typeof origin === "function" ? origin() : origin;
}

function serverNotConfigured(): ProtocolError {
  return new ProtocolError(
    500,
    "SERVER_NOT_CONFIGURED",
    "Server owner address not configured. Set VANA_MASTER_KEY_SIGNATURE environment variable.",
  );
}

function createOwnerSessionAuth(serverOwner: `0x${string}`): RequestAuth {
  return {
    signer: serverOwner,
    payload: {},
  };
}

function safeCompare(a: string, b: string): boolean {
  const left = new TextEncoder().encode(a);
  const right = new TextEncoder().encode(b);
  const length = Math.max(left.length, right.length);
  let diff = left.length ^ right.length;
  for (let index = 0; index < length; index += 1) {
    diff |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return diff === 0;
}

function getBearerToken(headerValue: string | null): string | null {
  if (!headerValue?.startsWith("Bearer ")) return null;
  return headerValue.slice(7);
}

async function requestBodyBytes(
  request: Request,
): Promise<Uint8Array | undefined> {
  if (request.method === "GET" || request.method === "HEAD") return undefined;
  return new Uint8Array(await request.clone().arrayBuffer());
}

function getErrorDetails(err: unknown): Record<string, unknown> | undefined {
  if (err && typeof err === "object" && "details" in err) {
    const details = err.details;
    if (details && typeof details === "object" && !Array.isArray(details)) {
      return details as Record<string, unknown>;
    }
  }
  return undefined;
}

export function mapSdkAuthError(err: unknown): ProtocolError | null {
  if (err instanceof SdkMissingAuthError) {
    return new MissingAuthError(getErrorDetails(err));
  }
  if (err instanceof SdkInvalidSignatureError) {
    return new InvalidSignatureError(getErrorDetails(err));
  }
  if (err instanceof SdkExpiredTokenError) {
    return new ExpiredTokenError(getErrorDetails(err));
  }
  return null;
}

function ownerTokenResult(
  serverOwner: `0x${string}` | undefined,
  mechanism: AuthMechanism,
  isPolicyBypass: boolean,
): AuthenticatedRequest {
  if (!serverOwner) throw serverNotConfigured();
  return {
    auth: createOwnerSessionAuth(serverOwner),
    mechanism,
    isPolicyBypass,
    devBypass: isPolicyBypass,
  };
}

export async function authenticateRequest(
  input: AuthenticateRequestInput,
): Promise<AuthenticatedRequest> {
  const authHeader = input.request.headers.get("authorization");
  const bearerToken = getBearerToken(authHeader);

  if (input.devToken && authHeader === `Bearer ${input.devToken}`) {
    return ownerTokenResult(input.serverOwner, "dev-token", true);
  }

  if (
    input.accessToken &&
    bearerToken &&
    safeCompare(bearerToken, input.accessToken)
  ) {
    return ownerTokenResult(input.serverOwner, "control-plane-token", false);
  }

  if (
    input.sessionTokenVerifier &&
    bearerToken &&
    (await input.sessionTokenVerifier.isValid(bearerToken))
  ) {
    return ownerTokenResult(input.serverOwner, "cli-session-token", false);
  }

  try {
    const url = new URL(input.request.url);
    const auth = await verifyWeb3Signed({
      headerValue: authHeader ?? undefined,
      expectedOrigin: resolveOrigin(input.serverOrigin),
      expectedMethod: input.request.method,
      expectedPath: url.pathname,
      bodyBytes: await requestBodyBytes(input.request),
      now: input.now?.(),
    });

    return {
      auth,
      mechanism: "web3-signed",
      isPolicyBypass: false,
      devBypass: false,
    };
  } catch (err) {
    const authError = mapSdkAuthError(err);
    if (authError) throw authError;
    throw err;
  }
}
