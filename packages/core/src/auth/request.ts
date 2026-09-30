import {
  ExpiredTokenError as SdkExpiredTokenError,
  InvalidSignatureError as SdkInvalidSignatureError,
  MissingAuthError as SdkMissingAuthError,
  verifyWeb3Signed,
  type Web3SignedPayload,
} from "@opendatalabs/vana-sdk/browser";
import {
  ContentTooLargeError,
  ExpiredTokenError,
  InvalidSignatureError,
  MissingAuthError,
  ProtocolError,
} from "../errors/catalog.js";

export type AuthMechanism =
  "web3-signed" | "dev-token" | "control-plane-token" | "cli-session-token";

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

const cachedRequestBodies = new WeakMap<Request, Uint8Array>();
const DEFAULT_SIGNED_BODY_MAX_BYTES = 1 * 1024 * 1024;

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

/**
 * Capture a request body before a handler parses it. The cached bytes are the
 * exact bytes owner authentication hashes, even when a later JSON parser has
 * consumed the adapter's Request body.
 */
export async function cacheRequestBodyBytes(
  request: Request,
  maxBytes = DEFAULT_SIGNED_BODY_MAX_BYTES,
  consumeBody = false,
): Promise<Uint8Array | undefined> {
  if (request.method === "GET" || request.method === "HEAD") return undefined;
  const cached = cachedRequestBodies.get(request);
  if (cached) return cached;

  const contentLength = request.headers.get("content-length");
  if (contentLength !== null) {
    const parsedLength = Number(contentLength);
    if (!Number.isSafeInteger(parsedLength) || parsedLength < 0) {
      void request.body?.cancel().catch(() => undefined);
      throw new ContentTooLargeError({ max: maxBytes });
    }
    if (parsedLength > maxBytes) {
      void request.body?.cancel().catch(() => undefined);
      throw new ContentTooLargeError({ max: maxBytes });
    }
  }

  const source = consumeBody ? request : request.clone();
  const body = source.body;
  if (!body) {
    // Some browser engines do not expose Request.body. Their request streams
    // cannot be bounded incrementally, so retain the compatibility path and
    // reject immediately after the engine materializes the clone.
    const bytes = new Uint8Array(await source.arrayBuffer());
    if (bytes.byteLength > maxBytes) {
      throw new ContentTooLargeError({ max: maxBytes });
    }
    cachedRequestBodies.set(request, bytes);
    return bytes;
  }

  // Allocate no more than the route's limit. Read one stream chunk at a time
  // and reject before copying any chunk that would cross that limit.
  const capacity = contentLength === null ? maxBytes : Number(contentLength);
  const buffer = new Uint8Array(capacity);
  const reader = body.getReader();
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (length + value.byteLength > maxBytes) {
        const cancellations = consumeBody
          ? [reader.cancel()]
          : [reader.cancel(), request.body?.cancel()];
        void Promise.allSettled(cancellations);
        throw new ContentTooLargeError({ max: maxBytes });
      }
      buffer.set(value, length);
      length += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = buffer.subarray(0, length);
  cachedRequestBodies.set(request, bytes);
  return bytes;
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
      bodyBytes: await cacheRequestBodyBytes(input.request),
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
