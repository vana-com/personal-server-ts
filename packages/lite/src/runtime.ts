import {
  ExpiredTokenError as SdkExpiredTokenError,
  InvalidSignatureError as SdkInvalidSignatureError,
  MissingAuthError as SdkMissingAuthError,
  verifyWeb3Signed as sdkVerifyWeb3Signed,
} from "@opendatalabs/vana-sdk/browser";
import {
  ExpiredTokenError,
  GrantRequiredError,
  InvalidSignatureError,
  MissingAuthError,
  NotOwnerError,
  ProtocolError,
  PsUnavailableError,
  UnregisteredBuilderError,
} from "@opendatalabs/personal-server-ts-core/errors";
import {
  approveDeviceSessionContract,
  createGrantContract,
  createMemoryDeviceSessionStore,
  initiateDeviceSessionContract,
  listGrantsContract,
  oauthTokenContract,
  parseJsonObjectBody,
  pollDeviceSessionContract,
  provisionDeviceTokenContract,
  revokeDeviceTokenContract,
  validateServerConfigContract,
  verifyGrantContract,
  type DeviceSessionStore,
} from "@opendatalabs/personal-server-ts-core/contracts";
import {
  handlePersonalServerAccessLogsRequest,
  handlePersonalServerDataRequest,
  handlePersonalServerSyncRequest,
  type PersonalServerApiAuthPort,
  type PersonalServerReadAuthInput,
  type PersonalServerReadAuthResult,
} from "@opendatalabs/personal-server-ts-core/api";
import {
  verifyDataReadPolicy,
  type DataReadPolicyPorts,
} from "@opendatalabs/personal-server-ts-core/policy";
import type {
  DataStoragePort,
  RuntimeAvailabilityPort,
} from "@opendatalabs/personal-server-ts-core/ports";
import type {
  DataPortabilityGatewayConfig,
  GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { AccessLogReader } from "@opendatalabs/personal-server-ts-core/logging/access-reader";
import type { ServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import type { SyncManager } from "@opendatalabs/personal-server-ts-core/sync";
import type { PsLiteStorageCapabilities } from "./storage.js";
import {
  createIndexedDbPsLiteAccessLogStore,
  createIndexedDbPsLiteStateStore,
  createIndexedDbPsLiteTokenStore,
  savePsLiteConfig,
} from "./state.js";

export interface PsLiteStorageAdapter {
  kind: "indexeddb" | "opfs" | "custom";
}

export type PsLiteReadAuthInput = PersonalServerReadAuthInput;

export type PsLiteReadAuthResult = PersonalServerReadAuthResult;

export type PsLiteAuthAdapter = PersonalServerApiAuthPort;

export interface PsLiteRuntimeOptions {
  storage: PsLiteStorageAdapter | DataStoragePort;
  auth?: PsLiteAuthAdapter;
  active?: boolean;
  now?: () => Date;
  config?: {
    server?: { origin?: string };
    gateway?: Partial<DataPortabilityGatewayConfig> & { url?: string };
  };
  saveConfig?: (config: unknown) => Promise<void>;
  identity?: { address: `0x${string}`; publicKey: `0x${string}` };
  gateway?: GatewayClient;
  serverOwner?: `0x${string}`;
  serverSigner?: Pick<
    ServerSigner,
    "signFileRegistration" | "signGrantRegistration"
  >;
  syncManager?: Pick<SyncManager, "trigger" | "getStatus"> | null;
  accessLogReader?: AccessLogReader;
  accessLogWriter?: AccessLogWriter;
  accessToken?: string;
  tokenStore?: PsLiteTokenStore;
  stateCapabilities?: Partial<PsLiteRuntimeStateCapabilities>;
}

export interface PsLiteRuntimeStateCapabilities {
  tokens: "indexeddb" | "memory" | "custom";
  accessLogs: "indexeddb" | "memory" | "custom";
  config: "indexeddb" | "memory" | "custom";
}

export interface PsLiteTokenStore {
  getTokens(): Promise<string[]>;
  isValid(token: string): Promise<boolean>;
  addToken(
    token: string,
    options?: { expiresAt?: string | Date | null },
  ): Promise<void>;
  removeToken(token: string): Promise<void>;
}

interface PsLiteRuntimeStoreCapabilities {
  capabilities?: Partial<PsLiteRuntimeStateCapabilities>;
}

export interface PsLiteRuntime extends RuntimeAvailabilityPort {
  readonly kind: "ps-lite";
  readonly storage: PsLiteStorageAdapter | DataStoragePort;
  activate(): void;
  deactivate(): void;
  fetch(request: Request): Promise<Response>;
}

export interface BearerTokenPsLiteAuthOptions {
  ownerToken: string;
  builderToken: string;
}

export interface Web3SignedPsLiteAuthOptions {
  origin: string | (() => string);
  ownerAddress: `0x${string}`;
  dataReadPolicyPorts?: DataReadPolicyPorts;
  now?: () => number;
}

type JsonStatus = 200 | 201 | 400 | 401 | 403 | 404 | 405 | 500 | 501 | 503;
function jsonResponse(body: unknown, init?: ResponseInit): Response {
  const headers = new Headers(init?.headers);
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify(body), { ...init, headers });
}

function protocolErrorResponse(err: ProtocolError): Response {
  return jsonResponse(err.toJSON(), { status: err.code });
}

function errorResponse(
  status: JsonStatus,
  errorCode: string,
  message: string,
): Response {
  return jsonResponse(
    {
      error: {
        code: status,
        errorCode,
        message,
      },
    },
    { status },
  );
}

function unavailableResponse(): Response {
  const err = new PsUnavailableError({
    runtime: "ps-lite",
    reason: "Browser runtime is inactive",
  });
  return protocolErrorResponse(err);
}

function parseBearerToken(request: Request): string | null {
  const authorization = request.headers.get("authorization");
  if (!authorization) return null;
  const match = /^Bearer\s+(.+)$/i.exec(authorization);
  return match?.[1] ?? null;
}

function assertBearerToken(
  request: Request,
  expectedToken: string,
  ownerOnly = false,
): void {
  const token = parseBearerToken(request);
  if (!token) {
    throw new MissingAuthError();
  }
  if (token !== expectedToken) {
    throw ownerOnly ? new NotOwnerError() : new InvalidSignatureError();
  }
}

function createMissingAuthAdapter(): PsLiteAuthAdapter {
  return {
    async authorizeOwner() {
      throw new MissingAuthError();
    },
    async authorizeBuilderList() {
      throw new MissingAuthError();
    },
    async authorizeBuilderRead() {
      throw new MissingAuthError();
    },
  };
}

export function createBearerTokenPsLiteAuth(
  options: BearerTokenPsLiteAuthOptions,
): PsLiteAuthAdapter {
  return {
    async authorizeOwner(request) {
      assertBearerToken(request, options.ownerToken, true);
    },
    async authorizeBuilderList(request) {
      assertBearerToken(request, options.builderToken);
    },
    async authorizeBuilderRead(input) {
      assertBearerToken(input.request, options.builderToken);
      if (!input.grantId) {
        throw new GrantRequiredError({
          reason: "No grantId in request",
        });
      }
      return { grantId: input.grantId };
    },
  };
}

function resolveOrigin(origin: string | (() => string)): string {
  return typeof origin === "function" ? origin() : origin;
}

async function verifyWeb3SignedRequest(
  request: Request,
  options: Web3SignedPsLiteAuthOptions,
) {
  const url = new URL(request.url);
  try {
    return await sdkVerifyWeb3Signed({
      headerValue: request.headers.get("authorization") ?? undefined,
      expectedOrigin: resolveOrigin(options.origin),
      expectedMethod: request.method,
      expectedPath: url.pathname,
      now: options.now?.(),
    });
  } catch (err) {
    if (err instanceof SdkMissingAuthError) {
      throw new MissingAuthError(getErrorDetails(err));
    }
    if (err instanceof SdkInvalidSignatureError) {
      throw new InvalidSignatureError(getErrorDetails(err));
    }
    if (err instanceof SdkExpiredTokenError) {
      throw new ExpiredTokenError(getErrorDetails(err));
    }
    throw err;
  }
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

export function createWeb3SignedPsLiteAuth(
  options: Web3SignedPsLiteAuthOptions,
): PsLiteAuthAdapter {
  return {
    async authorizeOwner(request) {
      const verified = await verifyWeb3SignedRequest(request, options);
      if (
        verified.signer.toLowerCase() !== options.ownerAddress.toLowerCase()
      ) {
        throw new NotOwnerError({
          expected: options.ownerAddress,
          actual: verified.signer,
        });
      }
    },
    async authorizeBuilderList(request) {
      const verified = await verifyWeb3SignedRequest(request, options);
      if (
        verified.signer.toLowerCase() === options.ownerAddress.toLowerCase()
      ) {
        return;
      }
      const builder =
        await options.dataReadPolicyPorts?.authSessionVerifier.getBuilder(
          verified.signer,
        );
      if (options.dataReadPolicyPorts && !builder) {
        throw new UnregisteredBuilderError();
      }
    },
    async authorizeBuilderRead(input) {
      const verified = await verifyWeb3SignedRequest(input.request, options);
      if (!options.dataReadPolicyPorts) {
        throw new ProtocolError(
          500,
          "SERVER_NOT_CONFIGURED",
          "Server is not configured",
          {
            reason: "PS Lite read policy ports are not configured",
          },
        );
      }
      const grant = await verifyDataReadPolicy(
        {
          signer: verified.signer,
          grantId: verified.payload.grantId ?? input.grantId,
          requestedScope: input.scope,
          fileId: input.fileId,
        },
        options.dataReadPolicyPorts,
      );
      return { builder: verified.signer, grantId: grant.id };
    },
  };
}

function toDataStoragePort(
  storage: PsLiteStorageAdapter | DataStoragePort,
): DataStoragePort {
  if ("listScopes" in storage) {
    return storage;
  }
  throw new Error(
    "PS Lite runtime requires a persistent DataStoragePort. Use createIndexedDbPsLiteRuntime() or createPersistentPsLiteStorage().",
  );
}

function indexedDbAvailable(): boolean {
  return typeof indexedDB !== "undefined";
}

function createDefaultAccessLogStore(): AccessLogReader & AccessLogWriter {
  if (!indexedDbAvailable()) {
    throw new Error(
      "IndexedDB is required for default PS Lite access log persistence.",
    );
  }
  return createIndexedDbPsLiteAccessLogStore();
}

function createLogId(): string {
  return globalThis.crypto?.randomUUID?.() ?? `log-${Date.now()}`;
}

function randomHex(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

function createDefaultTokenStore(): PsLiteTokenStore {
  if (!indexedDbAvailable()) {
    throw new Error("IndexedDB is required for default PS Lite token storage.");
  }
  return createIndexedDbPsLiteTokenStore();
}

function createDefaultSaveConfig(): (config: unknown) => Promise<void> {
  if (!indexedDbAvailable()) {
    throw new Error(
      "IndexedDB is required for default PS Lite config persistence.",
    );
  }
  const stateStore = createIndexedDbPsLiteStateStore();
  return async (nextConfig: unknown) => {
    await savePsLiteConfig(stateStore, nextConfig);
  };
}

function bearerToken(request: Request): string | null {
  const authorization = request.headers.get("authorization");
  if (!authorization?.startsWith("Bearer ")) return null;
  return authorization.slice(7);
}

async function readForm(request: Request): Promise<URLSearchParams> {
  return new URLSearchParams(await request.text());
}

export function createPsLiteRuntime(
  options: PsLiteRuntimeOptions,
): PsLiteRuntime {
  let active = options.active ?? false;
  const now = options.now ?? (() => new Date());
  const auth = options.auth ?? createMissingAuthAdapter();
  const dataStorage = toDataStoragePort(options.storage);
  let accessLogReader = options.accessLogReader;
  let accessLogWriter = options.accessLogWriter;
  if (!accessLogReader || !accessLogWriter) {
    const accessLogStore = createDefaultAccessLogStore();
    accessLogReader ??= accessLogStore;
    accessLogWriter ??= accessLogStore;
  }
  const tokenStore = options.tokenStore ?? createDefaultTokenStore();
  const saveConfig = options.saveConfig ?? createDefaultSaveConfig();
  const deviceSessions: DeviceSessionStore = createMemoryDeviceSessionStore();

  async function withProtocolErrors(
    handler: () => Promise<Response> | Response,
  ): Promise<Response> {
    try {
      return await handler();
    } catch (err) {
      if (err instanceof ProtocolError) {
        return protocolErrorResponse(err);
      }
      return errorResponse(500, "INTERNAL_ERROR", "Internal server error");
    }
  }

  function sendContractResult(result: {
    status: number;
    body: unknown;
  }): Response {
    return jsonResponse(result.body, { status: result.status });
  }

  function gatewayRequiredResponse(): Response {
    return errorResponse(
      500,
      "SERVER_NOT_CONFIGURED",
      "Gateway is not configured",
    );
  }

  function ownerAddress(): `0x${string}` | undefined {
    return options.serverOwner ?? options.identity?.address;
  }

  async function handleAuthDevice(request: Request, url: URL) {
    if (url.pathname === "/auth/device") {
      if (request.method !== "POST") {
        return errorResponse(405, "METHOD_NOT_ALLOWED", "Method not allowed");
      }
      return sendContractResult(
        initiateDeviceSessionContract({
          sessionStore: deviceSessions,
          serverOwner: ownerAddress(),
          requestOrigin: url.origin,
          approvalOrigin: url.origin,
          sessionId: randomHex(32),
          pollToken: randomHex(32),
          now: now().getTime(),
        }),
      );
    }

    if (url.pathname === "/auth/device/poll") {
      if (request.method !== "GET") {
        return errorResponse(405, "METHOD_NOT_ALLOWED", "Method not allowed");
      }
      return sendContractResult(
        pollDeviceSessionContract({
          sessionStore: deviceSessions,
          pollToken: url.searchParams.get("token"),
          serverOwner: ownerAddress(),
          now: now().getTime(),
        }),
      );
    }

    if (url.pathname === "/auth/device/approve") {
      const sessionId = url.searchParams.get("session");
      if (!sessionId) {
        return request.method === "GET"
          ? new Response("Missing session parameter", { status: 400 })
          : jsonResponse(
              { error: { code: 400, message: "Missing session parameter" } },
              { status: 400 },
            );
      }
      const session = deviceSessions.get(sessionId);
      if (!session) {
        return request.method === "GET"
          ? new Response("Session expired or invalid", { status: 404 })
          : jsonResponse(
              { error: { code: 404, message: "Session expired or invalid" } },
              { status: 404 },
            );
      }
      if (request.method === "GET") {
        return new Response("Device authorization pending", {
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }
      if (request.method !== "POST") {
        return errorResponse(405, "METHOD_NOT_ALLOWED", "Method not allowed");
      }
      if (session.status === "approved") {
        return jsonResponse({ status: "already_approved" });
      }
      await auth.authorizeOwner(request);
      return sendContractResult(
        await approveDeviceSessionContract({
          sessionStore: deviceSessions,
          tokenStore,
          sessionId,
          serverOwner: ownerAddress(),
          accessToken: `vana_ps_${randomHex(32)}`,
          now: now().getTime(),
        }),
      );
    }

    if (url.pathname === "/auth/device/token") {
      if (request.method === "DELETE") {
        const token = bearerToken(request);
        if (!token) {
          return jsonResponse(
            { error: { code: 401, message: "Missing Bearer token" } },
            { status: 401 },
          );
        }
        return sendContractResult(
          await revokeDeviceTokenContract({
            tokenStore,
            bearerToken: token,
          }),
        );
      }
      if (request.method !== "POST") {
        return errorResponse(405, "METHOD_NOT_ALLOWED", "Method not allowed");
      }
      const token = bearerToken(request);
      if (!options.accessToken || token !== options.accessToken) {
        return jsonResponse(
          {
            error: {
              code: 403,
              message:
                "Only control-plane tokens can provision Personal Server session tokens",
            },
          },
          { status: 403 },
        );
      }
      let body: { token?: string; expires_at?: string | null };
      try {
        body = (await request.json()) as {
          token?: string;
          expires_at?: string | null;
        };
      } catch {
        return jsonResponse(
          { error: { code: 400, message: "Request body must be valid JSON" } },
          { status: 400 },
        );
      }
      if (!body.token || typeof body.token !== "string") {
        return jsonResponse(
          { error: { code: 400, message: "Missing token" } },
          { status: 400 },
        );
      }
      return sendContractResult(
        await provisionDeviceTokenContract({
          tokenStore,
          body,
          now: now().getTime(),
        }),
      );
    }

    return undefined;
  }

  async function handleOauthToken(request: Request) {
    if (request.method !== "POST") {
      return errorResponse(405, "METHOD_NOT_ALLOWED", "Method not allowed");
    }
    const contentType = request.headers.get("content-type") ?? "";
    if (!contentType.includes("application/x-www-form-urlencoded")) {
      return jsonResponse(
        {
          error: "invalid_request",
          error_description:
            "Content-Type must be application/x-www-form-urlencoded",
        },
        { status: 400 },
      );
    }
    const form = await readForm(request);
    const result = await oauthTokenContract({
      body: form,
      authorizationHeader: request.headers.get("authorization"),
      tokenStore,
      controlPlaneSecret: options.accessToken,
      randomToken: () => `vana_ps_${randomHex(32)}`,
      now,
      deviceSessions: {
        findByDeviceCode(deviceCode) {
          const session = deviceSessions.findByPollToken(deviceCode);
          if (!session) return null;
          return {
            status: session.status,
            accessToken: session.accessToken,
            accessTokenExpiresAt: session.accessTokenExpiresAt,
            sessionId: session.sessionId,
          };
        },
        consume(sessionId) {
          deviceSessions.delete(sessionId);
        },
      },
    });
    return jsonResponse(result.body, {
      status: result.status,
      headers: result.headers,
    });
  }

  return {
    kind: "ps-lite",
    storage: options.storage,
    activate() {
      active = true;
    },
    deactivate() {
      active = false;
    },
    isAvailable() {
      return active;
    },
    async fetch(request: Request) {
      return withProtocolErrors(async () => {
        const url = new URL(request.url);

        if (url.pathname === "/health") {
          const apiOrigin = url.origin;
          const identity = options.identity ?? null;
          let serverId: string | null = null;
          if (identity && options.gateway) {
            try {
              const server = await options.gateway.getServer(identity.address);
              serverId = server?.id ?? null;
            } catch {
              serverId = null;
            }
          }
          const registration =
            options.serverOwner && identity
              ? {
                  ownerAddress: options.serverOwner,
                  serverAddress: identity.address,
                  publicKey: identity.publicKey,
                  serverUrl: apiOrigin,
                  serverId,
                  registered: Boolean(serverId),
                }
              : null;
          const capabilities = (
            dataStorage as DataStoragePort & {
              capabilities?: PsLiteStorageCapabilities;
            }
          ).capabilities;
          const stateCapabilities: PsLiteRuntimeStateCapabilities = {
            tokens:
              (tokenStore as PsLiteTokenStore & PsLiteRuntimeStoreCapabilities)
                .capabilities?.tokens ?? "custom",
            accessLogs:
              (
                accessLogReader as AccessLogReader &
                  PsLiteRuntimeStoreCapabilities
              ).capabilities?.accessLogs ?? "custom",
            config:
              options.stateCapabilities?.config ??
              (options.saveConfig ? "custom" : "indexeddb"),
          };
          return jsonResponse({
            status: active ? "healthy" : "unavailable",
            runtime: "ps-lite",
            storage: options.storage.kind,
            capabilities: capabilities ?? null,
            stateCapabilities,
            owner: options.serverOwner ?? null,
            apiOrigin,
            gatewayUrl: options.config?.gateway?.url ?? null,
            gatewayConfig: options.config?.gateway ?? null,
            identity,
            registration,
            active,
            checkedAt: now().toISOString(),
          });
        }

        if (!active) {
          return unavailableResponse();
        }

        const dataPrefix = "/v1/data";
        if (
          url.pathname === dataPrefix ||
          url.pathname.startsWith(`${dataPrefix}/`)
        ) {
          return handlePersonalServerDataRequest(
            request,
            {
              storage: dataStorage,
              auth,
              schemaResolver: options.gateway,
              accessLogWriter,
              syncManager: options.syncManager ?? null,
              now,
              createLogId,
            },
            { basePath: dataPrefix },
          );
        }

        if (url.pathname.startsWith("/auth/device")) {
          const response = await handleAuthDevice(request, url);
          if (response) return response;
        }

        if (url.pathname === "/oauth/token") {
          return handleOauthToken(request);
        }

        const grantsPrefix = "/v1/grants";
        if (
          url.pathname === grantsPrefix ||
          url.pathname === `${grantsPrefix}/`
        ) {
          if (request.method === "GET") {
            await auth.authorizeOwner(request);
            if (!options.gateway) return gatewayRequiredResponse();
            return sendContractResult(
              await listGrantsContract({
                gateway: options.gateway,
                serverOwner: options.serverOwner ?? options.identity?.address,
              }),
            );
          }
          if (request.method === "POST") {
            await auth.authorizeOwner(request);
            if (!options.gateway) return gatewayRequiredResponse();
            let body: unknown;
            try {
              body = await request.json();
            } catch {
              return errorResponse(400, "INVALID_BODY", "Invalid JSON body");
            }
            return sendContractResult(
              await createGrantContract({
                gateway: options.gateway,
                serverOwner: options.serverOwner ?? options.identity?.address,
                serverSigner: options.serverSigner,
                body,
                now: () => now().getTime(),
              }),
            );
          }
          return errorResponse(405, "METHOD_NOT_ALLOWED", "Method not allowed");
        }

        if (url.pathname === `${grantsPrefix}/verify`) {
          if (request.method !== "POST") {
            return errorResponse(
              405,
              "METHOD_NOT_ALLOWED",
              "Method not allowed",
            );
          }
          let body: unknown;
          try {
            body = await request.json();
          } catch {
            return errorResponse(400, "INVALID_BODY", "Invalid JSON body");
          }
          return sendContractResult(await verifyGrantContract(body));
        }

        const accessLogsPrefix = "/v1/access-logs";
        if (
          url.pathname === accessLogsPrefix ||
          url.pathname === `${accessLogsPrefix}/`
        ) {
          return handlePersonalServerAccessLogsRequest(
            request,
            { auth, accessLogReader },
            { basePath: accessLogsPrefix },
          );
        }

        const syncPrefix = "/v1/sync";
        if (
          url.pathname === `${syncPrefix}/trigger` ||
          url.pathname === `${syncPrefix}/status` ||
          url.pathname.startsWith(`${syncPrefix}/file/`)
        ) {
          return handlePersonalServerSyncRequest(
            request,
            { auth, syncManager: options.syncManager ?? null },
            { basePath: syncPrefix },
          );
        }

        if (url.pathname === "/ui/api/config") {
          if (request.method === "GET") {
            await auth.authorizeOwner(request);
            return jsonResponse(options.config ?? {});
          }
          if (request.method === "PUT") {
            await auth.authorizeOwner(request);
            const parsed = await parseJsonObjectBody(request);
            if (!parsed.ok) return sendContractResult(parsed.result);
            const result = validateServerConfigContract(parsed.body);
            if (!result.ok) return sendContractResult(result);
            await saveConfig?.((result.body as { config: unknown }).config);
            return sendContractResult(result);
          }
          return errorResponse(405, "METHOD_NOT_ALLOWED", "Method not allowed");
        }

        return errorResponse(404, "NOT_FOUND", "Not found");
      });
    },
  };
}
