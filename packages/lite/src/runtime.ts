import {
  GrantRequiredError,
  InvalidSignatureError,
  MissingAuthError,
  NotOwnerError,
  ProtocolError,
  PsUnavailableError,
  UnregisteredBuilderError,
} from "@opendatalabs/personal-server-ts-core/errors";
import {
  authenticateRequest,
  type AuthenticatedRequest,
  type SessionTokenVerifierPort,
} from "@opendatalabs/personal-server-ts-core/auth";
import {
  approveDeviceSessionContract,
  createMemoryDeviceSessionStore,
  initiateDeviceSessionContract,
  pollDeviceSessionContract,
  provisionDeviceTokenContract,
  revokeDeviceTokenContract,
  type DeviceSessionStore,
} from "@opendatalabs/personal-server-ts-core/contracts";
import {
  handlePersonalServerAccessLogsRequest,
  handlePersonalServerConfigRequest,
  handlePersonalServerDataRequest,
  handlePersonalServerGrantsRequest,
  handlePersonalServerOauthTokenRequest,
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
  syncManager?:
    | (Pick<SyncManager, "trigger" | "getStatus"> &
        Partial<Pick<SyncManager, "start" | "stop">>)
    | null;
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
  accessToken?: string;
  tokenStore?: SessionTokenVerifierPort;
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
      if (parseBearerToken(request) === options.ownerToken) return;
      assertBearerToken(request, options.builderToken);
    },
    async authorizeBuilderRead(input) {
      if (parseBearerToken(input.request) === options.ownerToken) {
        return { builder: "owner", grantId: "owner" };
      }
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

async function authenticatePsLiteRequest(
  request: Request,
  options: Web3SignedPsLiteAuthOptions,
): Promise<AuthenticatedRequest> {
  return authenticateRequest({
    request,
    serverOrigin: options.origin,
    serverOwner: options.ownerAddress,
    accessToken: options.accessToken,
    sessionTokenVerifier: options.tokenStore,
    now: options.now,
  });
}

function isOwnerSigner(
  auth: AuthenticatedRequest,
  ownerAddress: string,
): boolean {
  return auth.auth.signer.toLowerCase() === ownerAddress.toLowerCase();
}

function dataReadPolicyPortsRequired(): ProtocolError {
  return new ProtocolError(
    500,
    "SERVER_NOT_CONFIGURED",
    "Server is not configured",
    {
      reason: "PS Lite read policy ports are not configured",
    },
  );
}

export function createWeb3SignedPsLiteAuth(
  options: Web3SignedPsLiteAuthOptions,
): PsLiteAuthAdapter {
  return {
    async authorizeOwner(request) {
      const auth = await authenticatePsLiteRequest(request, options);
      if (!isOwnerSigner(auth, options.ownerAddress)) {
        throw new NotOwnerError({
          expected: options.ownerAddress,
          actual: auth.auth.signer,
        });
      }
    },
    async authorizeBuilderList(request) {
      const auth = await authenticatePsLiteRequest(request, options);
      if (auth.isPolicyBypass || isOwnerSigner(auth, options.ownerAddress)) {
        return;
      }
      if (!options.dataReadPolicyPorts) {
        throw dataReadPolicyPortsRequired();
      }
      const builder =
        await options.dataReadPolicyPorts.authSessionVerifier.getBuilder(
          auth.auth.signer,
        );
      if (!builder) {
        throw new UnregisteredBuilderError();
      }
    },
    async authorizeBuilderRead(input) {
      const auth = await authenticatePsLiteRequest(input.request, options);
      if (auth.isPolicyBypass) {
        return { builder: auth.auth.signer, grantId: "policy-bypass" };
      }
      if (isOwnerSigner(auth, options.ownerAddress)) {
        return { builder: auth.auth.signer, grantId: "owner" };
      }
      if (!options.dataReadPolicyPorts) {
        throw dataReadPolicyPortsRequired();
      }
      const grant = await verifyDataReadPolicy(
        {
          signer: auth.auth.signer,
          grantId: auth.auth.payload.grantId ?? input.grantId,
          requestedScope: input.scope,
          fileId: input.fileId,
        },
        options.dataReadPolicyPorts,
      );
      return { builder: auth.auth.signer, grantId: grant.id };
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

  return {
    kind: "ps-lite",
    storage: options.storage,
    activate() {
      active = true;
      options.syncManager?.start?.();
    },
    deactivate() {
      active = false;
      void options.syncManager?.stop?.();
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
          return handlePersonalServerOauthTokenRequest(request, {
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
        }

        const grantsPrefix = "/v1/grants";
        if (
          url.pathname === grantsPrefix ||
          url.pathname === `${grantsPrefix}/` ||
          url.pathname === `${grantsPrefix}/verify`
        ) {
          return handlePersonalServerGrantsRequest(
            request,
            {
              auth,
              gateway: options.gateway,
              gatewayConfig: options.config?.gateway as
                | DataPortabilityGatewayConfig
                | undefined,
              serverOwner: options.serverOwner ?? options.identity?.address,
              serverSigner: options.serverSigner,
              now,
            },
            { basePath: grantsPrefix },
          );
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
          return handlePersonalServerConfigRequest(request, {
            auth,
            async readConfig() {
              return options.config ?? {};
            },
            async writeConfig(config) {
              await saveConfig(config);
            },
          });
        }

        return errorResponse(404, "NOT_FOUND", "Not found");
      });
    },
  };
}
