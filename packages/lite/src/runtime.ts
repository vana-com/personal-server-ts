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
  createGrantContract,
  deleteDataScopeContract,
  getSyncStatusContract,
  ingestDataContract,
  listAccessLogsContract,
  listDataScopesContract,
  listDataVersionsContract,
  listGrantsContract,
  parseDataScopeContract,
  parseJsonObjectBody,
  readDataContract,
  syncFileContract,
  triggerSyncContract,
  validateServerConfigContract,
  verifyGrantContract,
  type DataContractError,
} from "@opendatalabs/personal-server-ts-core/contracts";
import {
  verifyDataReadPolicy,
  type DataReadPolicyPorts,
} from "@opendatalabs/personal-server-ts-core/policy";
import type {
  DataStoragePort,
  RuntimeAvailabilityPort,
} from "@opendatalabs/personal-server-ts-core/ports";
import type {
  DataFileEnvelope,
  GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import type { IndexEntry } from "@opendatalabs/personal-server-ts-core/storage/index";
import type {
  AccessLogEntry,
  AccessLogWriter,
} from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { AccessLogReader } from "@opendatalabs/personal-server-ts-core/logging/access-reader";
import type { ServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import type { SyncManager } from "@opendatalabs/personal-server-ts-core/sync";
import {
  createStorageReadMethods,
  readEnvelopeFromMap,
  sortEntries,
} from "./storage-utils.js";
import type { PsLiteStorageCapabilities } from "./storage.js";

export interface PsLiteStorageAdapter {
  kind: "indexeddb" | "opfs" | "custom";
}

export interface PsLiteReadAuthInput {
  request: Request;
  scope: string;
  grantId?: string;
  fileId?: string;
}

export interface PsLiteReadAuthResult {
  builder?: `0x${string}`;
  grantId?: string;
}

export interface PsLiteAuthAdapter {
  authorizeOwner(request: Request): Promise<void>;
  authorizeBuilderList(request: Request): Promise<void>;
  authorizeBuilderRead(
    input: PsLiteReadAuthInput,
  ): Promise<PsLiteReadAuthResult | void>;
}

export interface PsLiteRuntimeOptions {
  storage: PsLiteStorageAdapter | DataStoragePort;
  auth?: PsLiteAuthAdapter;
  active?: boolean;
  now?: () => Date;
  config?: { server?: { origin?: string }; gateway?: { url?: string } };
  saveConfig?: (config: unknown) => Promise<void>;
  identity?: { address: `0x${string}`; publicKey: `0x${string}` };
  gateway?: GatewayClient;
  serverOwner?: `0x${string}`;
  serverSigner?: Pick<ServerSigner, "signGrantRegistration">;
  syncManager?: Pick<SyncManager, "trigger" | "getStatus"> | null;
  accessLogReader?: AccessLogReader;
  accessLogWriter?: AccessLogWriter;
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

function contractErrorResponse(err: DataContractError): Response {
  return errorResponse(err.status, err.body.error, err.body.message);
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

function normalizeLimit(value: string | null, fallback: number): number {
  if (value === null) return fallback;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : fallback;
}

function toDataStoragePort(
  storage: PsLiteStorageAdapter | DataStoragePort,
): DataStoragePort {
  if ("listScopes" in storage) {
    return storage;
  }
  return createMemoryPsLiteStorage(storage);
}

function createMemoryAccessLogStore(): AccessLogReader & AccessLogWriter {
  const logs: AccessLogEntry[] = [];
  return {
    async write(entry) {
      logs.push(entry);
    },
    async read(options) {
      const limit = options?.limit ?? 50;
      const offset = options?.offset ?? 0;
      const sorted = [...logs].sort(
        (a, b) =>
          new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
      );
      return {
        logs: sorted.slice(offset, offset + limit),
        total: sorted.length,
        limit,
        offset,
      };
    },
  };
}

function createLogId(): string {
  return globalThis.crypto?.randomUUID?.() ?? `log-${Date.now()}`;
}

export function createMemoryPsLiteStorage(
  adapter: PsLiteStorageAdapter = { kind: "indexeddb" },
): DataStoragePort {
  const entries = new Map<string, IndexEntry>();
  const envelopes = new Map<string, DataFileEnvelope>();
  let nextId = 1;

  function envelopeKey(scope: string, collectedAt: string): string {
    return `${scope}\n${collectedAt}`;
  }

  function entriesForScope(scope: string): IndexEntry[] {
    return sortEntries(
      Array.from(entries.values()).filter((entry) => entry.scope === scope),
    );
  }

  const storagePort: DataStoragePort & {
    capabilities: PsLiteStorageCapabilities;
  } = {
    kind: adapter.kind === "custom" ? "custom" : "browser-indexeddb-opfs",
    capabilities: {
      metadata: "memory",
      files: "memory",
      opfsAvailable: false,
    } satisfies PsLiteStorageCapabilities,
    ...createStorageReadMethods(() => entries.values(), entriesForScope),

    async readEnvelope(scope, collectedAt) {
      return readEnvelopeFromMap(envelopes, envelopeKey(scope, collectedAt));
    },

    async writeEnvelope(envelope) {
      envelopes.set(
        envelopeKey(envelope.scope, envelope.collectedAt),
        envelope,
      );
      return {
        path: `${envelope.scope}/${envelope.collectedAt}.json`,
        relativePath: `${envelope.scope}/${envelope.collectedAt}.json`,
        sizeBytes: new TextEncoder().encode(JSON.stringify(envelope)).length,
      };
    },

    insertEntry(entry) {
      const indexed: IndexEntry = {
        ...entry,
        schemaId: entry.schemaId ?? null,
        id: nextId,
        createdAt: new Date().toISOString(),
      };
      nextId += 1;
      entries.set(entry.path, indexed);
      return indexed;
    },

    async deleteScope(scope) {
      let deleted = 0;
      for (const [path, entry] of entries.entries()) {
        if (entry.scope === scope) {
          entries.delete(path);
          envelopes.delete(envelopeKey(entry.scope, entry.collectedAt));
          deleted += 1;
        }
      }
      return deleted;
    },
  };
  return storagePort;
}

function parseScope(pathPart: string): string | Response {
  const scopeResult = parseDataScopeContract(decodeURIComponent(pathPart));
  if (!scopeResult.ok) return contractErrorResponse(scopeResult);
  return scopeResult.scope;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

async function parseJsonObject(
  request: Request,
): Promise<
  | { ok: true; body: Record<string, unknown> }
  | { ok: false; response: Response }
> {
  try {
    const body = (await request.json()) as unknown;
    if (!isRecord(body)) {
      return {
        ok: false,
        response: errorResponse(
          400,
          "INVALID_BODY",
          "Request body must be a JSON object",
        ),
      };
    }
    return { ok: true, body };
  } catch {
    return {
      ok: false,
      response: errorResponse(400, "INVALID_BODY", "Request body must be JSON"),
    };
  }
}

export function createPsLiteRuntime(
  options: PsLiteRuntimeOptions,
): PsLiteRuntime {
  let active = options.active ?? false;
  const now = options.now ?? (() => new Date());
  const auth = options.auth ?? createMissingAuthAdapter();
  const dataStorage = toDataStoragePort(options.storage);
  const accessLogStore = createMemoryAccessLogStore();
  const accessLogReader = options.accessLogReader ?? accessLogStore;
  const accessLogWriter = options.accessLogWriter ?? accessLogStore;

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
          const capabilities = (
            dataStorage as DataStoragePort & {
              capabilities?: PsLiteStorageCapabilities;
            }
          ).capabilities;
          return jsonResponse({
            status: active ? "healthy" : "unavailable",
            runtime: "ps-lite",
            storage: options.storage.kind,
            capabilities: capabilities ?? null,
            apiOrigin: options.config?.server?.origin ?? url.origin,
            gatewayUrl: options.config?.gateway?.url ?? null,
            identity: options.identity ?? null,
            active,
            checkedAt: now().toISOString(),
          });
        }

        if (!active) {
          return unavailableResponse();
        }

        const dataPrefix = "/v1/data";
        if (url.pathname === dataPrefix || url.pathname === `${dataPrefix}/`) {
          if (request.method !== "GET") {
            return errorResponse(
              405,
              "METHOD_NOT_ALLOWED",
              "Method not allowed",
            );
          }
          await auth.authorizeBuilderList(request);
          const limit = normalizeLimit(url.searchParams.get("limit"), 20);
          const offset = normalizeLimit(url.searchParams.get("offset"), 0);
          const result = listDataScopesContract({
            storage: dataStorage,
            scopePrefix: url.searchParams.get("scopePrefix") ?? undefined,
            limit,
            offset,
          });
          return jsonResponse(result.response);
        }

        if (!url.pathname.startsWith(`${dataPrefix}/`)) {
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
            return errorResponse(
              405,
              "METHOD_NOT_ALLOWED",
              "Method not allowed",
            );
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
            if (request.method !== "GET") {
              return errorResponse(
                405,
                "METHOD_NOT_ALLOWED",
                "Method not allowed",
              );
            }
            await auth.authorizeOwner(request);
            return sendContractResult(
              await listAccessLogsContract({
                accessLogReader,
                limit: url.searchParams.get("limit"),
                offset: url.searchParams.get("offset"),
              }),
            );
          }

          const syncPrefix = "/v1/sync";
          if (url.pathname === `${syncPrefix}/trigger`) {
            if (request.method !== "POST") {
              return errorResponse(
                405,
                "METHOD_NOT_ALLOWED",
                "Method not allowed",
              );
            }
            await auth.authorizeOwner(request);
            return sendContractResult(
              await triggerSyncContract(options.syncManager ?? null),
            );
          }
          if (url.pathname === `${syncPrefix}/status`) {
            if (request.method !== "GET") {
              return errorResponse(
                405,
                "METHOD_NOT_ALLOWED",
                "Method not allowed",
              );
            }
            await auth.authorizeOwner(request);
            return sendContractResult(
              getSyncStatusContract(options.syncManager ?? null),
            );
          }
          if (url.pathname.startsWith(`${syncPrefix}/file/`)) {
            if (request.method !== "POST") {
              return errorResponse(
                405,
                "METHOD_NOT_ALLOWED",
                "Method not allowed",
              );
            }
            await auth.authorizeOwner(request);
            const fileId = decodeURIComponent(
              url.pathname.slice(`${syncPrefix}/file/`.length),
            );
            return sendContractResult(
              await syncFileContract({
                fileId,
                syncManager: options.syncManager ?? null,
              }),
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
              await options.saveConfig?.(
                (result.body as { config: unknown }).config,
              );
              return sendContractResult(result);
            }
            return errorResponse(
              405,
              "METHOD_NOT_ALLOWED",
              "Method not allowed",
            );
          }

          return errorResponse(404, "NOT_FOUND", "Not found");
        }

        const parts = url.pathname.slice(dataPrefix.length + 1).split("/");
        const scope = parseScope(parts[0] ?? "");
        if (scope instanceof Response) {
          return scope;
        }

        if (parts.length === 2 && parts[1] === "versions") {
          if (request.method !== "GET") {
            return errorResponse(
              405,
              "METHOD_NOT_ALLOWED",
              "Method not allowed",
            );
          }
          await auth.authorizeBuilderList(request);
          const limit = normalizeLimit(url.searchParams.get("limit"), 20);
          const offset = normalizeLimit(url.searchParams.get("offset"), 0);
          const result = listDataVersionsContract({
            storage: dataStorage,
            scopeParam: scope,
            limit,
            offset,
          });
          if (!result.ok) return contractErrorResponse(result);
          return jsonResponse(result.response);
        }

        if (parts.length !== 1) {
          return errorResponse(404, "NOT_FOUND", "Not found");
        }

        if (request.method === "GET") {
          const grantId =
            url.searchParams.get("grantId") ??
            request.headers.get("x-ps-grant-id") ??
            undefined;
          const selectedEntry = dataStorage.findEntry({
            scope,
            fileId: url.searchParams.get("fileId") ?? undefined,
            at: url.searchParams.get("at") ?? undefined,
          });
          const authResult = await auth.authorizeBuilderRead({
            request,
            scope,
            grantId,
            fileId:
              url.searchParams.get("fileId") ??
              selectedEntry?.fileId ??
              undefined,
          });
          const result = await readDataContract({
            storage: dataStorage,
            scopeParam: scope,
            fileId: url.searchParams.get("fileId") ?? undefined,
            at: url.searchParams.get("at") ?? undefined,
          });
          if (!result.ok) return contractErrorResponse(result);
          await accessLogWriter.write({
            logId: createLogId(),
            grantId: authResult?.grantId ?? grantId ?? "unknown",
            builder: authResult?.builder ?? "unknown",
            action: "read",
            scope,
            timestamp: now().toISOString(),
            ipAddress:
              request.headers.get("x-forwarded-for") ??
              request.headers.get("x-real-ip") ??
              "unknown",
            userAgent: request.headers.get("user-agent") ?? "unknown",
          });
          return jsonResponse(result.envelope);
        }

        if (request.method === "POST") {
          await auth.authorizeOwner(request);
          const parsed = await parseJsonObject(request);
          if (!parsed.ok) {
            return parsed.response;
          }
          let schemaUrl: string | undefined;
          let schemaId: string | undefined;
          if (options.gateway) {
            const schema = await options.gateway.getSchemaForScope(scope);
            if (!schema) {
              return errorResponse(
                400,
                "NO_SCHEMA",
                `No schema registered for scope: ${scope}`,
              );
            }
            schemaUrl = schema.definitionUrl;
            schemaId = schema.id;
          }
          const collectedAt = now().toISOString();
          const result = await ingestDataContract({
            storage: dataStorage,
            scopeParam: scope,
            body: parsed.body,
            collectedAt,
            status: options.syncManager ? "syncing" : "stored",
            schemaUrl,
            schemaId,
          });
          if (!result.ok) return contractErrorResponse(result);
          options.syncManager?.trigger().catch(() => undefined);
          return jsonResponse(result.response, { status: 201 });
        }

        if (request.method === "DELETE") {
          await auth.authorizeOwner(request);
          const result = await deleteDataScopeContract({
            storage: dataStorage,
            scopeParam: scope,
          });
          if (!result.ok) return contractErrorResponse(result);
          return new Response(null, { status: 204 });
        }

        return errorResponse(405, "METHOD_NOT_ALLOWED", "Method not allowed");
      });
    },
  };
}
