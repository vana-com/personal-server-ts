import { ProtocolError } from "../errors/catalog.js";
import type { AccessLogWriter } from "../logging/access-log.js";
import type { AccessLogReader } from "../logging/access-reader.js";
import {
  type DataStoragePort,
  type RuntimeAvailabilityPort,
  type SchemaResolverPort,
  type SchemaRegistrarPort,
  type FeeVerifierPort,
} from "../ports/index.js";
import type { DataReadPolicyPorts } from "../policy/index.js";
import type { SyncManager } from "../sync/index.js";
import {
  deleteDataScopeContract,
  ingestDataContract,
  ingestBinaryDataContract,
  listAccessLogsContract,
  listDataScopesContract,
  listDataVersionsContract,
  parseDataScopeContract,
  parseJsonObjectBody,
  readDataContract,
  syncFileContract,
  triggerSyncContract,
  getSyncStatusContract,
  configReadErrorContract,
  configWriteErrorContract,
  createGrantContract,
  listGrantsContract,
  oauthTokenContract,
  revokeGrantContract,
  type ContractResult,
  type DataContractError,
  type OAuthDeviceSessionLookup,
  type OAuthTokenStorePort,
  type VerifyGrantContractInput,
  validateServerConfigContract,
  verifyGrantContract,
  decodeBinaryEnvelope,
  isBinaryEnvelope,
  parseMetadataHeader,
  stringifyMetadataHeader,
} from "../contracts/index.js";
import type {
  DataPortabilityGatewayConfig,
  GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import type { ServerSigner } from "../signing/index.js";

export {
  createSchemaRegistrar,
  NO_SCHEMA_DEFINITION_URL,
  NO_SCHEMA_DIALECT,
  NO_SCHEMA_NAME,
  type SchemaRegistrarDeps,
} from "./schema-registrar.js";

export interface PersonalServerReadAuthInput {
  request: Request;
  scope: string;
  grantId?: string;
  fileId?: string;
}

export interface PersonalServerReadAuthResult {
  builder?: `0x${string}` | string;
  grantId?: string;
}

export interface PersonalServerApiAuthPort {
  authorizeOwner(request: Request): Promise<void>;
  authorizeBuilderList(request: Request): Promise<void>;
  authorizeBuilderRead(
    input: PersonalServerReadAuthInput,
  ): Promise<PersonalServerReadAuthResult | void>;
}

export interface PersonalServerApiLogger {
  info?(payload: Record<string, unknown>, message: string): void;
  error?(payload: Record<string, unknown>, message: string): void;
}

export interface PersonalServerIngestSyncManager {
  trigger(): Promise<void>;
  notifyNewData?(): void;
  /** Propagate a scope deletion to R2 + the gateway before the local delete. */
  deleteScopeRemote?(scope: string): Promise<void>;
}

export interface PersonalServerDataApiDeps {
  storage: DataStoragePort;
  auth: PersonalServerApiAuthPort;
  schemaResolver?: SchemaResolverPort;
  /** Auto-registers a "no-schema" schema for binary scopes that lack one. */
  schemaRegistrar?: SchemaRegistrarPort;
  accessLogWriter: AccessLogWriter;
  syncManager?: PersonalServerIngestSyncManager | null;
  runtimeAvailability?: RuntimeAvailabilityPort;
  feeVerifier?: FeeVerifierPort;
  now?: () => Date;
  createLogId?: () => string;
  logger?: PersonalServerApiLogger;
}

export interface PersonalServerAccessLogsApiDeps {
  auth: Pick<PersonalServerApiAuthPort, "authorizeOwner">;
  accessLogReader: AccessLogReader;
}

export interface PersonalServerSyncApiDeps {
  auth: Pick<PersonalServerApiAuthPort, "authorizeOwner">;
  syncManager: Pick<SyncManager, "trigger" | "getStatus"> | null;
  logger?: PersonalServerApiLogger;
}

export interface PersonalServerGrantsApiDeps {
  auth: Pick<PersonalServerApiAuthPort, "authorizeOwner">;
  gateway?: Pick<
    GatewayClient,
    "getBuilder" | "createGrant" | "listGrantsByUser" | "revokeGrant"
  >;
  gatewayConfig?: DataPortabilityGatewayConfig;
  serverOwner?: `0x${string}`;
  serverSigner?: Pick<ServerSigner, "signGrantRegistration"> &
    Partial<Pick<ServerSigner, "signGrantRevocation">>;
  now?: () => Date;
}

export interface PersonalServerConfigApiDeps {
  auth: Pick<PersonalServerApiAuthPort, "authorizeOwner">;
  readConfig(): Promise<unknown>;
  writeConfig(config: unknown): Promise<void>;
}

export interface PersonalServerOauthTokenApiDeps {
  tokenStore: OAuthTokenStorePort;
  controlPlaneSecret?: string;
  deviceSessions?: OAuthDeviceSessionLookup;
  randomToken(): string;
  now?: () => Date;
  safeCompare?: (left: string, right: string) => boolean;
}

export interface PersonalServerApiDispatchOptions {
  basePath?: string;
}

type JsonStatus = 200 | 201 | 400 | 401 | 403 | 404 | 405 | 500 | 502 | 503;

function jsonResponse(body: unknown, init?: ResponseInit): Response {
  const headers = new Headers(init?.headers);
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify(body), { ...init, headers });
}

function contractResponse(result: ContractResult): Response {
  return jsonResponse(result.body, { status: result.status });
}

function contractErrorResponse(err: DataContractError): Response {
  return jsonResponse(err.body, { status: err.status });
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

function methodNotAllowed(): Response {
  return errorResponse(405, "METHOD_NOT_ALLOWED", "Method not allowed");
}

function notFound(): Response {
  return errorResponse(404, "NOT_FOUND", "Not found");
}

async function withApiErrors(
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

function normalizeLimit(value: string | null, fallback: number): number {
  if (value === null) return fallback;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : fallback;
}

function stripBasePath(pathname: string, basePath: string | undefined): string {
  if (!basePath || basePath === "/") return pathname;
  if (pathname === basePath) return "/";
  if (pathname.startsWith(`${basePath}/`)) {
    return pathname.slice(basePath.length);
  }
  return pathname;
}

function decodePathPart(value: string | undefined): string {
  return decodeURIComponent(value ?? "");
}

function selectedGrantId(request: Request, url: URL): string | undefined {
  return (
    url.searchParams.get("grantId") ??
    request.headers.get("x-ps-grant-id") ??
    undefined
  );
}

function collectedAt(now: () => Date): string {
  return now()
    .toISOString()
    .replace(/\.\d{3}Z$/, "Z");
}

async function resolveSchema(
  deps: Pick<PersonalServerDataApiDeps, "schemaResolver" | "logger">,
  scope: string,
): Promise<
  | { ok: true; schemaUrl: string | undefined; schemaId: string | undefined }
  | { ok: false; response: Response }
> {
  if (!deps.schemaResolver) {
    return {
      ok: false,
      response: errorResponse(
        500,
        "SERVER_NOT_CONFIGURED",
        "Gateway is not configured",
      ),
    };
  }

  try {
    const schema = await deps.schemaResolver.getSchemaForScope(scope);
    if (!schema) {
      return {
        ok: false,
        response: jsonResponse(
          {
            error: "NO_SCHEMA",
            message: `No schema registered for scope: ${scope}`,
          },
          { status: 400 },
        ),
      };
    }
    return {
      ok: true,
      schemaUrl: schema.definitionUrl,
      schemaId: schema.id,
    };
  } catch (err) {
    deps.logger?.error?.({ err, scope }, "Gateway schema lookup failed");
    return {
      ok: false,
      response: jsonResponse(
        {
          error: "GATEWAY_ERROR",
          message: "Failed to look up schema for scope",
        },
        { status: 502 },
      ),
    };
  }
}

/** True when the request body should be treated as a JSON object (the legacy
 * path). Missing/blank Content-Type is treated as JSON for backward compat. */
function isJsonContentType(request: Request): boolean {
  const ct = request.headers.get("content-type");
  if (!ct) return true;
  return ct.toLowerCase().includes("application/json");
}

function binaryMimeType(request: Request): string {
  const ct = request.headers.get("content-type");
  if (!ct) return "application/octet-stream";
  // Strip any "; charset=..." / boundary parameters.
  return ct.split(";")[0].trim() || "application/octet-stream";
}

/** Extract a filename from X-Filename or a Content-Disposition header. */
function binaryFilename(request: Request): string | undefined {
  const explicit = request.headers.get("x-filename");
  if (explicit) return explicit;
  const disposition = request.headers.get("content-disposition");
  const match = disposition?.match(/filename\*?=(?:UTF-8'')?"?([^";]+)"?/i);
  return match ? decodeURIComponent(match[1]) : undefined;
}

/**
 * Resolve a schema for a binary scope, registering a permissive "no-schema"
 * schema when none exists. Unlike the JSON path this never hard-fails on a
 * missing schema: if there is no registrar, ingestion proceeds with no schemaId
 * (the entry is registered against the gateway's resolved schema later).
 */
async function resolveBinarySchema(
  deps: Pick<
    PersonalServerDataApiDeps,
    "schemaResolver" | "schemaRegistrar" | "logger"
  >,
  scope: string,
): Promise<{ schemaId?: string; schemaUrl?: string }> {
  if (deps.schemaResolver) {
    const schema = await deps.schemaResolver.getSchemaForScope(scope);
    if (schema) {
      return { schemaId: schema.id, schemaUrl: schema.definitionUrl };
    }
  }
  if (deps.schemaRegistrar) {
    const registered = await deps.schemaRegistrar.registerNoSchema(scope);
    deps.logger?.info?.(
      { scope, schemaId: registered.schemaId },
      "Registered no-schema schema for binary scope",
    );
    return {
      schemaId: registered.schemaId,
      schemaUrl: registered.definitionUrl,
    };
  }
  return {};
}

function notifyNewData(
  syncManager: PersonalServerDataApiDeps["syncManager"],
): void {
  if (!syncManager) return;
  if (syncManager.notifyNewData) {
    syncManager.notifyNewData();
    return;
  }
  void syncManager.trigger().catch(() => undefined);
}

export async function handlePersonalServerDataRequest(
  request: Request,
  deps: PersonalServerDataApiDeps,
  options: PersonalServerApiDispatchOptions = {},
): Promise<Response> {
  return withApiErrors(async () => {
    const url = new URL(request.url);
    const pathname = stripBasePath(url.pathname, options.basePath);

    if (pathname === "/" || pathname === "") {
      if (request.method !== "GET") return methodNotAllowed();
      await deps.auth.authorizeBuilderList(request);
      const result = await listDataScopesContract({
        storage: deps.storage,
        scopePrefix: url.searchParams.get("scopePrefix") ?? undefined,
        limit: normalizeLimit(url.searchParams.get("limit"), 20),
        offset: normalizeLimit(url.searchParams.get("offset"), 0),
      });
      return jsonResponse(result.response);
    }

    const parts = pathname.split("/").filter(Boolean);
    if (parts.length === 2 && parts[1] === "versions") {
      if (request.method !== "GET") return methodNotAllowed();
      await deps.auth.authorizeBuilderList(request);
      const result = listDataVersionsContract({
        storage: deps.storage,
        scopeParam: decodePathPart(parts[0]),
        limit: normalizeLimit(url.searchParams.get("limit"), 20),
        offset: normalizeLimit(url.searchParams.get("offset"), 0),
      });
      if (!result.ok) return contractErrorResponse(result);
      return jsonResponse(result.response);
    }

    if (parts.length !== 1) return notFound();
    const scopeParam = decodePathPart(parts[0]);

    if (request.method === "GET") {
      const scopeResult = parseDataScopeContract(scopeParam);
      if (!scopeResult.ok) return contractErrorResponse(scopeResult);
      const selectedEntry = deps.storage.findEntry({
        scope: scopeResult.scope,
        fileId: url.searchParams.get("fileId") ?? undefined,
        at: url.searchParams.get("at") ?? undefined,
      });
      const grantId = selectedGrantId(request, url);
      const authResult = await deps.auth.authorizeBuilderRead({
        request,
        scope: scopeResult.scope,
        grantId,
        fileId:
          url.searchParams.get("fileId") ?? selectedEntry?.fileId ?? undefined,
      });
      const result = await readDataContract({
        storage: deps.storage,
        scopeParam: scopeResult.scope,
        fileId: url.searchParams.get("fileId") ?? undefined,
        at: url.searchParams.get("at") ?? undefined,
      });
      if (!result.ok) return contractErrorResponse(result);
      await deps.accessLogWriter.write({
        logId: deps.createLogId?.() ?? crypto.randomUUID(),
        grantId: authResult?.grantId ?? grantId ?? "unknown",
        builder: authResult?.builder ?? "unknown",
        action: "read",
        scope: scopeResult.scope,
        timestamp: (deps.now ?? (() => new Date()))().toISOString(),
        ipAddress:
          request.headers.get("x-forwarded-for") ??
          request.headers.get("x-real-ip") ??
          "unknown",
        userAgent: request.headers.get("user-agent") ?? "unknown",
      });

      // `?content=raw` streams the decoded bytes of a binary envelope with its
      // original media type, so a builder can download the file directly.
      if (
        url.searchParams.get("content") === "raw" &&
        isBinaryEnvelope(result.envelope)
      ) {
        const decoded = decodeBinaryEnvelope(result.envelope);
        const headers: Record<string, string> = {
          "Content-Type": decoded.mimeType,
          "Content-Length": String(decoded.bytes.length),
        };
        if (decoded.filename) {
          headers["Content-Disposition"] =
            `attachment; filename="${decoded.filename}"`;
        }
        if (decoded.metadata !== undefined) {
          headers["X-Vana-Metadata"] = stringifyMetadataHeader(
            decoded.metadata,
          );
        }
        return new Response(decoded.bytes as unknown as BodyInit, {
          status: 200,
          headers,
        });
      }
      return jsonResponse(result.envelope);
    }

    if (request.method === "POST") {
      await deps.auth.authorizeOwner(request);
      const scopeResult = parseDataScopeContract(scopeParam);
      if (!scopeResult.ok) return contractErrorResponse(scopeResult);
      const collectedAtValue = collectedAt(deps.now ?? (() => new Date()));
      const status = deps.syncManager ? "syncing" : "stored";

      // Binary / unstructured data (e.g. a PDF): the body is raw bytes and the
      // scope may not have a registered schema — auto-register a no-schema one.
      if (!isJsonContentType(request)) {
        const { schemaId, schemaUrl } = await resolveBinarySchema(
          deps,
          scopeResult.scope,
        );
        const bytes = new Uint8Array(await request.arrayBuffer());
        const result = await ingestBinaryDataContract({
          storage: deps.storage,
          scopeParam: scopeResult.scope,
          bytes,
          mimeType: binaryMimeType(request),
          filename: binaryFilename(request),
          metadata: parseMetadataHeader(request.headers.get("x-vana-metadata")),
          collectedAt: collectedAtValue,
          status,
          schemaUrl,
          schemaId,
        });
        if (!result.ok) return contractErrorResponse(result);
        deps.logger?.info?.(
          {
            scope: scopeResult.scope,
            collectedAt: collectedAtValue,
            path: result.writeResult.relativePath,
            mimeType: binaryMimeType(request),
            sizeBytes: bytes.length,
          },
          "Binary data file ingested",
        );
        notifyNewData(deps.syncManager);
        return jsonResponse(result.response, { status: 201 });
      }

      const parsed = await parseJsonObjectBody(
        request,
        "Request body must be valid JSON",
      );
      if (!parsed.ok) return contractResponse(parsed.result);
      const schema = await resolveSchema(deps, scopeResult.scope);
      if (!schema.ok) return schema.response;
      const result = await ingestDataContract({
        storage: deps.storage,
        scopeParam: scopeResult.scope,
        body: parsed.body,
        collectedAt: collectedAtValue,
        status,
        schemaUrl: schema.schemaUrl,
        schemaId: schema.schemaId,
      });
      if (!result.ok) return contractErrorResponse(result);
      deps.logger?.info?.(
        {
          scope: scopeResult.scope,
          collectedAt: collectedAtValue,
          path: result.writeResult.relativePath,
        },
        "Data file ingested",
      );
      notifyNewData(deps.syncManager);
      return jsonResponse(result.response, { status: 201 });
    }

    if (request.method === "DELETE") {
      await deps.auth.authorizeOwner(request);
      // Propagate the deletion to the authoritative stores (R2 blobs + gateway records) BEFORE the
      // local delete — it reads the local index to find what to remove. Best-effort: a remote
      // failure must not block the owner's local delete (and sync would otherwise resurrect it; the
      // download-worker reconciliation is the backstop). Parse the scope first so an invalid scope
      // still 400s without a wasted remote call.
      const parsed = parseDataScopeContract(scopeParam);
      if (parsed.ok && deps.syncManager?.deleteScopeRemote) {
        try {
          await deps.syncManager.deleteScopeRemote(parsed.scope);
        } catch (err) {
          deps.logger?.info?.(
            { scope: scopeParam, error: (err as Error).message },
            "Remote scope deletion failed; proceeding with local delete",
          );
        }
      }
      const result = await deleteDataScopeContract({
        storage: deps.storage,
        scopeParam,
      });
      if (!result.ok) return contractErrorResponse(result);
      deps.logger?.info?.(
        { scope: scopeParam, deletedCount: result.deletedCount },
        "Scope deleted",
      );
      return new Response(null, { status: 204 });
    }

    return methodNotAllowed();
  });
}

export async function handlePersonalServerAccessLogsRequest(
  request: Request,
  deps: PersonalServerAccessLogsApiDeps,
  options: PersonalServerApiDispatchOptions = {},
): Promise<Response> {
  return withApiErrors(async () => {
    const url = new URL(request.url);
    const pathname = stripBasePath(url.pathname, options.basePath);
    if (pathname !== "/" && pathname !== "") return notFound();
    if (request.method !== "GET") return methodNotAllowed();
    await deps.auth.authorizeOwner(request);
    return contractResponse(
      await listAccessLogsContract({
        accessLogReader: deps.accessLogReader,
        limit: url.searchParams.get("limit"),
        offset: url.searchParams.get("offset"),
      }),
    );
  });
}

export async function handlePersonalServerSyncRequest(
  request: Request,
  deps: PersonalServerSyncApiDeps,
  options: PersonalServerApiDispatchOptions = {},
): Promise<Response> {
  return withApiErrors(async () => {
    const url = new URL(request.url);
    const pathname = stripBasePath(url.pathname, options.basePath);

    if (pathname === "/trigger") {
      if (request.method !== "POST") return methodNotAllowed();
      await deps.auth.authorizeOwner(request);
      return contractResponse(await triggerSyncContract(deps.syncManager));
    }

    if (pathname === "/status") {
      if (request.method !== "GET") return methodNotAllowed();
      await deps.auth.authorizeOwner(request);
      return contractResponse(getSyncStatusContract(deps.syncManager));
    }

    if (pathname.startsWith("/file/")) {
      if (request.method !== "POST") return methodNotAllowed();
      await deps.auth.authorizeOwner(request);
      const fileId = decodeURIComponent(pathname.slice("/file/".length));
      deps.logger?.info?.(
        { fileId },
        "File sync requested, triggering full sync",
      );
      return contractResponse(
        await syncFileContract({
          fileId,
          syncManager: deps.syncManager,
        }),
      );
    }

    return notFound();
  });
}

export async function handlePersonalServerGrantsRequest(
  request: Request,
  deps: PersonalServerGrantsApiDeps,
  options: PersonalServerApiDispatchOptions = {},
): Promise<Response> {
  return withApiErrors(async () => {
    const url = new URL(request.url);
    const pathname = stripBasePath(url.pathname, options.basePath);

    if (pathname === "/" || pathname === "") {
      await deps.auth.authorizeOwner(request);
      if (!deps.gateway) {
        return errorResponse(
          500,
          "SERVER_NOT_CONFIGURED",
          "Gateway is not configured",
        );
      }
      if (request.method === "GET") {
        return contractResponse(
          await listGrantsContract({
            gateway: deps.gateway,
            serverOwner: deps.serverOwner,
          }),
        );
      }
      if (request.method === "POST") {
        const parsed = await parseJsonObjectBody(request);
        if (!parsed.ok) return contractResponse(parsed.result);
        return contractResponse(
          await createGrantContract({
            gateway: deps.gateway,
            serverOwner: deps.serverOwner,
            serverSigner: deps.serverSigner,
            body: parsed.body,
            now: () => deps.now?.().getTime() ?? Date.now(),
          }),
        );
      }
      return methodNotAllowed();
    }

    if (pathname === "/verify") {
      if (request.method !== "POST") return methodNotAllowed();
      const parsed = await parseJsonObjectBody(request);
      if (!parsed.ok) return contractResponse(parsed.result);
      return contractResponse(
        await verifyGrantContract({
          body: parsed.body,
          gatewayConfig: deps.gatewayConfig,
        } satisfies VerifyGrantContractInput),
      );
    }

    if (pathname.startsWith("/")) {
      if (request.method !== "DELETE") return methodNotAllowed();
      await deps.auth.authorizeOwner(request);
      if (!deps.gateway) {
        return errorResponse(
          500,
          "SERVER_NOT_CONFIGURED",
          "Gateway is not configured",
        );
      }
      return contractResponse(
        await revokeGrantContract({
          gateway: deps.gateway,
          serverOwner: deps.serverOwner,
          serverSigner: deps.serverSigner,
          grantId: decodeURIComponent(pathname.slice(1)),
        }),
      );
    }

    return notFound();
  });
}

export async function handlePersonalServerConfigRequest(
  request: Request,
  deps: PersonalServerConfigApiDeps,
): Promise<Response> {
  return withApiErrors(async () => {
    await deps.auth.authorizeOwner(request);
    if (request.method === "GET") {
      try {
        return jsonResponse(await deps.readConfig());
      } catch (err) {
        const kind =
          err instanceof Error &&
          "code" in err &&
          (err as { code?: string }).code === "ENOENT"
            ? "not-found"
            : "read";
        return contractResponse(configReadErrorContract(kind));
      }
    }
    if (request.method === "PUT") {
      const parsed = await parseJsonObjectBody(request);
      if (!parsed.ok) return contractResponse(parsed.result);
      const result = validateServerConfigContract(parsed.body);
      if (!result.ok) return contractResponse(result);
      try {
        await deps.writeConfig((result.body as { config: unknown }).config);
      } catch {
        return contractResponse(configWriteErrorContract());
      }
      return contractResponse(result);
    }
    return methodNotAllowed();
  });
}

export async function handlePersonalServerOauthTokenRequest(
  request: Request,
  deps: PersonalServerOauthTokenApiDeps,
): Promise<Response> {
  return withApiErrors(async () => {
    if (request.method !== "POST") return methodNotAllowed();
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
    const result = await oauthTokenContract({
      body: new URLSearchParams(await request.text()),
      authorizationHeader: request.headers.get("authorization"),
      tokenStore: deps.tokenStore,
      controlPlaneSecret: deps.controlPlaneSecret,
      deviceSessions: deps.deviceSessions,
      randomToken: deps.randomToken,
      now: deps.now,
      safeCompare: deps.safeCompare,
    });
    return jsonResponse(result.body, {
      status: result.status,
      headers: result.headers,
    });
  });
}

export type { DataReadPolicyPorts };
