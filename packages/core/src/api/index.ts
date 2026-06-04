import { ProtocolError } from "../errors/catalog.js";
import type { AccessLogWriter } from "../logging/access-log.js";
import type { AccessLogReader } from "../logging/access-reader.js";
import {
  type DataStoragePort,
  type RuntimeAvailabilityPort,
  type SchemaResolverPort,
} from "../ports/index.js";
import type { DataReadPolicyPorts } from "../policy/index.js";
import type { SyncManager } from "../sync/index.js";
import {
  deleteDataScopeContract,
  ingestDataContract,
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
} from "../contracts/index.js";
import type {
  DataPortabilityGatewayConfig,
  GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import type { ServerSigner } from "../signing/index.js";
import {
  buildChallenge,
  parsePaymentHeader,
  verifyPayment,
  type X402Challenge,
} from "../payment/index.js";

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
  warn?(payload: Record<string, unknown>, message: string): void;
  error?(payload: Record<string, unknown>, message: string): void;
}

export interface PersonalServerIngestSyncManager {
  trigger(): Promise<void>;
  notifyNewData?(): void;
}

export interface PersonalServerDataApiDeps {
  storage: DataStoragePort;
  auth: PersonalServerApiAuthPort;
  schemaResolver?: SchemaResolverPort;
  accessLogWriter: AccessLogWriter;
  syncManager?: PersonalServerIngestSyncManager | null;
  runtimeAvailability?: RuntimeAvailabilityPort;
  /**
   * Required when payment is on. Powers two things on GET /v1/data/:scope:
   *   - the X402 challenge generation (fee lookup, accessRecord binding)
   *   - the forward of validated X-PAYMENTs to gateway.payForOperation
   *
   * Two channels because the SDK client's payForOperation throws plain
   * Errors on non-2xx and loses the gateway's structured error body — we
   * need that body to map gateway 402/409/400 into fresh challenges.
   */
  gateway?: Pick<GatewayClient, "getGrant">;
  /**
   * Gateway base URL. Used for the direct-fetch forwarding of validated
   * X-PAYMENTs to POST /v1/escrow/pay so we can inspect the gateway's
   * structured error body (which the SDK's gateway.payForOperation
   * discards). Required when X402 is enabled.
   */
  gatewayUrl?: string;
  /**
   * Required to construct escrowPaymentDomain + dataRegistryDomain for
   * EIP-712 signature recovery during X-PAYMENT validation.
   */
  gatewayConfig?: DataPortabilityGatewayConfig;
  /**
   * Required for the X402 flow. Signs RECORD_DATA_ACCESS attestations
   * embedded in 402 challenges. Without it, challenges still issue but
   * never include an accessRecord — gateway accepts the resulting payment
   * but the on-chain recordDataAccess won't be scheduled.
   */
  serverSigner?: Pick<ServerSigner, "signRecordDataAccess">;
  serverOwner?: `0x${string}`;
  /**
   * The server's own account address — accessRecord signatures must
   * recover to this for the X-PAYMENT validation to accept them as
   * server-issued.
   */
  serverAddress?: `0x${string}`;
  /**
   * Identifier echoed in the X402 challenge as `accepts[].network`. Pure
   * convention (e.g. "vana-moksha"); the gateway doesn't read it.
   */
  network?: string;
  /**
   * When true, GET /v1/data/:scope enforces the X402 dance: missing /
   * invalid X-PAYMENT → 402 challenge; valid → forward to gateway then
   * serve. When false (default), reads bypass payment entirely.
   */
  paymentEnabled?: boolean;
  /**
   * Test seam for the gateway forwarding fetch. Defaults to the global
   * `fetch`; tests inject a mock that returns specific gateway statuses.
   */
  paymentFetch?: typeof fetch;
  /**
   * Test seam for the per-event recordId / paymentNonce / clock. Production
   * leaves these unset and the X402 module generates fresh values via
   * crypto.getRandomValues / Date.now.
   */
  generateRecordId?: () => `0x${string}`;
  generatePaymentNonce?: () => bigint;
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
    | "getBuilder"
    | "createGrant"
    | "listGrantsByUser"
    | "revokeGrant"
    // Canary RevokeGrantParams requires a monotonic `grantVersion` that
    // strictly exceeds the current value. revokeGrantContract reads the
    // live grant first to know what to bump.
    | "getGrant"
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

// X402 spec convention: payment responses are JSON, base64-encoded into a
// single header value. Returns undefined on encode failure so callers can
// just omit the header rather than fail the read. Uses btoa + TextEncoder
// to stay portable across Node and web runtimes.
function encodePaymentResponseHeader(body: unknown): string | undefined {
  try {
    const json = JSON.stringify(body ?? null);
    const bytes = new TextEncoder().encode(json);
    let binary = "";
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary);
  } catch {
    return undefined;
  }
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

interface X402CycleInput {
  deps: PersonalServerDataApiDeps;
  request: Request;
  scope: string;
  fileIdParam?: string;
  atParam?: string;
  grantId: string;
  builder: `0x${string}`;
  gateway: Pick<GatewayClient, "getGrant">;
  gatewayConfig: DataPortabilityGatewayConfig;
  gatewayUrl: string;
}

type X402CycleResult =
  | { kind: "ok"; payResponse: unknown }
  | { kind: "challenge"; body: X402Challenge }
  | { kind: "gateway-error"; status: number; body: unknown };

/**
 * Run the X402 dispatch for one read:
 *
 *   X-PAYMENT absent / malformed / fails local validation
 *     → challenge: fresh 402 with current fee + accessRecord
 *   X-PAYMENT valid, forward to gateway succeeds
 *     → ok: caller proceeds to read the data
 *   X-PAYMENT valid, gateway returns 4xx/5xx
 *     → gateway-error: relay the gateway's body verbatim so the builder
 *       can dispatch (insufficient balance vs. replay vs. race etc.)
 *
 * The gateway POST goes through `fetch` directly (not `gateway.payForOperation`)
 * because the SDK client throws plain Errors and loses the body — which is
 * exactly what we need to distinguish gateway 402 (insufficient balance) from
 * 409 (replay) from 400 (amount mismatch).
 */
async function handleX402Cycle(
  input: X402CycleInput,
): Promise<X402CycleResult> {
  const { deps, gateway, gatewayConfig, gatewayUrl, builder, scope } = input;
  // The gateway lowercases opId before EIP-712 recovery — we must do the
  // same in the challenge so the builder signs over the canonical form.
  const opIdLower = input.grantId.toLowerCase() as `0x${string}`;

  // Live grant — re-fetched every cycle. The fee.totalDue is a snapshot
  // (SDK comment: "clients shouldn't cache"); paymentStatus may have just
  // flipped if a concurrent payer paid the registration fee.
  const grant = await gateway.getGrant(opIdLower);
  if (!grant) {
    return {
      kind: "challenge",
      body: {
        x402Version: 1,
        error: "PAYMENT_REQUIRED",
        accepts: [],
      } as unknown as X402Challenge,
    };
  }

  // Bind the accessRecord to the entry being served, if it exists and has
  // been registered with DPv2 yet.
  const entryRow = deps.storage.findEntry({
    scope,
    fileId: input.fileIdParam,
    at: input.atParam,
  });
  const entryForChallenge = entryRow
    ? {
        dataPointId: entryRow.dataPointId as `0x${string}` | null,
        scope,
        version: entryRow.version,
      }
    : undefined;

  async function buildFreshChallenge(): Promise<X402Challenge> {
    return buildChallenge({
      builder,
      grantId: opIdLower,
      grant,
      network: deps.network ?? `vana:${gatewayConfig.chainId}`,
      gatewayConfig,
      serverSigner: deps.serverSigner,
      serverOwner: deps.serverOwner,
      entry: entryForChallenge,
      generateNonce: deps.generatePaymentNonce,
      generateRecordIdFn: deps.generateRecordId,
      now: deps.now,
    });
  }

  const headerValue = input.request.headers.get("x-payment");
  const parsed = parsePaymentHeader(headerValue);
  if (!parsed) {
    return { kind: "challenge", body: await buildFreshChallenge() };
  }

  if (!deps.serverAddress) {
    // Can't validate accessRecord recovery without our own address; fail
    // closed by reissuing a challenge.
    deps.logger?.error?.(
      { scope, grantId: opIdLower },
      "X402 enabled but serverAddress is not configured — cannot verify accessRecord",
    );
    return { kind: "challenge", body: await buildFreshChallenge() };
  }

  const verify = await verifyPayment({
    builder,
    grantId: opIdLower,
    grant,
    entry: entryForChallenge,
    serverAddress: deps.serverAddress,
    gatewayConfig,
    serverOwner: deps.serverOwner,
    payment: parsed,
  });
  if (!verify.ok) {
    deps.logger?.info?.(
      { scope, grantId: opIdLower, reason: verify.reason },
      "X402 payment verification failed; reissuing challenge",
    );
    return { kind: "challenge", body: await buildFreshChallenge() };
  }

  // Forward to gateway via direct fetch (preserves error body). The SDK
  // client wraps the same endpoint but throws away the structured response
  // on non-2xx, which is exactly the info we need to distinguish gateway
  // 402 (insufficient balance) from 409 (replay / race) from 400 (mismatch).
  const doFetch = deps.paymentFetch ?? fetch;
  const body: Record<string, unknown> = {
    payerAddress: verify.payment.payload.message.payerAddress,
    opType: verify.payment.payload.message.opType,
    opId: verify.payment.payload.message.opId,
    asset: verify.payment.payload.message.asset,
    amount: verify.payment.payload.message.amount,
    paymentNonce: verify.payment.payload.message.paymentNonce,
  };
  if (verify.payment.payload.accessRecord) {
    body["accessRecord"] = verify.payment.payload.accessRecord;
  }
  let gatewayRes: Response;
  try {
    gatewayRes = await doFetch(
      `${gatewayUrl.replace(/\/+$/, "")}/v1/escrow/pay`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Web3Signed ${verify.payment.payload.signature}`,
        },
        body: JSON.stringify(body),
      },
    );
  } catch (err) {
    deps.logger?.error?.(
      {
        scope,
        grantId: opIdLower,
        error: (err as Error).message,
      },
      "X402 gateway forward threw; reissuing challenge",
    );
    return { kind: "challenge", body: await buildFreshChallenge() };
  }

  if (gatewayRes.ok) {
    // Preserve the gateway's structured success body so the request
    // handler can echo it back via the X-PAYMENT-RESPONSE header (canonical
    // X402 convention). Empty/malformed body → propagate as null; the
    // header still gets set so builders can tell payment succeeded.
    let payResponseBody: unknown = null;
    try {
      payResponseBody = await gatewayRes.json();
    } catch {
      // Body unreadable but status was 2xx — treat as success with no payload.
    }
    return { kind: "ok", payResponse: payResponseBody };
  }

  // Read the gateway's structured error body if there is one.
  let errorBody: unknown;
  try {
    errorBody = await gatewayRes.json();
  } catch {
    errorBody = { error: gatewayRes.statusText };
  }

  // 409 (replay or race) and 400 (amount mismatch / shape error) are
  // recoverable with a fresh challenge — the builder re-signs with the
  // new state and retries. 402 (insufficient balance) is relayed verbatim
  // because the builder needs to fix their escrow, not their signature.
  // 5xx is treated like 402-relayed since the personal server can't
  // distinguish "transient" from "permanent" without more info.
  if (gatewayRes.status === 409 || gatewayRes.status === 400) {
    deps.logger?.info?.(
      { scope, grantId: opIdLower, status: gatewayRes.status, errorBody },
      "Gateway rejected X-PAYMENT; reissuing X402 challenge",
    );
    return { kind: "challenge", body: await buildFreshChallenge() };
  }
  return { kind: "gateway-error", status: gatewayRes.status, body: errorBody };
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
  // No resolver configured — proceed without a schema. The on-disk envelope
  // tolerates a missing schemaId (the field is optional in DataFileEnvelope
  // anyway), and the canary X402 read path doesn't consult it. The legacy
  // sync-worker registerFile call DOES require schemaId, and will surface
  // its own error there if the operator has sync enabled but no resolver.
  if (!deps.schemaResolver) {
    deps.logger?.info?.(
      { scope },
      "Ingesting without a schema lookup (no schemaResolver configured)",
    );
    return { ok: true, schemaUrl: undefined, schemaId: undefined };
  }

  try {
    const schema = await deps.schemaResolver.getSchemaForScope(scope);
    if (!schema) {
      // Soft fall-through: schema not on the gateway. Canary
      // registerDataPoint doesn't need it; X402 doesn't need it. The
      // operator's sync worker (if enabled) will fail at registerFile
      // time with a clearer "no schemaId" error from the gateway. We
      // intentionally don't block ingest here.
      deps.logger?.warn?.(
        { scope },
        "No schema registered for scope at gateway — ingesting without schemaId",
      );
      return { ok: true, schemaUrl: undefined, schemaId: undefined };
    }
    return {
      ok: true,
      schemaUrl: schema.definitionUrl,
      schemaId: schema.id,
    };
  } catch (err) {
    // Network / gateway outage is different from "schema not found" —
    // keep this a hard error so the ingest doesn't write data the
    // operator can't trace back. Schema lookup failures are observable;
    // a hung gateway is not the right time to silently proceed.
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
      const result = listDataScopesContract({
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
      // Holds the base64-encoded gateway payForOperation response body when
      // X402 succeeds — emitted on the final read response as X-PAYMENT-RESPONSE.
      let paymentResponseHeader: string | undefined;
      const grantId = selectedGrantId(request, url);
      const authResult = await deps.auth.authorizeBuilderRead({
        request,
        scope: scopeResult.scope,
        grantId,
        fileId:
          url.searchParams.get("fileId") ?? selectedEntry?.fileId ?? undefined,
      });

      // X402 payment dance for builder reads. Owner-exempt reads (the
      // grantId sentinels "owner" / "policy-bypass") skip payment entirely
      // since there's no payable op to attach the payment to.
      //
      // The grantId we pay against is the one verifyDataReadPolicy resolved
      // from the Web3Signed payload (authoritative source) — not the URL /
      // header hint, which may be absent when the payload carries it.
      const isOwnerSignal =
        authResult?.grantId === "owner" ||
        authResult?.grantId === "policy-bypass";
      const builder = authResult?.builder;
      const resolvedGrantId =
        !isOwnerSignal && authResult?.grantId ? authResult.grantId : undefined;
      if (
        deps.paymentEnabled &&
        !isOwnerSignal &&
        typeof builder === "string" &&
        builder.startsWith("0x") &&
        resolvedGrantId &&
        deps.gateway &&
        deps.gatewayConfig &&
        deps.gatewayUrl
      ) {
        const x402Result = await handleX402Cycle({
          deps,
          request,
          scope: scopeResult.scope,
          fileIdParam: url.searchParams.get("fileId") ?? undefined,
          atParam: url.searchParams.get("at") ?? undefined,
          grantId: resolvedGrantId,
          builder: builder as `0x${string}`,
          gateway: deps.gateway,
          gatewayConfig: deps.gatewayConfig,
          gatewayUrl: deps.gatewayUrl,
        });
        if (x402Result.kind === "challenge") {
          return jsonResponse(x402Result.body, { status: 402 });
        }
        if (x402Result.kind === "gateway-error") {
          // Relay the gateway's structured body verbatim so the builder can
          // dispatch on it (insufficient balance vs. replay vs. race etc.).
          return jsonResponse(x402Result.body, { status: x402Result.status });
        }
        // x402Result.kind === "ok" — payment accepted, proceed to read.
        // The gateway's success body is forwarded back to the builder via
        // X-PAYMENT-RESPONSE (canonical X402 convention) so callers can see
        // breakdown / paidAt / paymentNonce without a second gateway round-trip.
        paymentResponseHeader = encodePaymentResponseHeader(
          x402Result.payResponse,
        );
      }

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

      const headers: Record<string, string> = {};
      if (paymentResponseHeader) {
        headers["X-PAYMENT-RESPONSE"] = paymentResponseHeader;
      }
      return jsonResponse(result.envelope, { headers });
    }

    if (request.method === "POST") {
      await deps.auth.authorizeOwner(request);
      const scopeResult = parseDataScopeContract(scopeParam);
      if (!scopeResult.ok) return contractErrorResponse(scopeResult);
      const parsed = await parseJsonObjectBody(
        request,
        "Request body must be valid JSON",
      );
      if (!parsed.ok) return contractResponse(parsed.result);
      const schema = await resolveSchema(deps, scopeResult.scope);
      if (!schema.ok) return schema.response;
      const collectedAtValue = collectedAt(deps.now ?? (() => new Date()));
      const result = await ingestDataContract({
        storage: deps.storage,
        scopeParam: scopeResult.scope,
        body: parsed.body,
        collectedAt: collectedAtValue,
        status: deps.syncManager ? "syncing" : "stored",
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
        // Canary createGrant doesn't need a clock — grantVersion defaults
        // to "1" and callers re-registering pass a strictly higher value.
        return contractResponse(
          await createGrantContract({
            gateway: deps.gateway,
            serverOwner: deps.serverOwner,
            serverSigner: deps.serverSigner,
            body: parsed.body,
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
