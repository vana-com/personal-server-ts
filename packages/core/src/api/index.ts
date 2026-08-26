import {
  DataDeletedError,
  DeleteTombstoneFailedError,
  GrantRequiredError,
  InvalidCascadeError,
  LineageCascadeUnavailableError,
  LineageGatewayError,
  LineageUnavailableError,
  ProtocolError,
  ServerNotConfiguredError,
} from "../errors/catalog.js";
import type { AccessLogWriter } from "../logging/access-log.js";
import type { AccessLogReader } from "../logging/access-reader.js";
import {
  type DataStoragePort,
  type RuntimeAvailabilityPort,
} from "../ports/index.js";
import type { DataReadPolicyPorts } from "../policy/index.js";
import type { SyncManager } from "../sync/index.js";
import { computeDataPointId } from "../sync/data-point-id.js";
import {
  isEntryCoveredByTombstone,
  type ScopeDeletionTracker,
} from "../sync/scope-deletions.js";
import type { IndexEntry } from "../storage/index/types.js";
import {
  deleteScope as deleteScopeLocally,
  type DeleteScopeResult,
} from "../sync/workers/delete.js";
import {
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
  IngestPersistedError,
} from "../contracts/index.js";
import type {
  DataPortabilityGatewayConfig,
  GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import type { ServerSigner } from "../signing/index.js";
import type { WriterAttribution } from "../write/attribution.js";
import {
  extractLineageField,
  prepareLineage,
  type StoredLineage,
} from "../lineage/lineage.js";
import type { LineageGatewayPort } from "../lineage/gateway.js";
import { computeDataPointId } from "../sync/data-point-id.js";
import {
  binaryFilename,
  binaryMimeType,
  isJsonContentType,
} from "../contracts/binary.js";
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
  /**
   * The `collectedAt` version the read is pinned to (cursor-pinned or
   * `?at=`-pinned reads). Payment-enforcing auth ports use it to bind the
   * x402 challenge/settlement to the exact version served, not the latest.
   */
  at?: string;
}

export interface PersonalServerReadAuthResult {
  builder?: `0x${string}` | string;
  grantId?: string;
}

export interface PersonalServerWriteAuthInput {
  request: Request;
  /** Raw scope path param (validated by parseDataScopeContract after auth,
   * same precedence as the owner write path). */
  scope: string;
}

/**
 * Result of authorizing a DELEGATED (write-session) write. A void return
 * means the request was authorized as the owner instead — the ingest then
 * proceeds exactly as today, with no attribution stamped.
 */
export interface PersonalServerWriteAuthResult {
  builder: `0x${string}`;
  grantId: string;
  attribution: WriterAttribution;
  /**
   * Rolls back the per-write proof reservation (replay guard). The handler
   * calls it when the write fails BEFORE the record is committed, so the
   * builder can retry with the same still-valid proof.
   */
  releaseProof?: () => Promise<void>;
}

export interface PersonalServerReadFulfillment {
  builder: string;
  fileId?: string;
  grantId: string;
  ipAddress: string;
  logId: string;
  scope: string;
  servedAt: string;
  userAgent: string;
}

export interface PersonalServerReadFulfillmentReporter {
  report(event: PersonalServerReadFulfillment): Promise<void>;
}

export interface PersonalServerApiAuthPort {
  authorizeOwner(request: Request): Promise<void>;
  authorizeBuilderList(request: Request): Promise<void>;
  authorizeBuilderRead(
    input: PersonalServerReadAuthInput,
  ): Promise<PersonalServerReadAuthResult | void>;
  /**
   * Authorize a data ingest (POST /v1/data/:scope). Optional — auth ports
   * that don't support delegated writes omit it and the handler falls back
   * to authorizeOwner, preserving today's owner-only behavior. Ports that DO
   * support write sessions handle BOTH paths here: a recognized session
   * token authorizes as the builder (write policy + attribution proof) and
   * returns the attribution to store; anything else falls through to the
   * owner path and returns void.
   */
  authorizeWrite?(
    input: PersonalServerWriteAuthInput,
  ): Promise<PersonalServerWriteAuthResult | void>;
}

export interface PersonalServerApiLogger {
  debug?(payload: Record<string, unknown>, message: string): void;
  info?(payload: Record<string, unknown>, message: string): void;
  warn?(payload: Record<string, unknown>, message: string): void;
  error?(payload: Record<string, unknown>, message: string): void;
}

export interface PersonalServerIngestSyncManager {
  trigger(): Promise<void>;
  notifyNewData?(): void;
  /**
   * Durable scope deletion (gateway tombstone -> storage blobs -> local).
   * When absent the DELETE route deletes the local copy only and reports
   * `durable: false`.
   */
  deleteScope?(scope: string): Promise<DeleteScopeResult>;
}

export interface PersonalServerDataApiDeps {
  storage: DataStoragePort;
  auth: PersonalServerApiAuthPort;
  accessLogWriter: AccessLogWriter;
  syncManager?: PersonalServerIngestSyncManager | null;
  runtimeAvailability?: RuntimeAvailabilityPort;
  readFulfillmentReporter?: PersonalServerReadFulfillmentReporter;
  /**
   * Read-side memory of gateway tombstones (see sync/scope-deletions.ts for
   * the consistency window). Every read consults it before serving or
   * charging: a scope the gateway reports deleted answers 410 DATA_DELETED
   * whether or not a stale local copy still exists, and a local miss on a
   * deleted scope answers 410 instead of 404 so SDK readers can tell
   * "deleted" from "never had it". Without it reads are local-only.
   */
  scopeDeletions?: ScopeDeletionTracker;
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
  /**
   * Gateway access for derivative data (docs/derivative-data-api.md): source
   * lookups for lineage validation on write and the signed lineage read
   * behind GET /v1/data/:scope/lineage. Absent = writes with lineage can
   * only cite local scopes and the lineage read answers 503.
   */
  lineageGateway?: LineageGatewayPort;
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

export interface X402CycleInput {
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

export type X402CycleResult =
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
export async function handleX402Cycle(
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

  // `grant` is narrowed to non-null above, but that narrowing is not carried
  // into this closure (vana-sdk 3.14.0 made getGrant return `... | null`), so
  // capture the guaranteed-present value via a typed alias for the closure.
  const liveGrant: NonNullable<typeof grant> = grant;
  async function buildFreshChallenge(): Promise<X402Challenge> {
    return buildChallenge({
      builder,
      grantId: opIdLower,
      grant: liveGrant,
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

/**
 * The deletion that applies to a read of `scope`, or null when the read may
 * be served. `entry` is the local version the read would serve (undefined
 * on a local miss).
 *
 * - A local copy is refused when the gateway holds a tombstone that covers
 *   it (see `isEntryCoveredByTombstone`: registry versions and the ingest
 *   marker, never clocks). A local re-add on top of the tombstone is served.
 * - A local miss asks the tracker to consult the gateway (bounded by its
 *   per-scope verdict cache and failure back-off): the local index cannot
 *   tell "deleted long ago" from "never had it".
 * Gateway unreachability never fails the read: the tracker answers from its
 * last known state, which is the documented offline behaviour.
 */
export async function resolveReadDeletion(
  deps: Pick<PersonalServerDataApiDeps, "scopeDeletions" | "serverOwner">,
  scope: string,
  entry: ReadDeletionEntry | null | undefined,
): Promise<{
  scope: string;
  dataPointId: string | null;
  deletedAt: string;
} | null> {
  if (!deps.scopeDeletions) return null;
  const verdict = await deps.scopeDeletions.resolve(scope, {
    consultGateway: entry ? "if-stale" : "always",
  });
  if (!verdict.deleted) return null;
  if (entry && !isEntryCoveredByTombstone(entry, verdict)) {
    return null;
  }
  return {
    scope,
    dataPointId: deps.serverOwner
      ? computeDataPointId(deps.serverOwner, scope)
      : null,
    deletedAt: verdict.deletedAt,
  };
}

/**
 * Throw 410 DATA_DELETED when `resolveReadDeletion` says the read must not be
 * served. Call it before any payment step: a builder must never be charged
 * for a scope the owner deleted.
 */
export async function assertScopeNotDeleted(
  deps: Pick<PersonalServerDataApiDeps, "scopeDeletions" | "serverOwner">,
  scope: string,
  entry: ReadDeletionEntry | null | undefined,
): Promise<void> {
  const deletion = await resolveReadDeletion(deps, scope, entry);
  if (deletion) throw new DataDeletedError(deletion);
}

/** The index fields the deletion gate needs from the entry a read would serve. */
export type ReadDeletionEntry = Pick<
  IndexEntry,
  "version" | "dataPointId" | "afterTombstoneVersion"
>;

/**
 * The causal marker a fresh ingest carries: the tombstone version this
 * replica currently knows for the scope, if any, so the new entry is a
 * deliberate re-add that survives that deletion (and only that one). Uses
 * the same verdict path as reads, so it costs a gateway lookup only when the
 * tracker's view is stale. An unknown or unsafe version leaves the marker
 * null: the entry is then covered, never resurrected on a guess.
 */
async function ingestTombstoneMarker(
  deps: Pick<PersonalServerDataApiDeps, "scopeDeletions">,
  scope: string,
): Promise<number | null> {
  if (!deps.scopeDeletions) return null;
  const verdict = await deps.scopeDeletions.resolve(scope);
  if (!verdict.deleted || verdict.version === null) return null;
  const version = Number(verdict.version);
  return Number.isSafeInteger(version) ? version : null;
}

// The delete worker wants a full Logger; the API logger is all-optional.
function apiLoggerAsLogger(logger: PersonalServerApiLogger | undefined) {
  const noop = () => undefined;
  return {
    debug: (payload: unknown, message?: string) =>
      (logger?.debug ?? noop)(
        payload as Record<string, unknown>,
        message ?? "",
      ),
    info: (payload: unknown, message?: string) =>
      (logger?.info ?? noop)(payload as Record<string, unknown>, message ?? ""),
    warn: (payload: unknown, message?: string) =>
      (logger?.warn ?? noop)(payload as Record<string, unknown>, message ?? ""),
    error: (payload: unknown, message?: string) =>
      (logger?.error ?? noop)(
        payload as Record<string, unknown>,
        message ?? "",
      ),
  };
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

function shouldReportReadFulfillment(grantId: string): boolean {
  return (
    grantId !== "unknown" && grantId !== "owner" && grantId !== "policy-bypass"
  );
}

function warnReadFulfillmentReporterFailed(
  deps: PersonalServerDataApiDeps,
  event: PersonalServerReadFulfillment,
  err: unknown,
): void {
  deps.logger?.warn?.(
    {
      builder: event.builder,
      error: err instanceof Error ? err.message : String(err),
      grantId: event.grantId,
      logId: event.logId,
      scope: event.scope,
    },
    "Read fulfillment reporter failed",
  );
}

export function reportPersonalServerReadFulfillment(
  deps: PersonalServerDataApiDeps,
  event: PersonalServerReadFulfillment,
): void {
  if (
    !deps.readFulfillmentReporter ||
    !shouldReportReadFulfillment(event.grantId)
  ) {
    return;
  }
  try {
    void Promise.resolve(deps.readFulfillmentReporter.report(event)).catch(
      (err) => warnReadFulfillmentReporterFailed(deps, event, err),
    );
  } catch (err) {
    warnReadFulfillmentReporterFailed(deps, event, err);
  }
}

/**
 * Validate a write's caller-supplied `lineage` (JSON body top level, or the
 * binary metadata object) into the `$lineage` record to stamp. `undefined`
 * (or null) means a root record. Throws ProtocolErrors; the write handler
 * lets them propagate before anything is stored.
 */
async function prepareWriteLineage(
  deps: PersonalServerDataApiDeps,
  scope: string,
  field: unknown,
): Promise<StoredLineage | undefined> {
  if (field === undefined || field === null) return undefined;
  return prepareLineage({
    scope,
    field,
    serverOwner: deps.serverOwner,
    storage: deps.storage,
    gateway: deps.lineageGateway,
    now: deps.now ?? (() => new Date()),
  });
}

/**
 * The lineage view a read auth result entitles the caller to. The auth port
 * answers an owner read with no result or with the "owner" / "policy-bypass"
 * sentinels (see api-auth): those get the full view. A builder read carries
 * the grant the read policy resolved, and that grant names the view. A
 * builder result with no resolved grant (or an "unknown" one) proves
 * nothing and is refused: a missing grantId must never widen to the full
 * view.
 */
function resolveLineageGrantView(
  authResult: PersonalServerReadAuthResult | void,
): { grantId: string | undefined } {
  if (
    authResult === undefined ||
    authResult.grantId === "owner" ||
    authResult.grantId === "policy-bypass"
  ) {
    return { grantId: undefined };
  }
  const grantId = authResult.grantId;
  if (typeof grantId !== "string" || grantId === "" || grantId === "unknown") {
    throw new GrantRequiredError({
      reason: "a lineage read by a builder needs a resolved grant",
    });
  }
  return { grantId };
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

    if ((parts.length === 2 || parts.length === 3) && parts[1] === "lineage") {
      if (request.method !== "GET") return methodNotAllowed();
      const scopeResult = parseDataScopeContract(decodePathPart(parts[0]));
      if (!scopeResult.ok) return contractErrorResponse(scopeResult);
      // The version is a PATH segment (/v1/data/:scope/lineage/:version), so
      // it is inside the signed request uri: a builder's signature for one
      // version cannot be replayed to read another. The grant view is the
      // signed grantId claim the read auth already honours. Query
      // parameters would be unsigned inputs to the view and are refused.
      if (url.searchParams.has("version")) {
        return errorResponse(
          400,
          "INVALID_VERSION",
          "version is a path segment (/v1/data/:scope/lineage/:version), not a query parameter",
        );
      }
      if (url.search.length > 0) {
        return errorResponse(
          400,
          "INVALID_QUERY",
          "lineage reads take no query parameters; the version is a path segment and the grant view is the signed grantId claim",
        );
      }
      const version = parts.length === 3 ? decodePathPart(parts[2]) : undefined;
      if (version !== undefined && !/^[1-9]\d*$/.test(version)) {
        return errorResponse(
          400,
          "INVALID_VERSION",
          "version must be a positive decimal integer",
        );
      }
      // Same gate as a read of the scope: the owner, or a builder whose grant
      // covers it. The gateway then attests the view that grant sees, so a
      // builder only learns the scopes of nodes its grant covers.
      const authResult = await deps.auth.authorizeBuilderRead({
        request,
        scope: scopeResult.scope,
        grantId: selectedGrantId(request, url),
      });
      if (!deps.serverOwner) {
        throw new ServerNotConfiguredError({
          reason: "serverOwner is required to resolve the data point id",
        });
      }
      if (!deps.lineageGateway) throw new LineageUnavailableError();
      const { grantId } = resolveLineageGrantView(authResult);
      let result: Awaited<ReturnType<LineageGatewayPort["getLineage"]>>;
      try {
        result = await deps.lineageGateway.getLineage({
          dataPointId: computeDataPointId(deps.serverOwner, scopeResult.scope),
          version,
          grantId,
        });
      } catch (err) {
        // Transport failures (DNS, refused, timeout) are gateway errors to
        // the caller, not internal ones: same 502 as a gateway error body.
        if (err instanceof ProtocolError) throw err;
        throw new LineageGatewayError({
          status: 0,
          body: { error: err instanceof Error ? err.message : String(err) },
        });
      }
      if (!result.ok) {
        if (result.status === 404) {
          return errorResponse(
            404,
            "NOT_FOUND",
            version
              ? `Scope "${scopeResult.scope}" has no registered version ${version}`
              : `Scope "${scopeResult.scope}" is not registered at the gateway`,
          );
        }
        if (result.status === 403) {
          throw new ProtocolError(
            403,
            "LINEAGE_FORBIDDEN",
            "The gateway refused the lineage view for this grant",
            { gateway: result.body },
          );
        }
        throw new LineageGatewayError({
          status: result.status,
          body: result.body,
        });
      }
      return jsonResponse({ data: result.data, proof: result.proof });
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
        at: url.searchParams.get("at") ?? undefined,
      });

      // Deletion gate, after auth (so unauthenticated callers learn nothing)
      // and before payment (so nobody is charged for deleted data). Covers
      // both a stale local copy of a tombstoned scope and a local miss.
      await assertScopeNotDeleted(deps, scopeResult.scope, selectedEntry);

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
      const willCharge = Boolean(
        deps.paymentEnabled &&
        !isOwnerSignal &&
        typeof builder === "string" &&
        builder.startsWith("0x") &&
        resolvedGrantId &&
        deps.gateway &&
        deps.gatewayConfig &&
        deps.gatewayUrl,
      );
      // Diagnostic: makes it explicit why a read is/isn't charged. x402 has
      // many "served free" branches (owner read, payment disabled, missing
      // gateway deps); this surfaces the deciding inputs.
      //
      // Routing: when a logger is wired (the Node server always provides one),
      // log the full detail through it at debug level so the operator's level
      // controls + redaction apply and access metadata (scope/grantId/builder)
      // doesn't unconditionally hit stdout. The browser PS-Lite runtime wires
      // no logger; there we fall back to console but log ONLY the non-identifying
      // decision booleans — never scope/grantId/builder.
      if (deps.logger?.debug) {
        deps.logger.debug(
          {
            scope: scopeResult.scope,
            grantId: authResult?.grantId,
            isOwnerSignal,
            builder,
            resolvedGrantId,
            paymentEnabled: Boolean(deps.paymentEnabled),
            hasGateway: Boolean(deps.gateway),
            hasGatewayConfig: Boolean(deps.gatewayConfig),
            hasGatewayUrl: Boolean(deps.gatewayUrl),
            willCharge,
          },
          "[x402-gate] read",
        );
      } else {
        console.info("[x402-gate] read", {
          isOwnerSignal,
          paymentEnabled: Boolean(deps.paymentEnabled),
          hasGateway: Boolean(deps.gateway),
          hasGatewayConfig: Boolean(deps.gatewayConfig),
          hasGatewayUrl: Boolean(deps.gatewayUrl),
          willCharge,
        });
      }
      // Keep the full condition inline (not `if (willCharge)`) so TS narrows
      // deps.gateway/gatewayConfig/gatewayUrl to non-undefined in the block.
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
      if (!result.ok) {
        if (result.status === 404) {
          // The entry selected above can vanish before the read (a sync
          // reconcile applying a tombstone concurrently); answer 410, not
          // 404, when that is why.
          await assertScopeNotDeleted(deps, scopeResult.scope, undefined);
        }
        return contractErrorResponse(result);
      }

      const logId = deps.createLogId?.() ?? crypto.randomUUID();
      const timestamp = (deps.now ?? (() => new Date()))().toISOString();
      const ipAddress =
        request.headers.get("x-forwarded-for") ??
        request.headers.get("x-real-ip") ??
        "unknown";
      const userAgent = request.headers.get("user-agent") ?? "unknown";
      const loggedGrantId = authResult?.grantId ?? grantId ?? "unknown";
      const loggedBuilder = authResult?.builder ?? "unknown";
      await deps.accessLogWriter.write({
        logId,
        grantId: loggedGrantId,
        builder: loggedBuilder,
        action: "read",
        scope: scopeResult.scope,
        timestamp,
        ipAddress,
        userAgent,
      });
      const reportReadFulfillment = () => {
        if (!authResult?.grantId || !authResult.builder) return;
        reportPersonalServerReadFulfillment(deps, {
          builder: authResult.builder,
          fileId:
            url.searchParams.get("fileId") ??
            selectedEntry?.fileId ??
            undefined,
          grantId: authResult.grantId,
          ipAddress,
          logId,
          scope: scopeResult.scope,
          servedAt: timestamp,
          userAgent,
        });
      };

      const headers: Record<string, string> = {};
      if (paymentResponseHeader) {
        headers["X-PAYMENT-RESPONSE"] = paymentResponseHeader;
      }

      const wantsRawContent = url.searchParams.get("content") === "raw";

      // `?content=raw` streams the decoded bytes of a binary envelope with its
      // original media type, so a builder can download the file directly. The
      // X-PAYMENT-RESPONSE header (if any) rides along on the raw response too.
      if (wantsRawContent) {
        if (!isBinaryEnvelope(result.envelope)) {
          return jsonResponse(
            {
              error: "NOT_BINARY_SCOPE",
              message: `Scope "${scopeResult.scope}" does not expose raw binary content.`,
            },
            { status: 400, headers },
          );
        }
        const decoded = decodeBinaryEnvelope(result.envelope);
        headers["Content-Type"] = decoded.mimeType;
        headers["Content-Length"] = String(decoded.bytes.length);
        if (decoded.filename) {
          headers["Content-Disposition"] =
            `attachment; filename="${decoded.filename}"`;
        }
        if (decoded.metadata !== undefined) {
          headers["X-Vana-Metadata"] = stringifyMetadataHeader(
            decoded.metadata,
          );
        }
        const response = new Response(decoded.bytes as unknown as BodyInit, {
          status: 200,
          headers,
        });
        return response;
      }
      const response = jsonResponse(result.envelope, { headers });
      reportReadFulfillment();
      return response;
    }

    if (request.method === "POST") {
      // Delegated writes: an auth port that supports write sessions handles
      // both paths in authorizeWrite (builder session token -> write policy +
      // attribution; anything else -> owner path). Ports without it keep
      // today's owner-only gate.
      let writeAuth: PersonalServerWriteAuthResult | undefined;
      if (deps.auth.authorizeWrite) {
        writeAuth =
          (await deps.auth.authorizeWrite({ request, scope: scopeParam })) ??
          undefined;
      } else {
        await deps.auth.authorizeOwner(request);
      }
      // A write that fails before commit hands the proof back (replay guard)
      // so the builder's retry with the same still-valid proof is accepted;
      // after commit the proof stays consumed (a retry would be a duplicate).
      let committed = false;
      const failWrite = async <T>(response: T): Promise<T> => {
        await writeAuth?.releaseProof?.();
        return response;
      };
      try {
        const scopeResult = parseDataScopeContract(scopeParam);
        if (!scopeResult.ok)
          return failWrite(contractErrorResponse(scopeResult));
        const collectedAtValue = collectedAt(deps.now ?? (() => new Date()));
        const status = deps.syncManager ? "syncing" : "stored";
        const afterTombstoneVersion = await ingestTombstoneMarker(
          deps,
          scopeResult.scope,
        );

        // Builder writes land in the same access log as builder reads, so the
        // owner sees who wrote what under which grant.
        // Best-effort: it runs AFTER the record is committed, so a log failure
        // must not turn a successful write into a 500 (the builder would retry
        // and store a duplicate). The ingest log line above still names the
        // builder; the failure itself is logged for the owner.
        const logBuilderWrite = async (): Promise<void> => {
          if (!writeAuth) return;
          try {
            await deps.accessLogWriter.write({
              logId: deps.createLogId?.() ?? crypto.randomUUID(),
              grantId: writeAuth.grantId,
              builder: writeAuth.builder,
              action: "write",
              scope: scopeResult.scope,
              timestamp: (deps.now ?? (() => new Date()))().toISOString(),
              ipAddress:
                request.headers.get("x-forwarded-for") ??
                request.headers.get("x-real-ip") ??
                "unknown",
              userAgent: request.headers.get("user-agent") ?? "unknown",
            });
          } catch (err) {
            deps.logger?.warn?.(
              {
                scope: scopeResult.scope,
                builder: writeAuth.builder,
                grantId: writeAuth.grantId,
                error: err instanceof Error ? err.message : String(err),
              },
              "Builder write access-log entry failed; record already stored",
            );
          }
        };

        // Binary / unstructured data (e.g. a PDF): the body is raw bytes. DPv2
        // data points are scope-addressed and carry no schemaId, so unstructured
        // data needs no schema at all — we ingest it schemaless. (Structured JSON
        // below still resolves a schema for validation/metadata.)
        if (!isJsonContentType(request)) {
          const bytes = new Uint8Array(await request.arrayBuffer());
          const metadata = parseMetadataHeader(
            request.headers.get("x-vana-metadata"),
          );
          // A binary derivative names its sources inside the metadata
          // object; the validated mirror lands at the top of the record.
          const lineage = await prepareWriteLineage(
            deps,
            scopeResult.scope,
            extractLineageField(metadata),
          );
          const result = await ingestBinaryDataContract({
            storage: deps.storage,
            scopeParam: scopeResult.scope,
            bytes,
            mimeType: binaryMimeType(request),
            filename: binaryFilename(request),
            metadata,
            collectedAt: collectedAtValue,
            status,
            attribution: writeAuth?.attribution,
            lineage,
            afterTombstoneVersion,
          });
          if (!result.ok) return failWrite(contractErrorResponse(result));
          committed = true;
          deps.logger?.info?.(
            {
              scope: scopeResult.scope,
              collectedAt: collectedAtValue,
              path: result.writeResult.relativePath,
              mimeType: binaryMimeType(request),
              sizeBytes: bytes.length,
              ...(writeAuth ? { builder: writeAuth.builder } : {}),
            },
            "Binary data file ingested",
          );
          await logBuilderWrite();
          notifyNewData(deps.syncManager);
          return jsonResponse(result.response, { status: 201 });
        }

        const parsed = await parseJsonObjectBody(
          request,
          "Request body must be valid JSON",
        );
        if (!parsed.ok) return failWrite(contractResponse(parsed.result));
        // Derivative writes: validate the caller's `lineage` before anything
        // is stored (a failure here throws, releasing the builder's proof).
        const lineage = await prepareWriteLineage(
          deps,
          scopeResult.scope,
          extractLineageField(parsed.body),
        );
        // DPv2 is scope-addressed and the gateway records no schemas, so JSON
        // ingest is schemaless too — no lookup, no schemaId/$schema stamped.
        const result = await ingestDataContract({
          storage: deps.storage,
          scopeParam: scopeResult.scope,
          body: parsed.body,
          collectedAt: collectedAtValue,
          status,
          attribution: writeAuth?.attribution,
          lineage,
          afterTombstoneVersion,
        });
        if (!result.ok) return failWrite(contractErrorResponse(result));
        committed = true;
        deps.logger?.info?.(
          {
            scope: scopeResult.scope,
            collectedAt: collectedAtValue,
            path: result.writeResult.relativePath,
            ...(writeAuth ? { builder: writeAuth.builder } : {}),
          },
          "Data file ingested",
        );
        await logBuilderWrite();
        notifyNewData(deps.syncManager);
        return jsonResponse(result.response, { status: 201 });
      } catch (err) {
        // An envelope that reached storage before indexing failed is
        // persisted (a re-index surfaces it): keep the proof consumed so a
        // retry cannot store it twice; the builder needs a fresh proof.
        if (err instanceof IngestPersistedError) {
          deps.logger?.error?.(
            {
              scope: scopeParam,
              path: err.relativePath,
              error:
                err.cause instanceof Error
                  ? err.cause.message
                  : String(err.cause),
            },
            "Envelope written but indexing failed; record persisted unindexed",
          );
        } else if (!committed) {
          await writeAuth?.releaseProof?.();
        }
        throw err;
      }
    }

    if (request.method === "DELETE") {
      await deps.auth.authorizeOwner(request);
      const cascade = url.searchParams.get("cascade");
      if (cascade !== null && cascade !== "lineage") {
        throw new InvalidCascadeError({ cascade });
      }
      // Parse the scope first so an invalid scope still 400s without a
      // wasted remote call.
      const parsed = parseDataScopeContract(scopeParam);
      if (!parsed.ok) return contractErrorResponse(parsed);
      if (cascade === "lineage") {
        // Specified (docs/derivative-data-api.md, "Delete") but not
        // implemented here: the cascade must tombstone every derivative at
        // the gateway, and DPv2 deletion is separate work (the tombstone
        // based delete branch). Until that lands the only honest answer is
        // 501; a local-only cascade would report derivatives deleted while
        // their gateway records and ciphertext remain and sync could bring
        // them back.
        throw new LineageCascadeUnavailableError({ scope: parsed.scope });
      }

      // Durable order: gateway tombstone -> storage blobs -> local copy. The
      // sync manager owns the remote ports; without one (sync disabled or
      // no owner key material) only the local copy goes and the result says
      // so (`durable: false`) rather than pretending.
      const result = deps.syncManager?.deleteScope
        ? await deps.syncManager.deleteScope(parsed.scope)
        : await deleteScopeLocally(
            {
              storage: deps.storage,
              serverOwner: deps.serverOwner,
              deleteData: null,
              logger: apiLoggerAsLogger(deps.logger),
            },
            parsed.scope,
          );

      if (result.steps.gateway.status === "failed") {
        // Nothing was deleted: the local copy is kept on purpose so sync
        // cannot resurrect a half-deleted scope. Surface it as an upstream
        // failure with the per-step result attached.
        throw new DeleteTombstoneFailedError({
          scope: parsed.scope,
          result,
        });
      }

      await deps.accessLogWriter.write({
        logId: deps.createLogId?.() ?? crypto.randomUUID(),
        grantId: "owner",
        builder: deps.serverOwner ?? "owner",
        action: "delete",
        scope: parsed.scope,
        timestamp: (deps.now ?? (() => new Date()))().toISOString(),
        ipAddress:
          request.headers.get("x-forwarded-for") ??
          request.headers.get("x-real-ip") ??
          "unknown",
        userAgent: request.headers.get("user-agent") ?? "unknown",
      });
      deps.logger?.info?.(
        {
          scope: parsed.scope,
          durable: result.durable,
          gateway: result.steps.gateway.status,
          storage: result.steps.storage.status,
          local: result.steps.local.status,
          deletedCount: result.steps.local.deletedCount,
        },
        "Scope deleted",
      );
      return jsonResponse(result, { status: 200 });
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
