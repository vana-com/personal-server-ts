/**
 * Owner-only MCP connection management. Implements the four endpoints listed
 * in §2 of 260604-PLAN-vana-mcp-personal-server.md:
 *
 *   POST   /v1/mcp/connections
 *   GET    /v1/mcp/connections
 *   POST   /v1/mcp/connections/:id/approve
 *   DELETE /v1/mcp/connections/:id
 *
 * plus the server-signed answer to an MCP client's `request_scope_access`:
 *
 *   POST   /v1/mcp/connections/:id/scope-request/approve
 *   POST   /v1/mcp/connections/:id/scope-request/deny
 *
 * These endpoints DO NOT read user data. They only manage connection records
 * — create the per-connection grantee/token, store grant ids after the user
 * approves them, and mark connections revoked.
 */

import { generateMcpGrantee } from "./grantee.js";
import { createGrantContract } from "../contracts/index.js";
import {
  ScopeSchema,
  type DataPortabilityGatewayConfig,
  type GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import type { ServerSigner } from "../signing/index.js";
import {
  appUrlFromOAuthRedirectUri,
  ensureMcpGranteeRegistered,
  McpGranteeRegistrationError,
} from "./builder-registration.js";
import type {
  McpConnectionRecord,
  McpConnectionStore,
  McpConnectionGrant,
  McpScopeAccessDecision,
  McpScopeAccessRequest,
  McpOAuthAuthorizationRecord,
  McpOAuthAuthorizationStore,
} from "./types.js";
import { MCP_SCOPE_ACCESS_REQUEST_LIMIT } from "./types.js";
import {
  isMcpRefreshExpired,
  MCP_TOKEN_TTL_MS,
  mcpRefreshExpiry,
  mcpTokenExpiry,
} from "./token-expiry.js";

const TOKEN_BYTES = 32;
const OAUTH_AUTHORIZATION_TTL_MS = 10 * 60 * 1000;

/** Store patch that drops every refresh token a connection still answers to. */
const CLEARED_REFRESH_FAMILY = {
  refreshTokenHash: undefined,
  previousRefreshTokenHash: undefined,
  refreshExpiresAt: undefined,
} as const;

function nowIso(now?: () => Date): string {
  return (now ? now() : new Date()).toISOString();
}

function nowMs(now?: () => Date): number {
  return (now ? now() : new Date()).getTime();
}

function randomBytes(byteLength: number): Uint8Array {
  const bytes = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  // `btoa` exists in modern browsers AND Node ≥18 (the engines version that
  // PS Lite and personal-server-ts already target).
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function hashConnectionToken(token: string): Promise<string> {
  const data = new TextEncoder().encode(token);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", data);
  return bytesToHex(new Uint8Array(digest));
}

function randomId(): string {
  return (
    globalThis.crypto?.randomUUID?.() ?? `mcp-${bytesToHex(randomBytes(8))}`
  );
}

function randomToken(): string {
  return bytesToBase64Url(randomBytes(TOKEN_BYTES));
}

export interface CreateMcpConnectionInput {
  displayName?: string;
}

export interface CreateMcpConnectionOutput {
  connectionId: string;
  granteeAddress: `0x${string}`;
  /** Raw token. Returned ONCE — the store keeps only the SHA-256 hash. */
  connectionToken: string;
  /** Convenience: the full URL Claude should call. */
  mcpUrl: string;
  createdAt: string;
}

export interface CreateMcpConnectionOptions {
  store: McpConnectionStore;
  /**
   * Public origin Claude will hit. Used to build the returned `mcpUrl`. The
   * caller (route handler) typically resolves this from the request's public
   * URL (relay) at call time.
   */
  publicOrigin: string;
  now?: () => Date;
}

export async function createMcpConnection(
  input: CreateMcpConnectionInput,
  options: CreateMcpConnectionOptions,
): Promise<CreateMcpConnectionOutput> {
  const grantee = generateMcpGrantee();
  const token = randomToken();
  const tokenHash = await hashConnectionToken(token);
  const id = randomId();
  const createdAt = nowIso(options.now);

  const record: McpConnectionRecord = {
    id,
    displayName: input.displayName?.trim() || "Claude",
    granteeAddress: grantee.key.address,
    granteePublicKey: grantee.key.publicKey,
    encryptedGranteePrivateKey: grantee.key.encryptedPrivateKey,
    tokenHash,
    tokenExpiresAt: mcpTokenExpiry(nowMs(options.now)),
    status: "pending",
    grants: [],
    createdAt,
  };

  await options.store.create(record);

  return {
    connectionId: id,
    granteeAddress: grantee.key.address,
    connectionToken: token,
    mcpUrl: buildMcpUrl(options.publicOrigin, token),
    createdAt,
  };
}

export function buildMcpUrl(publicOrigin: string, token: string): string {
  const base = publicOrigin.endsWith("/")
    ? publicOrigin.slice(0, -1)
    : publicOrigin;
  return `${base}/mcp/${encodeURIComponent(token)}`;
}

export function buildStableMcpUrl(publicOrigin: string): string {
  const base = publicOrigin.endsWith("/")
    ? publicOrigin.slice(0, -1)
    : publicOrigin;
  return `${base}/mcp`;
}

export function buildMcpProtectedResourceMetadataUrl(
  publicOrigin: string,
): string {
  const base = publicOrigin.endsWith("/")
    ? publicOrigin.slice(0, -1)
    : publicOrigin;
  return `${base}/.well-known/oauth-protected-resource/mcp`;
}

export interface ApproveMcpConnectionInput {
  connectionId: string;
  grants: McpConnectionGrant[];
}

export interface ApproveMcpConnectionOptions {
  store: McpConnectionStore;
  now?: () => Date;
}

/**
 * errorCode for an unknown connection id on the single-connection and
 * scope-request routes. Distinct from the generic `NOT_FOUND` a server
 * answers for a route it does not have, so a caller (Vana Web) can tell
 * "this request is gone" from "this server predates the route".
 */
export const MCP_CONNECTION_NOT_FOUND = "MCP_CONNECTION_NOT_FOUND";

export class McpConnectionNotFoundError extends Error {
  constructor(public connectionId: string) {
    super(`mcp connection ${connectionId} not found`);
  }
}

export class McpConnectionStateError extends Error {
  constructor(
    public connectionId: string,
    public state: string,
    public expected: string,
  ) {
    super(`mcp connection ${connectionId} is ${state}; expected ${expected}`);
  }
}

export async function approveMcpConnection(
  input: ApproveMcpConnectionInput,
  options: ApproveMcpConnectionOptions,
): Promise<McpConnectionRecord> {
  if (!input.grants.length) {
    throw new Error(
      "approveMcpConnection requires at least one grant; the consent flow must mint grants first",
    );
  }
  const approvedAt = nowIso(options.now);
  const updated = await options.store.mutate(input.connectionId, (existing) => {
    if (existing.status === "revoked") {
      throw new McpConnectionStateError(
        input.connectionId,
        existing.status,
        "pending or approved",
      );
    }
    const pendingRequest = existing.scopeAccessRequest;
    const remainingRequestScopes = pendingRequest?.scopes.filter(
      (scope) => !input.grants.some((grant) => grantCoversScope(grant, scope)),
    );
    return {
      ...existing,
      status: "approved",
      grants: input.grants,
      approvedAt,
      scopeAccessRequest:
        pendingRequest &&
        remainingRequestScopes &&
        remainingRequestScopes.length > 0
          ? { ...pendingRequest, scopes: remainingRequestScopes }
          : undefined,
    };
  });
  if (!updated) throw new McpConnectionNotFoundError(input.connectionId);
  return updated;
}

function grantCoversScope(grant: McpConnectionGrant, scope: string): boolean {
  return grant.scopes.some(
    (granted) =>
      granted === "*" ||
      granted === scope ||
      (granted.endsWith(".*") && scope.startsWith(granted.slice(0, -1))),
  );
}

export async function requestMcpScopeAccess(
  input: { connectionId: string; scopes: string[]; reason?: string },
  options: { store: McpConnectionStore; now?: () => Date },
): Promise<{
  connection: McpConnectionRecord;
  requestRecorded: boolean;
}> {
  const requestedAt = nowIso(options.now);
  const inputScopes = Array.from(
    new Set(input.scopes.map((scope) => scope.trim()).filter(Boolean)),
  ).sort();
  const updated = await options.store.mutate(input.connectionId, (existing) => {
    if (existing.status !== "approved") {
      throw new McpConnectionStateError(
        input.connectionId,
        existing.status,
        "approved",
      );
    }
    const scopes = Array.from(
      new Set(
        [...(existing.scopeAccessRequest?.scopes ?? []), ...inputScopes]
          .map((scope) => scope.trim())
          .filter(
            (scope) =>
              scope.length > 0 &&
              !existing.grants.some((grant) => grantCoversScope(grant, scope)),
          ),
      ),
    ).sort();
    if (scopes.length === 0) return existing;
    if (scopes.length > MCP_SCOPE_ACCESS_REQUEST_LIMIT) return existing;
    const reason = input.reason?.trim() || existing.scopeAccessRequest?.reason;
    const request: McpScopeAccessRequest = {
      scopes,
      ...(reason ? { reason } : {}),
      requestedAt,
    };
    return { ...existing, scopeAccessRequest: request };
  });
  if (!updated) throw new McpConnectionNotFoundError(input.connectionId);
  const missingInputScopes = inputScopes.filter(
    (scope) => !updated.grants.some((grant) => grantCoversScope(grant, scope)),
  );
  return {
    connection: updated,
    requestRecorded:
      missingInputScopes.length > 0 &&
      missingInputScopes.every((scope) =>
        updated.scopeAccessRequest?.scopes.includes(scope),
      ),
  };
}

/** A scope-request answer the owner cannot give in the connection's state. */
export class McpScopeRequestError extends Error {
  constructor(
    public code: string,
    message: string,
    public status: 400 | 409 | 500 | 502 = 400,
    public body?: unknown,
  ) {
    super(message);
    this.name = "McpScopeRequestError";
  }
}

export interface ApproveMcpScopeAccessRequestInput {
  connectionId: string;
  /** Scopes the owner approves; must be a subset of the pending request. */
  scopes: unknown;
}

export interface ApproveMcpScopeAccessRequestOptions {
  store: McpConnectionStore;
  gateway: Pick<GatewayClient, "getBuilder" | "getGrant" | "createGrant">;
  serverOwner?: `0x${string}`;
  serverSigner?: Pick<ServerSigner, "signGrantRegistration">;
  now?: () => Date;
}

export interface ApproveMcpScopeAccessRequestOutput {
  connection: McpConnectionRecord;
  grantId: string;
  /** Every scope the connection's grant now covers. */
  grantedScopes: string[];
  approvedScopes: string[];
  deniedScopes: string[];
}

/**
 * Owner approves (part of) a pending `request_scope_access` without an
 * external signer: the server signs the grant itself, as the OAuth approve
 * path does.
 *
 * The gateway keeps ONE grant per (owner, grantee) and a new registration
 * replaces its scopes, so the grant is re-signed over the union of every
 * scope the connection already holds plus the approved ones. Signing only
 * the new scopes would silently revoke the old ones.
 */
export async function approveMcpScopeAccessRequest(
  input: ApproveMcpScopeAccessRequestInput,
  options: ApproveMcpScopeAccessRequestOptions,
): Promise<ApproveMcpScopeAccessRequestOutput> {
  const connection = await options.store.getById(input.connectionId);
  if (!connection) throw new McpConnectionNotFoundError(input.connectionId);
  const pending = requirePendingScopeRequest(connection);
  const approvedScopes = parseApprovedScopes(input.scopes, pending);

  const live = await readLiveGrantState(connection, options.gateway);
  const grantedScopes = sortedUnique([...live.scopes, ...approvedScopes]);

  let grantResult: Awaited<ReturnType<typeof createGrantContract>>;
  try {
    grantResult = await createGrantContract({
      gateway: options.gateway,
      serverOwner: options.serverOwner,
      serverSigner: options.serverSigner,
      body: {
        granteeAddress: connection.granteeAddress,
        scopes: grantedScopes,
        grantVersion: live.nextGrantVersion,
        ...(live.expiresAt !== undefined ? { expiresAt: live.expiresAt } : {}),
      },
    });
  } catch (err) {
    throw new McpScopeRequestError(
      "GRANT_CREATION_FAILED",
      err instanceof Error ? err.message : String(err),
      502,
    );
  }
  if (!grantResult.ok) {
    throw new McpScopeRequestError(
      "GRANT_CREATION_FAILED",
      extractGrantErrorMessage(grantResult.body),
      grantResult.status >= 500 ? 502 : grantResult.status === 409 ? 409 : 400,
      grantResult.body,
    );
  }
  const grantId = (grantResult.body as { grantId?: string }).grantId;
  if (!grantId) {
    throw new McpScopeRequestError(
      "GRANT_CREATION_FAILED",
      "Gateway did not return a grant id.",
      502,
      grantResult.body,
    );
  }

  const decidedAt = nowIso(options.now);
  const deniedScopes = pending.scopes.filter(
    (scope) => !approvedScopes.includes(scope),
  );
  const updated = await options.store.mutate(input.connectionId, (latest) => {
    // The grant above was signed from the state read before the gateway
    // round trip; refuse to store it over a change made in between.
    requirePendingScopeRequest(latest);
    if (JSON.stringify(latest.grants) !== JSON.stringify(connection.grants)) {
      throw new McpScopeRequestError(
        "CONCURRENT_UPDATE",
        "The connection's grants changed during approval; retry.",
        409,
      );
    }
    const decision: McpScopeAccessDecision = {
      decision: "approved",
      approvedScopes,
      deniedScopes,
      requestedAt: pending.requestedAt,
      decidedAt,
    };
    return {
      ...latest,
      grants: [{ grantId, scopes: grantedScopes }],
      scopeAccessRequest: undefined,
      scopeAccessDecision: decision,
    };
  });
  if (!updated) throw new McpConnectionNotFoundError(input.connectionId);
  return {
    connection: updated,
    grantId,
    grantedScopes,
    approvedScopes,
    deniedScopes,
  };
}

/** Owner declines the pending request; the decision stays for the client. */
export async function denyMcpScopeAccessRequest(
  input: { connectionId: string },
  options: { store: McpConnectionStore; now?: () => Date },
): Promise<McpConnectionRecord> {
  const decidedAt = nowIso(options.now);
  const updated = await options.store.mutate(input.connectionId, (latest) => {
    const pending = requirePendingScopeRequest(latest);
    const decision: McpScopeAccessDecision = {
      decision: "denied",
      approvedScopes: [],
      deniedScopes: pending.scopes,
      requestedAt: pending.requestedAt,
      decidedAt,
    };
    return {
      ...latest,
      scopeAccessRequest: undefined,
      scopeAccessDecision: decision,
    };
  });
  if (!updated) throw new McpConnectionNotFoundError(input.connectionId);
  return updated;
}

function requirePendingScopeRequest(
  connection: McpConnectionRecord,
): McpScopeAccessRequest {
  if (connection.status !== "approved") {
    throw new McpConnectionStateError(
      connection.id,
      connection.status,
      "approved",
    );
  }
  const pending = connection.scopeAccessRequest;
  if (!pending || pending.scopes.length === 0) {
    throw new McpScopeRequestError(
      "NO_PENDING_REQUEST",
      `mcp connection ${connection.id} has no pending scope request`,
      409,
    );
  }
  return pending;
}

function parseApprovedScopes(
  value: unknown,
  pending: McpScopeAccessRequest,
): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new McpScopeRequestError(
      "SCOPES_REQUIRED",
      "Approve requires a non-empty scopes array; use deny to decline all.",
    );
  }
  const scopes: string[] = [];
  for (const raw of value) {
    const scope = typeof raw === "string" ? raw.trim() : "";
    if (!ScopeSchema.safeParse(scope).success) {
      throw new McpScopeRequestError(
        "INVALID_SCOPE",
        `Invalid scope: ${JSON.stringify(raw)}`,
      );
    }
    if (!pending.scopes.includes(scope)) {
      throw new McpScopeRequestError(
        "SCOPE_NOT_REQUESTED",
        `Scope ${scope} is not part of the pending request`,
      );
    }
    if (!scopes.includes(scope)) scopes.push(scope);
  }
  return scopes.sort();
}

interface LiveGrantState {
  /** Scopes the connection holds now: its record plus the live gateway grant. */
  scopes: string[];
  nextGrantVersion: string;
  /** Unix seconds of the live grant's expiry, carried over so approval never extends it. */
  expiresAt?: number;
}

/**
 * Read what the gateway holds for this connection's grantee: the scopes the
 * replacement grant must keep, the version counter it must advance past, and
 * the expiry it must not outlive. A revoked grant contributes its version but
 * no scopes, so approval never resurrects access the owner already pulled.
 */
async function readLiveGrantState(
  connection: McpConnectionRecord,
  gateway: Pick<GatewayClient, "getGrant">,
): Promise<LiveGrantState> {
  const grantIds = sortedUnique(
    connection.grants.map((grant) => grant.grantId),
  );
  const revoked = new Set<string>();
  const scopes = new Set<string>();
  let maxVersion = 0n;
  let expiresAt: number | undefined;
  for (const grantId of grantIds) {
    let live: Awaited<ReturnType<typeof gateway.getGrant>>;
    try {
      live = await gateway.getGrant(grantId);
    } catch (err) {
      throw new McpScopeRequestError(
        "GATEWAY_UNAVAILABLE",
        `Could not read grant ${grantId}: ${err instanceof Error ? err.message : String(err)}`,
        502,
      );
    }
    if (!live) continue;
    const version = parseUint(live.grantVersion);
    if (version !== null && version > maxVersion) maxVersion = version;
    if (live.revokedAt) {
      revoked.add(grantId);
      continue;
    }
    for (const scope of live.scopes) scopes.add(scope);
    const liveExpiry = parseExpirySeconds(live.expiresAt);
    if (liveExpiry !== undefined) {
      expiresAt =
        expiresAt === undefined ? liveExpiry : Math.max(expiresAt, liveExpiry);
    }
  }
  for (const grant of connection.grants) {
    if (revoked.has(grant.grantId)) continue;
    for (const scope of grant.scopes) scopes.add(scope);
  }
  return {
    scopes: sortedUnique(scopes),
    nextGrantVersion: (maxVersion + 1n).toString(),
    ...(expiresAt !== undefined ? { expiresAt } : {}),
  };
}

function parseUint(value: unknown): bigint | null {
  if (typeof value !== "string" || !/^\d+$/u.test(value)) return null;
  return BigInt(value);
}

/** Gateway expiry may be unix seconds or an ISO date; 0/null means perpetual. */
function parseExpirySeconds(value: string | null): number | undefined {
  if (!value) return undefined;
  if (/^\d+$/u.test(value)) {
    const seconds = Number(value);
    return seconds > 0 ? seconds : undefined;
  }
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : undefined;
}

function sortedUnique(values: Iterable<string>): string[] {
  return Array.from(new Set(values)).sort();
}

export interface RevokeMcpConnectionOptions {
  store: McpConnectionStore;
  now?: () => Date;
}

export async function revokeMcpConnection(
  connectionId: string,
  options: RevokeMcpConnectionOptions,
): Promise<McpConnectionRecord> {
  const existing = await options.store.getById(connectionId);
  if (!existing) throw new McpConnectionNotFoundError(connectionId);
  if (existing.status === "revoked") return existing;
  const revokedAt = nowIso(options.now);
  // The refresh token outlives the access token by weeks, so a revoke that
  // left it in place would hand the holder a fresh bearer minutes later.
  const updated = await options.store.update(connectionId, {
    status: "revoked",
    revokedAt,
    ...CLEARED_REFRESH_FAMILY,
  });
  if (!updated) throw new McpConnectionNotFoundError(connectionId);
  return updated;
}

/**
 * Public representation of a connection — never includes the encrypted
 * private key or token hash. Safe to return to owner clients (Vana Web).
 */
export interface McpConnectionView {
  id: string;
  displayName: string;
  granteeAddress: `0x${string}`;
  status: "pending" | "approved" | "revoked";
  grants: McpConnectionGrant[];
  /** Every scope the connection's grants cover, deduplicated and sorted. */
  grantedScopes: string[];
  /** Scopes the MCP client is still asking for, if any. */
  scopeAccessRequest?: McpScopeAccessRequest;
  /** Owner's answer to the most recent scope request. */
  scopeAccessDecision?: McpScopeAccessDecision;
  createdAt: string;
  approvedAt?: string;
  revokedAt?: string;
  lastUsedAt?: string;
}

export function toMcpConnectionView(
  record: McpConnectionRecord,
): McpConnectionView {
  return {
    id: record.id,
    displayName: record.displayName,
    granteeAddress: record.granteeAddress,
    status: record.status,
    grants: record.grants,
    grantedScopes: sortedUnique(record.grants.flatMap((grant) => grant.scopes)),
    scopeAccessRequest: record.scopeAccessRequest,
    scopeAccessDecision: record.scopeAccessDecision,
    createdAt: record.createdAt,
    approvedAt: record.approvedAt,
    revokedAt: record.revokedAt,
    lastUsedAt: record.lastUsedAt,
  };
}

/** One connection as the owner sees it; throws when the id is unknown. */
export async function getMcpConnectionView(
  connectionId: string,
  store: McpConnectionStore,
): Promise<McpConnectionView> {
  const record = await store.getById(connectionId);
  if (!record) throw new McpConnectionNotFoundError(connectionId);
  return toMcpConnectionView(record);
}

export async function listMcpConnectionViews(
  store: McpConnectionStore,
): Promise<McpConnectionView[]> {
  const records = await store.list();
  return records.map(toMcpConnectionView);
}

export interface CreateMcpOAuthAuthorizationInput {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  scope?: string;
  state?: string;
}

export interface CreateMcpOAuthAuthorizationOptions {
  connectionStore: McpConnectionStore;
  authorizationStore: McpOAuthAuthorizationStore;
  publicOrigin: string;
  now?: () => Date;
}

export interface CreateMcpOAuthAuthorizationOutput {
  authorizationId: string;
  connectionId: string;
  granteeAddress: `0x${string}`;
  expiresAt: string;
}

export class McpOAuthAuthorizationError extends Error {
  constructor(
    public code: string,
    message: string,
    public status = 400,
    public body?: unknown,
  ) {
    super(message);
    this.name = "McpOAuthAuthorizationError";
  }
}

export async function createMcpOAuthAuthorization(
  input: CreateMcpOAuthAuthorizationInput,
  options: CreateMcpOAuthAuthorizationOptions,
): Promise<CreateMcpOAuthAuthorizationOutput> {
  if (!input.clientId.trim()) {
    throw new McpOAuthAuthorizationError(
      "invalid_client",
      "client_id is required",
    );
  }
  if (!input.redirectUri.trim()) {
    throw new McpOAuthAuthorizationError(
      "invalid_request",
      "redirect_uri is required",
    );
  }
  if (!input.codeChallenge.trim()) {
    throw new McpOAuthAuthorizationError(
      "invalid_request",
      "code_challenge is required",
    );
  }
  if (input.codeChallengeMethod !== "S256") {
    throw new McpOAuthAuthorizationError(
      "invalid_request",
      "Only S256 PKCE is supported",
    );
  }

  const now = options.now ? options.now() : new Date();
  const expiresAt = new Date(
    now.getTime() + OAUTH_AUTHORIZATION_TTL_MS,
  ).toISOString();
  const created = await createMcpConnection(
    { displayName: "Claude" },
    {
      store: options.connectionStore,
      publicOrigin: options.publicOrigin,
      now: () => now,
    },
  );
  const authorizationId = randomId();
  const record: McpOAuthAuthorizationRecord = {
    id: authorizationId,
    clientId: input.clientId,
    redirectUri: input.redirectUri,
    codeChallenge: input.codeChallenge,
    codeChallengeMethod: "S256",
    ...(input.scope ? { scope: input.scope } : {}),
    ...(input.state ? { state: input.state } : {}),
    connectionId: created.connectionId,
    granteeAddress: created.granteeAddress,
    status: "pending",
    createdAt: now.toISOString(),
    expiresAt,
  };
  await options.authorizationStore.create(record);

  return {
    authorizationId,
    connectionId: created.connectionId,
    granteeAddress: created.granteeAddress,
    expiresAt,
  };
}

export interface McpOAuthAuthorizationView {
  id: string;
  clientId: string;
  redirectUri: string;
  scope?: string;
  state?: string;
  connectionId: string;
  granteeAddress: `0x${string}`;
  status: McpOAuthAuthorizationRecord["status"];
  createdAt: string;
  expiresAt: string;
}

export function toMcpOAuthAuthorizationView(
  record: McpOAuthAuthorizationRecord,
): McpOAuthAuthorizationView {
  return {
    id: record.id,
    clientId: record.clientId,
    redirectUri: record.redirectUri,
    ...(record.scope ? { scope: record.scope } : {}),
    ...(record.state ? { state: record.state } : {}),
    connectionId: record.connectionId,
    granteeAddress: record.granteeAddress,
    status: record.status,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
  };
}

export interface ApproveMcpOAuthAuthorizationInput {
  authorizationId: string;
  grants: McpConnectionGrant[];
}

export interface ApproveMcpOAuthAuthorizationScopesInput {
  authorizationId: string;
  scopes: string[];
  expiresAt?: number;
  nonce?: number;
}

export interface ApproveMcpOAuthAuthorizationOptions {
  connectionStore: McpConnectionStore;
  authorizationStore: McpOAuthAuthorizationStore;
  now?: () => Date;
}

export interface ApproveMcpOAuthAuthorizationOutput {
  redirectTo: string;
  authorizationCode: string;
}

export async function approveMcpOAuthAuthorization(
  input: ApproveMcpOAuthAuthorizationInput,
  options: ApproveMcpOAuthAuthorizationOptions,
): Promise<ApproveMcpOAuthAuthorizationOutput> {
  const record = await options.authorizationStore.getById(
    input.authorizationId,
  );
  if (!record) {
    throw new McpOAuthAuthorizationError(
      "not_found",
      `mcp oauth authorization ${input.authorizationId} not found`,
    );
  }
  if (record.status !== "pending") {
    throw new McpOAuthAuthorizationError(
      "invalid_state",
      `mcp oauth authorization ${input.authorizationId} is ${record.status}; expected pending`,
    );
  }
  if (
    Date.parse(record.expiresAt) <= (options.now?.() ?? new Date()).getTime()
  ) {
    await options.authorizationStore.update(record.id, { status: "expired" });
    throw new McpOAuthAuthorizationError(
      "expired",
      "MCP OAuth authorization expired before approval",
    );
  }
  if (input.grants.length === 0) {
    throw new McpOAuthAuthorizationError(
      "grants_required",
      "Approve requires at least one grant",
    );
  }

  await approveMcpConnection(
    { connectionId: record.connectionId, grants: input.grants },
    { store: options.connectionStore, now: options.now },
  );

  const authorizationCode = randomToken();
  const authorizationCodeHash =
    await hashMcpOAuthAuthorizationCode(authorizationCode);
  const approvedAt = (options.now ? options.now() : new Date()).toISOString();
  await options.authorizationStore.update(record.id, {
    status: "approved",
    approvedAt,
    authorizationCodeHash,
  });

  const redirectTo = new URL(record.redirectUri);
  redirectTo.searchParams.set("code", authorizationCode);
  if (record.state) {
    redirectTo.searchParams.set("state", record.state);
  }

  return { redirectTo: redirectTo.toString(), authorizationCode };
}

export interface ApproveMcpOAuthAuthorizationScopesOptions extends ApproveMcpOAuthAuthorizationOptions {
  gateway: Pick<GatewayClient, "getBuilder" | "createGrant">;
  gatewayConfig: DataPortabilityGatewayConfig;
  gatewayUrl: string;
  serverOwner?: `0x${string}`;
  serverSigner?: Pick<ServerSigner, "signGrantRegistration">;
  fetch?: typeof fetch;
}

export async function approveMcpOAuthAuthorizationWithScopes(
  input: ApproveMcpOAuthAuthorizationScopesInput,
  options: ApproveMcpOAuthAuthorizationScopesOptions,
): Promise<ApproveMcpOAuthAuthorizationOutput> {
  const record = await options.authorizationStore.getById(
    input.authorizationId,
  );
  if (!record) {
    throw new McpOAuthAuthorizationError(
      "not_found",
      `mcp oauth authorization ${input.authorizationId} not found`,
      404,
    );
  }
  if (!Array.isArray(input.scopes) || input.scopes.length === 0) {
    throw new McpOAuthAuthorizationError(
      "scopes_required",
      "Approve requires at least one scope",
    );
  }

  const connection = await options.connectionStore.getById(record.connectionId);
  if (!connection) {
    throw new McpOAuthAuthorizationError(
      "connection_not_found",
      `mcp connection ${record.connectionId} not found`,
      404,
    );
  }

  try {
    await ensureMcpGranteeRegistered({
      connection,
      gateway: options.gateway,
      gatewayConfig: options.gatewayConfig,
      gatewayUrl: options.gatewayUrl,
      appUrl: appUrlFromOAuthRedirectUri(record.redirectUri, record.clientId),
      fetch: options.fetch,
    });
  } catch (err) {
    if (err instanceof McpGranteeRegistrationError) {
      throw new McpOAuthAuthorizationError(
        err.code,
        err.message,
        err.status ?? 502,
        err.body,
      );
    }
    throw err;
  }

  const grantResult = await createGrantContract({
    gateway: options.gateway,
    serverOwner: options.serverOwner,
    serverSigner: options.serverSigner,
    body: {
      granteeAddress: connection.granteeAddress,
      scopes: input.scopes,
      ...(input.expiresAt !== undefined ? { expiresAt: input.expiresAt } : {}),
      ...(input.nonce !== undefined ? { nonce: input.nonce } : {}),
    },
  });
  if (!grantResult.ok) {
    throw new McpOAuthAuthorizationError(
      "grant_creation_failed",
      extractGrantErrorMessage(grantResult.body),
      grantResult.status,
      grantResult.body,
    );
  }

  const grantId = (grantResult.body as { grantId?: string }).grantId;
  if (!grantId) {
    throw new McpOAuthAuthorizationError(
      "grant_creation_failed",
      "Personal Server did not return a grant id.",
      500,
      grantResult.body,
    );
  }

  return approveMcpOAuthAuthorization(
    {
      authorizationId: input.authorizationId,
      grants: [{ grantId, scopes: input.scopes }],
    },
    options,
  );
}

export interface RedeemMcpOAuthAuthorizationCodeInput {
  authorizationCode: string;
  codeVerifier: string;
  clientId: string;
  redirectUri: string;
}

export interface RedeemMcpOAuthAuthorizationCodeOptions {
  authorizationStore: McpOAuthAuthorizationStore;
  connectionStore: McpConnectionStore;
  now?: () => Date;
}

export interface McpOAuthTokenOutput {
  accessToken: string;
  /** Presented to `grant_type=refresh_token` for the next pair. Single use. */
  refreshToken: string;
  /** Seconds until the bearer stops resolving — RFC 6749 `expires_in`. */
  expiresIn: number;
  scope?: string;
}

export type RedeemMcpOAuthAuthorizationCodeOutput = McpOAuthTokenOutput;

export async function redeemMcpOAuthAuthorizationCode(
  input: RedeemMcpOAuthAuthorizationCodeInput,
  options: RedeemMcpOAuthAuthorizationCodeOptions,
): Promise<RedeemMcpOAuthAuthorizationCodeOutput> {
  const codeHash = await hashMcpOAuthAuthorizationCode(input.authorizationCode);
  const record = await options.authorizationStore.getByCodeHash(codeHash);
  if (!record) {
    throw new McpOAuthAuthorizationError(
      "invalid_grant",
      "Unknown MCP authorization code",
    );
  }
  if (record.status !== "approved") {
    throw new McpOAuthAuthorizationError(
      "invalid_grant",
      "MCP authorization code has already been used or is not approved",
    );
  }
  if (record.clientId !== input.clientId) {
    throw new McpOAuthAuthorizationError(
      "invalid_grant",
      "client_id does not match authorization request",
    );
  }
  if (record.redirectUri !== input.redirectUri) {
    throw new McpOAuthAuthorizationError(
      "invalid_grant",
      "redirect_uri does not match authorization request",
    );
  }
  if (
    Date.parse(record.expiresAt) <= (options.now?.() ?? new Date()).getTime()
  ) {
    await options.authorizationStore.update(record.id, { status: "expired" });
    throw new McpOAuthAuthorizationError(
      "invalid_grant",
      "MCP authorization code expired",
    );
  }
  if (
    !(await verifyPkceS256({
      codeVerifier: input.codeVerifier,
      expectedChallenge: record.codeChallenge,
    }))
  ) {
    throw new McpOAuthAuthorizationError(
      "invalid_grant",
      "PKCE verification failed",
    );
  }

  const issued = await issueMcpTokenPair(
    {
      connectionId: record.connectionId,
      clientId: record.clientId,
      issuedAtMs: nowMs(options.now),
    },
    options.connectionStore,
  );
  if (!issued) {
    throw new McpOAuthAuthorizationError(
      "invalid_grant",
      "MCP connection for authorization no longer exists",
    );
  }

  await options.authorizationStore.update(record.id, {
    status: "redeemed",
    redeemedAt: (options.now ? options.now() : new Date()).toISOString(),
  });

  return {
    ...issued,
    ...(record.scope ? { scope: record.scope } : {}),
  };
}

export interface RefreshMcpOAuthTokenInput {
  refreshToken: string;
  clientId: string;
}

export interface RefreshMcpOAuthTokenOptions {
  connectionStore: McpConnectionStore;
  now?: () => Date;
}

/**
 * RFC 6749 §6 refresh grant with RFC 9700 §4.14.2 rotation: every exchange
 * mints a new pair and retires the presented refresh token, so the MCP client
 * renews silently instead of re-consenting once an hour.
 */
export async function refreshMcpOAuthToken(
  input: RefreshMcpOAuthTokenInput,
  options: RefreshMcpOAuthTokenOptions,
): Promise<McpOAuthTokenOutput> {
  const presentedHash = await hashMcpRefreshToken(input.refreshToken);
  const connection =
    await options.connectionStore.getByRefreshTokenHash(presentedHash);
  if (!connection) {
    throw new McpOAuthAuthorizationError(
      "invalid_grant",
      "Unknown MCP refresh token",
    );
  }

  // Reuse detection. A rotated-out token still matching means two holders have
  // the family — the legitimate client and a thief — and we cannot tell which
  // one is calling, so the whole family dies. The access token keeps its own
  // expiry: cutting it short would only punish the client that behaved.
  if (connection.refreshTokenHash !== presentedHash) {
    await options.connectionStore.update(connection.id, CLEARED_REFRESH_FAMILY);
    throw new McpOAuthAuthorizationError(
      "invalid_grant",
      "MCP refresh token was already rotated; the refresh family is revoked",
    );
  }

  if (connection.status !== "approved") {
    throw new McpOAuthAuthorizationError(
      "invalid_grant",
      "MCP connection is not approved",
    );
  }
  if (connection.clientId !== input.clientId) {
    throw new McpOAuthAuthorizationError(
      "invalid_grant",
      "client_id does not match the issued refresh token",
    );
  }
  if (isMcpRefreshExpired(connection, nowMs(options.now))) {
    throw new McpOAuthAuthorizationError(
      "invalid_grant",
      "MCP refresh token expired",
    );
  }

  const issued = await issueMcpTokenPair(
    {
      connectionId: connection.id,
      clientId: input.clientId,
      issuedAtMs: nowMs(options.now),
      retiredRefreshHash: presentedHash,
    },
    options.connectionStore,
  );
  if (!issued) {
    throw new McpOAuthAuthorizationError(
      "invalid_grant",
      "MCP connection no longer exists",
    );
  }

  return issued;
}

interface IssueMcpTokenPairInput {
  connectionId: string;
  clientId: string;
  issuedAtMs: number;
  /** Hash of the refresh token this pair replaces, kept for reuse detection. */
  retiredRefreshHash?: string;
}

/**
 * Mint one access/refresh pair. The rotation is a single store `update`, so a
 * concurrent refresh either sees the old pair or the new one — never a
 * connection with the old refresh already dead and no new one issued.
 */
async function issueMcpTokenPair(
  input: IssueMcpTokenPairInput,
  store: McpConnectionStore,
): Promise<Omit<McpOAuthTokenOutput, "scope"> | null> {
  const accessToken = randomToken();
  const refreshToken = randomToken();

  const updated = await store.update(input.connectionId, {
    clientId: input.clientId,
    tokenHash: await hashConnectionToken(accessToken),
    tokenExpiresAt: mcpTokenExpiry(input.issuedAtMs),
    refreshTokenHash: await hashMcpRefreshToken(refreshToken),
    previousRefreshTokenHash: input.retiredRefreshHash,
    refreshExpiresAt: mcpRefreshExpiry(input.issuedAtMs),
  });
  if (!updated) return null;

  return {
    accessToken,
    refreshToken,
    expiresIn: Math.floor(MCP_TOKEN_TTL_MS / 1000),
  };
}

/** Domain-separated so a refresh token can never resolve as a bearer. */
async function hashMcpRefreshToken(token: string): Promise<string> {
  return hashConnectionToken(`mcp-oauth-refresh:${token}`);
}

async function hashMcpOAuthAuthorizationCode(code: string): Promise<string> {
  return hashConnectionToken(`mcp-oauth-code:${code}`);
}

async function verifyPkceS256(input: {
  codeVerifier: string;
  expectedChallenge: string;
}): Promise<boolean> {
  const data = new TextEncoder().encode(input.codeVerifier);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", data);
  return bytesToBase64Url(new Uint8Array(digest)) === input.expectedChallenge;
}

function extractGrantErrorMessage(body: unknown): string {
  if (body && typeof body === "object") {
    const record = body as Record<string, unknown>;
    if (typeof record.message === "string") return record.message;
    const nested = record.error;
    if (nested && typeof nested === "object") {
      const message = (nested as Record<string, unknown>).message;
      if (typeof message === "string") return message;
    }
  }
  return "Could not create MCP grant";
}
