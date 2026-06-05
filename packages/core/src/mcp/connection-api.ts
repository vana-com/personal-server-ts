/**
 * Owner-only MCP connection management. Implements the four endpoints listed
 * in §2 of 260604-PLAN-vana-mcp-personal-server.md:
 *
 *   POST   /v1/mcp/connections
 *   GET    /v1/mcp/connections
 *   POST   /v1/mcp/connections/:id/approve
 *   DELETE /v1/mcp/connections/:id
 *
 * These endpoints DO NOT read user data. They only manage connection records
 * — create the per-connection grantee/token, store grant ids after the user
 * approves them, and mark connections revoked.
 */

import { generateMcpGrantee } from "./grantee.js";
import type {
  McpConnectionRecord,
  McpConnectionStore,
  McpConnectionGrant,
  McpOAuthAuthorizationRecord,
  McpOAuthAuthorizationStore,
} from "./types.js";

const TOKEN_BYTES = 32;
const OAUTH_AUTHORIZATION_TTL_MS = 10 * 60 * 1000;

function nowIso(now?: () => Date): string {
  return (now ? now() : new Date()).toISOString();
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
  const existing = await options.store.getById(input.connectionId);
  if (!existing) throw new McpConnectionNotFoundError(input.connectionId);
  if (existing.status === "revoked") {
    throw new McpConnectionStateError(
      input.connectionId,
      existing.status,
      "pending or approved",
    );
  }
  if (!input.grants.length) {
    throw new Error(
      "approveMcpConnection requires at least one grant; the consent flow must mint grants first",
    );
  }
  const approvedAt = nowIso(options.now);
  const updated = await options.store.update(input.connectionId, {
    status: "approved",
    grants: input.grants,
    approvedAt,
  });
  if (!updated) throw new McpConnectionNotFoundError(input.connectionId);
  return updated;
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
  const updated = await options.store.update(connectionId, {
    status: "revoked",
    revokedAt,
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
    createdAt: record.createdAt,
    approvedAt: record.approvedAt,
    revokedAt: record.revokedAt,
    lastUsedAt: record.lastUsedAt,
  };
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

export interface RedeemMcpOAuthAuthorizationCodeOutput {
  accessToken: string;
  scope?: string;
}

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

  const accessToken = randomToken();
  const tokenHash = await hashConnectionToken(accessToken);
  const updatedConnection = await options.connectionStore.update(
    record.connectionId,
    {
      tokenHash,
    },
  );
  if (!updatedConnection) {
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
    accessToken,
    ...(record.scope ? { scope: record.scope } : {}),
  };
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
