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
} from "./types.js";

const TOKEN_BYTES = 32;

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
