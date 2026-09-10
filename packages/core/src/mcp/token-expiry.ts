/**
 * Lifetime of an MCP connection bearer — one policy, shared by every store
 * that resolves a token, so the fleet and local paths cannot diverge.
 */

import type { McpConnectionRecord } from "./types.js";

/**
 * 24 h. The bearer is the only credential the MCP client holds and there is
 * no refresh grant (`grant_types_supported: ["authorization_code"]`), so each
 * expiry costs the owner one re-consent — a 60 min TTL would mean hourly
 * consent screens.
 */
export const MCP_TOKEN_TTL_MS = 24 * 60 * 60 * 1000;

/** ISO expiry for a token minted at `nowMs`. */
export function mcpTokenExpiry(nowMs: number): string {
  return new Date(nowMs + MCP_TOKEN_TTL_MS).toISOString();
}

/**
 * Fail closed. A record written before `tokenExpiresAt` existed carries no
 * proven lifetime, so it reads as expired: connections issued before this
 * change need one re-consent rather than living forever.
 */
export function isMcpTokenExpired(
  record: Pick<McpConnectionRecord, "tokenExpiresAt">,
  nowMs: number = Date.now(),
): boolean {
  if (!record.tokenExpiresAt) return true;

  const expiry = Date.parse(record.tokenExpiresAt);
  return !Number.isFinite(expiry) || expiry <= nowMs;
}
