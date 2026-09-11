/**
 * Lifetime and lookup policy for the two MCP OAuth credentials — one policy,
 * shared by every store that resolves a token, so the fleet and local paths
 * cannot diverge.
 */

import type { McpConnectionRecord } from "./types.js";

/**
 * 1 h. Short because the bearer is replayable and the store cannot revoke an
 * already-issued one; the refresh grant below is what keeps the owner from
 * re-consenting hourly.
 */
export const MCP_TOKEN_TTL_MS = 60 * 60 * 1000;

/**
 * 30 d. The refresh token is single-use and rotates on every exchange, so its
 * lifetime bounds how long a connection survives without the owner touching
 * it — not how long a leaked credential is usable.
 */
export const MCP_REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/** ISO expiry for an access token minted at `nowMs`. */
export function mcpTokenExpiry(nowMs: number): string {
  return new Date(nowMs + MCP_TOKEN_TTL_MS).toISOString();
}

/** ISO expiry for a refresh token minted at `nowMs`. */
export function mcpRefreshExpiry(nowMs: number): string {
  return new Date(nowMs + MCP_REFRESH_TTL_MS).toISOString();
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
  return isExpired(record.tokenExpiresAt, nowMs);
}

/** Fail closed, same rule: no proven lifetime means no refresh. */
export function isMcpRefreshExpired(
  record: Pick<McpConnectionRecord, "refreshExpiresAt">,
  nowMs: number = Date.now(),
): boolean {
  return isExpired(record.refreshExpiresAt, nowMs);
}

/**
 * True when `hash` is this record's current or rotated-out refresh hash. Every
 * store resolves a refresh token through this one predicate.
 */
export function matchesMcpRefreshHash(
  record: Pick<
    McpConnectionRecord,
    "refreshTokenHash" | "previousRefreshTokenHash"
  >,
  hash: string,
): boolean {
  if (!hash) return false;

  return (
    record.refreshTokenHash === hash || record.previousRefreshTokenHash === hash
  );
}

function isExpired(expiresAt: string | undefined, nowMs: number): boolean {
  if (!expiresAt) return true;

  const expiry = Date.parse(expiresAt);
  return !Number.isFinite(expiry) || expiry <= nowMs;
}
