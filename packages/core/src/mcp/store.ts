/**
 * In-memory `McpConnectionStore` — the default for tests and a fallback
 * runtime store. Durable implementations of this port live with their host
 * runtime (the enclave persists connection state inside the CVM).
 */

import type {
  McpConnectionRecord,
  McpConnectionStore,
  McpOAuthAuthorizationRecord,
  McpOAuthAuthorizationStore,
} from "./types.js";
import { isMcpTokenExpired, matchesMcpRefreshHash } from "./token-expiry.js";

export function createInMemoryMcpConnectionStore(): McpConnectionStore {
  const byId = new Map<string, McpConnectionRecord>();
  const byTokenHash = new Map<string, string>(); // tokenHash → id

  return {
    async create(record) {
      if (byId.has(record.id)) {
        throw new Error(`mcp connection ${record.id} already exists`);
      }
      byId.set(record.id, { ...record });
      byTokenHash.set(record.tokenHash, record.id);
    },

    async list() {
      return Array.from(byId.values()).map((r) => ({ ...r }));
    },

    async getById(id) {
      const record = byId.get(id);
      return record ? { ...record } : null;
    },

    async getByTokenHash(tokenHash) {
      const id = byTokenHash.get(tokenHash);
      if (!id) return null;
      const record = byId.get(id);
      if (!record) return null;
      if (record.status !== "approved") return null;
      if (isMcpTokenExpired(record)) return null;
      return { ...record };
    },

    async getByRefreshTokenHash(refreshTokenHash) {
      // Scanned, not indexed: a presented token may match either the current
      // or the rotated-out hash, and a store holds a handful of connections.
      const record = Array.from(byId.values()).find((candidate) =>
        matchesMcpRefreshHash(candidate, refreshTokenHash),
      );
      return record ? { ...record } : null;
    },

    async update(id, patch) {
      const record = byId.get(id);
      if (!record) return null;
      if (patch.tokenHash && patch.tokenHash !== record.tokenHash) {
        byTokenHash.delete(record.tokenHash);
        byTokenHash.set(patch.tokenHash, id);
      }
      const updated = { ...record, ...patch };
      byId.set(id, updated);
      return { ...updated };
    },
  };
}

export function createInMemoryMcpOAuthAuthorizationStore(): McpOAuthAuthorizationStore {
  const byId = new Map<string, McpOAuthAuthorizationRecord>();
  const byCodeHash = new Map<string, string>(); // authorizationCodeHash -> id

  return {
    async create(record) {
      if (byId.has(record.id)) {
        throw new Error(`mcp oauth authorization ${record.id} already exists`);
      }
      byId.set(record.id, { ...record });
      if (record.authorizationCodeHash) {
        byCodeHash.set(record.authorizationCodeHash, record.id);
      }
    },

    async getById(id) {
      const record = byId.get(id);
      return record ? { ...record } : null;
    },

    async getByCodeHash(authorizationCodeHash) {
      const id = byCodeHash.get(authorizationCodeHash);
      if (!id) return null;
      const record = byId.get(id);
      return record ? { ...record } : null;
    },

    async update(id, patch) {
      const record = byId.get(id);
      if (!record) return null;
      if (
        patch.authorizationCodeHash &&
        patch.authorizationCodeHash !== record.authorizationCodeHash
      ) {
        byCodeHash.set(patch.authorizationCodeHash, id);
      }
      const updated = { ...record, ...patch };
      byId.set(id, updated);
      return { ...updated };
    },

    async delete(id) {
      const record = byId.get(id);
      if (record?.authorizationCodeHash) {
        byCodeHash.delete(record.authorizationCodeHash);
      }
      byId.delete(id);
    },
  };
}
