/**
 * In-memory `McpConnectionStore` — Phase 1 default for tests and as a fallback
 * runtime store. Production Web PS Lite is expected to back this with the same
 * IndexedDB state mechanism used for server-identity and token storage.
 *
 * The PS-Lite browser adapter for this port lives in
 * `packages/lite/src/mcp-store.ts` (not part of this change set yet) — that
 * adapter mirrors `createIndexedDbPsLiteTokenStore()`.
 */

import type {
  McpConnectionRecord,
  McpConnectionStore,
  McpOAuthAuthorizationRecord,
  McpOAuthAuthorizationStore,
  McpOAuthClientRecord,
  McpOAuthClientStore,
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

    async mutate(id, update) {
      const record = byId.get(id);
      if (!record) return null;
      const updated = update(structuredClone(record));
      if (updated.tokenHash !== record.tokenHash) {
        byTokenHash.delete(record.tokenHash);
        byTokenHash.set(updated.tokenHash, id);
      }
      byId.set(id, structuredClone(updated));
      return structuredClone(updated);
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

/** Registration is unauthenticated; past this, the oldest client is evicted. */
export const MAX_MCP_OAUTH_CLIENTS = 500;

/**
 * Client to evict before adding one, or undefined while under the cap.
 * Authorizations copy the client's name, so eviction only forgets
 * registrations never authorized. Ties keep insertion order.
 */
export function evictableMcpClient(
  clients: McpOAuthClientRecord[],
): string | undefined {
  if (clients.length < MAX_MCP_OAUTH_CLIENTS) return undefined;
  return clients.reduce((oldest, client) =>
    client.createdAt < oldest.createdAt ? client : oldest,
  ).clientId;
}

export function createInMemoryMcpOAuthClientStore(): McpOAuthClientStore {
  const byId = new Map<string, McpOAuthClientRecord>();

  return {
    async create(record) {
      const evicted = evictableMcpClient(Array.from(byId.values()));
      if (evicted) byId.delete(evicted);
      byId.set(record.clientId, { ...record });
    },

    async getById(clientId) {
      const record = byId.get(clientId);
      return record ? { ...record } : null;
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
