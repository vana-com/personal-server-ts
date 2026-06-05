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
} from "./types.js";

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
      return { ...record };
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
