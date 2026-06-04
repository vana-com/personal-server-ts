/**
 * In-memory `McpConnectionStore` — Phase 1 default for tests and as a fallback
 * runtime store. Production Web PS Lite is expected to back this with the same
 * IndexedDB state mechanism used for server-identity and token storage.
 *
 * The PS-Lite browser adapter for this port lives in
 * `packages/lite/src/mcp-store.ts` (not part of this change set yet) — that
 * adapter mirrors `createIndexedDbPsLiteTokenStore()`.
 */

import type { McpConnectionRecord, McpConnectionStore } from "./types.js";

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
      const updated = { ...record, ...patch };
      byId.set(id, updated);
      return { ...updated };
    },
  };
}
