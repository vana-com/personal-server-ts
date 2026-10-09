/**
 * The per-scope first-seen ledger in PS-Lite: written by an ingest through
 * the runtime, persisted with the storage state, never an index row, and
 * removed with the scope.
 */

import { describe, expect, it } from "vitest";
import { ingestDataContract } from "@opendatalabs/personal-server-ts-core/contracts";
import { readScopeFirstSeenLedger } from "@opendatalabs/personal-server-ts-core/additions";
import { createBearerTokenPsLiteAuth, createPsLiteRuntime } from "./runtime.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLitePersistence,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";
import { createPersistentPsLiteStorage } from "./storage.js";

const SCOPE = "notes.entries";
const items = (...ids: string[]) => ({ items: ids.map((id) => ({ id })) });

function createRuntime() {
  const storage = createMemoryPsLiteStorage();
  const accessLogStore = createMemoryPsLiteAccessLogStore();
  const runtime = createPsLiteRuntime({
    storage,
    gateway: createMockPsLiteGateway(),
    accessLogReader: accessLogStore,
    accessLogWriter: accessLogStore,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
    auth: createBearerTokenPsLiteAuth({
      ownerToken: "owner-token",
      builderToken: "builder-token",
    }),
    active: true,
  });
  return { runtime, storage };
}

const owner = { Authorization: "Bearer owner-token" };

describe("PS-Lite first-seen sidecar", () => {
  it("writes the sidecar on ingest and serves /additions from it", async () => {
    const { runtime, storage } = createRuntime();
    for (const body of [items("a"), items("a", "b")]) {
      const res = await runtime.fetch(
        new Request(`https://ps.local/v1/data/${SCOPE}`, {
          method: "POST",
          headers: { ...owner, "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }),
      );
      expect(res.status).toBe(201);
    }

    const ledger = readScopeFirstSeenLedger(
      await storage.readFirstSeenLedger!(SCOPE),
    );
    expect(ledger?.scope).toBe(SCOPE);
    expect(ledger?.latest.total).toBe(2);
    expect(Object.keys(ledger!.records)).toEqual(["items:i:a", "items:i:b"]);
    // The sidecar is not a version.
    expect(storage.listVersions(SCOPE, { limit: 100 })).toHaveLength(
      storage.countVersions(SCOPE),
    );

    const res = await runtime.fetch(
      new Request("https://ps.local/v1/data/additions?days=3", {
        headers: owner,
      }),
    );
    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      total: number;
      days: unknown[];
      scopes: unknown[];
    };
    expect(json.total).toBe(2);
    expect(json.days).toHaveLength(3);
    expect(json.scopes).toHaveLength(1);

    const stored = await runtime.fetch(
      new Request(`https://ps.local/v1/data/${SCOPE}`, { headers: owner }),
    );
    expect(JSON.stringify(await stored.json())).not.toContain("items:i:");
  });

  it("refuses /additions to a builder token", async () => {
    const { runtime } = createRuntime();
    const res = await runtime.fetch(
      new Request("https://ps.local/v1/data/additions", {
        headers: { Authorization: "Bearer builder-token" },
      }),
    );
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(500);
  });

  it("persists the sidecar with the storage state and removes it with the scope", async () => {
    const persistence = createMemoryPsLitePersistence();
    const first = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    await ingestDataContract({
      storage: first,
      scopeParam: SCOPE,
      body: items("a"),
      collectedAt: "2026-10-01T12:00:00.000Z",
      status: "stored",
    });
    expect(await first.readFirstSeenLedger!(SCOPE)).not.toBeNull();

    const reloaded = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    const ledger = readScopeFirstSeenLedger(
      await reloaded.readFirstSeenLedger!(SCOPE),
    );
    expect(ledger?.records["items:i:a"]).toEqual([
      "2026-10-01T12:00:00.000Z",
      "2026-10-01T12:00:00.000Z",
    ]);
    // Entries hold only the one version; the sidecar is not among them.
    expect(reloaded.listVersions(SCOPE, { limit: 100 })).toHaveLength(1);
    expect(reloaded.findUnsynced()).toHaveLength(1);

    await reloaded.deleteScope(SCOPE);
    expect(await reloaded.readFirstSeenLedger!(SCOPE)).toBeNull();
    const afterDelete = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      persistence,
    );
    expect(await afterDelete.readFirstSeenLedger!(SCOPE)).toBeNull();
  });
});
