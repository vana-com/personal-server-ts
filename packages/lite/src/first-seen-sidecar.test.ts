/**
 * The per-scope first-seen ledger in PS-Lite: written by an ingest through
 * the runtime, persisted with the storage state, never an index row, and
 * removed with the scope.
 */

import { describe, expect, it } from "vitest";
import { ingestDataContract } from "@opendatalabs/personal-server-ts-core/contracts";
import {
  ensureScopeLedger,
  listAddedTimestamps,
  readScopeFirstSeenLedger,
} from "@opendatalabs/personal-server-ts-core/additions";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
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

  it("drops the sidecar with the scope's last version, keeps it while others remain", async () => {
    const storage = await createPersistentPsLiteStorage(
      { kind: "indexeddb" },
      createMemoryPsLitePersistence(),
    );
    for (const [at, ids] of [
      ["2026-10-01T12:00:00.000Z", ["a"]],
      ["2026-10-02T12:00:00.000Z", ["a", "b"]],
    ] as const) {
      await ingestDataContract({
        storage,
        scopeParam: SCOPE,
        body: items(...ids),
        collectedAt: at,
        status: "stored",
      });
    }
    await storage.deleteVersion(SCOPE, "2026-10-01T12:00:00.000Z");
    expect(await storage.readFirstSeenLedger!(SCOPE)).not.toBeNull();
    await storage.deleteVersion(SCOPE, "2026-10-02T12:00:00.000Z");
    expect(await storage.readFirstSeenLedger!(SCOPE)).toBeNull();
  });

  describe("each scope's ledger is persisted on its own (B3)", () => {
    const AT = "2026-10-01T12:00:00.000Z";
    const bigLedger = (scope: string, records: number) => ({
      version: 3,
      scope,
      baseline: AT,
      current: AT,
      latest: { collectedAt: AT, total: records },
      through: AT,
      records: Object.fromEntries(
        Array.from({ length: records }, (_, i) => [`items:i:r${i}`, [AT, AT]]),
      ),
    });

    it("an ingest into scope A does not rewrite scope B's ledger", async () => {
      const persistence = createMemoryPsLitePersistence();
      const writes: string[] = [];
      const writeAux = persistence.writeAux!.bind(persistence);
      persistence.writeAux = async (name, value) => {
        writes.push(name);
        return writeAux(name, value);
      };
      const storage = await createPersistentPsLiteStorage(
        { kind: "indexeddb" },
        persistence,
      );
      await ingestDataContract({
        storage,
        scopeParam: "notes.b",
        body: items("b1"),
        collectedAt: AT,
        status: "stored",
      });
      writes.length = 0;

      await ingestDataContract({
        storage,
        scopeParam: "notes.a",
        body: items("a1"),
        collectedAt: AT,
        status: "stored",
      });
      expect(writes).toEqual(["first-seen:notes.a"]);
    });

    it("keeps ledgers out of the main state, whatever their size", async () => {
      const persistence = createMemoryPsLitePersistence();
      const storage = await createPersistentPsLiteStorage(
        { kind: "indexeddb" },
        persistence,
      );
      await ingestDataContract({
        storage,
        scopeParam: "notes.a",
        body: items("a1"),
        collectedAt: AT,
        status: "stored",
      });
      const before = JSON.stringify(await persistence.read()).length;

      await storage.writeFirstSeenLedger!(
        "notes.big",
        bigLedger("notes.big", 20_000),
      );
      await ingestDataContract({
        storage,
        scopeParam: "notes.a",
        body: items("a1", "a2"),
        collectedAt: "2026-10-02T12:00:00.000Z",
        status: "stored",
      });
      const state = await persistence.read();
      expect(Object.keys(state!)).not.toContain("firstSeenLedgers");
      expect(JSON.stringify(state)).not.toContain("items:i:r");
      // Only the second version's envelope and index row were added.
      expect(JSON.stringify(state).length - before).toBeLessThan(2_000);
    });

    it("survives a reload", async () => {
      const persistence = createMemoryPsLitePersistence();
      const first = await createPersistentPsLiteStorage(
        { kind: "indexeddb" },
        persistence,
      );
      await first.writeFirstSeenLedger!(
        "notes.big",
        bigLedger("notes.big", 50),
      );
      const reloaded = await createPersistentPsLiteStorage(
        { kind: "indexeddb" },
        persistence,
      );
      expect(await reloaded.readFirstSeenLedger!("notes.big")).toEqual(
        bigLedger("notes.big", 50),
      );
    });

    it("discards ledgers the previous build kept inside the main state", async () => {
      const seed = {
        version: 1 as const,
        nextId: 1,
        entries: [],
        envelopes: [],
        firstSeenLedgers: [
          { scope: "notes.old", ledger: { version: 2, scope: "notes.old" } },
        ],
      };
      const persistence = createMemoryPsLitePersistence(seed);
      const storage = await createPersistentPsLiteStorage(
        { kind: "indexeddb" },
        persistence,
      );
      expect(await storage.readFirstSeenLedger!("notes.old")).toBeNull();
      await ingestDataContract({
        storage,
        scopeParam: "notes.a",
        body: items("a1"),
        collectedAt: AT,
        status: "stored",
      });
      // The next persist drops the old field; the state keeps its old shape.
      const state = (await persistence.read()) as Record<string, unknown>;
      expect(Object.keys(state).sort()).toEqual(
        [
          "blockManifests",
          "blockPayloads",
          "entries",
          "envelopes",
          "nextId",
          "version",
        ].sort(),
      );
    });

    it("keeps working with a persistence adapter that has no side records", async () => {
      const full = createMemoryPsLitePersistence();
      const persistence = {
        read: full.read.bind(full),
        write: full.write.bind(full),
      };
      const storage = await createPersistentPsLiteStorage(
        { kind: "indexeddb" },
        persistence,
      );
      await ingestDataContract({
        storage,
        scopeParam: "notes.a",
        body: items("a1"),
        collectedAt: AT,
        status: "stored",
      });
      expect(await storage.readFirstSeenLedger!("notes.a")).not.toBeNull();
      await storage.deleteScope("notes.a");
      expect(await storage.readFirstSeenLedger!("notes.a")).toBeNull();
    });

    it("a failed ledger delete never blocks the data delete, and is collected on load (F5)", async () => {
      const persistence = createMemoryPsLitePersistence();
      let failing = true;
      const deleteAux = persistence.deleteAux!.bind(persistence);
      persistence.deleteAux = async (name) => {
        if (failing) throw new Error("aux store unavailable");
        return deleteAux(name);
      };
      const storage = await createPersistentPsLiteStorage(
        { kind: "indexeddb" },
        persistence,
      );
      await ingestDataContract({
        storage,
        scopeParam: "notes.a",
        body: items("secret"),
        collectedAt: AT,
        status: "stored",
      });
      await expect(storage.deleteScope("notes.a")).resolves.toBe(1);
      expect(storage.countVersions("notes.a")).toBe(0);
      expect(await persistence.readAux!("first-seen:notes.a")).not.toBeNull();
      expect(
        ((await persistence.read()) as { pendingLedgerDeletes?: string[] })
          .pendingLedgerDeletes,
      ).toEqual(["notes.a"]);

      failing = false;
      const reloaded = await createPersistentPsLiteStorage(
        { kind: "indexeddb" },
        persistence,
      );
      expect(await persistence.readAux!("first-seen:notes.a")).toBeNull();
      expect(
        (await persistence.read()) as { pendingLedgerDeletes?: string[] },
      ).not.toHaveProperty("pendingLedgerDeletes");
      expect(await reloaded.readFirstSeenLedger!("notes.a")).toBeNull();
    });
  });

  it("a first version numbered above 1 is partial; after a deletion it counts (follow-up review)", async () => {
    for (const [afterTombstone, partial] of [
      [null, true],
      [4, undefined],
    ] as const) {
      const storage = await createPersistentPsLiteStorage(
        { kind: "indexeddb" },
        createMemoryPsLitePersistence(),
      );
      const envelope = createDataFileEnvelope(
        SCOPE,
        "2026-10-01T12:00:00.000Z",
        items("a", "b"),
      );
      const written = await storage.writeEnvelope(envelope);
      await storage.insertEntry({
        fileId: null,
        schemaId: null,
        path: written.relativePath,
        scope: SCOPE,
        collectedAt: envelope.collectedAt,
        sizeBytes: written.sizeBytes,
        version: 5,
        afterTombstoneVersion: afterTombstone,
      });
      const ledger = (await ensureScopeLedger(storage, SCOPE))!;
      expect(ledger.partial).toBe(partial);
      expect(listAddedTimestamps(ledger)).toHaveLength(partial ? 0 : 2);
    }
  });
});
