import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import pino from "pino";
import { createApp } from "./app.js";
import { initializeDatabase } from "./storage/index-schema.js";
import {
  createIndexManager,
  type IndexManager,
} from "./storage/index-manager.js";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import { createTestWallet } from "@opendatalabs/personal-server-ts-core/test-utils";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { AccessLogReader } from "@opendatalabs/personal-server-ts-core/logging/access-reader";

const SERVER_ORIGIN = "http://localhost:8080";
const ownerWallet = createTestWallet(0);

function createMockGateway(): GatewayClient {
  return {
    isRegisteredBuilder: async () => true,
    getBuilder: async () => null,
    getGrant: async () => null,
    listGrantsByUser: async () => [],
    getSchemaForScope: async () => null,
    getServer: async () => null,
    getFile: async () => null,
    listFilesSince: async () => ({ files: [], cursor: null }),
    getSchema: async () => null,
    registerServer: async () => ({ alreadyRegistered: false }),
    registerFile: async () => ({}),
    createGrant: async () => ({}),
    revokeGrant: async () => undefined,
  } as unknown as GatewayClient;
}

function createMockAccessLogWriter(): AccessLogWriter {
  return { append: async () => undefined } as unknown as AccessLogWriter;
}

function createMockAccessLogReader(): AccessLogReader {
  return {
    list: async () => ({ entries: [], cursor: null }),
  } as unknown as AccessLogReader;
}

/**
 * Proves the PDPP §8 routes are genuinely mounted into the real composed
 * Hono app (createApp), not just unit-tested as bare sub-app handlers — the
 * request goes through the same app instance createApp returns, exercised
 * via the same app.request(...) pattern the rest of this repo's route tests
 * use (see packages/server/src/app.test.ts).
 */
describe("createApp: PDPP routes are reachable through the real app", () => {
  let tempDir: string;
  let indexManager: IndexManager;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "app-pdpp-test-"));
    const db = initializeDatabase(":memory:");
    indexManager = createIndexManager(db);
  });

  afterEach(async () => {
    indexManager.close();
    await rm(tempDir, { recursive: true, force: true });
  });

  function makeApp() {
    const store = createMemoryRecordStore();
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", name: "road trip" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
    );
    const declarations = createStreamDeclarationRegistry([
      {
        name: "playlists",
        semantics: "mutable_state",
        primaryKey: ["id"],
        cursorField: "emitted_at",
        requiredFields: ["id"],
      },
    ]);
    const auth = createFixtureAuthorizationService({
      "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" },
    });

    const logger = pino({ level: "silent" });
    return createApp({
      logger,
      version: "0.0.1",
      startedAt: new Date(),
      indexManager,
      hierarchyOptions: { dataDir: join(tempDir, "data") },
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway: createMockGateway(),
      accessLogWriter: createMockAccessLogWriter(),
      accessLogReader: createMockAccessLogReader(),
      pdpp: {
        store,
        auth,
        declarations,
        instancesForSubject: () => ["inst_1"],
        resource: SERVER_ORIGIN,
      },
    });
  }

  it("GET /v1/streams reaches the mounted PDPP route through the real app", async () => {
    const app = makeApp();
    const res = await app.request("/v1/streams", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toEqual([
      {
        object: "stream",
        name: "playlists",
        record_count: 1,
        last_updated: "2026-04-01T00:00:00.000Z",
      },
    ]);
  });

  it("GET /v1/streams/playlists/records reaches the mounted route and returns the ingested record", async () => {
    const app = makeApp();
    const res = await app.request("/v1/streams/playlists/records", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toHaveLength(1);
    expect(body.data[0].data.name).toBe("road trip");
  });

  it("GET /.well-known/oauth-protected-resource is mounted and reachable without auth", async () => {
    const app = makeApp();
    const res = await app.request("/.well-known/oauth-protected-resource");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.pdpp_core_query_base).toBe("/v1");
  });

  it("existing non-PDPP routes are unaffected when pdpp deps are supplied", async () => {
    const app = makeApp();
    const res = await app.request("/health");
    expect(res.status).toBe(200);
  });
});
