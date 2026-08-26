/**
 * Derivative data through the data routes: lineage on write (session and
 * owner, JSON and binary), the proxied lineage read, and cascade delete.
 * See docs/derivative-data-api.md.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { pino } from "pino";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import type { HierarchyManagerOptions } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type {
  Builder,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/node";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  WRITE_SIGNATURE_HEADER,
  binaryWriteSignedBytes,
  createInMemoryWriteSessionStore,
  hashWriteSessionToken,
  verifyStoredWriterAttribution,
  type WriteSessionStore,
} from "@opendatalabs/personal-server-ts-core/write";
import {
  computeDataPointId,
  type LineageGatewayPort,
  type LineageView,
} from "@opendatalabs/personal-server-ts-core/lineage";
import { createSyncManager } from "@opendatalabs/personal-server-ts-core/sync/manager";
import { createNodeDataStorage } from "../storage/node-data-storage.js";
import { dataRoutes, type DataRouteDeps } from "./data.js";

const SERVER_ORIGIN = "http://localhost:8080";
const builderWallet = createTestWallet(0);
const ownerWallet = createTestWallet(9);

const BUILDER_ID = "0xbuilder1";
const SESSION_TOKEN = "vana_write_test_token";
const WRITE_GRANT_ID = "grant-w-1";
const READ_GRANT_ID = "grant-r-1";
const SOURCE_SCOPE = "chatgpt.conversations";
const OTHER_SOURCE_SCOPE = "oura.sleep";
const DERIVED_SCOPE = "spine.health.summary";
const SOURCE_ID = computeDataPointId(ownerWallet.address, SOURCE_SCOPE);
const OTHER_SOURCE_ID = computeDataPointId(
  ownerWallet.address,
  OTHER_SOURCE_SCOPE,
);
const DERIVED_ID = computeDataPointId(ownerWallet.address, DERIVED_SCOPE);
const UNKNOWN_ID = `0x${"9".repeat(64)}`;

function createMockGateway(
  overrides: Partial<GatewayClient> = {},
): GatewayClient {
  return {
    isRegisteredBuilder: vi.fn().mockResolvedValue(true),
    getBuilder: vi.fn().mockResolvedValue({
      id: BUILDER_ID,
      ownerAddress: "0xOwner",
      granteeAddress: builderWallet.address,
      publicKey: "0x04key",
      appUrl: "https://app.example.com",
      addedAt: "2026-01-21T10:00:00.000Z",
    } satisfies Builder),
    getGrant: vi.fn().mockResolvedValue(null),
    ...overrides,
  } as unknown as GatewayClient;
}

function makeGrant(
  overrides: Partial<GatewayGrantResponse> = {},
): GatewayGrantResponse {
  return {
    id: WRITE_GRANT_ID,
    grantorAddress: ownerWallet.address,
    granteeId: BUILDER_ID,
    scopes: [`write:spine.*`, `write:chatgpt.*`],
    status: "confirmed",
    addedAt: "2026-01-21T10:00:00.000Z",
    expiresAt: null,
    expired: false,
    revokedAt: null,
    revocationSignature: null,
    paymentStatus: "paid",
    paidAt: null,
    paidBy: null,
    grantVersion: "1",
    settleTxHash: null,
    settleSubmittedAt: null,
    revocationTxHash: null,
    revocationSubmittedAt: null,
    fee: {
      asset: "0x0000000000000000000000000000000000000000",
      registrationFee: "0",
      dataAccessFee: "0",
      totalDue: "0",
    },
    ...overrides,
  };
}

const grants: Record<string, GatewayGrantResponse> = {
  [WRITE_GRANT_ID]: makeGrant(),
  [READ_GRANT_ID]: makeGrant({
    id: READ_GRANT_ID,
    scopes: [DERIVED_SCOPE],
  }),
};

const logger = pino({ level: "silent" });

async function seedSession(store: WriteSessionStore): Promise<void> {
  await store.create({
    tokenHash: await hashWriteSessionToken(SESSION_TOKEN),
    builderAddress: builderWallet.address,
    grantId: WRITE_GRANT_ID,
    writeScopes: ["spine.*", "chatgpt.*"],
    createdAt: new Date().toISOString(),
    expiresAtMs: Date.now() + 60_000,
  });
}

function lineageView(overrides: Partial<LineageView> = {}): LineageView {
  return {
    dataPointId: DERIVED_ID,
    ownerAddress: ownerWallet.address,
    scope: DERIVED_SCOPE,
    version: "1",
    deletedAt: null,
    sources: [
      {
        dataPointId: SOURCE_ID,
        scope: SOURCE_SCOPE,
        version: "3",
        deletedAt: null,
      },
    ],
    derivatives: [],
    ...overrides,
  };
}

function createMockLineageGateway(
  overrides: Partial<LineageGatewayPort> = {},
): LineageGatewayPort {
  return {
    getDataPoint: vi.fn().mockResolvedValue(null),
    getLineage: vi
      .fn()
      .mockResolvedValue({ ok: true, data: lineageView(), proof: { p: 1 } }),
    registerDataPoint: vi.fn(),
    ...overrides,
  };
}

describe("derivative data routes", () => {
  let dataDir: string;
  let hierarchyOptions: HierarchyManagerOptions;
  let app: ReturnType<typeof dataRoutes>;
  let cleanup: () => void;
  let writeSessionStore: WriteSessionStore;
  let accessLogWriter: AccessLogWriter;
  let lineageGateway: LineageGatewayPort;
  let deps: DataRouteDeps;

  beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), "data-lineage-route-test-"));
    hierarchyOptions = { dataDir };
    const db = initializeDatabase(":memory:");
    const indexManager = createIndexManager(db);
    writeSessionStore = createInMemoryWriteSessionStore();
    await seedSession(writeSessionStore);
    accessLogWriter = { write: vi.fn().mockResolvedValue(undefined) };
    lineageGateway = createMockLineageGateway();
    deps = {
      indexManager,
      hierarchyOptions,
      logger,
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway: createMockGateway({
        getGrant: vi.fn(async (id: string) => grants[id] ?? null),
      }),
      accessLogWriter,
      writeSessionStore,
      lineageGateway,
    };
    app = dataRoutes(deps);
    cleanup = () => indexManager.close();
  });

  afterEach(async () => {
    cleanup();
    await rm(dataDir, { recursive: true, force: true });
  });

  async function ownerHeader(method: string, uri: string, body?: string) {
    return buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method,
      uri,
      body: body === undefined ? undefined : new TextEncoder().encode(body),
    });
  }

  async function ownerWrite(scope: string, body: unknown) {
    const raw = JSON.stringify(body);
    return app.request(`/${scope}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: await ownerHeader("POST", `/${scope}`, raw),
      },
      body: raw,
    });
  }

  async function ownerRead(scope: string) {
    return app.request(`/${scope}`, {
      headers: { Authorization: await ownerHeader("GET", `/${scope}`) },
    });
  }

  async function sessionWrite(scope: string, body: unknown) {
    const raw = JSON.stringify(body);
    return app.request(`/${scope}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${SESSION_TOKEN}`,
        [WRITE_SIGNATURE_HEADER]: await buildWeb3SignedHeader({
          wallet: builderWallet,
          aud: SERVER_ORIGIN,
          method: "POST",
          uri: `/${scope}`,
          body: new TextEncoder().encode(raw),
          grantId: WRITE_GRANT_ID,
        }),
      },
      body: raw,
    });
  }

  async function seedSource(scope = SOURCE_SCOPE) {
    const res = await ownerWrite(scope, { messages: ["hi"] });
    expect(res.status).toBe(201);
  }

  describe("POST /v1/data/:scope with lineage", () => {
    it("stores a session-written derivative with $lineage and verifiable attribution", async () => {
      await seedSource();
      const res = await sessionWrite(DERIVED_SCOPE, {
        summary: "sleep improved",
        lineage: [SOURCE_ID.toUpperCase().replace("0X", "0x")],
      });
      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.lineage).toEqual({ sources: [SOURCE_ID] });

      const read = await ownerRead(DERIVED_SCOPE);
      expect(read.status).toBe(200);
      const envelope = await read.json();
      expect(envelope.data.summary).toBe("sleep improved");
      // The caller's field is kept verbatim (it is inside the signed bytes)
      // and the validated mirror is stamped next to $writtenBy.
      expect(envelope.data.lineage).toEqual([
        SOURCE_ID.toUpperCase().replace("0X", "0x"),
      ]);
      expect(envelope.data.$lineage.sources).toEqual([SOURCE_ID]);
      expect(typeof envelope.data.$lineage.writtenAt).toBe("string");
      expect(envelope.data.$writtenBy.builder).toBe(builderWallet.address);
      const verified = await verifyStoredWriterAttribution(envelope, {
        expectedOrigin: SERVER_ORIGIN,
      });
      expect(verified.grantId).toBe(WRITE_GRANT_ID);
      // Local sources never need the gateway.
      expect(lineageGateway.getDataPoint).not.toHaveBeenCalled();
    });

    it("accepts an owner write with lineage", async () => {
      await seedSource();
      const res = await ownerWrite(DERIVED_SCOPE, {
        summary: "x",
        lineage: [SOURCE_ID],
      });
      expect(res.status).toBe(201);
      const envelope = await (await ownerRead(DERIVED_SCOPE)).json();
      expect(envelope.data.$lineage.sources).toEqual([SOURCE_ID]);
      expect(envelope.data.$writtenBy).toBeUndefined();
    });

    it("resolves a non-local source at the gateway, deleted sources allowed", async () => {
      (
        lineageGateway.getDataPoint as ReturnType<typeof vi.fn>
      ).mockResolvedValue({
        dataPointId: OTHER_SOURCE_ID,
        ownerAddress: ownerWallet.address.toLowerCase(),
        scope: OTHER_SOURCE_SCOPE,
        version: "2",
        deletedAt: "2026-08-01T00:00:00.000Z",
      });
      const res = await sessionWrite(DERIVED_SCOPE, {
        summary: "x",
        lineage: [OTHER_SOURCE_ID],
      });
      expect(res.status).toBe(201);
      expect(lineageGateway.getDataPoint).toHaveBeenCalledWith(OTHER_SOURCE_ID);
    });

    it("rejects an unknown source with 422 and stores nothing", async () => {
      const res = await sessionWrite(DERIVED_SCOPE, {
        summary: "x",
        lineage: [UNKNOWN_ID],
      });
      expect(res.status).toBe(422);
      const body = await res.json();
      expect(body.error.errorCode).toBe("LINEAGE_SOURCE_UNKNOWN");
      expect(body.error.details.unknown).toEqual([UNKNOWN_ID]);
      expect((await ownerRead(DERIVED_SCOPE)).status).toBe(404);
    });

    it("rejects another owner's data point as a source", async () => {
      (
        lineageGateway.getDataPoint as ReturnType<typeof vi.fn>
      ).mockResolvedValue({
        dataPointId: UNKNOWN_ID,
        ownerAddress: "0x1111111111111111111111111111111111111111",
        scope: "foreign.scope",
        version: "1",
        deletedAt: null,
      });
      const res = await sessionWrite(DERIVED_SCOPE, {
        summary: "x",
        lineage: [UNKNOWN_ID],
      });
      expect(res.status).toBe(422);
    });

    it("hands the builder's proof back on a rejected lineage so the same signed request can be retried", async () => {
      const raw = JSON.stringify({ summary: "x", lineage: [SOURCE_ID] });
      const headers = {
        "Content-Type": "application/json",
        Authorization: `Bearer ${SESSION_TOKEN}`,
        [WRITE_SIGNATURE_HEADER]: await buildWeb3SignedHeader({
          wallet: builderWallet,
          aud: SERVER_ORIGIN,
          method: "POST",
          uri: `/${DERIVED_SCOPE}`,
          body: new TextEncoder().encode(raw),
          grantId: WRITE_GRANT_ID,
        }),
      };
      const first = await app.request(`/${DERIVED_SCOPE}`, {
        method: "POST",
        headers,
        body: raw,
      });
      expect(first.status).toBe(422);
      await seedSource();
      const retry = await app.request(`/${DERIVED_SCOPE}`, {
        method: "POST",
        headers,
        body: raw,
      });
      expect(retry.status).toBe(201);
    });

    it("enforces the naming rule: a derivative under a source namespace is 400", async () => {
      await seedSource();
      const res = await sessionWrite("chatgpt.summary", {
        summary: "x",
        lineage: [SOURCE_ID],
      });
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body.error.errorCode).toBe("LINEAGE_SCOPE_UNDER_SOURCE_PREFIX");
      expect(body.error.details.sourceScope).toBe(SOURCE_SCOPE);
    });

    it("rejects malformed lineage with 400 LINEAGE_INVALID", async () => {
      const res = await sessionWrite(DERIVED_SCOPE, {
        summary: "x",
        lineage: ["0x1234"],
      });
      expect(res.status).toBe(400);
      expect((await res.json()).error.errorCode).toBe("LINEAGE_INVALID");
    });

    it("rejects a body carrying the reserved $lineage key", async () => {
      const res = await ownerWrite(DERIVED_SCOPE, {
        summary: "x",
        $lineage: { sources: [SOURCE_ID], writtenAt: "now" },
      });
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe("INVALID_BODY");
    });

    it("stores a binary derivative whose lineage rides in X-Vana-Metadata", async () => {
      await seedSource();
      const bytes = new TextEncoder().encode("%PDF-1.7 report");
      const representation = {
        contentType: "application/pdf",
        filename: "report.pdf",
        metadataHeader: JSON.stringify({
          description: "Quarterly",
          lineage: [SOURCE_ID],
        }),
      };
      const res = await app.request("/spine.health.report", {
        method: "POST",
        headers: {
          "Content-Type": representation.contentType,
          "X-Filename": representation.filename,
          "X-Vana-Metadata": representation.metadataHeader,
          Authorization: `Bearer ${SESSION_TOKEN}`,
          [WRITE_SIGNATURE_HEADER]: await buildWeb3SignedHeader({
            wallet: builderWallet,
            aud: SERVER_ORIGIN,
            method: "POST",
            uri: "/spine.health.report",
            body: await binaryWriteSignedBytes({ bytes, ...representation }),
            grantId: WRITE_GRANT_ID,
          }),
        },
        body: bytes,
      });
      expect(res.status).toBe(201);
      const envelope = await (await ownerRead("spine.health.report")).json();
      expect(envelope.data.$binary).toBe(true);
      expect(envelope.data.metadata).toEqual({
        description: "Quarterly",
        lineage: [SOURCE_ID],
      });
      expect(envelope.data.$lineage.sources).toEqual([SOURCE_ID]);
      const verified = await verifyStoredWriterAttribution(envelope, {
        expectedOrigin: SERVER_ORIGIN,
      });
      expect(verified.grantId).toBe(WRITE_GRANT_ID);
    });

    it("treats an empty lineage as a root record: nothing stamped", async () => {
      const res = await ownerWrite("notes.entries", {
        note: "root",
        lineage: [],
      });
      expect(res.status).toBe(201);
      expect((await res.json()).lineage).toBeUndefined();
      const envelope = await (await ownerRead("notes.entries")).json();
      expect(envelope.data.$lineage).toBeUndefined();
    });

    it("leaves a root write untouched (no lineage field, no $lineage)", async () => {
      const res = await ownerWrite("notes.entries", { note: "root" });
      expect(res.status).toBe(201);
      expect((await res.json()).lineage).toBeUndefined();
      const envelope = await (await ownerRead("notes.entries")).json();
      expect(envelope.data).toEqual({ note: "root" });
    });
  });

  describe("GET /v1/data/:scope/lineage", () => {
    async function builderLineageRead(scope: string, query = "") {
      const uri = `/${scope}/lineage`;
      return app.request(`${uri}${query}`, {
        headers: {
          Authorization: await buildWeb3SignedHeader({
            wallet: builderWallet,
            aud: SERVER_ORIGIN,
            method: "GET",
            uri,
            grantId: READ_GRANT_ID,
          }),
        },
      });
    }

    it("returns the owner's full view straight from the gateway, attested", async () => {
      const res = await app.request(`/${DERIVED_SCOPE}/lineage`, {
        headers: {
          Authorization: await ownerHeader("GET", `/${DERIVED_SCOPE}/lineage`),
        },
      });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({
        data: lineageView(),
        proof: { p: 1 },
      });
      expect(lineageGateway.getLineage).toHaveBeenCalledWith({
        dataPointId: DERIVED_ID,
        version: undefined,
        grantId: undefined,
      });
    });

    it("asks the gateway for the builder's grant view under its read grant", async () => {
      const redacted = lineageView({
        sources: [{ dataPointId: SOURCE_ID, redacted: true }],
      });
      (lineageGateway.getLineage as ReturnType<typeof vi.fn>).mockResolvedValue(
        {
          ok: true,
          data: redacted,
          proof: { p: 2 },
        },
      );
      const res = await builderLineageRead(DERIVED_SCOPE, "?version=1");
      expect(res.status).toBe(200);
      expect((await res.json()).data).toEqual(redacted);
      expect(lineageGateway.getLineage).toHaveBeenCalledWith({
        dataPointId: DERIVED_ID,
        version: "1",
        grantId: READ_GRANT_ID,
      });
    });

    it("refuses a builder whose grant does not cover the scope", async () => {
      const res = await builderLineageRead(SOURCE_SCOPE);
      expect(res.status).toBe(403);
      expect(lineageGateway.getLineage).not.toHaveBeenCalled();
    });

    it("maps a gateway 404 to NOT_FOUND and a malformed version to 400", async () => {
      (lineageGateway.getLineage as ReturnType<typeof vi.fn>).mockResolvedValue(
        {
          ok: false,
          status: 404,
          body: { error: "Data point not found" },
        },
      );
      const missing = await app.request(`/${DERIVED_SCOPE}/lineage`, {
        headers: {
          Authorization: await ownerHeader("GET", `/${DERIVED_SCOPE}/lineage`),
        },
      });
      expect(missing.status).toBe(404);
      const bad = await app.request(`/${DERIVED_SCOPE}/lineage?version=0`, {
        headers: {
          Authorization: await ownerHeader("GET", `/${DERIVED_SCOPE}/lineage`),
        },
      });
      expect(bad.status).toBe(400);
    });

    it("relays other gateway failures as 502 LINEAGE_GATEWAY_ERROR", async () => {
      (lineageGateway.getLineage as ReturnType<typeof vi.fn>).mockResolvedValue(
        {
          ok: false,
          status: 500,
          body: { error: "boom" },
        },
      );
      const res = await app.request(`/${DERIVED_SCOPE}/lineage`, {
        headers: {
          Authorization: await ownerHeader("GET", `/${DERIVED_SCOPE}/lineage`),
        },
      });
      expect(res.status).toBe(502);
      expect((await res.json()).error.errorCode).toBe("LINEAGE_GATEWAY_ERROR");
    });

    it("answers 503 when the server has no lineage gateway", async () => {
      const localApp = dataRoutes({ ...deps, lineageGateway: undefined });
      const res = await localApp.request(`/${DERIVED_SCOPE}/lineage`, {
        headers: {
          Authorization: await ownerHeader("GET", `/${DERIVED_SCOPE}/lineage`),
        },
      });
      expect(res.status).toBe(503);
      expect((await res.json()).error.errorCode).toBe("LINEAGE_UNAVAILABLE");
    });

    it("requires authentication", async () => {
      const res = await app.request(`/${DERIVED_SCOPE}/lineage`);
      expect(res.status).toBe(401);
    });
  });

  describe("DELETE /v1/data/:scope?cascade=lineage", () => {
    const DERIVED2_SCOPE = "coach.weekly";
    const DERIVED2_ID = computeDataPointId(ownerWallet.address, DERIVED2_SCOPE);
    const DELETED_SCOPE = "old.summary";
    const DELETED_ID = computeDataPointId(ownerWallet.address, DELETED_SCOPE);

    function graph(): Record<string, LineageView> {
      // source -> derived -> derived2 ; source -> deleted (already tombstoned)
      return {
        [SOURCE_ID]: lineageView({
          dataPointId: SOURCE_ID,
          scope: SOURCE_SCOPE,
          sources: [],
          derivatives: [
            {
              dataPointId: DERIVED_ID,
              scope: DERIVED_SCOPE,
              version: "1",
              deletedAt: null,
            },
            {
              dataPointId: DELETED_ID,
              scope: DELETED_SCOPE,
              version: "1",
              deletedAt: "2026-08-01T00:00:00.000Z",
            },
          ],
        }),
        [DERIVED_ID]: lineageView({
          derivatives: [
            {
              dataPointId: DERIVED2_ID,
              scope: DERIVED2_SCOPE,
              version: "1",
              deletedAt: null,
            },
          ],
        }),
        [DERIVED2_ID]: lineageView({
          dataPointId: DERIVED2_ID,
          scope: DERIVED2_SCOPE,
          sources: [
            {
              dataPointId: DERIVED_ID,
              scope: DERIVED_SCOPE,
              version: "1",
              deletedAt: null,
            },
          ],
        }),
        [DELETED_ID]: lineageView({
          dataPointId: DELETED_ID,
          scope: DELETED_SCOPE,
          deletedAt: "2026-08-01T00:00:00.000Z",
          derivatives: [],
        }),
      };
    }

    let deleteScopeRemote: ReturnType<typeof vi.fn>;
    let deleteScope: ReturnType<typeof vi.fn>;

    beforeEach(async () => {
      const nodes = graph();
      (
        lineageGateway.getLineage as ReturnType<typeof vi.fn>
      ).mockImplementation(async ({ dataPointId }: { dataPointId: string }) => {
        const data = nodes[dataPointId];
        return data
          ? { ok: true, data, proof: {} }
          : { ok: false, status: 404, body: {} };
      });
      deleteScopeRemote = vi.fn().mockResolvedValue(undefined);
      // The durable (tombstone) delete port the cascade requires. No current
      // runtime provides it (the tombstone-based delete is separate work), so
      // these tests exercise the port contract; the 501 test below covers
      // what a real SyncManager-only deployment answers.
      deleteScope = vi.fn(async (scope: string) => {
        await deps.indexManager.deleteScope?.(scope);
        return { durable: true };
      });
      app = dataRoutes({
        ...deps,
        syncManager: {
          start: vi.fn(),
          stop: vi.fn(),
          trigger: vi.fn(),
          getStatus: vi.fn(),
          notifyNewData: vi.fn(),
          deleteScopeRemote,
          running: false,
        },
        durableDelete: { deleteScope },
      });
      await seedSource(SOURCE_SCOPE);
      await seedSource(DERIVED_SCOPE);
      await seedSource(DERIVED2_SCOPE);
    });

    async function ownerDelete(scope: string, query = "") {
      return app.request(`/${scope}${query}`, {
        method: "DELETE",
        headers: { Authorization: await ownerHeader("DELETE", `/${scope}`) },
      });
    }

    it("deletes derivatives deepest-first, then the scope, skipping already-deleted nodes", async () => {
      const res = await ownerDelete(SOURCE_SCOPE, "?cascade=lineage");
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({
        scope: SOURCE_SCOPE,
        cascade: "lineage",
        deleted: [
          { dataPointId: DERIVED2_ID, scope: DERIVED2_SCOPE },
          { dataPointId: DERIVED_ID, scope: DERIVED_SCOPE },
          { dataPointId: SOURCE_ID, scope: SOURCE_SCOPE },
        ],
      });
      expect(deleteScope.mock.calls.map((c) => c[0])).toEqual([
        DERIVED2_SCOPE,
        DERIVED_SCOPE,
        SOURCE_SCOPE,
      ]);
      expect(deleteScopeRemote).not.toHaveBeenCalled();
    });

    it("stops with 502 when a node's deletion did not reach the gateway", async () => {
      deleteScope.mockResolvedValueOnce({ durable: false });
      const res = await ownerDelete(SOURCE_SCOPE, "?cascade=lineage");
      expect(res.status).toBe(502);
      const body = await res.json();
      expect(body.error.errorCode).toBe("LINEAGE_CASCADE_INCOMPLETE");
      expect(body.error.details.failed.scope).toBe(DERIVED2_SCOPE);
      expect(deleteScope).toHaveBeenCalledTimes(1);
    });

    it("deleting a derivative never touches its sources", async () => {
      const res = await ownerDelete(DERIVED2_SCOPE, "?cascade=lineage");
      expect(res.status).toBe(200);
      expect((await res.json()).deleted).toEqual([
        { dataPointId: DERIVED2_ID, scope: DERIVED2_SCOPE },
      ]);
      expect(deleteScope).toHaveBeenCalledTimes(1);
      expect(deleteScope).toHaveBeenCalledWith(DERIVED2_SCOPE);
    });

    it("cascades a local-only scope the gateway does not know as a single node", async () => {
      await seedSource("local.only");
      const res = await ownerDelete("local.only", "?cascade=lineage");
      expect(res.status).toBe(200);
      expect((await res.json()).deleted).toHaveLength(1);
    });

    it("refuses the whole cascade on a foreign-owner node with nothing deleted", async () => {
      const nodes = graph();
      nodes[DERIVED_ID] = lineageView({
        ownerAddress: "0x1111111111111111111111111111111111111111",
      });
      (
        lineageGateway.getLineage as ReturnType<typeof vi.fn>
      ).mockImplementation(
        async ({ dataPointId }: { dataPointId: string }) => ({
          ok: true,
          data: nodes[dataPointId],
          proof: {},
        }),
      );
      const res = await ownerDelete(SOURCE_SCOPE, "?cascade=lineage");
      expect(res.status).toBe(409);
      expect((await res.json()).error.errorCode).toBe("LINEAGE_CROSS_OWNER");
      expect(deleteScope).not.toHaveBeenCalled();
      expect((await ownerRead(SOURCE_SCOPE)).status).toBe(200);
    });

    it("aborts with 502 and nothing deleted when the gateway walk fails", async () => {
      (lineageGateway.getLineage as ReturnType<typeof vi.fn>).mockResolvedValue(
        {
          ok: false,
          status: 500,
          body: {},
        },
      );
      const res = await ownerDelete(SOURCE_SCOPE, "?cascade=lineage");
      expect(res.status).toBe(502);
      expect(deleteScope).not.toHaveBeenCalled();
    });

    it("answers 501 without a lineage gateway or a durable delete, and 400 for an unknown cascade mode", async () => {
      const realSyncManager = createSyncManager(
        {
          storage: createNodeDataStorage({
            indexManager: deps.indexManager,
            hierarchyOptions: deps.hierarchyOptions,
          }),
          storageAdapter: {} as never,
          gateway: deps.gateway,
          signer: {} as never,
          masterKey: new Uint8Array(65),
          serverOwner: ownerWallet.address,
          logger: logger as never,
        },
        {} as never,
      );
      for (const variant of [
        { ...deps, lineageGateway: undefined, durableDelete: { deleteScope } },
        // What every current runtime wires: the real sync manager and no
        // durable delete port.
        { ...deps, syncManager: realSyncManager },
      ]) {
        const localApp = dataRoutes(variant);
        const res = await localApp.request(`/${SOURCE_SCOPE}?cascade=lineage`, {
          method: "DELETE",
          headers: {
            Authorization: await ownerHeader("DELETE", `/${SOURCE_SCOPE}`),
          },
        });
        expect(res.status).toBe(501);
        expect((await res.json()).error.errorCode).toBe(
          "LINEAGE_CASCADE_UNAVAILABLE",
        );
      }
      const bad = await ownerDelete(SOURCE_SCOPE, "?cascade=all");
      expect(bad.status).toBe(400);
      expect((await bad.json()).error.errorCode).toBe("INVALID_CASCADE");
    });

    it("keeps the default single-node delete at 204 without walking lineage", async () => {
      const res = await ownerDelete(SOURCE_SCOPE);
      expect(res.status).toBe(204);
      expect(lineageGateway.getLineage).not.toHaveBeenCalled();
      expect(deleteScopeRemote).toHaveBeenCalledWith(SOURCE_SCOPE);
      expect((await ownerRead(DERIVED_SCOPE)).status).toBe(200);
    });

    it("is owner-only", async () => {
      const res = await app.request(`/${SOURCE_SCOPE}?cascade=lineage`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${SESSION_TOKEN}` },
      });
      expect(res.status).toBe(401);
    });
  });
});
