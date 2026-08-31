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

const READ_REPORT_GRANT_ID = "grant-r-2";
const REPORT_SCOPE = "spine.health.report";

const grants: Record<string, GatewayGrantResponse> = {
  [WRITE_GRANT_ID]: makeGrant(),
  [READ_GRANT_ID]: makeGrant({
    id: READ_GRANT_ID,
    scopes: [DERIVED_SCOPE],
  }),
  [READ_REPORT_GRANT_ID]: makeGrant({
    id: READ_REPORT_GRANT_ID,
    scopes: [REPORT_SCOPE],
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

const PROOF = {
  userSignature: "0xuser",
  gatewaySignature: "0xgw",
  timestamp: 1756630000,
  status: "confirmed",
  estimatedConfirmation: null,
  chainBlockHeight: 42,
};

function createMockLineageGateway(
  overrides: Partial<LineageGatewayPort> = {},
): LineageGatewayPort {
  return {
    getDataPoint: vi.fn().mockResolvedValue(null),
    getLineage: vi
      .fn()
      .mockResolvedValue({ ok: true, data: lineageView(), proof: PROOF }),
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

    it("keeps an explicit empty lineage as a stamped root statement", async () => {
      const res = await ownerWrite("notes.entries", {
        note: "root",
        lineage: [],
      });
      expect(res.status).toBe(201);
      expect((await res.json()).lineage).toEqual({ sources: [] });
      const envelope = await (await ownerRead("notes.entries")).json();
      expect(envelope.data.$lineage.sources).toEqual([]);
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
    async function builderLineageRead(
      scope: string,
      options: { version?: string; signedUri?: string; query?: string } = {},
    ) {
      const uri = `/${scope}/lineage${options.version ? `/${options.version}` : ""}`;
      return app.request(`${uri}${options.query ?? ""}`, {
        headers: {
          Authorization: await buildWeb3SignedHeader({
            wallet: builderWallet,
            aud: SERVER_ORIGIN,
            method: "GET",
            uri: options.signedUri ?? uri,
            grantId: READ_GRANT_ID,
          }),
        },
      });
    }

    it("rejects ?version= with 400 INVALID_VERSION (version is a path segment)", async () => {
      const res = await builderLineageRead(DERIVED_SCOPE, {
        query: "?version=2",
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { error: { errorCode: string } };
      expect(body.error.errorCode).toBe("INVALID_VERSION");
      expect(lineageGateway.getLineage).not.toHaveBeenCalled();
    });

    it("rejects any other query string with 400 INVALID_QUERY (unsigned view inputs)", async () => {
      for (const query of [
        "?grantId=0x1234",
        "?foo=bar",
        "?includeDeleted=true",
      ]) {
        const res = await builderLineageRead(DERIVED_SCOPE, { query });
        expect(res.status).toBe(400);
        const body = (await res.json()) as { error: { errorCode: string } };
        expect(body.error.errorCode).toBe("INVALID_QUERY");
      }
      expect(lineageGateway.getLineage).not.toHaveBeenCalled();
    });

    it("returns the owner's full view straight from the gateway, attested", async () => {
      const res = await app.request(`/${DERIVED_SCOPE}/lineage`, {
        headers: {
          Authorization: await ownerHeader("GET", `/${DERIVED_SCOPE}/lineage`),
        },
      });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({
        data: lineageView(),
        proof: PROOF,
      });
      expect(lineageGateway.getLineage).toHaveBeenCalledWith({
        dataPointId: DERIVED_ID,
        version: undefined,
        grantId: undefined,
      });
    });

    it("a builder's redacted view carries no identifier besides the view's own data point", async () => {
      const redacted = lineageView({
        sources: [{ redacted: true }, { redacted: true }],
        derivatives: [{ redacted: true }],
      });
      (lineageGateway.getLineage as ReturnType<typeof vi.fn>).mockResolvedValue(
        { ok: true, data: redacted, proof: PROOF },
      );
      const res = await builderLineageRead(DERIVED_SCOPE);
      expect(res.status).toBe(200);
      const body = (await res.json()) as { data: Record<string, unknown> };
      const text = JSON.stringify({ ...body.data, dataPointId: undefined });
      // Nothing that looks like a data point id may survive redaction: a
      // grantee knows the owner, and ids are keccak256(owner, scope).
      expect(text.match(/0x[0-9a-fA-F]{64}/g) ?? []).toEqual([]);
      expect(body.data.sources).toEqual([
        { redacted: true },
        { redacted: true },
      ]);
    });

    it("asks the gateway for the builder's grant view under its read grant", async () => {
      const redacted = lineageView({
        sources: [{ redacted: true }],
      });
      (lineageGateway.getLineage as ReturnType<typeof vi.fn>).mockResolvedValue(
        {
          ok: true,
          data: redacted,
          proof: PROOF,
        },
      );
      const res = await builderLineageRead(DERIVED_SCOPE, { version: "1" });
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
      const bad = await app.request(`/${DERIVED_SCOPE}/lineage/0`, {
        headers: {
          Authorization: await ownerHeader(
            "GET",
            `/${DERIVED_SCOPE}/lineage/0`,
          ),
        },
      });
      expect(bad.status).toBe(400);
      const query = await app.request(`/${DERIVED_SCOPE}/lineage?version=1`, {
        headers: {
          Authorization: await ownerHeader("GET", `/${DERIVED_SCOPE}/lineage`),
        },
      });
      expect(query.status).toBe(400);
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

    it("maps a gateway transport failure to 502 LINEAGE_GATEWAY_ERROR", async () => {
      (lineageGateway.getLineage as ReturnType<typeof vi.fn>).mockRejectedValue(
        new TypeError("fetch failed"),
      );
      const res = await app.request(`/${DERIVED_SCOPE}/lineage`, {
        headers: {
          Authorization: await ownerHeader("GET", `/${DERIVED_SCOPE}/lineage`),
        },
      });
      expect(res.status).toBe(502);
      const body = await res.json();
      expect(body.error.errorCode).toBe("LINEAGE_GATEWAY_ERROR");
      expect(body.error.details.body.error).toBe("fetch failed");
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

    it("a builder's signature for one version cannot be replayed for another (version is in the signed path)", async () => {
      const res = await builderLineageRead(DERIVED_SCOPE, {
        version: "3",
        signedUri: `/${DERIVED_SCOPE}/lineage/2`,
      });
      expect(res.status).toBe(401);
      expect(lineageGateway.getLineage).not.toHaveBeenCalled();
      const ok = await builderLineageRead(DERIVED_SCOPE, { version: "2" });
      expect(ok.status).toBe(200);
      expect(lineageGateway.getLineage).toHaveBeenCalledWith({
        dataPointId: DERIVED_ID,
        version: "2",
        grantId: READ_GRANT_ID,
      });
    });
  });

  describe("DELETE /v1/data/:scope?cascade=lineage", () => {
    async function ownerDelete(scope: string, query = "") {
      return app.request(`/${scope}${query}`, {
        method: "DELETE",
        headers: { Authorization: await ownerHeader("DELETE", `/${scope}`) },
      });
    }

    it("is a specified 501 stub until the lineage walk is implemented", async () => {
      await seedSource(SOURCE_SCOPE);
      const res = await ownerDelete(SOURCE_SCOPE, "?cascade=lineage");
      expect(res.status).toBe(501);
      const body = await res.json();
      expect(body.error.errorCode).toBe("LINEAGE_CASCADE_UNAVAILABLE");
      // Nothing was walked or deleted.
      expect(lineageGateway.getLineage).not.toHaveBeenCalled();
      expect((await ownerRead(SOURCE_SCOPE)).status).toBe(200);
    });

    it("rejects an unknown cascade mode with 400 and keeps the default single-node durable delete", async () => {
      await seedSource(SOURCE_SCOPE);
      const bad = await ownerDelete(SOURCE_SCOPE, "?cascade=all");
      expect(bad.status).toBe(400);
      expect((await bad.json()).error.errorCode).toBe("INVALID_CASCADE");
      const res = await ownerDelete(SOURCE_SCOPE);
      // The single-node delete answers with its per-step result.
      expect(res.status).toBe(200);
      expect(await res.json()).toMatchObject({
        scope: SOURCE_SCOPE,
        steps: { local: { status: "ok" } },
      });
      expect((await ownerRead(SOURCE_SCOPE)).status).toBe(404);
    });

    it("is owner-only", async () => {
      const res = await app.request(`/${SOURCE_SCOPE}?cascade=lineage`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${SESSION_TOKEN}` },
      });
      expect(res.status).toBe(401);
    });
  });

  describe("grantee read redaction of server-stamped keys", () => {
    async function builderRecordRead(
      scope: string,
      options: { grantId?: string; query?: string } = {},
    ) {
      const uri = `/${scope}`;
      return app.request(`${uri}${options.query ?? ""}`, {
        headers: {
          Authorization: await buildWeb3SignedHeader({
            wallet: builderWallet,
            aud: SERVER_ORIGIN,
            method: "GET",
            uri,
            grantId: options.grantId ?? READ_GRANT_ID,
          }),
        },
      });
    }

    async function writeBinaryDerivative() {
      const bytes = new TextEncoder().encode("%PDF-1.7 report");
      const representation = {
        contentType: "application/pdf",
        filename: "report.pdf",
        metadataHeader: JSON.stringify({
          description: "Quarterly",
          lineage: [SOURCE_ID],
        }),
      };
      const res = await app.request(`/${REPORT_SCOPE}`, {
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
            uri: `/${REPORT_SCOPE}`,
            body: await binaryWriteSignedBytes({ bytes, ...representation }),
            grantId: WRITE_GRANT_ID,
          }),
        },
        body: bytes,
      });
      expect(res.status).toBe(201);
    }

    it("serves a grantee read without $writtenBy, $lineage, or the consumed lineage field", async () => {
      await seedSource();
      const write = await sessionWrite(DERIVED_SCOPE, {
        summary: "seven hours",
        lineage: [SOURCE_ID],
      });
      expect(write.status).toBe(201);

      const res = await builderRecordRead(DERIVED_SCOPE);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.summary).toBe("seven hours");
      expect(body.data.$writtenBy).toBeUndefined();
      expect(body.data.$lineage).toBeUndefined();
      expect(body.data.lineage).toBeUndefined();
    });

    it("keeps the server-stamped keys on the owner's read", async () => {
      await seedSource();
      await sessionWrite(DERIVED_SCOPE, {
        summary: "seven hours",
        lineage: [SOURCE_ID],
      });
      const envelope = await (await ownerRead(DERIVED_SCOPE)).json();
      expect(envelope.data.$writtenBy.builder).toBe(builderWallet.address);
      expect(envelope.data.$lineage.sources).toEqual([SOURCE_ID]);
      expect(envelope.data.lineage).toEqual([SOURCE_ID]);
    });

    it("redacts a binary derivative's stamped keys and metadata lineage on a grantee JSON read", async () => {
      await seedSource();
      await writeBinaryDerivative();

      const res = await builderRecordRead(REPORT_SCOPE, {
        grantId: READ_REPORT_GRANT_ID,
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.$binary).toBe(true);
      expect(body.data.metadata).toEqual({ description: "Quarterly" });
      expect(body.data.$writtenBy).toBeUndefined();
      expect(body.data.$lineage).toBeUndefined();
    });

    it("omits the consumed metadata lineage from a grantee raw read's X-Vana-Metadata", async () => {
      await seedSource();
      await writeBinaryDerivative();

      const res = await builderRecordRead(REPORT_SCOPE, {
        grantId: READ_REPORT_GRANT_ID,
        query: "?content=raw",
      });
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toBe("application/pdf");
      const metadata = JSON.parse(res.headers.get("X-Vana-Metadata") ?? "{}");
      expect(metadata).toEqual({ description: "Quarterly" });
    });
  });

  describe("lineage read access logging", () => {
    it("logs a builder lineage read with the resolved grant", async () => {
      const res = await app.request(`/${DERIVED_SCOPE}/lineage`, {
        headers: {
          Authorization: await buildWeb3SignedHeader({
            wallet: builderWallet,
            aud: SERVER_ORIGIN,
            method: "GET",
            uri: `/${DERIVED_SCOPE}/lineage`,
            grantId: READ_GRANT_ID,
          }),
        },
      });
      expect(res.status).toBe(200);
      expect(accessLogWriter.write).toHaveBeenCalledWith(
        expect.objectContaining({
          action: "lineage",
          scope: DERIVED_SCOPE,
          grantId: READ_GRANT_ID,
          builder: builderWallet.address,
        }),
      );
    });

    it("logs an owner lineage read under the owner sentinel", async () => {
      const res = await app.request(`/${DERIVED_SCOPE}/lineage`, {
        headers: {
          Authorization: await ownerHeader("GET", `/${DERIVED_SCOPE}/lineage`),
        },
      });
      expect(res.status).toBe(200);
      expect(accessLogWriter.write).toHaveBeenCalledWith(
        expect.objectContaining({
          action: "lineage",
          scope: DERIVED_SCOPE,
          grantId: "owner",
        }),
      );
    });

    it("does not log a refused lineage read", async () => {
      (lineageGateway.getLineage as ReturnType<typeof vi.fn>).mockResolvedValue(
        { ok: false, status: 403, body: { error: "forbidden" } },
      );
      const res = await app.request(`/${DERIVED_SCOPE}/lineage`, {
        headers: {
          Authorization: await ownerHeader("GET", `/${DERIVED_SCOPE}/lineage`),
        },
      });
      expect(res.status).toBe(403);
      expect(accessLogWriter.write).not.toHaveBeenCalledWith(
        expect.objectContaining({ action: "lineage" }),
      );
    });
  });
});
