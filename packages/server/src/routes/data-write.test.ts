/**
 * Delegated (Write API) ingest through the data routes: a write-session
 * bearer token + a builder-signed attribution proof drive the EXISTING
 * POST /v1/data/:scope path, and the record lands with `$writtenBy` stamped.
 * Read-back separation: the write-grant never satisfies a builder read.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { pino } from "pino";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import type { HierarchyManagerOptions } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type { GatewayClient, Builder } from "@opendatalabs/vana-sdk/node";
import type { GatewayGrantResponse } from "@opendatalabs/vana-sdk/node";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  WRITE_SIGNATURE_HEADER,
  WRITER_ATTRIBUTION_KEY,
  createInMemoryWriteSessionStore,
  hashWriteSessionToken,
  verifyStoredWriterAttribution,
  type WriteSessionStore,
} from "@opendatalabs/personal-server-ts-core/write";
import { dataRoutes } from "./data.js";

const SERVER_ORIGIN = "http://localhost:8080";
const builderWallet = createTestWallet(0);
const ownerWallet = createTestWallet(9);

const BUILDER_ID = "0xbuilder1";
const SESSION_TOKEN = "vana_write_test_token";
const WRITE_GRANT_ID = "grant-w-1";
const SCOPE = "notes.entries";

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
    scopes: [`write:${SCOPE}`],
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

const logger = pino({ level: "silent" });

async function seedSession(store: WriteSessionStore): Promise<void> {
  await store.create({
    tokenHash: await hashWriteSessionToken(SESSION_TOKEN),
    builderAddress: builderWallet.address,
    grantId: WRITE_GRANT_ID,
    writeScopes: [SCOPE],
    createdAt: new Date().toISOString(),
    expiresAtMs: Date.now() + 60_000,
  });
}

async function sessionWrite(
  app: ReturnType<typeof dataRoutes>,
  scope: string,
  body: unknown,
  options: {
    signatureWallet?: typeof builderWallet;
    omitSignature?: boolean;
    token?: string;
    /** Exact bytes to send (and sign) instead of JSON.stringify(body). */
    rawBody?: string;
  } = {},
) {
  const rawBody = options.rawBody ?? JSON.stringify(body);
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${options.token ?? SESSION_TOKEN}`,
  };
  if (!options.omitSignature) {
    headers[WRITE_SIGNATURE_HEADER] = await buildWeb3SignedHeader({
      wallet: options.signatureWallet ?? builderWallet,
      aud: SERVER_ORIGIN,
      method: "POST",
      uri: `/${scope}`,
      body: new TextEncoder().encode(rawBody),
    });
  }
  return app.request(`/${scope}`, {
    method: "POST",
    headers,
    body: rawBody,
  });
}

describe("POST /v1/data/:scope with a write session", () => {
  let dataDir: string;
  let hierarchyOptions: HierarchyManagerOptions;
  let app: ReturnType<typeof dataRoutes>;
  let cleanup: () => void;
  let writeSessionStore: WriteSessionStore;
  let accessLogWriter: AccessLogWriter;
  let gateway: GatewayClient;

  beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), "data-write-route-test-"));
    hierarchyOptions = { dataDir };

    const db = initializeDatabase(":memory:");
    const indexManager = createIndexManager(db);

    writeSessionStore = createInMemoryWriteSessionStore();
    await seedSession(writeSessionStore);
    accessLogWriter = { write: vi.fn().mockResolvedValue(undefined) };
    gateway = createMockGateway({
      getGrant: vi.fn().mockResolvedValue(makeGrant()),
    });

    app = dataRoutes({
      indexManager,
      hierarchyOptions,
      logger,
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway,
      accessLogWriter,
      writeSessionStore,
    });
    cleanup = () => {
      indexManager.close();
    };
  });

  afterEach(async () => {
    cleanup();
    await rm(dataDir, { recursive: true, force: true });
  });

  async function ownerRead(scope: string) {
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "GET",
      uri: `/${scope}`,
    });
    return app.request(`/${scope}`, { headers: { Authorization: auth } });
  }

  it("accepts a session write and stores the record with builder attribution", async () => {
    const res = await sessionWrite(app, SCOPE, { note: "written by builder" });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.scope).toBe(SCOPE);
    expect(body.status).toBe("stored");

    // Read back as owner: payload intact + $writtenBy stamped.
    const read = await ownerRead(SCOPE);
    expect(read.status).toBe(200);
    const envelope = await read.json();
    expect(envelope.data.note).toBe("written by builder");
    const attribution = envelope.data[WRITER_ATTRIBUTION_KEY];
    expect(attribution.builder).toBe(builderWallet.address);
    expect(attribution.grantId).toBe(WRITE_GRANT_ID);
    expect(attribution.signature).toContain(".");
    expect(attribution.bodyHash).toMatch(/^sha256:/);
    // The attribution is verifiable from the read-back record alone: the
    // stored data re-hashes to the signed bodyHash and the proof recovers to
    // the builder.
    const verified = await verifyStoredWriterAttribution(envelope.data);
    expect(verified.builder.toLowerCase()).toBe(
      builderWallet.address.toLowerCase(),
    );
    expect(verified.grantId).toBe(WRITE_GRANT_ID);

    // The write landed in the access log under the grant.
    expect(accessLogWriter.write).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "write",
        builder: builderWallet.address,
        grantId: WRITE_GRANT_ID,
        scope: SCOPE,
      }),
    );
  });

  it("rejects a non-compact JSON body whose attribution could not be verified after read-back", async () => {
    const res = await sessionWrite(app, SCOPE, null, {
      rawBody: JSON.stringify({ note: "pretty" }, null, 2),
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error.errorCode).toBe("WRITE_BODY_NOT_CANONICAL");
    // Nothing was stored.
    const read = await ownerRead(SCOPE);
    expect(read.status).toBe(404);
  });

  it("an access-log failure after the record is committed does not fail the write", async () => {
    (accessLogWriter.write as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("access log unavailable"),
    );
    const res = await sessionWrite(app, SCOPE, { note: "still stored" });
    // The record is committed before logging; a 500 here would make the
    // builder retry and store a duplicate.
    expect(res.status).toBe(201);
    const read = await ownerRead(SCOPE);
    expect(read.status).toBe(200);
    const envelope = await read.json();
    expect(envelope.data.note).toBe("still stored");
    expect(envelope.data[WRITER_ATTRIBUTION_KEY].builder).toBe(
      builderWallet.address,
    );
  });

  it("rejects a session write without the attribution proof", async () => {
    const res = await sessionWrite(
      app,
      SCOPE,
      { note: "x" },
      {
        omitSignature: true,
      },
    );
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error.errorCode).toBe("WRITE_ATTRIBUTION_REQUIRED");
  });

  it("rejects an attribution proof signed by a different key", async () => {
    const res = await sessionWrite(
      app,
      SCOPE,
      { note: "x" },
      {
        signatureWallet: createTestWallet(5),
      },
    );
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error.errorCode).toBe("WRITE_ATTRIBUTION_SIGNER_MISMATCH");
  });

  it("rejects a session write to a scope the grant does not cover", async () => {
    const res = await sessionWrite(app, "other.scope", { note: "x" });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error.errorCode).toBe("SCOPE_MISMATCH");
  });

  it("re-checks the live grant per write: a revoked grant is rejected even with a live token", async () => {
    (gateway.getGrant as ReturnType<typeof vi.fn>).mockResolvedValue(
      makeGrant({ revokedAt: "2026-08-20T00:00:00.000Z" }),
    );
    const res = await sessionWrite(app, SCOPE, { note: "x" });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error.errorCode).toBe("GRANT_REVOKED");
  });

  it("rejects a payload that carries the reserved $writtenBy key", async () => {
    const res = await sessionWrite(app, SCOPE, {
      note: "x",
      [WRITER_ATTRIBUTION_KEY]: { builder: "0xforged" },
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("INVALID_BODY");
  });

  it("falls through to owner auth for an unknown bearer token", async () => {
    const res = await sessionWrite(
      app,
      SCOPE,
      { note: "x" },
      {
        token: "not-a-session-token",
      },
    );
    expect(res.status).toBe(401);
  });

  it("owner writes remain unchanged: no attribution is stamped", async () => {
    const rawBody = JSON.stringify({ note: "owner write" });
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "POST",
      uri: `/${SCOPE}`,
      body: new TextEncoder().encode(rawBody),
    });
    const res = await app.request(`/${SCOPE}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: auth },
      body: rawBody,
    });
    expect(res.status).toBe(201);

    const read = await ownerRead(SCOPE);
    const envelope = await read.json();
    expect(envelope.data.note).toBe("owner write");
    expect(envelope.data[WRITER_ATTRIBUTION_KEY]).toBeUndefined();
  });

  it("a write-grant never satisfies a builder READ of the same scope", async () => {
    // Land a record first (via the session write).
    const write = await sessionWrite(app, SCOPE, { note: "secret" });
    expect(write.status).toBe(201);

    // Builder read authorized by the WRITE grant must fail scope coverage.
    const auth = await buildWeb3SignedHeader({
      wallet: builderWallet,
      aud: SERVER_ORIGIN,
      method: "GET",
      uri: `/${SCOPE}`,
      grantId: WRITE_GRANT_ID,
    });
    const res = await app.request(`/${SCOPE}`, {
      headers: { Authorization: auth },
    });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error.errorCode).toBe("SCOPE_MISMATCH");
  });

  it("a separate read-grant on the same scope authorizes the read-back", async () => {
    const write = await sessionWrite(app, SCOPE, { note: "readable" });
    expect(write.status).toBe(201);

    const READ_GRANT_ID = "grant-r-1";
    (gateway.getGrant as ReturnType<typeof vi.fn>).mockImplementation(
      async (id: string) =>
        id === READ_GRANT_ID
          ? makeGrant({ id: READ_GRANT_ID, scopes: [SCOPE] })
          : makeGrant(),
    );

    const auth = await buildWeb3SignedHeader({
      wallet: builderWallet,
      aud: SERVER_ORIGIN,
      method: "GET",
      uri: `/${SCOPE}`,
      grantId: READ_GRANT_ID,
    });
    const res = await app.request(`/${SCOPE}`, {
      headers: { Authorization: auth },
    });
    expect(res.status).toBe(200);
    const envelope = await res.json();
    expect(envelope.data.note).toBe("readable");
    // Attribution rides along on the read — verifiable by the reader.
    expect(envelope.data[WRITER_ATTRIBUTION_KEY].builder).toBe(
      builderWallet.address,
    );
  });

  it("rejects an expired session token", async () => {
    const expired = "vana_write_expired_token";
    await writeSessionStore.create({
      tokenHash: await hashWriteSessionToken(expired),
      builderAddress: builderWallet.address,
      grantId: WRITE_GRANT_ID,
      writeScopes: [SCOPE],
      createdAt: new Date().toISOString(),
      expiresAtMs: Date.now() - 1,
    });
    const res = await sessionWrite(
      app,
      SCOPE,
      { note: "x" },
      {
        token: expired,
      },
    );
    // Expired session is unknown to the store -> owner fall-through -> 401.
    expect(res.status).toBe(401);
  });
});
