import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import pino from "pino";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  Builder,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { buildDataBlocksAsync } from "@opendatalabs/personal-server-ts-core/storage/blocks";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { initializeDatabase } from "./storage/index-schema.js";
import { createIndexManager } from "./storage/index-manager.js";
import { createNodeDataStorage } from "./storage/node-data-storage.js";
import {
  computeQuestion,
  createFakeInferenceProvider,
  createInMemoryQuestionStore,
  type QuestionRegistration,
} from "@opendatalabs/personal-server-ts-core/derivatives";
import { dataRoutes } from "./routes/data.js";

const logger = pino({ level: "silent" });
const ORIGIN = "http://localhost:8080";
const owner = createTestWallet(0);
const builder = createTestWallet(5);
const GRANT_ID = "grant-probe";
const DERIVED = "coach.weekly";

/**
 * An owner-registered derivative reads its sources as the owner, so an answer
 * computed from PDPP data must carry PDPP origin. Otherwise a legacy chain
 * grant that covers the derived scope reads PDPP data past the disclosure
 * policy. Real Node storage, real compute, real GET /v1/data route.
 */
const SECRET = "pdpp-only-score-99";
const AT = "2026-09-01T00:00:00.000Z";

function sourceEnvelope(scope: string, native: boolean): DataFileEnvelope {
  return {
    version: "1.0",
    scope,
    collectedAt: AT,
    data: native
      ? {
          id: "a1",
          score: SECRET,
          $pdpp: { version: 1, sourceId: "https://registry.pdpp.dev/oura" },
        }
      : { id: "legacy-row", score: "legacy-score-7" },
  } as DataFileEnvelope;
}

let dataDir: string;
let indexManager: IndexManager;
let storage: DataStoragePort;

function gatewayFor(granteeAddress: `0x${string}`): GatewayClient {
  const grant = {
    id: GRANT_ID,
    grantorAddress: owner.address,
    granteeId: granteeAddress,
    scopes: ["coach.*"],
    status: "confirmed",
    addedAt: "2026-01-21T10:00:00.000Z",
    expiresAt: null,
    expired: false,
    revokedAt: null,
    paymentStatus: "paid",
    grantVersion: "1",
  } as unknown as GatewayGrantResponse;
  const registered: Builder = {
    id: granteeAddress,
    ownerAddress: owner.address,
    granteeAddress,
    publicKey: "0x04",
    appUrl: "https://app.test",
    addedAt: "2026-01-21T10:00:00.000Z",
  };
  return {
    isRegisteredBuilder: vi.fn().mockResolvedValue(true),
    getBuilder: vi.fn().mockResolvedValue(registered),
    getGrant: vi.fn().mockResolvedValue(grant),
    listGrantsByUser: vi.fn().mockResolvedValue([]),
    getSchemaForScope: vi.fn().mockResolvedValue(null),
    getServer: vi.fn().mockResolvedValue(null),
    getDataPoint: vi.fn().mockResolvedValue(null),
    listDataPointsByOwner: vi
      .fn()
      .mockResolvedValue({ dataPoints: [], cursor: null }),
    getSchema: vi.fn().mockResolvedValue(null),
    registerServer: vi.fn().mockResolvedValue({ alreadyRegistered: false }),
    registerDataPoint: vi.fn().mockResolvedValue({ dataPointId: "0xdp" }),
    createGrant: vi.fn().mockResolvedValue({ grantId: GRANT_ID }),
    revokeGrant: vi.fn().mockResolvedValue(undefined),
  } as unknown as GatewayClient;
}

async function put(envelope: DataFileEnvelope) {
  const written = await storage.writeEnvelope(envelope);
  const built = await buildDataBlocksAsync({
    scope: envelope.scope,
    collectedAt: envelope.collectedAt,
    content: envelope,
  });
  await storage.writeBlockManifest?.(
    envelope.scope,
    envelope.collectedAt,
    built.manifest,
    built.blocks,
  );
  return storage.insertEntry({
    fileId: null,
    path: written.relativePath,
    scope: envelope.scope,
    collectedAt: envelope.collectedAt,
    sizeBytes: written.sizeBytes,
  });
}

function registration(sourceScopes: string[]): QuestionRegistration {
  return {
    questionId: "q-1",
    derivedScope: DERIVED,
    sourceScopes,
    question: "How did I sleep?",
    model: null,
    answerShape: null,
    recompute: "on-change",
    registeredBy: { kind: "owner" },
    status: "pending",
    error: null,
    errorCode: null,
    createdAt: "2026-08-27T00:00:00.000Z",
    updatedAt: "2026-08-27T00:00:00.000Z",
    lastComputedAt: null,
    derivedVersion: null,
    derivedCollectedAt: null,
  };
}

async function computeOwnerDerivative(sourceScopes: string[]) {
  const outcome = await computeQuestion("q-1", {
    storage,
    store: createInMemoryQuestionStore({
      initial: [registration(sourceScopes)],
    }),
    provider: createFakeInferenceProvider({
      respond: () => ({
        content: JSON.stringify({
          answer: "sources said: " + SECRET + " legacy-score-7",
          evidence: null,
        }),
      }),
    }),
    serverOwner: owner.address,
    now: () => new Date("2026-09-02T00:00:00.000Z"),
    retryDelaysMs: [0, 0],
  });
  expect(outcome.status, JSON.stringify(outcome)).toBe("ready");
}

beforeEach(async () => {
  dataDir = await mkdtemp(join(tmpdir(), "derivative-origin-"));
  indexManager = createIndexManager(initializeDatabase(":memory:"));
  storage = createNodeDataStorage({
    indexManager,
    hierarchyOptions: { dataDir },
  });
});

afterEach(async () => {
  indexManager.close();
  await rm(dataDir, { recursive: true, force: true });
});

function app() {
  return dataRoutes({
    indexManager,
    hierarchyOptions: { dataDir },
    logger,
    serverOrigin: ORIGIN,
    serverOwner: owner.address,
    gateway: gatewayFor(builder.address),
    accessLogWriter: { write: async () => undefined },
  });
}

async function signedGet(
  wallet: ReturnType<typeof createTestWallet>,
  path: string,
) {
  return app().request(path, {
    headers: {
      Authorization: await buildWeb3SignedHeader({
        wallet,
        aud: ORIGIN,
        method: "GET",
        uri: path,
        ...(wallet === owner ? {} : { grantId: GRANT_ID }),
      }),
    },
  });
}

describe("derivative output carries the origin of its sources", () => {
  it("a derivative over a PDPP source is refused to a chain grant and read by the owner", async () => {
    await put(sourceEnvelope("oura.sleep", true));
    await computeOwnerDerivative(["oura.sleep"]);

    const chain = await signedGet(builder, `/${DERIVED}`);
    const chainText = await chain.text();
    expect(chain.status, chainText).toBe(403);
    expect(chainText).toContain("GRANT_REQUIRED");
    expect(chainText).not.toContain(SECRET);

    const owned = await signedGet(owner, `/${DERIVED}`);
    const ownedText = await owned.text();
    expect(owned.status, ownedText).toBe(200);
    expect(ownedText).toContain(SECRET);

    expect(storage.findEntry({ scope: DERIVED })).toMatchObject({
      producer: "pdpp-derivative",
      pdppOrigin: true,
    });
  });

  it("a derivative over a mix of PDPP and legacy sources is refused", async () => {
    await put(sourceEnvelope("oura.sleep", true));
    await put(sourceEnvelope("oura.legacy", false));
    await computeOwnerDerivative(["oura.legacy", "oura.sleep"]);
    const chain = await signedGet(builder, `/${DERIVED}`);
    expect(chain.status, await chain.text()).toBe(403);
  });

  it("a derivative over legacy-only sources stays readable by the chain grant", async () => {
    await put(sourceEnvelope("oura.legacy", false));
    await computeOwnerDerivative(["oura.legacy"]);

    const chain = await signedGet(builder, `/${DERIVED}`);
    const text = await chain.text();
    expect(chain.status, text).toBe(200);
    expect(text).toContain("legacy-score-7");
    expect(storage.findEntry({ scope: DERIVED })).toMatchObject({
      producer: null,
      pdppOrigin: false,
    });
  });

  it("a request cannot assert the server-only pdpp-derivative producer", async () => {
    const raw = JSON.stringify({ id: "x" });
    const res = await app().request(`/${DERIVED}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Vana-Producer": "pdpp-derivative",
        Authorization: await buildWeb3SignedHeader({
          wallet: owner,
          aud: ORIGIN,
          method: "POST",
          uri: `/${DERIVED}`,
          body: new TextEncoder().encode(raw),
        }),
      },
      body: raw,
    });
    expect(res.status).toBe(400);
  });
});
