import { afterEach, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pino from "pino";
import { createApp } from "../app.js";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import { createNodeDataStorage } from "../storage/node-data-storage.js";
import { createLegacyPublicationPolicy } from "../storage/legacy-publication-policy.js";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  withLegacyGatewayFence,
  withLegacySignerFence,
} from "../storage/legacy-publication-issuance.js";
import type { ServerSigner } from "@opendatalabs/personal-server-ts-core/signing";

const owner = createTestWallet(0);
const outsider = createTestWallet(1);
const cleanups: (() => void)[] = [];
afterEach(() => {
  for (const cleanup of cleanups.splice(0).reverse()) cleanup();
});
function fixture(enabled = false) {
  const root = mkdtempSync(join(tmpdir(), "legacy-policy-http-"));
  cleanups.push(() => rmSync(root, { recursive: true, force: true }));
  const db = initializeDatabase(join(root, "index.db"));
  cleanups.push(() => db.close());
  const index = createIndexManager(db);
  const hierarchyOptions = { dataDir: join(root, "data") };
  const storage = createNodeDataStorage({
    indexManager: index,
    hierarchyOptions,
  });
  const policy = createLegacyPublicationPolicy(db, {
    owner: owner.address,
    serverGeneration: "server-1",
    enabled: () => enabled,
  });
  const rawGateway = {
    getBuilder: vi.fn(async () => ({
      id: `0x${"1".repeat(64)}`,
      granteeAddress: outsider.address,
    })),
    getGrant: vi.fn(async () => null),
    getServer: vi.fn(async () => null),
    getSchemaForScope: vi.fn(async () => null),
    createGrant: vi.fn(async () => ({ grantId: "grant-1" })),
    registerDataPoint: vi.fn(async () => ({ dataPointId: "data-1" })),
  } as unknown as GatewayClient;
  const rawSigner = {
    signGrantRegistration: vi.fn(async () => "0xsigned"),
    signAddData: vi.fn(async () => "0xpublication"),
  } as unknown as ServerSigner;
  const gateway = withLegacyGatewayFence(db, rawGateway);
  const signer = withLegacySignerFence(db, rawSigner);
  const app = createApp({
    logger: pino({ level: "silent" }),
    version: "test",
    startedAt: new Date(),
    indexManager: index,
    hierarchyOptions,
    dataStorage: storage,
    serverOrigin: "http://localhost:8080",
    serverOwner: owner.address,
    gateway,
    serverSigner: signer,
    legacyPublicationPolicy: policy,
    accessLogWriter: { write: vi.fn(async () => undefined) },
    accessLogReader: {
      read: vi.fn(async () => ({ logs: [], total: 0, limit: 50, offset: 0 })),
    },
    accessToken: "owner-test-token",
  });
  return {
    app,
    db,
    index,
    policy,
    storage,
    gateway,
    signer,
    rawGateway,
    rawSigner,
  };
}
const auth = { Authorization: "Bearer owner-test-token" };

it("owner read and default-off transition retain the normal error shape and CORS", async () => {
  expect(ServerConfigSchema.parse({}).legacyWriteShutdownEnabled).toBe(false);
  const { app } = fixture();
  const path = "/v1/legacy-publication-policy/spotify.profile";
  const read = await app.request(path, {
    headers: { ...auth, Origin: "https://desktop.example" },
  });
  expect(read.status).toBe(200);
  expect(read.headers.get("Access-Control-Allow-Origin")).toBe("*");
  expect(await read.json()).toMatchObject({
    policy: { state: "mirroring", epoch: 0 },
    capabilities: {
      shutdown: false,
      nativeCanonicalCoverage: false,
      rollback: false,
      missing: expect.arrayContaining([
        "authoritative_inventory_and_global_issuance_fence",
        "qualified_canonical_retention_and_recovery",
        "native_canonical_coverage",
      ]),
    },
    canonical: null,
  });
  const preflight = await app.request(`${path}/stop`, {
    method: "OPTIONS",
    headers: {
      Origin: "https://desktop.example",
      "Access-Control-Request-Method": "POST",
      "Access-Control-Request-Headers": "authorization,content-type",
    },
  });
  expect(preflight.status).toBe(204);
  expect(preflight.headers.get("Access-Control-Allow-Origin")).toBe("*");
  const stopped = await app.request(`${path}/stop`, {
    method: "POST",
    headers: { ...auth, "Content-Type": "application/json" },
    body: JSON.stringify({ expectedEpoch: 0, ownerOptIn: true }),
  });
  expect(stopped.status).toBe(409);
  expect(await stopped.json()).toMatchObject({
    error: { code: 409, errorCode: "LEGACY_SHUTDOWN_DISABLED" },
  });
  expect((await app.request(path)).status).toBe(401);
  const url = `http://localhost:8080${path}`;
  const authorization = await buildWeb3SignedHeader({
    wallet: outsider,
    aud: "http://localhost:8080",
    method: "GET",
    uri: path,
  });
  const foreign = await app.request(url, { headers: { authorization } });
  expect(foreign.status).toBe(401);
  expect(await foreign.json()).toMatchObject({
    error: { errorCode: "NOT_OWNER" },
  });
});

it("missing runtime authority refuses stop and rejects caller-supplied proofs", async () => {
  const { app, policy } = fixture(true);
  const path = "/v1/legacy-publication-policy/spotify.profile/stop";
  const request = (body: unknown) =>
    app.request(path, {
      method: "POST",
      headers: { ...auth, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  expect(
    (await request({ expectedEpoch: 0, ownerOptIn: true, evidence: {} }))
      .status,
  ).toBe(400);
  const result = await request({ expectedEpoch: 0, ownerOptIn: true });
  expect(result.status).toBe(503);
  expect(await result.json()).toMatchObject({
    error: { errorCode: "LEGACY_SHUTDOWN_UNAVAILABLE" },
  });
  expect(policy.read("spotify.profile").state).toBe("mirroring");
});

it("default-off preserves fresh HTTP writes, import replay, signatures and registration", async () => {
  const { app, storage, index, signer, gateway, rawSigner, rawGateway } =
    fixture();
  const path = "/v1/data/spotify.profile";
  const send = (url = path, method = "POST") =>
    app.request(url, {
      method,
      headers: { ...auth, "Content-Type": "application/json" },
      body: JSON.stringify({ name: "owner" }),
    });
  expect((await send()).status).toBe(201);
  const first = index.findLatestByScope("spotify.profile")!;
  expect((await send()).status).toBe(201);
  const second = index.findLatestByScope("spotify.profile")!;
  expect(second.version).toBeGreaterThan(first.version);
  expect(Date.parse(second.collectedAt)).toBeGreaterThan(
    Date.parse(first.collectedAt),
  );
  const operation = "a".repeat(64);
  expect((await send(`${path}/imports/${operation}`, "PUT")).status).toBe(201);
  expect((await send(`${path}/imports/${operation}`, "PUT")).status).toBe(200);
  expect(storage.countVersions("spotify.profile")).toBe(3);
  const message = {
    grantorAddress: owner.address,
    granteeId: `0x${"1".repeat(64)}` as `0x${string}`,
    scopes: ["spotify.profile"],
    grantVersion: 1n,
    expiresAt: 0n,
  };
  expect(await signer.signGrantRegistration(message)).toBe("0xsigned");
  expect(rawSigner.signGrantRegistration).toHaveBeenCalledWith(message);
  const grant = {
    ...message,
    grantVersion: "1",
    expiresAt: "0",
    signature: "0xsigned" as `0x${string}`,
  };
  await gateway.createGrant(grant);
  expect(rawGateway.createGrant).toHaveBeenCalledWith(grant);
});

it("stopped gate refuses every legacy HTTP write and cleanup without deleting history", async () => {
  const { app, db, storage, index } = fixture();
  const path = "/v1/data/spotify.profile";
  const headers = { ...auth, "Content-Type": "application/json" };
  expect(
    (await app.request(path, { method: "POST", headers, body: '{"old":true}' }))
      .status,
  ).toBe(201);
  const old = index.findLatestByScope("spotify.profile")!;
  const bytes = await storage.readEnvelopeBytes!(old.scope, old.collectedAt);
  db.prepare(
    "INSERT INTO legacy_publication_policy VALUES (?, 'server-1', 'spotify.profile', 'stopped', 2, 1, NULL)",
  ).run(owner.address.toLowerCase());
  db.prepare(
    "INSERT INTO legacy_publication_retained_versions SELECT id FROM data_files",
  ).run();
  for (const url of [
    path,
    `${path}?supersede=legacy`,
    `${path}/imports/${"b".repeat(64)}`,
  ]) {
    const response = await app.request(url, {
      method: url.includes("/imports/") ? "PUT" : "POST",
      headers,
      body: '{"new":true}',
    });
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({
      error: { errorCode: "legacy_scope_retired" },
    });
  }
  await expect(storage.deleteScope("spotify.profile")).rejects.toMatchObject({
    errorCode: "legacy_history_retained",
  });
  expect(storage.countVersions("spotify.profile")).toBe(1);
  expect(await storage.readEnvelopeBytes!(old.scope, old.collectedAt)).toEqual(
    bytes,
  );
});

it("fences alternate storage and remote upload/cleanup paths before effects", async () => {
  const { db, storage, index } = fixture();
  const { createDataFileEnvelope } =
    await import("@opendatalabs/vana-sdk/node");
  const { withLegacyStorageFence, withLegacyDeletionFence } =
    await import("../storage/legacy-publication-issuance.js");
  const envelope = createDataFileEnvelope(
    "spotify.profile",
    "2026-10-24T00:00:00Z",
    { id: "new" },
  );
  const entry = {
    scope: envelope.scope,
    collectedAt: envelope.collectedAt,
    fileId: null,
    path: "new.json",
    sizeBytes: 12,
  };
  db.prepare(
    "INSERT INTO legacy_publication_policy VALUES (?, 'server-1', 'spotify.profile', 'stopped', 2, 1, NULL)",
  ).run(owner.address.toLowerCase());
  for (const run of [
    () => storage.writeEnvelope(envelope),
    () => storage.commitEnvelope!(envelope, entry),
    () => storage.commitVersion!({ kind: "append", envelope, metadata: {} }),
    () =>
      storage.commitVersion!({
        kind: "replica",
        envelope,
        metadata: { schemaId: null, dataPointId: "replica", version: 1 },
      }),
    () => storage.insertEntry(entry),
  ])
    await expect(run()).rejects.toMatchObject({
      errorCode: "legacy_scope_retired",
    });
  expect(() => index.insertRecovered(entry)).toThrow(
    expect.objectContaining({ errorCode: "legacy_scope_retired" }),
  );
  const upload = vi.fn(async () => "remote-url");
  const remote = withLegacyStorageFence(db, owner.address, { upload } as any);
  await expect(
    remote.upload("spotify.profile/1", new Uint8Array([1])),
  ).rejects.toMatchObject({ errorCode: "legacy_scope_retired" });
  expect(upload).not.toHaveBeenCalled();
  const remove = vi.fn();
  const deletion = withLegacyDeletionFence(db, {
    tombstone: remove,
    deleteBlobVersions: remove,
  });
  await expect(
    deletion.deleteBlobVersions("spotify.profile", ["1"]),
  ).rejects.toMatchObject({ errorCode: "legacy_scope_retired" });
  expect(remove).not.toHaveBeenCalled();
  expect(index.countByScope("spotify.profile")).toBe(0);
});
