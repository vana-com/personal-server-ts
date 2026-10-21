/** Deterministic factory integration; no live grants or network mutations. */
import { afterEach, expect, it, vi } from "vitest";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import pino from "pino";
import { privateKeyToAccount } from "viem/accounts";
import { recoverTypedDataAddress } from "viem";
import {
  createGatewayClient,
  GRANT_REGISTRATION_TYPES,
  grantRegistrationDomain,
} from "@opendatalabs/vana-sdk/node";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { createServerSigner } from "../packages/core/src/signing/signer.js";
import { createAccessLogWriter } from "../packages/server/src/logging/access-log.js";
import {
  createReplicaOwnerLegacyRoutes,
  openReplicaOwnerLegacyStorage,
} from "./pdpp-replica-owner-legacy-routes.js";

const owner = createTestWallet(0);
const grantee = createTestWallet(1);
const server = privateKeyToAccount(createTestWallet(2).privateKey);
const origin = "http://127.0.0.1:3286";
const builderId = `0x${"11".repeat(32)}` as const;
const grantId = `0x${"22".repeat(32)}`;
const gatewayConfig = {
  chainId: 14800,
  contracts: {
    dataRegistry: "0x0000000000000000000000000000000000000001",
    dataPortabilityPermissions: "0x0000000000000000000000000000000000000002",
    dataPortabilityServer: "0x0000000000000000000000000000000000000003",
    dataPortabilityGrantees: "0x0000000000000000000000000000000000000004",
    dataPortabilityEscrow: "0x0000000000000000000000000000000000000005",
    feeRegistry: "0x0000000000000000000000000000000000000006",
  },
} as const;
const cleanups: (() => void)[] = [];
afterEach(() => {
  vi.unstubAllGlobals();
  for (const close of cleanups.splice(0).reverse()) close();
});

function setup() {
  const root = mkdtempSync(join(homedir(), ".tmp/legacy-routes-test-"));
  cleanups.push(() => rmSync(root, { recursive: true, force: true }));
  const storage = openReplicaOwnerLegacyStorage({ root });
  cleanups.push(storage.close);
  const { indexManager, hierarchyOptions, rawDataStorage } = storage;
  const serverSigner = createServerSigner(
    {
      address: server.address,
      publicKey: server.publicKey,
      signTypedData: (params) => server.signTypedData(params),
      signMessage: (message) => server.signMessage({ message }),
    },
    gatewayConfig,
  );
  const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === `https://gateway.invalid/v1/builders/${grantee.address}`) {
      return Response.json({
        data: { id: builderId, granteeAddress: grantee.address },
      });
    }
    if (
      url === "https://gateway.invalid/v1/grants" &&
      init?.method === "POST"
    ) {
      return Response.json({ grantId }, { status: 201 });
    }
    throw new Error(`Unexpected deterministic gateway request: ${url}`);
  });
  vi.stubGlobal("fetch", fetch);
  const deps = {
    logger: pino({ level: "silent" }),
    serverOwner: owner.address,
    serverOrigin: origin,
    serverSigner,
    gatewayConfig,
    gateway: createGatewayClient("https://gateway.invalid"),
    indexManager,
    hierarchyOptions,
    rawDataStorage,
    accessLogWriter: createAccessLogWriter(join(root, "logs")),
    granteeAddress: grantee.address,
  };
  return { app: createReplicaOwnerLegacyRoutes(deps), deps, fetch };
}

async function signed(
  wallet: typeof owner,
  method: string,
  uri: string,
  body?: string,
) {
  return buildWeb3SignedHeader({
    wallet,
    aud: origin,
    method,
    uri,
    ...(body === undefined ? {} : { body: new TextEncoder().encode(body) }),
  });
}

it("mounts the production grant factory and submits a real server EIP-712 signature through the SDK", async () => {
  const { app, fetch } = setup();
  const body = JSON.stringify({
    granteeAddress: grantee.address,
    scopes: ["strava.activities"],
    grantVersion: "2",
    expiresAt: 2000000000,
  });
  const response = await app.request(`${origin}/v1/grants`, {
    method: "POST",
    body,
    headers: {
      "content-type": "application/json",
      authorization: await signed(owner, "POST", "/v1/grants", body),
    },
  });
  expect(response.status, await response.clone().text()).toBe(201);
  expect(await response.json()).toEqual({ grantId });
  expect(fetch).toHaveBeenCalledTimes(2);
  const [url, init] = fetch.mock.calls[1];
  expect(url).toBe("https://gateway.invalid/v1/grants");
  expect(init?.method).toBe("POST");
  expect(JSON.parse(init!.body as string)).toEqual({
    grantorAddress: owner.address,
    granteeId: builderId,
    scopes: ["strava.activities"],
    grantVersion: "2",
    expiresAt: "2000000000",
  });
  const authorization = new Headers(init?.headers).get("authorization")!;
  expect(authorization).toMatch(/^Web3Signed 0x[0-9a-f]+$/i);
  expect(
    await recoverTypedDataAddress({
      domain: grantRegistrationDomain(gatewayConfig),
      types: GRANT_REGISTRATION_TYPES,
      primaryType: "GrantRegistration",
      message: {
        grantorAddress: owner.address,
        granteeId: builderId,
        scopes: ["strava.activities"],
        grantVersion: 2n,
        expiresAt: 2000000000n,
      },
      signature: authorization.slice("Web3Signed ".length) as `0x${string}`,
    }),
  ).toBe(server.address);
});

it.each(["/v1/grants", "/v1/grants/"])(
  "restricts grant creation at %s to the explicit DCR grantee without submitting a gateway mutation",
  async (path) => {
    const { app, fetch } = setup();
    const body = JSON.stringify({
      granteeAddress: createTestWallet(4).address,
      scopes: ["strava.activities"],
    });
    const response = await app.request(`${origin}${path}`, {
      method: "POST",
      body,
      headers: {
        "content-type": "application/json",
        authorization: await signed(owner, "POST", path, body),
      },
    });
    expect(response.status).toBe(403);
    expect(fetch).not.toHaveBeenCalled();
  },
);

it("opens real normal raw storage under A's root without creating data or authority", async () => {
  const root = mkdtempSync(join(homedir(), ".tmp/legacy-storage-test-"));
  cleanups.push(() => rmSync(root, { recursive: true, force: true }));
  const storage = openReplicaOwnerLegacyStorage({ root });
  cleanups.push(storage.close);
  expect(existsSync(join(root, "legacy-index.db"))).toBe(true);
  expect(storage.hierarchyOptions).toEqual({ dataDir: join(root, "data") });
  expect(storage.rawDataStorage.kind).toBe("node-fs-sqlite");
  expect(
    storage.rawDataStorage.findEntry({ scope: "strava.activities" }),
  ).toBeUndefined();
  expect(existsSync(join(root, "auth.sqlite"))).toBe(false);
  expect(existsSync(join(root, "runtime.db"))).toBe(false);
  storage.close();
  storage.close();
});

it("uses production owner auth to deny missing, foreign, wrong-audience and altered-body grant proofs", async () => {
  const { app, fetch } = setup();
  const body = JSON.stringify({
    granteeAddress: grantee.address,
    scopes: ["strava.activities"],
  });
  const headers = [
    undefined,
    "Bearer not-an-owner-token",
    await signed(grantee, "POST", "/v1/grants", body),
    await signed(owner, "POST", "/v1/grants", `${body} `),
    await buildWeb3SignedHeader({
      wallet: owner,
      aud: "http://127.0.0.1:9999",
      method: "POST",
      uri: "/v1/grants",
      body: new TextEncoder().encode(body),
    }),
  ];
  for (const authorization of headers) {
    const response = await app.request(`${origin}/v1/grants`, {
      method: "POST",
      body,
      headers: {
        "content-type": "application/json",
        ...(authorization ? { authorization } : {}),
      },
    });
    expect([401, 403]).toContain(response.status);
  }
  expect(fetch).not.toHaveBeenCalled();
});

it("runs the production data handler: unauthenticated denial, then owner-signed absent raw data stays 404", async () => {
  const { app, fetch } = setup();
  const path = "/v1/data/strava.activities";
  const denied = await app.request(`${origin}${path}`);
  expect(denied.status).toBe(401);
  const absent = await app.request(`${origin}${path}`, {
    headers: {
      authorization: await signed(owner, "GET", path),
    },
  });
  expect(absent.status, await absent.clone().text()).toBe(404);
  expect(fetch).not.toHaveBeenCalled();
});

it("serves an actual normal retained envelope from the filesystem, using deterministic test data only", async () => {
  const { app, deps, fetch } = setup();
  const scope = "strava.activities";
  const collectedAt = "2026-10-20T00:00:00.000Z";
  const data = {
    activities: [{ id: "deterministic-test-activity", distance: 123 }],
  };
  const written = await deps.rawDataStorage.writeEnvelope({
    version: "1.0",
    scope,
    collectedAt,
    data,
  });
  deps.indexManager.insert({
    scope,
    collectedAt,
    path: written.relativePath,
    sizeBytes: written.sizeBytes,
    fileId: null,
    schemaId: null,
  });
  const path = `/v1/data/${scope}`;
  const response = await app.request(`${origin}${path}`, {
    headers: {
      authorization: await signed(owner, "GET", path),
    },
  });
  expect(response.status, await response.clone().text()).toBe(200);
  expect(await response.json()).toMatchObject({ data });
  expect(fetch).not.toHaveBeenCalled();
});
