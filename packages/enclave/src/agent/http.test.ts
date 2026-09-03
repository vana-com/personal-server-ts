import {
  MASTER_KEY_MESSAGE as SDK_MASTER_KEY_MESSAGE,
  NodeECIESProvider,
  serializeECIES,
} from "@opendatalabs/vana-sdk/node";
import {
  MASTER_SIGNATURE_DELIVERY_VERSION,
  type MasterSignatureDelivery,
} from "@opendatalabs/vana-sdk/protocol/identity";
import { vi } from "vitest";
import type { Address, Hex } from "viem";
import { keccak256, toBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { createFakeDstackClient } from "../dstack/fake.js";
import type { DstackClient } from "../dstack/client.js";
import { userPsId } from "../identity/paths.js";
import { deriveEnclaveIdentity } from "../identity/wallet.js";
import { unseal } from "../sealing/envelope.js";
import { createAgentServer, type AgentJobsControl } from "./http.js";
import type { SealRequestBody } from "./types.js";

const SECRET = "agent-test-secret";
const OWNER_KEY = keccak256(toBytes("enclave-agent-test:http-owner"));
const OTHER_KEY = keccak256(toBytes("enclave-agent-test:http-other"));
const OWNER = privateKeyToAccount(OWNER_KEY);
const OTHER = privateKeyToAccount(OTHER_KEY);
const CHAIN_ID = 14_800;
const EPOCH = 2;
const FAKE_APP_ID = "0000000000000000000000000000000000000003";
const HEALTH_PATH = "/agent/v1/health";
const IDENTITY_PATH = "/agent/v1/identity";
const SEAL_PATH = "/agent/v1/secrets/seal";
const DRAIN_PATH = "/agent/v1/drain";
const INVALID_ADDRESS = "invalid-address";
const INVALID_HEX = "invalid-hex";
const VALID_HEX = "0x00";
const INFO_FAILURE = "info failed";
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const INSTANCE_ID_PATTERN = /^[0-9a-f]{40}$/;
const JSON_HEADERS = {
  authorization: `Bearer ${SECRET}`,
  "content-type": "application/json",
};

let server: ReturnType<typeof createAgentServer> | undefined;
let origin = "";

async function startServer(
  client: DstackClient = createFakeDstackClient({ appId: FAKE_APP_ID }),
  jobs?: AgentJobsControl,
): Promise<void> {
  server = createAgentServer({
    client,
    secret: SECRET,
    ...(jobs ? { jobs } : {}),
  });
  await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("test server did not bind a TCP port");
  }
  origin = `http://127.0.0.1:${address.port}`;
}

async function stopServer(): Promise<void> {
  if (server) {
    await new Promise<void>((resolve, reject) =>
      server!.close((error) => (error ? reject(error) : resolve())),
    );
  }
  server = undefined;
}

beforeEach(async () => {
  await startServer();
});

afterEach(async () => {
  await stopServer();
});

async function sealRequest(
  signer = OWNER,
  deliveryOwner = OWNER.address,
): Promise<{ request: SealRequestBody; signature: Hex }> {
  const client = createFakeDstackClient({ appId: FAKE_APP_ID });
  const id = userPsId(CHAIN_ID, OWNER.address);
  const identity = await deriveEnclaveIdentity(client, id, EPOCH);
  const signature = await signer.signMessage({
    message: SDK_MASTER_KEY_MESSAGE,
  });
  const delivery: MasterSignatureDelivery = {
    v: MASTER_SIGNATURE_DELIVERY_VERSION,
    userPsId: id,
    epoch: EPOCH,
    enclaveAddress: identity.address,
    ownerAddress: deliveryOwner,
    masterSignature: signature,
    issuedAt: Math.floor(Date.now() / 1000),
  };
  const encrypted = await new NodeECIESProvider().encrypt(
    toBytes(identity.publicKey),
    new TextEncoder().encode(JSON.stringify(delivery)),
  );

  return {
    signature,
    request: {
      ownerAddress: OWNER.address,
      chainId: CHAIN_ID,
      epoch: EPOCH,
      enclaveAddress: identity.address,
      ciphertext: `0x${serializeECIES(encrypted)}`,
    },
  };
}

async function post(path: string, body: unknown, headers = JSON_HEADERS) {
  return fetch(`${origin}${path}`, {
    method: "POST",
    headers,
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

async function expectError(
  response: Response,
  status: number,
  code: string,
): Promise<void> {
  const body = (await response.json()) as { code: string; error: string };

  expect(response.status).toBe(status);
  expect(body.code).toBe(code);
  expect(body.error.length).toBeGreaterThan(0);
}

describe("agent HTTP server", () => {
  it.each([
    ["missing", undefined],
    ["wrong length", "Bearer no"],
    ["same length", `Bearer ${"x".repeat(SECRET.length)}`],
  ])("returns 401 for %s bearer auth", async (_label, authorization) => {
    const headers = authorization ? { authorization } : undefined;
    const response = await fetch(`${origin}${HEALTH_PATH}`, { headers });

    await expectError(response, 401, "UNAUTHORIZED");
  });

  it("returns health information", async () => {
    const response = await fetch(`${origin}${HEALTH_PATH}`, {
      headers: JSON_HEADERS,
    });
    const body = (await response.json()) as {
      appId: string;
      composeHash: string;
      instanceId: string;
      osImageHash: string;
      osVersion: string;
      activeSandboxes: number;
      draining: boolean;
    };

    expect(response.status).toBe(200);
    expect(body).toMatchObject({
      appId: FAKE_APP_ID,
      osVersion: "fake",
      activeSandboxes: 0,
      draining: false,
    });
    expect(body.composeHash).toMatch(HASH_PATTERN);
    expect(body.instanceId).toMatch(INSTANCE_ID_PATTERN);
    expect(body.osImageHash).toMatch(HASH_PATTERN);
  });

  it("reports jobs state and drains through the operator route", async () => {
    const jobs = {
      activeCount: vi.fn().mockReturnValue(3),
      draining: vi.fn().mockReturnValue(true),
      drain: vi.fn().mockResolvedValue(undefined),
    } satisfies AgentJobsControl;
    await stopServer();
    await startServer(createFakeDstackClient({ appId: FAKE_APP_ID }), jobs);

    const health = await fetch(`${origin}${HEALTH_PATH}`, {
      headers: JSON_HEADERS,
    });
    expect(await health.json()).toMatchObject({
      activeSandboxes: 3,
      draining: true,
    });

    const drain = await post(DRAIN_PATH, {});
    expect(drain.status).toBe(200);
    expect(await drain.json()).toEqual({ draining: true });
    expect(jobs.drain).toHaveBeenCalledOnce();
  });

  it("returns INTERNAL and logs an unexpected health failure", async () => {
    const client = createFakeDstackClient({ appId: FAKE_APP_ID });
    client.info = async () => {
      throw new Error(INFO_FAILURE);
    };
    await stopServer();
    await startServer(client);
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    try {
      const response = await fetch(`${origin}${HEALTH_PATH}`, {
        headers: JSON_HEADERS,
      });

      expect(response.status).toBe(500);
      expect(await response.json()).toEqual({
        code: "INTERNAL",
        error: "internal server error",
      });
      expect(errorSpy).toHaveBeenCalledWith({
        path: HEALTH_PATH,
        error: `Error: ${INFO_FAILURE}`,
      });
    } finally {
      errorSpy.mockRestore();
    }
  });

  it("returns identity evidence", async () => {
    const response = await post(IDENTITY_PATH, {
      ownerAddress: OWNER.address,
      chainId: CHAIN_ID,
      epoch: EPOCH,
    });
    const body = (await response.json()) as {
      ownerAddress: Address;
      v: number;
    };

    expect(response.status).toBe(200);
    expect(body).toMatchObject({ ownerAddress: OWNER.address, v: 1 });
  });

  it("seals a valid delivery", async () => {
    const { request, signature } = await sealRequest();
    const response = await post(SEAL_PATH, request);
    const body = (await response.json()) as {
      envelope: Parameters<typeof unseal>[3];
      secretHash: Hex;
    };
    const recovered = await unseal(
      createFakeDstackClient({ appId: FAKE_APP_ID }),
      userPsId(CHAIN_ID, OWNER.address),
      EPOCH,
      body.envelope,
    );

    expect(response.status).toBe(200);
    expect(`0x${Buffer.from(recovered).toString("hex")}`).toBe(signature);
    expect(body.secretHash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("maps a retired epoch to 409", async () => {
    const { request } = await sealRequest();
    const response = await post(SEAL_PATH, {
      ...request,
      minEpoch: EPOCH + 1,
    });

    await expectError(response, 409, "EPOCH_RETIRED");
  });

  it("maps an owner mismatch to 422", async () => {
    const { request } = await sealRequest(OTHER);
    const response = await post(SEAL_PATH, request);

    await expectError(response, 422, "OWNER_MISMATCH");
  });

  it("maps a delivery ownerAddress mismatch to 422", async () => {
    const { request } = await sealRequest(OWNER, OTHER.address);
    const response = await post(SEAL_PATH, request);

    await expectError(response, 422, "OWNER_MISMATCH");
  });

  it("rejects bodies over 64 KiB", async () => {
    const response = await post(
      IDENTITY_PATH,
      JSON.stringify({ padding: "x".repeat(64 * 1024) }),
    );

    await expectError(response, 413, "BODY_TOO_LARGE");
  });

  it("rejects bad JSON", async () => {
    const response = await post(IDENTITY_PATH, "{");

    await expectError(response, 400, "BAD_REQUEST");
  });

  it.each([
    [
      "bad ownerAddress",
      IDENTITY_PATH,
      { ownerAddress: INVALID_ADDRESS, chainId: CHAIN_ID, epoch: EPOCH },
    ],
    [
      "zero epoch",
      IDENTITY_PATH,
      { ownerAddress: OWNER.address, chainId: CHAIN_ID, epoch: 0 },
    ],
    [
      "fractional chainId",
      IDENTITY_PATH,
      { ownerAddress: OWNER.address, chainId: 1.5, epoch: EPOCH },
    ],
    [
      "non-hex ciphertext",
      SEAL_PATH,
      {
        ownerAddress: OWNER.address,
        chainId: CHAIN_ID,
        epoch: EPOCH,
        enclaveAddress: OTHER.address,
        ciphertext: INVALID_HEX,
      },
    ],
    [
      "zero minEpoch",
      SEAL_PATH,
      {
        ownerAddress: OWNER.address,
        chainId: CHAIN_ID,
        epoch: EPOCH,
        enclaveAddress: OTHER.address,
        ciphertext: VALID_HEX,
        minEpoch: 0,
      },
    ],
    ["JSON array", IDENTITY_PATH, []],
  ])("returns BAD_REQUEST for %s", async (_label, path, body) => {
    const response = await post(path, body);

    await expectError(response, 400, "BAD_REQUEST");
  });

  it("returns NOT_FOUND for the wrong method on a known route", async () => {
    const response = await fetch(`${origin}${IDENTITY_PATH}`, {
      headers: JSON_HEADERS,
    });

    await expectError(response, 404, "NOT_FOUND");
  });

  it("returns 404 for unknown paths", async () => {
    const response = await fetch(`${origin}/agent/v1/missing`, {
      headers: JSON_HEADERS,
    });

    await expectError(response, 404, "NOT_FOUND");
  });
});
