import {
  MASTER_KEY_MESSAGE as SDK_MASTER_KEY_MESSAGE,
  NodeECIESProvider,
  serializeECIES,
} from "@opendatalabs/vana-sdk/node";
import {
  MASTER_SIGNATURE_DELIVERY_VERSION,
  type MasterSignatureDelivery,
} from "@opendatalabs/vana-sdk/protocol/identity";
import type { Address, Hex } from "viem";
import { keccak256, toBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { createFakeDstackClient } from "../dstack/fake.js";
import { userPsId } from "../identity/paths.js";
import { deriveEnclaveIdentity } from "../identity/wallet.js";
import { unseal } from "../sealing/envelope.js";
import { createAgentServer } from "./http.js";
import type { SealRequestBody } from "./types.js";

const SECRET = "agent-test-secret";
const OWNER_KEY = keccak256(toBytes("enclave-agent-test:http-owner"));
const OTHER_KEY = keccak256(toBytes("enclave-agent-test:http-other"));
const OWNER = privateKeyToAccount(OWNER_KEY);
const CHAIN_ID = 14_800;
const EPOCH = 2;
const JSON_HEADERS = {
  authorization: `Bearer ${SECRET}`,
  "content-type": "application/json",
};

let server: ReturnType<typeof createAgentServer> | undefined;
let origin = "";

beforeEach(async () => {
  server = createAgentServer({
    client: createFakeDstackClient({ appId: "http-app" }),
    secret: SECRET,
  });
  await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("test server did not bind a TCP port");
  }
  origin = `http://127.0.0.1:${address.port}`;
});

afterEach(async () => {
  if (server) {
    await new Promise<void>((resolve, reject) =>
      server!.close((error) => (error ? reject(error) : resolve())),
    );
  }
  server = undefined;
});

async function sealRequest(
  signer = OWNER,
): Promise<{ request: SealRequestBody; signature: Hex }> {
  const client = createFakeDstackClient({ appId: "http-app" });
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
    ownerAddress: OWNER.address,
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

describe("agent HTTP server", () => {
  it.each([
    ["missing", undefined],
    ["wrong length", "Bearer no"],
    ["same length", `Bearer ${"x".repeat(SECRET.length)}`],
  ])("returns 401 for %s bearer auth", async (_label, authorization) => {
    const headers = authorization ? { authorization } : undefined;
    const response = await fetch(`${origin}/agent/v1/health`, { headers });

    expect(response.status).toBe(401);
  });

  it("returns health information", async () => {
    const response = await fetch(`${origin}/agent/v1/health`, {
      headers: JSON_HEADERS,
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      appId: "http-app",
      composeHash: "fake-compose-hash",
      instanceId: "fake-instance",
      osVersion: "fake",
    });
  });

  it("returns identity evidence", async () => {
    const response = await post("/agent/v1/identity", {
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
    const response = await post("/agent/v1/secrets/seal", request);
    const body = (await response.json()) as {
      envelope: Parameters<typeof unseal>[3];
      secretHash: Hex;
    };
    const recovered = await unseal(
      createFakeDstackClient({ appId: "http-app" }),
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
    const response = await post("/agent/v1/secrets/seal", {
      ...request,
      minEpoch: EPOCH + 1,
    });

    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({ error: "EPOCH_RETIRED" });
  });

  it("maps an owner mismatch to 422", async () => {
    const { request } = await sealRequest(privateKeyToAccount(OTHER_KEY));
    const response = await post("/agent/v1/secrets/seal", request);

    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({ error: "OWNER_MISMATCH" });
  });

  it("rejects bodies over 64 KiB", async () => {
    const response = await post(
      "/agent/v1/identity",
      JSON.stringify({ padding: "x".repeat(64 * 1024) }),
    );

    expect(response.status).toBe(413);
  });

  it("rejects bad JSON", async () => {
    const response = await post("/agent/v1/identity", "{");

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "BAD_REQUEST" });
  });

  it("returns 404 for unknown paths", async () => {
    const response = await fetch(`${origin}/agent/v1/missing`, {
      headers: JSON_HEADERS,
    });

    expect(response.status).toBe(404);
  });
});
