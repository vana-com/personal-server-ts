import { createServer, type Server } from "node:http";
import { once } from "node:events";
import { afterEach, beforeEach, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { recoverTypedDataAddress, keccak256, stringToHex } from "viem";
import {
  verifyWeb3Signed,
  ADD_DATA_TYPES,
  MASTER_KEY_MESSAGE,
} from "@opendatalabs/vana-sdk/node";
import { createFakeDstackClient } from "../dstack/fake.js";
import { deriveEnclaveIdentity } from "../identity/wallet.js";
import { userPsId } from "../identity/paths.js";
import { createAgentServer, type AgentJobsControl } from "./http.js";
import type { SandboxLookup } from "../sandbox/registry.js";
import { createEnclaveAdditionsPorts } from "../../../server/src/enclave-main.js";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";

const owner = privateKeyToAccount(`0x${"11".repeat(32)}`);
const chainId = 14800;
const contract = "0x1111111111111111111111111111111111111111";
const client = createFakeDstackClient({
  appId: "0000000000000000000000000000000000000003",
});
const scope = "vana.system.additions.chatgpt.conversations";
const commitment = `0x${"aa".repeat(32)}` as const;
let servers: Server[];
let agent: string;
let gateway: string;
let lookup: SandboxLookup;
let registered: boolean;
let afterInventory: (() => void) | undefined;
let inventoryCount: number;
let malformedEvidence: boolean;
let stored: Uint8Array | undefined;

async function listen(server: Server) {
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("No listener");
  return `http://127.0.0.1:${address.port}`;
}
async function call(body: Record<string, unknown>, token = "sandbox") {
  return fetch(`${agent}/agent/v1/additions/sign`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ owner: owner.address, chainId, ...body }),
  });
}
beforeEach(async () => {
  servers = [];
  registered = true;
  inventoryCount = 0;
  malformedEvidence = false;
  stored = undefined;
  afterInventory = undefined;
  const identity = await deriveEnclaveIdentity(
    client,
    userPsId(chainId, owner.address),
    2,
  );
  lookup = {
    kind: "active",
    key: "placement",
    generation: 3,
    identity: { userPsId: userPsId(chainId, owner.address), epoch: 2 },
  };
  gateway = await listen(
    createServer(async (req, res) => {
      try {
        const bytes: Buffer[] = [];
        for await (const chunk of req) bytes.push(Buffer.from(chunk));
        if (req.method === "GET") {
          const proof = await verifyWeb3Signed({
            headerValue: req.headers.authorization,
            expectedOrigin: gateway,
            expectedMethod: "GET",
            expectedPath: req.url ?? "",
          });
          expect(proof.signer.toLowerCase()).toBe(
            identity.address.toLowerCase(),
          );
          inventoryCount++;
          afterInventory?.();
          res.writeHead(registered ? 200 : 403, {
            "Content-Type": "application/json",
          });
          res.end(
            JSON.stringify(
              malformedEvidence
                ? { error: "upstream unavailable" }
                : {
                    data: {
                      ownerAddress: owner.address,
                      dataPointId: (req.url ?? "").split("/")[3],
                      scope: new URL(req.url ?? "", gateway).searchParams.get(
                        "scope",
                      ),
                      versions: [],
                    },
                  },
            ),
          );
        } else if (req.method === "PUT") {
          const body = Buffer.concat(bytes);
          const proof = await verifyWeb3Signed({
            headerValue: req.headers.authorization,
            expectedOrigin: gateway,
            expectedMethod: "PUT",
            expectedPath: req.url ?? "",
            bodyBytes: body,
          });
          expect(proof.signer.toLowerCase()).toBe(
            identity.address.toLowerCase(),
          );
          stored = body;
          res.writeHead(200);
          res.end();
        } else {
          res.writeHead(404);
          res.end();
        }
      } catch (error) {
        res.writeHead(500);
        res.end(String(error));
      }
    }),
  );
  const jobs: AgentJobsControl = {
    nodeId: "local",
    chainId,
    storageApiUrl: gateway,
    additions: { gatewayUrl: gateway, dataRegistry: contract },
    activeCount: () => 1,
    draining: () => false,
    drain: async () => {},
    sandboxDebug: false,
    listSandboxes: async () => [],
    sandboxLogs: async () => undefined,
    lookupSandboxJob: () => ({ kind: "unauthorized" }),
    lookupSandbox: (token) =>
      token === "sandbox" ? lookup : { kind: "unauthorized" },
    postAccessRecords: async () => {},
    prewarm: () => {},
  };
  agent = await listen(
    createAgentServer({ client, secret: "host-secret", jobs }),
  );
});
afterEach(async () => {
  await Promise.all(
    servers.map(
      (server) =>
        new Promise<void>((resolve, reject) => {
          server.close((error) => (error ? reject(error) : resolve()));
          server.closeAllConnections();
        }),
    ),
  );
});

it("runs the native sandbox adapters through the host RPC, uploads exact bytes and signs registered-server AddData", async () => {
  const identity = await deriveEnclaveIdentity(
    client,
    userPsId(chainId, owner.address),
    2,
  );
  const config = ServerConfigSchema.parse({});
  config.gateway.url = gateway;
  config.gateway.chainId = chainId;
  config.gateway.contracts.dataRegistry = contract;
  config.storage.config.vana = { apiUrl: gateway };
  const ports = await createEnclaveAdditionsPorts(config, {
    ownerSignature: await owner.signMessage({ message: MASTER_KEY_MESSAGE }),
    accessToken: "sandbox",
    serverAddress: identity.address,
    serverPublicKey: identity.publicKey,
    agentUrl: agent,
  });
  const writer = ports.additionsWriter;
  if (!writer || !ports.additionsInventorySigner)
    throw new Error("Missing wired ports");
  const bytes = new Uint8Array([10, 20, 30]);
  expect(await writer.storageAdapter.upload(`${scope}/1`, bytes)).toBe(
    `${gateway}/v1/chains/${chainId}/blobs/${owner.address.toLowerCase()}/${scope}/1`,
  );
  expect(Array.from(stored ?? [])).toEqual([10, 20, 30]);
  const message = {
    ownerAddress: owner.address,
    scope,
    expectedVersion: 1n,
    dataHash: commitment,
    metadataHash: commitment,
  };
  const signature = await writer.signer.signAddData(message);
  expect(
    await recoverTypedDataAddress({
      domain: {
        name: "Vana Data Portability",
        version: "1",
        chainId,
        verifyingContract: contract,
      },
      types: ADD_DATA_TYPES,
      primaryType: "AddData",
      message,
      signature,
    }),
  ).toBe(identity.address);
  expect(inventoryCount).toBe(2);
  await expect(
    ports.additionsInventorySigner.signRequest({
      aud: gateway,
      method: "GET",
      uri: "/v1/data",
    }),
  ).rejects.toThrow("Only canonical inventory");
  registered = false;
  await expect(writer.signer.signAddData(message)).rejects.toThrow("403");
  expect(inventoryCount).toBe(3);
});

it.each([
  { owner: "0x2222222222222222222222222222222222222222" },
  { chainId: 1480 },
  { scope: "ordinary.scope" },
  { scope: "vana.system.other" },
  {
    scope: "vana.system.additions.vana.system.private",
    sourceScope: "vana.system.private",
  },
  { scope: "vana.system.additions.../evil", sourceScope: "../evil" },
  { version: "01" },
  { grantId: "0x1234" },
  { dataHash: keccak256(stringToHex("vana.data-point.tombstone.v1")) },
  { dataHash: "0x12" },
])(
  "refuses checkpoint authority outside the closed contract: %j",
  async (extra) => {
    expect(
      (
        await call({
          kind: "register",
          scope,
          sourceScope: "chatgpt.conversations",
          version: "1",
          dataHash: commitment,
          metadataHash: commitment,
          ...extra,
        })
      ).status,
    ).toBe(403);
  },
);

it("denies unknown tokens, stale placement and placement changes during registry freshness checks", async () => {
  const request = {
    kind: "upload",
    scope,
    sourceScope: "chatgpt.conversations",
    version: "1",
    bodyHash: `sha256:${"aa".repeat(32)}`,
  };
  expect((await call(request, "wrong")).status).toBe(403);
  lookup = { kind: "stale" };
  expect((await call(request)).status).toBe(403);
  lookup = {
    kind: "active",
    key: "placement",
    generation: 3,
    identity: { userPsId: userPsId(chainId, owner.address), epoch: 2 },
  };
  afterInventory = () => {
    lookup = { ...lookup, kind: "stale" };
  };
  expect((await call(request)).status).toBe(403);
  expect(stored).toBeUndefined();
});

it("binds inventory proofs to canonical owner, origin, method, selectors, fresh nonce and expiry", async () => {
  const first = await call({
    kind: "inventory",
    scope: "chatgpt.conversations",
    after: "0",
    limit: "100",
  });
  const second = await call({
    kind: "inventory",
    scope: "chatgpt.conversations",
    after: "0",
    limit: "100",
  });
  expect(first.status).toBe(200);
  expect(second.status).toBe(200);
  const a = await first.json();
  const b = await second.json();
  expect(a.authorization).not.toBe(b.authorization);
  const payload = JSON.parse(
    Buffer.from(
      a.authorization.split(" ")[1].split(".")[0],
      "base64url",
    ).toString(),
  );
  expect(payload).toMatchObject({
    aud: gateway,
    method: "GET",
  });
  expect(payload.grantId).toBeUndefined();
  expect(payload.exp - payload.iat).toBe(60);
  expect(payload.uri).toContain(
    `user=${owner.address.toLowerCase()}&scope=chatgpt.conversations&after=0&limit=100`,
  );
  expect(
    (
      await call({
        kind: "inventory",
        scope,
        after: "0",
        limit: "100",
        aud: "https://evil.test",
      })
    ).status,
  ).toBe(403);
});

it("refuses malformed successful registry responses and retired epoch/generation evidence", async () => {
  const request = {
    kind: "upload",
    scope,
    sourceScope: "chatgpt.conversations",
    version: "1",
    bodyHash: `sha256:${"aa".repeat(32)}`,
  };
  malformedEvidence = true;
  expect((await call(request)).status).toBe(403);
  malformedEvidence = false;
  afterInventory = () => {
    if (lookup.kind === "active")
      lookup = { ...lookup, identity: { ...lookup.identity, epoch: 3 } };
  };
  expect((await call(request)).status).toBe(403);
  expect(stored).toBeUndefined();
});

it("derives long ledger scopes from non-system sources and permits the exact summary only", async () => {
  const sourceScope = "x".repeat(240);
  const hashedScope = `vana.system.additions-hash.${keccak256(stringToHex(sourceScope)).slice(2)}`;
  const base = {
    kind: "register",
    version: "1",
    dataHash: commitment,
    metadataHash: commitment,
  };
  expect(
    (await call({ ...base, scope: hashedScope, sourceScope })).status,
  ).toBe(200);
  expect(
    (await call({ ...base, scope: hashedScope, sourceScope: "other" })).status,
  ).toBe(403);
  expect((await call({ ...base, scope: "vana.system.additions" })).status).toBe(
    200,
  );
  expect(
    (await call({ ...base, scope: "vana.system.additions", sourceScope }))
      .status,
  ).toBe(403);
});

it.each([
  "test.percent%scope",
  "test.control\u0001scope",
  `${"x".repeat(235)}/suffix`,
  `${"x".repeat(235)}\\suffix`,
])(
  "signs canonical checkpoint scopes for existing registered source %j",
  async (sourceScope) => {
    const literal = `vana.system.additions.${sourceScope}`;
    const checkpoint =
      Buffer.byteLength(literal) <= 256
        ? literal
        : `vana.system.additions-hash.${keccak256(stringToHex(sourceScope)).slice(2)}`;
    const result = await call({
      kind: "register",
      scope: checkpoint,
      sourceScope,
      version: "1",
      dataHash: commitment,
      metadataHash: commitment,
    });
    expect(result.status).toBe(200);
  },
);
