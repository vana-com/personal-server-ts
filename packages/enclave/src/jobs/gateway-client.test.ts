import { createServer, type IncomingMessage, type Server } from "node:http";
import {
  createGatewayClient,
  GatewayHttpError,
  LeaseLostError,
  NodeNotAdmittedError,
} from "./gateway-client.js";

const NODE_ID = "node-1";
const NODE_SECRET = "node-secret";
const JOB_ID = "123e4567-e89b-42d3-a456-426614174000";
const FENCING_TOKEN = 2;

let server: Server;
let origin: string;
let responder: (request: IncomingMessage) => number;
let responseBody: unknown;

beforeEach(async () => {
  responder = () => 204;
  responseBody = { code: "ERROR" };
  server = createServer((request, response) => {
    response.statusCode = responder(request);
    if (response.statusCode !== 204) {
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify(responseBody));
      return;
    }

    response.end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Gateway test server did not bind");
  }
  origin = `http://127.0.0.1:${address.port}`;
});

afterEach(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
});

describe("GatewayClient", () => {
  it("returns a valid successful claim body", async () => {
    responder = () => 200;
    responseBody = {
      job: {
        jobId: JOB_ID,
        chainId: 14800,
        fencingToken: FENCING_TOKEN,
        requestCiphertext: "ciphertext",
      },
      identity: {
        userPsId: "0x01",
        epoch: 1,
        enclaveAddress: "0x1111111111111111111111111111111111111111",
        enclavePublicKey: "0x02",
        sealedEnvelope: {},
      },
    };
    const client = createGatewayClient({
      baseUrl: origin,
      nodeId: NODE_ID,
      nodeSecret: NODE_SECRET,
    });

    await expect(
      client.claim(25, { leaseSeconds: 30, capacity: 20 }),
    ).resolves.toEqual(responseBody);
  });

  it("normalizes an uppercase claim job id", async () => {
    responder = () => 200;
    responseBody = {
      job: {
        jobId: JOB_ID.toUpperCase(),
        chainId: 14800,
        fencingToken: FENCING_TOKEN,
        requestCiphertext: "ciphertext",
      },
      identity: {
        userPsId: "0x01",
        epoch: 1,
        enclaveAddress: "0x1111111111111111111111111111111111111111",
        enclavePublicKey: "0x02",
        sealedEnvelope: {},
      },
    };
    const client = createGatewayClient({
      baseUrl: origin,
      nodeId: NODE_ID,
      nodeSecret: NODE_SECRET,
    });

    const claim = await client.claim(25, { leaseSeconds: 30, capacity: 20 });

    expect(claim?.job.jobId).toBe(JOB_ID);
  });

  it("rejects a traversal claim job id", async () => {
    responder = () => 200;
    responseBody = {
      job: {
        jobId: "../../chains/14800/owner/scope",
        chainId: 14800,
        fencingToken: FENCING_TOKEN,
        requestCiphertext: "ciphertext",
      },
      identity: {
        userPsId: "0x01",
        epoch: 1,
        enclaveAddress: "0x1111111111111111111111111111111111111111",
        enclavePublicKey: "0x02",
        sealedEnvelope: {},
      },
    };
    const client = createGatewayClient({
      baseUrl: origin,
      nodeId: NODE_ID,
      nodeSecret: NODE_SECRET,
    });

    await expect(
      client.claim(25, { leaseSeconds: 30, capacity: 20 }),
    ).rejects.toBeInstanceOf(GatewayHttpError);
  });

  it("rejects a malformed successful claim body", async () => {
    responder = () => 200;
    const client = createGatewayClient({
      baseUrl: origin,
      nodeId: NODE_ID,
      nodeSecret: NODE_SECRET,
    });

    await expect(
      client.claim(25, { leaseSeconds: 30, capacity: 20 }),
    ).rejects.toBeInstanceOf(GatewayHttpError);
  });

  it("accepts a deployed Gateway claim without a chain id", async () => {
    responder = () => 200;
    responseBody = {
      job: {
        jobId: JOB_ID,
        fencingToken: FENCING_TOKEN,
        requestCiphertext: "ciphertext",
      },
      identity: {
        userPsId: "0x01",
        epoch: 1,
        enclaveAddress: "0x1111111111111111111111111111111111111111",
        enclavePublicKey: "0x02",
        sealedEnvelope: {},
      },
    };
    const client = createGatewayClient({
      baseUrl: origin,
      nodeId: NODE_ID,
      nodeSecret: NODE_SECRET,
    });

    await expect(
      client.claim(25, { leaseSeconds: 30, capacity: 20 }),
    ).resolves.toEqual(responseBody);
  });

  it("accepts a finite future chain id for mismatch handling", async () => {
    responder = () => 200;
    responseBody = {
      job: {
        jobId: JOB_ID,
        chainId: 14_801,
        fencingToken: FENCING_TOKEN,
        requestCiphertext: "ciphertext",
      },
      identity: {
        userPsId: "0x01",
        epoch: 1,
        enclaveAddress: "0x1111111111111111111111111111111111111111",
        enclavePublicKey: "0x02",
        sealedEnvelope: {},
      },
    };
    const client = createGatewayClient({
      baseUrl: origin,
      nodeId: NODE_ID,
      nodeSecret: NODE_SECRET,
    });

    await expect(
      client.claim(25, { leaseSeconds: 30, capacity: 20 }),
    ).resolves.toEqual(responseBody);
  });

  it("sends node headers and maps an empty claim to null", async () => {
    responder = (request) => {
      expect(request.url).toBe("/v1/jobs/claim?wait=25");
      expect(request.headers.authorization).toBe(`Bearer ${NODE_SECRET}`);
      expect(request.headers["x-node-id"]).toBe(NODE_ID);

      return 204;
    };
    const client = createGatewayClient({
      baseUrl: origin,
      nodeId: NODE_ID,
      nodeSecret: NODE_SECRET,
    });

    await expect(
      client.claim(25, { leaseSeconds: 30, capacity: 20 }),
    ).resolves.toBeNull();
  });

  it("maps a fenced conflict to LeaseLostError", async () => {
    responder = () => 409;
    const client = createGatewayClient({
      baseUrl: origin,
      nodeId: NODE_ID,
      nodeSecret: NODE_SECRET,
    });

    await expect(
      client.heartbeat(JOB_ID, { fencingToken: FENCING_TOKEN }),
    ).rejects.toBeInstanceOf(LeaseLostError);
  });

  it("posts signed access records with the node bearer", async () => {
    const seen: { url?: string; auth?: string; body?: string } = {};
    const client = createGatewayClient({
      baseUrl: origin,
      nodeId: NODE_ID,
      nodeSecret: NODE_SECRET,
      fetch: async (input, init) => {
        seen.url = String(input);
        seen.auth = (init?.headers as Record<string, string>).Authorization;
        seen.body = String(init?.body);
        return new Response(null, { status: 202 });
      },
    });
    const records = [
      {
        action: "read",
        chainId: 14_800,
        epoch: 1,
        grantId: "grant-1",
        granteeAddress: `0x${"11".repeat(20)}`,
        logId: "log-1",
        nodeId: NODE_ID,
        occurredAt: "2026-09-09T00:00:00.000Z",
        outcome: "served",
        scope: "instagram.profile",
        source: "mcp",
        userPsId: `0x${"22".repeat(32)}`,
        signature: `0x${"33".repeat(65)}`,
      },
    ] as Parameters<typeof client.postAccessRecords>[0]["records"];

    await expect(
      client.postAccessRecords({ records }),
    ).resolves.toBeUndefined();
    expect(seen.url).toBe(`${origin}/v1/access-records`);
    expect(seen.auth).toBe(`Bearer ${NODE_SECRET}`);
    expect(JSON.parse(seen.body!)).toEqual({ records });
  });

  it("maps a forbidden node request to NodeNotAdmittedError", async () => {
    responder = () => 403;
    const client = createGatewayClient({
      baseUrl: origin,
      nodeId: NODE_ID,
      nodeSecret: NODE_SECRET,
    });

    await expect(
      client.nodeHeartbeat(NODE_ID, {
        composeHash: `0x${"11".repeat(32)}`,
        instanceId: "instance-1",
        activeSandboxes: 0,
        capacity: 20,
      }),
    ).rejects.toBeInstanceOf(NodeNotAdmittedError);
  });
});
