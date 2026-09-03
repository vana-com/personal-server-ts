import { createServer, type IncomingMessage, type Server } from "node:http";
import {
  createGatewayClient,
  LeaseLostError,
  NodeNotAdmittedError,
} from "./gateway-client.js";

const NODE_ID = "node-1";
const NODE_SECRET = "node-secret";
const JOB_ID = "job-1";
const FENCING_TOKEN = 2;

let server: Server;
let origin: string;
let responder: (request: IncomingMessage) => number;

beforeEach(async () => {
  responder = () => 204;
  server = createServer((request, response) => {
    response.statusCode = responder(request);
    if (response.statusCode !== 204) {
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ code: "ERROR" }));
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
