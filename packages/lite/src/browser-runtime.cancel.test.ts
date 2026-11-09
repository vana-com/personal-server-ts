/**
 * The default Lite composition: `createIndexedDbPsLiteRuntime` builds the SDK
 * gateway itself. Its registry write must still be closed at the attempt
 * deadline, or one hung request holds its entry for the rest of the session.
 */
import { createUnswitchedIndexedDbPsLiteRuntime } from "./test-support/unswitched-runtime.js";
import http from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { signOwnerMasterKey } from "@opendatalabs/personal-server-ts-core/keys";
import {
  ADD_DATA_TYPES,
  createDataFileEnvelope,
  dataRegistryDomain,
  type AddDataMessage,
} from "@opendatalabs/vana-sdk/browser";
import { createBearerTokenPsLiteAuth } from "./runtime.js";
import type { PsLitePersistenceBundle } from "./persistence.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import {
  createInMemoryMcpConnectionStore,
  createInMemoryMcpOAuthAuthorizationStore,
} from "@opendatalabs/personal-server-ts-core/mcp";

const SCHEMA_ID =
  "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

/** Answers every request, except POSTs for `hangScope`, which it holds open. */
function startStub(hangScope: string) {
  const closed: string[] = [];
  const posts: string[] = [];
  const sockets = new Set<Socket>();
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      res.setHeader("content-type", "application/json");
      if (req.method === "POST" && req.url === "/v1/data") {
        const scope = (JSON.parse(body) as { scope: string }).scope;
        posts.push(scope);
        if (scope === hangScope) {
          res.on("close", () => closed.push(scope));
          return;
        }
        res.end(
          JSON.stringify({
            dataPointId: `0x${"de".repeat(32)}`,
            expectedVersion: "1",
          }),
        );
        return;
      }
      if (req.method === "PUT") {
        res.end(
          JSON.stringify({
            url: "https://storage.test/blob",
            key: "k",
            size: 1,
            etag: "e",
          }),
        );
        return;
      }
      res.statusCode = 404;
      res.end("{}");
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  return new Promise<{
    url: string;
    closed: string[];
    posts: string[];
    stop(): Promise<void>;
  }>((resolve) =>
    server.listen(0, "127.0.0.1", () =>
      resolve({
        url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
        closed,
        posts,
        async stop() {
          for (const socket of sockets) socket.destroy();
          await new Promise((done) => server.close(done));
        },
      }),
    ),
  );
}

const realWait = async (check: () => boolean, what: string) => {
  for (let i = 0; i < 100 && !check(); i++)
    await new Promise((r) => setTimeout(r, 20));
  if (!check()) throw new Error(`never happened: ${what}`);
};

describe("default Lite composition cancels a hung registry write", () => {
  let stop: (() => Promise<void>) | undefined;
  beforeEach(() => vi.spyOn(console, "error").mockImplementation(() => {}));
  afterEach(async () => {
    vi.restoreAllMocks();
    await stop?.();
  });

  it("closes the socket at the deadline and uploads the next entry in the same cycle", async () => {
    const owner = privateKeyToAccount(`0x${"11".repeat(32)}`);
    const ownerSignature = await signOwnerMasterKey(owner);
    const stub = await startStub("scope.hung");
    stop = stub.stop;
    const storage = createMemoryPsLiteStorage();
    for (const scope of ["scope.hung", "scope.ok"]) {
      const envelope = createDataFileEnvelope(
        scope,
        "2026-11-07T10:00:00.000Z",
        { value: scope },
        "https://schemas.example/s.json",
        SCHEMA_ID,
      );
      const write = await storage.writeEnvelope(envelope);
      storage.insertEntry({
        fileId: null,
        schemaId: SCHEMA_ID,
        path: write.relativePath,
        scope,
        collectedAt: envelope.collectedAt,
        sizeBytes: write.sizeBytes,
      });
    }
    const bundle: PsLitePersistenceBundle = {
      storage,
      state: createMemoryPsLiteStateStore(),
      tokens: createMemoryPsLiteTokenStore(),
      accessLog: createMemoryPsLiteAccessLogStore(),
      mcpConnections: createInMemoryMcpConnectionStore(),
      mcpOAuthAuthorizations: createInMemoryMcpOAuthAuthorizationStore(),
      relayTlsIdentity: { read: () => null, write: () => {} },
    };
    // The sockets and the clock are real; only the ten-minute attempt deadline
    // is shortened, so nothing but the deadline can close the hung request.
    const realSetTimeout = globalThis.setTimeout;
    vi.spyOn(globalThis, "setTimeout").mockImplementation(((
      fn: () => void,
      ms?: number,
      ...rest: unknown[]
    ) =>
      realSetTimeout(
        fn,
        ms === 10 * 60_000 ? 300 : ms,
        ...rest,
      )) as typeof setTimeout);
    const config = {
      gateway: { url: stub.url },
      storage: { backend: "vana", config: { vana: { apiUrl: stub.url } } },
      sync: { enabled: true },
    } as const;
    const runtime = await createUnswitchedIndexedDbPsLiteRuntime({
      ownerAddress: owner.address,
      ownerSignature,
      persistence: bundle,
      // No `gateway`: the runtime builds the default SDK client.
      dataPointFeed: {
        getDataPoint: async () => null,
        listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
      },
      ownerSyncSigner: {
        address: owner.address,
        signMessage: (message: string) => owner.signMessage({ message }),
        signAddData: (message: AddDataMessage) =>
          owner.signTypedData({
            domain: dataRegistryDomain({
              chainId: 14800,
              contracts: {} as never,
            } as never),
            types: ADD_DATA_TYPES,
            primaryType: "AddData",
            message,
          }),
        signLineageAttestation: vi.fn(),
      },
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      active: true,
      configDefaults: config as never,
    });
    try {
      await realWait(
        () => stub.posts.includes("scope.hung"),
        "the hung registry write started",
      );
      await realWait(
        () => stub.closed.length > 0,
        "the client closed the hung registry socket at the deadline",
      );

      expect(stub.closed).toEqual(["scope.hung"]);
      await realWait(
        () => stub.posts.includes("scope.ok"),
        "the next entry was uploaded in the same cycle",
      );
      expect(stub.posts).toContain("scope.ok");
    } finally {
      await runtime.syncManager?.stop();
    }
  }, 20_000);
});
