import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import http from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { createGatewayClient } from "@opendatalabs/vana-sdk/browser";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";

import { uploadAll, type UploadWorkerDeps } from "./upload.js";
import { createUploadStateTracker } from "../upload-state.js";
import { withCancellableRegistration } from "../cancellable-gateway.js";
import { createVanaSyncStorageAdapter } from "../../storage/adapters/vana.js";
import { ServerConfigSchema } from "../../schemas/server-config.js";
import type { ServerAccount } from "../../keys/server-account.js";
import type { IndexEntry } from "../../storage/index/types.js";
import type { DataStoragePort } from "../../ports/index.js";
import type { ServerSigner } from "../../signing/signer.js";
import type { Logger } from "../../logger/index.js";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12" as const;
const DEADLINE_MS = 400;

/**
 * A server that holds the connection open and answers nothing until the
 * client goes away; it records which sockets the client closed.
 */
function startServer(
  onRequest: (req: http.IncomingMessage) => "hang" | object,
) {
  const closed: string[] = [];
  const seen: string[] = [];
  const sockets = new Set<Socket>();
  const server = http.createServer((req, res) => {
    const path = req.url ?? "";
    seen.push(`${req.method} ${path}`);
    req.resume();
    req.on("end", () => {
      const reply = onRequest(req);
      if (reply === "hang") {
        res.on("close", () => closed.push(path));
        return;
      }
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(reply));
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  return new Promise<{
    url: string;
    closed: string[];
    seen: string[];
    stop(): Promise<void>;
  }>((resolve) =>
    server.listen(0, "127.0.0.1", () =>
      resolve({
        url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
        closed,
        seen,
        async stop() {
          for (const socket of sockets) socket.destroy();
          await new Promise((done) => server.close(done));
        },
      }),
    ),
  );
}

function entry(n: number): IndexEntry {
  const collectedAt = `2026-11-07T10:0${n}:00Z`;
  return {
    id: n,
    fileId: null,
    schemaId: null,
    path: `scope.${n}/${collectedAt}.json`,
    scope: `scope.${n}`,
    collectedAt,
    createdAt: collectedAt,
    sizeBytes: 1024,
    version: 1,
    dataPointId: null,
  };
}

function hostFor(
  rows: IndexEntry[],
  parts: Pick<UploadWorkerDeps, "storageAdapter" | "gateway">,
) {
  const storage: Partial<DataStoragePort> = {
    findUnsynced: vi.fn(() => rows.filter((row) => row.dataPointId === null)),
    updateDataPointId: vi.fn((path: string, id: string | null) => {
      const row = rows.find((r) => r.path === path);
      if (row) row.dataPointId = id;
      return true;
    }),
    updateEntryVersion: vi.fn().mockReturnValue(true),
    readEnvelope: vi.fn(
      async (scope: string, collectedAt: string) =>
        ({
          version: "1.0",
          scope,
          collectedAt,
          data: { ok: true },
        }) as DataFileEnvelope,
    ),
  };
  const uploadState = createUploadStateTracker();
  const deps: UploadWorkerDeps = {
    ...parts,
    storage: storage as DataStoragePort,
    signer: {
      signAddData: vi.fn().mockResolvedValue("0xsig"),
      signLineageAttestation: vi.fn().mockResolvedValue("0xsig"),
    } as unknown as ServerSigner,
    masterKey: new Uint8Array(65).fill(0xaa),
    serverOwner: OWNER,
    logger: {
      info: vi.fn(),
      error: vi.fn(),
      warn: vi.fn(),
      debug: vi.fn(),
    } as unknown as Logger,
    uploadState,
  };
  return { deps, uploadState };
}

const account: ServerAccount = {
  address: OWNER,
  publicKey: `0x04${"00".repeat(64)}` as `0x${string}`,
  signMessage: async () => "0xsig" as `0x${string}`,
  signTypedData: async () => "0xsig" as `0x${string}`,
};

const eventually = async (check: () => boolean) => {
  for (let i = 0; i < 100 && !check(); i++)
    await new Promise((r) => setTimeout(r, 20));
};

describe("attempt deadline closes the request in flight", () => {
  const stops: Array<() => Promise<void>> = [];
  beforeEach(() => vi.spyOn(console, "error").mockImplementation(() => {}));
  afterEach(async () => {
    vi.restoreAllMocks();
    for (const stop of stops.splice(0)) await stop();
  });

  it("cancels a storage PUT that never answers and uploads the next entry in the same cycle", async () => {
    const [a, b] = [entry(1), entry(2)];
    const storage = await startServer((req) =>
      (req.url ?? "").includes(a.scope)
        ? "hang"
        : { url: "https://storage.test/blob", size: 1, key: "k", etag: "e" },
    );
    stops.push(storage.stop);
    const registry = await startServer(() => ({
      dataPointId: `0x${"de".repeat(32)}`,
      expectedVersion: "1",
    }));
    stops.push(registry.stop);
    const config = ServerConfigSchema.parse({
      storage: { backend: "vana", config: { vana: { apiUrl: storage.url } } },
    });
    const { deps, uploadState } = hostFor([a, b], {
      storageAdapter: createVanaSyncStorageAdapter({
        config,
        serverOwner: OWNER,
        serverAccount: account,
      }),
      gateway: withCancellableRegistration(
        createGatewayClient(registry.url),
        registry.url,
      ),
    });

    const results = await uploadAll(deps, { attemptDeadlineMs: DEADLINE_MS });
    await eventually(() => storage.closed.length > 0);

    expect(results.map((r) => r.path)).toEqual([b.path]);
    expect(uploadState.snapshot().retrying).toEqual([
      expect.objectContaining({
        path: a.path,
        lastError: expect.stringMatching(/deadline/i),
      }),
    ]);
    expect(storage.closed).toHaveLength(1);
    expect(storage.closed[0]).toContain(a.scope);
  });

  it("cancels a registry write that never answers and moves on", async () => {
    const [a, b] = [entry(1), entry(2)];
    const storage = await startServer(() => ({
      url: "https://storage.test/blob",
      size: 1,
      key: "k",
      etag: "e",
    }));
    stops.push(storage.stop);
    const registry = await startServer(() => "hang");
    stops.push(registry.stop);
    // The registry hangs for every write; entry a is the one in flight at the
    // deadline, then b gets its own attempt and deadline.
    const config = ServerConfigSchema.parse({
      storage: { backend: "vana", config: { vana: { apiUrl: storage.url } } },
    });
    const { deps, uploadState } = hostFor([a, b], {
      storageAdapter: createVanaSyncStorageAdapter({
        config,
        serverOwner: OWNER,
        serverAccount: account,
      }),
      gateway: withCancellableRegistration(
        createGatewayClient(registry.url),
        registry.url,
      ),
    });

    await uploadAll(deps, { attemptDeadlineMs: DEADLINE_MS });
    await eventually(() => registry.closed.length >= 2);

    expect(
      uploadState
        .snapshot()
        .retrying.map((r) => r.path)
        .sort(),
    ).toEqual([a.path, b.path]);
    // Both hung POSTs were closed by the client, not left open.
    expect(registry.closed).toHaveLength(2);
  });
});
