/**
 * The Lite reader's durability wiring (`durable` in `createPsLiteSyncManager`):
 * a durable reader acknowledges each import, so the writer reclaims the run's
 * spool; a reader on caller files never acknowledges, so the spool stays.
 *
 * The registry is a stateful fake over `fetch`, the same wire shape the
 * gateway answers, so the real writer publishes and the real reader imports.
 */

import { privateKeyToAccount } from "viem/accounts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { computeDataPointId } from "@opendatalabs/personal-server-ts-core/sync";
import { createMemoryStreamSyncFiles } from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  createMemoryStreamSyncReadFiles,
  type StreamSyncReadFiles,
} from "@opendatalabs/personal-server-ts-core/stream-sync-read";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import type { StreamSyncOverlaySnapshotSource } from "@opendatalabs/personal-server-ts-core/stream-sync-read";
import {
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
} from "./test-support/memory.js";
import { loadOrCreatePsLiteServerIdentity } from "./state.js";
import { createPsLiteSyncManager } from "./sync.js";

const GATEWAY = "https://gateway.local";
const SHAPE = { primaryKey: ["id"], profile: { key: null, version: "1.0.0" } };

interface FakeRow {
  scope: string;
  dataHash: string;
  metadataHash: string;
  expectedVersion: string;
  addedAt: string;
  deletedAt: null;
}

/**
 * The registry: exclusive versions per scope, the single-row read by data
 * point id, and the listing. Any other URL answers 404.
 */
function fakeRegistry(ownerAddress: string) {
  const rows = new Map<string, FakeRow>();
  // Blob storage (the vana-storage paths the writer PUTs and the reader GETs).
  const blobs = new Map<string, Uint8Array>();
  const byId = (id: string) =>
    [...rows.values()].find(
      (row) => computeDataPointId(ownerAddress, row.scope) === id,
    );
  const fetchImpl = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      if (init?.method === "PUT") {
        const bytes = new Uint8Array(
          await new Response(init.body).arrayBuffer(),
        );
        blobs.set(url.pathname, bytes);
        return Response.json({
          url: url.pathname,
          key: url.pathname,
          etag: `"${bytes.length}"`,
          size: bytes.length,
        });
      }
      if (blobs.has(url.pathname)) {
        return new Response(blobs.get(url.pathname)!);
      }
      if (init?.method === "POST") {
        const body = JSON.parse(String(init.body)) as {
          scope: string;
          dataHash: string;
          metadataHash: string;
          expectedVersion: string | number;
        };
        const current = Number(rows.get(body.scope)?.expectedVersion ?? 0);
        if (Number(body.expectedVersion) !== current + 1) {
          return Response.json(
            { latestVersion: String(current) },
            { status: 409 },
          );
        }
        rows.set(body.scope, {
          scope: body.scope,
          dataHash: body.dataHash,
          metadataHash: body.metadataHash,
          expectedVersion: String(current + 1),
          addedAt: new Date(1_800_000_000_000 + current * 1000).toISOString(),
          deletedAt: null,
        });
        return new Response(null, { status: 201 });
      }
      if (url.pathname === "/v1/data") {
        return Response.json({
          data: { dataPoints: [...rows.values()] },
          pagination: { hasMore: false, nextCursor: null },
        });
      }
      const single = url.pathname.match(/^\/v1\/data\/([^/]+)$/);
      if (single) {
        const row = byId(single[1]!);
        return row
          ? Response.json({ data: row })
          : new Response(null, { status: 404 });
      }
      return new Response(null, { status: 404 });
    },
  );
  /** What the listing feed shows the reader: every row the registry holds. */
  const feed = (): FakeRow[] => [...rows.values()];
  return { fetchImpl, feed };
}

const OWNER_KEY = `0x${"13".repeat(32)}` as const;
const OWNER_ADDRESS = privateKeyToAccount(OWNER_KEY).address;

async function startManager(options: {
  homeFiles: ReturnType<typeof createMemoryStreamSyncFiles>;
  readFiles?: StreamSyncReadFiles;
  overlay?: StreamSyncOverlaySnapshotSource;
}) {
  const owner = privateKeyToAccount(OWNER_KEY);
  const ownerSignature = await owner.signMessage({
    message: "vana-master-key-v1",
  });
  const stateStore = createMemoryPsLiteStateStore();
  const identity = await loadOrCreatePsLiteServerIdentity({
    store: stateStore,
    ownerSignature,
  });
  const manager = await createPsLiteSyncManager({
    streamSyncDeclaredStreams: () => [],
    config: ServerConfigSchema.parse({
      gateway: { url: GATEWAY },
      sync: { enabled: true },
      streamSync: { write: true, read: true },
    }),
    storage: createMemoryPsLiteStorage(),
    stateStore,
    ownerSignature,
    serverAccount: identity.account,
    ownerSyncSigner: {
      address: owner.address,
      signMessage: (message: string) => owner.signMessage({ message }),
      signAddData: async () => `0x${"22".repeat(65)}`,
      signLineageAttestation: vi.fn(),
    },
    gateway: { getServer: vi.fn().mockResolvedValue(null) } as never,
    dataPointFeed: {
      getDataPoint: async () => null,
      listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
    },
    autoStartSync: false,
    streamSyncFiles: () => options.homeFiles,
    streamSyncRead: {
      ...(options.readFiles ? { files: options.readFiles } : {}),
      ...(options.overlay ? { overlay: options.overlay } : {}),
    },
  });
  return manager;
}

/** Collect and publish run-1, import it, and count the run's spool files. */
async function publishAndImport(readFiles?: StreamSyncReadFiles) {
  const homeFiles = createMemoryStreamSyncFiles();
  const registry = fakeRegistry(OWNER_ADDRESS);
  // The registry client captures `fetch` when the manager starts: stub first.
  vi.stubGlobal("fetch", registry.fetchImpl);
  const manager = await startManager({ homeFiles, readFiles });
  const writer = manager.streamSyncWriter!;
  const reader = manager.streamSyncRead!;
  await writer.refreshControls();
  await writer.beginRun({
    runId: "run-1",
    connector: "acme",
    userConnect: false,
    observedAt: Date.now(),
    identity: "none",
    checkpointUsed: null,
  });
  await writer.declareStream("run-1", "items", SHAPE);
  await writer.append("run-1", "items", { id: "a", v: 1 });
  await writer.finishRun("run-1", { checkpointCandidate: { cursor: "run-1" } });
  await writer.publishPending();
  const spoolOf = () =>
    homeFiles.paths().filter((path) => path.startsWith("runs/run-1/")).length;
  const before = spoolOf();
  await reader.observe(registry.feed(), {
    fromStart: true,
    lastPage: true,
  });
  await reader.importPending();
  const after = spoolOf();
  await manager.closeStreamSync();
  return { before, after };
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("PS Lite stream-sync reader durability", () => {
  it("a durable reader (writer-home cache) acknowledges its import, so the writer reclaims the run's spool", async () => {
    const { before, after } = await publishAndImport();
    expect(before).toBeGreaterThan(0);
    expect(after).toBe(0);
  });

  it("rejects a caller overlay without caller read files, so no acknowledgment reaches a foreign source", async () => {
    const homeFiles = createMemoryStreamSyncFiles();
    vi.stubGlobal("fetch", fakeRegistry(OWNER_ADDRESS).fetchImpl);
    const overlay = {
      snapshot: vi.fn(),
      acknowledge: vi.fn(),
    } as never;
    await expect(startManager({ homeFiles, overlay })).rejects.toThrow(
      "streamSyncRead.overlay needs streamSyncRead.files",
    );
  });

  it("a reader on caller files never acknowledges, so the run's spool stays", async () => {
    const { before, after } = await publishAndImport(
      createMemoryStreamSyncReadFiles(),
    );
    expect(before).toBeGreaterThan(0);
    expect(after).toBe(before);
  });
});
