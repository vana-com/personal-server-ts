// The save path of a Web write: begin, batch and end a run on a Personal Server
// that has the log protocol and publish-while-collecting on, a sync manager
// running, then `handle.publish()`: what a connect-sheet save awaits.
//
// Real Lite runtime, real SQLite, the real gateway adapter over a fake gateway.
// Only the wire is simulated: every registry request and every blob PUT takes
// a fixed delay, so what overlaps and what waits for what shows in the times.
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { signOwnerMasterKey } from "@opendatalabs/personal-server-ts-core/keys";
import {
  createGatewayStreamSyncRegistry,
  createMemoryStreamSyncBlobs,
  type StreamSyncBlobs,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  controlScope,
  logScope,
  streamScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { openBetterSqlite3 } from "../../server/src/localdb/better-sqlite3-driver.js";
import { createFakeGateway } from "../../server/src/localdb/fake-gateway.js";
import { endRequest } from "../../core/src/test-utils/run-end.js";
import { startPersonalServer } from "./client.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";
import {
  createMemoryModeRecordStore,
  type ModeRecordStore,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
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

function memoryBundle(): PsLitePersistenceBundle {
  return {
    storage: createMemoryPsLiteStorage(),
    state: createMemoryPsLiteStateStore(),
    tokens: createMemoryPsLiteTokenStore(),
    accessLog: createMemoryPsLiteAccessLogStore(),
    mcpConnections: createInMemoryMcpConnectionStore(),
    mcpOAuthAuthorizations: createInMemoryMcpOAuthAuthorizationStore(),
    relayTlsIdentity: { read: () => null, write: () => {} },
  };
}

const WIRE_MS = 40;
const CONNECTOR = "acme";
const LOG = logScope(CONNECTOR, "");
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

let ownerAddress: `0x${string}`;
let ownerSignature: `0x${string}`;
beforeAll(async () => {
  const account = privateKeyToAccount(`0x${"11".repeat(32)}`);
  ownerAddress = account.address;
  ownerSignature = await signOwnerMasterKey(account);
});

const servers: Awaited<ReturnType<typeof startPersonalServer>>[] = [];
afterEach(async () => {
  for (const server of servers.splice(0)) await server.stop();
  vi.unstubAllGlobals();
});

/** One Personal Server over a timed wire, and what the wire saw. */
async function savePathWorld(autoStartSync = true) {
  const gateway = createFakeGateway({
    owner: ownerAddress,
    isTombstone: () => false,
  });
  /** Each registry commit of the connection's log that was sent, and whether it landed. */
  const commits: { readonly landed: boolean }[] = [];
  /** Holds every registry listing until `releaseListings` (see the second test). */
  let releaseListings!: () => void;
  const listingsHeld = new Promise<void>((r) => (releaseListings = r));
  let holdListings = false;
  let failListings = false;
  const reads: string[] = [];
  const timedFetch = (async (input: string, init?: RequestInit) => {
    if ((init?.method ?? "GET") === "GET") reads.push(new URL(input).pathname);
    await sleep(WIRE_MS);
    if (
      failListings &&
      (init?.method ?? "GET") === "GET" &&
      new URL(input).pathname === "/v1/data"
    )
      throw new TypeError("listing unreachable");
    if (
      holdListings &&
      (init?.method ?? "GET") === "GET" &&
      new URL(input).pathname === "/v1/data"
    )
      await listingsHeld;
    const response = await gateway.fetch(input, init);
    if (new URL(input).pathname === "/v1/data/batch") {
      const body = JSON.parse(String(init?.body)) as {
        rows: { scope: string }[];
      };
      if (body.rows.some((row) => row.scope === LOG))
        commits.push({ landed: response.ok });
    }
    return response;
  }) as unknown as typeof fetch;
  const inner = createMemoryStreamSyncBlobs();
  const segmentPuts: string[] = [];
  const blobs: StreamSyncBlobs = {
    ...inner,
    governor: inner.governor,
    async put(key, bytes) {
      await sleep(WIRE_MS);
      if (key.startsWith(`${LOG}/s-`)) segmentPuts.push(key);
      return inner.put(key, bytes);
    },
    get: inner.get,
    exists: inner.exists,
  };
  const modes: ModeRecordStore = createMemoryModeRecordStore();
  await modes.save(ownerAddress.toLowerCase(), {
    answer: "on",
    generation: 0,
    receivedAt: 1,
  });
  const logger = {
    info: () => {},
    warn: () => {},
    error: () => {},
    debug: () => {},
  } as never;
  const server = await startPersonalServer({
    ownerAddress,
    ownerSignature,
    active: autoStartSync,
    persistence: memoryBundle(),
    accountModeStore: modes,
    gateway: {
      ...createMockPsLiteGateway(),
      // Registered, so the sync manager's cycles run (`canSync`).
      getServer: async () => ({ id: "server-1" }) as never,
    },
    relay: false as const,
    logger,
    localDb: { openDriver: async () => openBetterSqlite3(":memory:") },
    streamSyncRegistry: createGatewayStreamSyncRegistry({
      gatewayUrl: "https://gateway.test",
      ownerAddress,
      fetch: timedFetch,
    }),
    streamSyncBlobs: blobs,
    streamSyncPublishWhileCollecting: true,
    streamSyncDeclaredStreams: () => ["items"],
    streamSyncDeclarations: (connector: string) => ({
      connector,
      version: "1",
      streams: [
        {
          name: "items",
          semantics: "mutable_state" as const,
          primaryKey: ["id"],
        },
      ],
    }),
    configDefaults: {
      gateway: { url: "https://gateway.local" },
      sync: { enabled: autoStartSync },
    },
  } as never);
  servers.push(server);
  /** What a connect-sheet save does before it awaits `publish()`. */
  const collect = async (runId: string, connector = CONNECTOR) => {
    await server.streamSyncIntake!.begin(runId, {
      connector,
      artifactDigest: connector,
      join: true,
      owner: { address: ownerAddress, leaseId: null },
      observedAt: Date.now(),
      connect: true,
    });
    await server.streamSyncIntake!.batch(runId, {
      batch: 0,
      records: [
        { stream: "items", data: { id: "1", value: runId } },
        { stream: "items", data: { id: "2" } },
      ],
    });
    await server.streamSyncIntake!.end(
      runId,
      endRequest({
        live: ["items"],
        provenFullStreams: ["items"],
        lastBatch: 0,
      }),
    );
  };
  return {
    server,
    collect,
    commits,
    segmentPuts,
    gateway,
    reads,
    /** From now on every registry listing rejects. */
    failListings: () => {
      failListings = true;
    },
    /** From now on a registry listing answers only after the returned release. */
    holdListings: () => {
      holdListings = true;
      return releaseListings;
    },
  };
}

describe("the save path of a Web write", () => {
  it("admits and publishes a first full collection with one registry GET and a warm one with none", async () => {
    const { server, collect, reads, segmentPuts, commits } =
      await savePathWorld(false);
    for (const id of ["first", "warm"]) {
      reads.length = 0;
      await collect(id);
      await server.publish();
      // The first save asks the registry once whether the connection already
      // exists (the join gate); a joined device then admits without a GET.
      expect(reads).toHaveLength(id === "first" ? 1 : 0);
    }
    expect(segmentPuts).toHaveLength(2);
    expect(commits).toEqual([{ landed: true }, { landed: true }]);
  });

  it("publishes a save's records once: one segment PUT and one registry commit", async () => {
    const { server, collect, commits, segmentPuts } = await savePathWorld();
    await collect("run-1");
    const receipt = await server.publish();
    expect(receipt.publications.map((p) => p.runIds)).toEqual([["run-1"]]);
    // A second publish waits for any publish still running, so what it sees
    // afterwards is everything the save sent.
    await server.publish();
    expect(segmentPuts).toHaveLength(1);
    expect(commits).toHaveLength(1);
  });

  it("rejects a save whose registry commit fails", async () => {
    const { server, collect, commits, gateway } = await savePathWorld();
    gateway.beforeBatch = () => {
      throw new TypeError("commit timed out");
    };
    await collect("run-1");
    await expect(server.publish()).rejects.toThrow(/no reply/);
    expect(commits).toEqual([]);
  });

  describe("when a sibling connection's registry commit fails", () => {
    const SIBLING = "beta";
    async function withFailingSibling() {
      // No background cycle: it could publish the caller's run before the
      // publish under test, leaving that publish nothing to receipt.
      const world = await savePathWorld(false);
      world.gateway.beforeBatch = (call) => {
        if (call.body.rows.some((row) => row.scope === logScope(SIBLING, "")))
          throw new TypeError("commit timed out");
      };
      await world.collect("run-own");
      await world.collect("run-sibling", SIBLING);
      return world;
    }

    it("resolves for the caller's own connection and returns every connection's result", async () => {
      const { server } = await withFailingSibling();
      const own = controlScope(CONNECTOR, "");
      const receipt = await server.publish({ connections: [own] });
      expect(receipt.outcome).toBe("published");
      expect(receipt.publications.map((p) => p.runIds)).toEqual([["run-own"]]);
      expect(
        receipt.connections.map((c) => [c.connectionId, c.outcome]),
      ).toEqual(
        expect.arrayContaining([
          [own, "published"],
          [controlScope(SIBLING, ""), "failed"],
        ]),
      );
      expect(
        receipt.connections.find(
          (c) => c.connectionId === controlScope(SIBLING, ""),
        )?.error,
      ).toMatch(/no reply/);
    });

    it("keeps the caller's acknowledged receipt when the fallback's registry listing rejects", async () => {
      const { server, failListings } = await withFailingSibling();
      failListings();
      const own = controlScope(CONNECTOR, "");
      const receipt = await server.publish({ connections: [own] });
      expect(receipt.outcome).toBe("published");
      expect(receipt.publications.map((p) => p.runIds)).toEqual([["run-own"]]);
    });

    it("keeps the caller's receipt when its own log holds a row this build cannot read", async () => {
      const { server, gateway } = await withFailingSibling();
      // A later build reserved another `~` name beside the caller's log.
      gateway.write(streamScope(CONNECTOR, "", "~future"), {
        dataHash: `0x${"ab".repeat(32)}`,
        metadataHash: `0x${"cd".repeat(32)}`,
      });
      const own = controlScope(CONNECTOR, "");
      const receipt = await server.publish({ connections: [own] });
      expect(receipt.outcome).toBe("published");
      expect(receipt.publications.map((p) => p.runIds)).toEqual([["run-own"]]);
      const mine = receipt.connections.find((c) => c.connectionId === own);
      expect(mine?.outcome).toBe("published");
      // The fallback does not apply the caller's connection.
      expect(mine?.error).toBeUndefined();
    });

    it("still rejects for the sibling when the caller names it", async () => {
      const { server } = await withFailingSibling();
      await expect(
        server.publish({ connections: [controlScope(SIBLING, "")] }),
      ).rejects.toThrow(/no reply/);
    });

    it("still rejects a publish that names no connection", async () => {
      const { server } = await withFailingSibling();
      await expect(server.publish()).rejects.toThrow(/no reply/);
    });
  });

  it("resolves publish() at the registry commit, with every registry listing still unanswered", async () => {
    const { server, collect, commits, holdListings } = await savePathWorld();
    const release = holdListings();
    // Always release the fake wire, including on an intake failure.
    try {
      await collect("run-1");
      // A publish that waited for the cycle's listing and apply would wait here
      // for ever; the bound only turns that into a failure.
      const outcome = await Promise.race([
        server.publish().then(() => "resolved"),
        sleep(5000).then(() => "waited for a listing"),
      ]);
      release();
      expect(outcome).toBe("resolved");
      expect(commits).toHaveLength(1);
    } finally {
      release();
    }
  });
});
