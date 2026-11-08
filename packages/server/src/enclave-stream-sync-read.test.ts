import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { privateKeyToAccount } from "viem/accounts";
import { MASTER_KEY_MESSAGE } from "@opendatalabs/vana-sdk/node";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  bindStreamSyncHome,
  createMemoryStreamSyncFiles,
  createStreamSyncKeyPorts,
  StreamSyncWriter,
  type SignedRegistryPost,
  type StreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  StreamSyncReadService,
  type MirrorFeedRow,
} from "@opendatalabs/personal-server-ts-core/stream-sync-read";
import {
  controlScope,
  parseScope,
  type ControlRead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type * as Bootstrap from "./bootstrap.js";
import { runEnclaveMain } from "./enclave-main.js";

const host = vi.hoisted(() => ({
  createServer: vi.fn(),
  createStorageAdapter: vi.fn(),
  loadConfig: vi.fn(),
  listenHttpServer: vi.fn(),
  getServer: vi.fn(),
}));

// Replace the config loader, listening socket, and network boundaries. The
// entrypoint still supplies the enclave profile, owner signature, and public
// account to the actual createServer. The gateway is deliberately
// unregistered, keeping the background sync loop idle while this test feeds
// the actual read service.
vi.mock("./bootstrap.js", async (importOriginal) => {
  const actual = await importOriginal<typeof Bootstrap>();
  host.createServer.mockImplementation(
    (
      config: Bootstrap.ServerContext["config"],
      options: Bootstrap.CreateServerOptions,
    ) =>
      actual.createServer(config, {
        ...options,
        gatewayClient: {
          getServer: host.getServer,
        } as unknown as NonNullable<
          Bootstrap.CreateServerOptions["gatewayClient"]
        >,
      }),
  );
  return { ...actual, createServer: host.createServer };
});
vi.mock("./config/index.js", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  loadConfig: host.loadConfig,
}));
vi.mock("./listen.js", () => ({
  listenHttpServer: host.listenHttpServer,
}));
vi.mock(
  "@opendatalabs/personal-server-ts-core/storage/adapters",
  async (importOriginal) => ({
    ...(await importOriginal<Record<string, unknown>>()),
    createVanaSyncStorageAdapter: host.createStorageAdapter,
  }),
);

const OWNER = privateKeyToAccount(`0x${"11".repeat(32)}`);
const MASTER_SIGNATURE = await OWNER.signMessage({
  message: MASTER_KEY_MESSAGE,
});
const SERVER = privateKeyToAccount(`0x${"22".repeat(32)}`);
const TOKEN = "synthetic-hosted-reader-token";
const ORIGIN = "http://127.0.0.1:18080";
const GATEWAY = "https://hosted-reader-gateway.invalid";
const STORAGE = "https://hosted-reader-storage.invalid";
const OBSERVED_AT = Date.parse("2026-11-08T00:00:00.000Z");
const ITEMS = [
  { id: "a", value: "written by the real writer" },
  { id: "b", value: "read by the hosted enclave" },
];
const CONVERSATION = {
  id: "synthetic-conversation",
  title: "A synthetic conversation",
  create_time: "2026-11-01T00:00:00.000Z",
  update_time: "2026-11-02T00:00:00.000Z",
  current_node: "synthetic-message",
  message_count_on_current_branch: 1,
};
const MESSAGE = {
  id: "synthetic-message",
  conversation_id: CONVERSATION.id,
  parent_id: null,
  role: "user",
  content: "A synthetic message from a writer-generated part",
  content_type: "text",
  model_slug: null,
  create_time: "2026-11-01T00:00:00.000Z",
  on_current_branch: true,
};

/** Memory network ports, not a test publisher: only StreamSyncWriter makes heads. */
class PublishedFixture {
  readonly rows = new Map<string, MirrorFeedRow>();
  readonly blobs = new Map<string, Uint8Array>();
  readonly posts: SignedRegistryPost[] = [];
  readonly puts: string[] = [];
  readonly downloads: string[] = [];
  readonly serverWrites: string[] = [];

  private controlRead(scope: string): ControlRead {
    const row = this.rows.get(scope);
    return row
      ? {
          found: true,
          version: Number(row.expectedVersion),
          dataHash: row.dataHash,
          metadataHash: row.metadataHash,
          deleted: Boolean(row.deletedAt),
        }
      : { found: false };
  }

  readonly registry: StreamSyncRegistry = {
    read: async (scope) => this.controlRead(scope),
    listControlRows: async () =>
      [...this.rows.keys()]
        .filter((scope) => parseScope(scope)?.kind === "control")
        .map((scope) => ({ scope, read: this.controlRead(scope) })),
    post: async (request) => {
      const previous = this.rows.get(request.scope);
      if (
        Number(request.expectedVersion) !==
        Number(previous?.expectedVersion ?? 0) + 1
      ) {
        return {
          kind: "conflict",
          latestVersion: previous?.expectedVersion ?? null,
        };
      }
      this.posts.push(request);
      this.rows.set(request.scope, {
        scope: request.scope,
        dataHash: request.dataHash,
        metadataHash: request.metadataHash,
        expectedVersion: request.expectedVersion,
        addedAt: new Date(OBSERVED_AT + this.posts.length * 1000).toISOString(),
        deletedAt: null,
      });
      return { kind: "committed" };
    },
  };

  readonly writer = new StreamSyncWriter({
    ownerAddress: OWNER.address,
    registry: this.registry,
    blobs: {
      put: async (key, bytes) => {
        this.puts.push(key);
        this.blobs.set(key, bytes.slice());
      },
      get: async (key) => this.blobs.get(key)?.slice() ?? null,
    },
    home: bindStreamSyncHome({
      ownerAddress: OWNER.address,
      network: `vana:14800:${GATEWAY}`,
      open: () => createMemoryStreamSyncFiles(),
    }),
    keys: createStreamSyncKeyPorts(MASTER_SIGNATURE),
    // The memory registry does not verify AddData signatures. This port signs
    // the exact writer request with a synthetic owner; no hosted signer exists.
    signer: {
      signAddData: async (message) =>
        OWNER.signMessage({
          message: JSON.stringify({
            ...message,
            expectedVersion: String(message.expectedVersion),
          }),
        }),
    },
    now: () => OBSERVED_AT,
  });

  async publish(
    connector: string,
    streams: Record<string, Record<string, unknown>[]>,
    profileKey: string | null,
  ) {
    const runId = `hosted-${connector}`;
    await this.writer.refreshControls();
    await this.writer.beginRun({
      runId,
      connector,
      userConnect: true,
      issue: { wantFull: true },
      observedAt: OBSERVED_AT,
    });
    for (const [stream, records] of Object.entries(streams)) {
      await this.writer.declareStream(runId, stream, {
        primaryKey: ["id"],
        profile: { key: profileKey, version: "1.0.0" },
      });
      for (const record of records) {
        expect(await this.writer.append(runId, stream, record)).toBe("spooled");
      }
    }
    await this.writer.finishRun(runId, {
      checkpointCandidate: { complete: true },
    });
    const report = await this.writer.cycle();
    expect(report.runs).toContainEqual(
      expect.objectContaining({
        runId,
        phase: "done",
        outcome: expect.objectContaining({ kind: "checkpointed" }),
      }),
    );
  }

  /** The public storage-adapter boundary used by createServer, backed by writer bytes. */
  storageAdapter() {
    const keyFromUrl = (url: string) =>
      decodeURIComponent(new URL(url).pathname.slice(1));
    const refuseWrite = async (operation: string): Promise<never> => {
      this.serverWrites.push(operation);
      throw new Error(`Hosted reader attempted ${operation}`);
    };
    const download = async (url: string) => {
      const key = keyFromUrl(url);
      this.downloads.push(key);
      const bytes = this.blobs.get(key);
      if (!bytes) throw new Error(`Missing fixture blob: ${key}`);
      return bytes.slice();
    };
    return {
      urlForKey: (key: string) => `${STORAGE}/${encodeURIComponent(key)}`,
      download,
      downloadBounded: (url: string) => download(url),
      exists: async (url: string) => this.blobs.has(keyFromUrl(url)),
      upload: () => refuseWrite("storage upload"),
      delete: () => refuseWrite("storage delete"),
    };
  }

  deleteConnection(connector: string) {
    const scope = controlScope(connector, "");
    const previous = this.rows.get(scope);
    if (!previous) throw new Error(`Writer did not publish ${scope}`);
    this.rows.set(scope, {
      ...previous,
      expectedVersion: String(Number(previous.expectedVersion) + 1),
      deletedAt: "2026-11-08T01:00:00.000Z",
    });
  }
}

describe("hosted enclave stream-sync reader", () => {
  let root: string;
  let context: Bootstrap.ServerContext | undefined;
  let service: StreamSyncReadService | undefined;
  let fixture: PublishedFixture;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "hosted-stream-reader-"));
    fixture = new PublishedFixture();
    service = undefined;
    context = undefined;
    host.loadConfig.mockResolvedValue(
      ServerConfigSchema.parse({
        server: { port: 18080, origin: ORIGIN },
        logging: { level: "error" },
        gateway: { url: GATEWAY },
        // Deliberately true: the enclave bootstrap guard, not this test's
        // configuration, must prevent writer construction and intake routes.
        streamSync: { read: false, write: true },
        inference: { e2ee: false },
      }),
    );
    host.getServer.mockResolvedValue(null);
    host.listenHttpServer.mockResolvedValue({ close: vi.fn() });
    host.createStorageAdapter.mockImplementation(() =>
      fixture.storageAdapter(),
    );
    vi.spyOn(process, "on").mockImplementation(() => process);
    const open = StreamSyncReadService.open;
    vi.spyOn(StreamSyncReadService, "open").mockImplementation(
      async (options) => {
        service = await open.call(StreamSyncReadService, options);
        return service;
      },
    );
    // Any unexpected outbound write is observable even when background code
    // catches the exception. Tombstone lookups outside the seeded stream feed
    // return absent. No request may leave this test process.
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(input, init);
        if (request.method !== "GET" && request.method !== "HEAD") {
          fixture.serverWrites.push(`${request.method} ${request.url}`);
          throw new Error("Unexpected hosted network write");
        }
        if (new URL(request.url).origin !== GATEWAY) {
          throw new Error(`Unexpected hosted network read: ${request.url}`);
        }
        return new Response(null, { status: 404 });
      }),
    );
    vi.stubEnv("VANA_OWNER_PRIVATE_KEY", undefined);
    vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", MASTER_SIGNATURE);
    vi.stubEnv("PS_ACCESS_TOKEN", TOKEN);
    vi.stubEnv("PS_SERVER_ADDRESS", SERVER.address);
    vi.stubEnv("PS_SERVER_PUBLIC_KEY", SERVER.publicKey);
    vi.stubEnv("ENCLAVE_AGENT_URL", "http://hosted-reader-agent.invalid");
    vi.stubEnv("PERSONAL_SERVER_ROOT_PATH", root);
    vi.stubEnv("GATEWAY_URL", GATEWAY);
    vi.stubEnv("STORAGE_API_URL", STORAGE);
    vi.stubEnv("CHAIN_ID", "14800");
    vi.stubEnv("SYNC_ENABLED", "true");
    vi.stubEnv("PS_STREAM_SYNC_READ", "true");
    vi.stubEnv("VERCEL_PROTECTION_BYPASS", undefined);
    vi.stubEnv("PS_HYDRATE_SCOPES", undefined);
    vi.stubEnv("CLOUD_MODE", undefined);
    for (const name of [
      "DATA_REGISTRY_CONTRACT",
      "DATA_PORTABILITY_SERVER_CONTRACT",
      "DATA_PORTABILITY_GRANTEES_CONTRACT",
      "DATA_PORTABILITY_PERMISSIONS_CONTRACT",
    ])
      vi.stubEnv(name, undefined);
  });

  afterEach(async () => {
    await context?.cleanup();
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.clearAllMocks();
    await rm(root, { recursive: true, force: true });
  });

  async function boot() {
    await runEnclaveMain();
    const result = host.createServer.mock.results.at(-1);
    if (!result || result.type !== "return")
      throw new Error("createServer did not return");
    context = (await result.value) as Bootstrap.ServerContext;
    expect(host.createServer).toHaveBeenCalledWith(
      expect.objectContaining({
        streamSync: { read: Boolean(service), write: true },
      }),
      expect.objectContaining({
        profile: "enclave",
        ownerSignature: MASTER_SIGNATURE,
      }),
    );
    expect(process.env.VANA_MASTER_KEY_SIGNATURE).toBeUndefined();
    expect(context.serverAccount?.address).toBe(SERVER.address);
    expect(context.streamSyncWriter).toBeNull();
    expect(
      host.createStorageAdapter.mock.calls.every(
        ([options]) => options.reads === "public",
      ),
    ).toBe(true);
    return context;
  }

  async function importPublishedRows() {
    if (!service)
      throw new Error("Hosted entrypoint did not construct the reader");
    // This is the explicit feed boundary of this test. It does not claim to
    // cover the gateway pagination/cursor adapter or download worker.
    await service.observe([...fixture.rows.values()], {
      fromStart: true,
      lastPage: true,
    });
    await service.importPending();
    expect(service.status().issues).toEqual([]);
  }

  async function request(path: string, method = "GET") {
    if (!context) throw new Error("Server has not booted");
    return context.app.request(`${ORIGIN}${path}`, {
      method,
      headers: { authorization: `Bearer ${TOKEN}` },
    });
  }

  it("reads writer-generated heads and parts through the hosted signature path without a writer", async () => {
    await fixture.publish("acme", { items: ITEMS }, null);
    await fixture.publish(
      "chatgpt",
      {
        conversations: [CONVERSATION],
        messages: [MESSAGE],
      },
      "chatgpt",
    );
    const writerPosts = fixture.posts.length;
    const writerPuts = fixture.puts.length;
    expect(writerPosts).toBe(5); // Two control rows and three stream heads.
    expect(writerPuts).toBeGreaterThanOrEqual(6); // A head and a part per stream.
    expect(fixture.puts.some((key) => key.includes("/h-"))).toBe(true);
    expect(fixture.puts.some((key) => key.includes("/g1-p-"))).toBe(true);

    const server = await boot();
    expect(server.config.streamSync.read).toBe(true);
    await importPublishedRows();

    const logical = await request("/v1/data/pdpp.acme.items");
    expect(logical.status).toBe(200);
    const envelope = await logical.json();
    expect(envelope).toMatchObject({
      version: "1.0",
      scope: "pdpp.acme.items",
    });
    expect(
      envelope.data.records.sort((a: { id: string }, b: { id: string }) =>
        a.id.localeCompare(b.id),
      ),
    ).toEqual(ITEMS);
    expect(
      fixture.downloads.some((key) => key.startsWith("pdpp.acme~.items/h-")),
    ).toBe(true);
    expect(
      fixture.downloads.some((key) => key.startsWith("pdpp.acme~.items/g1-p-")),
    ).toBe(true);

    const legacy = await request("/v1/data/chatgpt.conversations");
    expect(legacy.status).toBe(200);
    const projected = await legacy.json();
    expect(projected.scope).toBe("chatgpt.conversations");
    expect(projected.data.conversations).toHaveLength(1);
    expect(JSON.stringify(projected.data)).toContain(CONVERSATION.title);
    expect(JSON.stringify(projected.data)).toContain(MESSAGE.content);
    expect(projected.data).not.toHaveProperty("records");

    const status = await request("/v1/stream-sync/read-status");
    expect(status.status).toBe(200);
    expect(await status.json()).toMatchObject({
      listed: true,
      issues: 0,
      streams: expect.arrayContaining([
        { connector: "acme", ns: "", stream: "items", records: ITEMS.length },
      ]),
    });
    const writeRoutes = server.app.routes.filter(
      ({ path }) =>
        /\/stream-sync(?:\/|$)/.test(path) &&
        !path.includes("/read-status") &&
        !path.startsWith("/v1/stream-sync/seed") &&
        !path.endsWith("/*"),
    );
    expect(writeRoutes).toEqual([]);
    const localFiles = await readdir(root, { recursive: true });
    expect(
      localFiles.some((path) =>
        /(?:^|[/\\])(?:runs|outbox)(?:[/\\]|$)/.test(path),
      ),
    ).toBe(false);
    expect(fixture.posts).toHaveLength(writerPosts);
    expect(fixture.puts).toHaveLength(writerPuts);
    expect(fixture.serverWrites).toEqual([]);
  });

  it("leaves the reader off when the hosted switch is absent", async () => {
    vi.stubEnv("PS_STREAM_SYNC_READ", undefined);
    const server = await boot();
    expect(server.config.streamSync.read).toBe(false);
    expect(StreamSyncReadService.open).not.toHaveBeenCalled();
    const status = await request("/v1/stream-sync/read-status");
    expect(status.status).toBe(404);
    expect(await status.json()).toMatchObject({
      error: { code: 404, errorCode: "STREAM_SYNC_READ_OFF" },
    });
    expect(fixture.downloads).toEqual([]);
    expect(fixture.serverWrites).toEqual([]);
  });

  it("does not construct a writer or expose intake even when persisted write is true", async () => {
    const server = await boot();
    expect(server.config.streamSync.write).toBe(true);
    expect(server.streamSyncWriter).toBeNull();
    // The seed routes and the /v1/stream-sync/* admission middleware are mounted
    // on every profile; they are checked by the probes below, not by route list.
    expect(
      server.app.routes.filter(
        ({ path }) =>
          /\/stream-sync(?:\/|$)/.test(path) &&
          !path.includes("/read-status") &&
          !path.startsWith("/v1/stream-sync/seed") &&
          !path.endsWith("/*"),
      ),
    ).toEqual([]);
    const before = await readdir(root, { recursive: true });
    const seedBody =
      [
        JSON.stringify({
          primaryKey: ["id"],
          profile: { key: null, version: "1.0.0" },
          records: 1,
        }),
        JSON.stringify({ id: "probe" }),
      ].join("\n") + "\n";
    // Probe the seed write route: the enclave has no seed port, so it answers 404.
    const seedPut = await server.app.request(
      `${ORIGIN}/v1/stream-sync/seed/acme/items`,
      {
        method: "PUT",
        headers: {
          authorization: `Bearer ${TOKEN}`,
          "content-type": "application/x-ndjson",
        },
        body: seedBody,
      },
    );
    expect(seedPut.status).toBe(404);
    expect(await seedPut.json()).toMatchObject({
      error: { errorCode: "STREAM_SYNC_WRITE_OFF" },
    });
    // Probe an intake write route the route filter cannot see: it is absent here.
    const runPut = await server.app.request(
      `${ORIGIN}/v1/stream-sync/runs/hosted-probe`,
      {
        method: "PUT",
        headers: {
          authorization: `Bearer ${TOKEN}`,
          "content-type": "application/json",
        },
        body: "{}",
      },
    );
    expect(runPut.ok).toBe(false);
    // Nothing staged, written to the home, or sent to storage or the gateway.
    expect(await readdir(root, { recursive: true })).toEqual(before);
    const localFiles = await readdir(root, { recursive: true });
    expect(
      localFiles.some((path) =>
        /(?:^|[/\\])(?:runs|outbox|seed)(?:[/\\]|$)/.test(path),
      ),
    ).toBe(false);
    expect(fixture.puts).toEqual([]);
    expect(fixture.posts).toEqual([]);
    expect(fixture.serverWrites).toEqual([]);
  });

  it("stops serving a writer-generated legacy projection after its connection is deleted", async () => {
    await fixture.publish(
      "chatgpt",
      {
        conversations: [CONVERSATION],
        messages: [MESSAGE],
      },
      "chatgpt",
    );
    await boot();
    await importPublishedRows();
    expect((await request("/v1/data/chatgpt.conversations")).status).toBe(200);

    fixture.deleteConnection("chatgpt");
    await importPublishedRows();
    expect(
      await service!.resolve({
        scope: "chatgpt.conversations",
        connection: null,
        cursor: null,
        legacyFile: true,
      }),
    ).toEqual({ kind: "unavailable", reason: "deleted" });
    const response = await request("/v1/data/chatgpt.conversations");
    expect(response.status).not.toBe(200);
    expect(await response.text()).not.toContain(CONVERSATION.title);
    expect(fixture.serverWrites).toEqual([]);
  });

  it("does not project a legacy name from a head whose profile key is not its binding", async () => {
    // Connector "chatgpt" under profile key "chatgpt-export": the chatgpt legacy
    // binding is keyed by "chatgpt", so the projector must refuse this head.
    await fixture.publish(
      "chatgpt",
      { conversations: [CONVERSATION], messages: [MESSAGE] },
      "chatgpt-export",
    );
    await boot();
    await importPublishedRows();
    // A refused projection may fail mid-body; either way the title must not appear.
    const served = await (async () => {
      try {
        const response = await request("/v1/data/chatgpt.conversations");
        return response.status === 200
          ? await response.text()
          : `status ${response.status}`;
      } catch {
        return "projection error";
      }
    })();
    expect(served).not.toContain(CONVERSATION.title);
    expect(fixture.serverWrites).toEqual([]);
  });

  // Coverage boundary: legacyFile: true above exercises real reader
  // eligibility, not a disk-backed fallback. A separate real-file test needs
  // a positive-control HTTP read of the fallback before tombstoning.
});
