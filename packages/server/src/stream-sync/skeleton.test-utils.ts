/**
 * Walking skeleton of whole-file stream sync: ONE record flows through the
 * real path on three hosts.
 *
 *   connector run -> run intake (begin -> batches -> end) -> publish
 *     -> read on the full server
 *     -> read on PS-Lite as the phone hosts it
 *     -> read on PS-Lite as the Account frame hosts it
 *   and back: PS-Lite writes, the full server (and the frame) read.
 *
 * Real: the stream-sync writer, publish driver, encryption, heads and parts,
 * the read service (mirror, import, view, legacy `{records}` projection), the
 * production storage adapter against a local write-once blob store, the full
 * server's filesystem adapters and Lite's IndexedDB adapter.
 *
 * Stubbed (each marked `SKELETON STUB`): the intake adapter, the connector
 * fixture, the registry (in-memory, gateway rules) and its listing feed, and
 * the phone and frame hosts' writers (their reads run through the real
 * PS-Lite startup code). The list is in the hand-back.
 *
 * Run: `npm run e2e:stream-sync-skeleton` (needs `streamSync.write`).
 */

import { createHash } from "node:crypto";
import type { GatewayClient } from "@opendatalabs/vana-sdk/browser";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { privateKeyToAccount } from "viem/accounts";
import { buildPersonalServerLiteOwnerBindingMessage } from "@opendatalabs/vana-sdk/protocol/personal-server-lite-owner-binding";
import {
  canonicalJson,
  streamMasterKeyFromSignature,
  type JsonValue,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  StreamSyncWriter,
  createStreamSyncKeyPorts,
  createGatewayStreamSyncRegistry,
  type StreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  createStreamSyncReadKeys,
  StreamSyncReadService,
} from "@opendatalabs/personal-server-ts-core/stream-sync-read";
import {
  computeDataPointId,
  createGatewayDataPointFeed,
  downloadAll,
} from "@opendatalabs/personal-server-ts-core/sync";
import { createMemoryDataStorage } from "@opendatalabs/personal-server-ts-core/test-utils";
import type { StorageAdapter } from "@opendatalabs/personal-server-ts-core/storage/adapters";
import type { Logger } from "@opendatalabs/personal-server-ts-core/logger";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  createBearerTokenPsLiteAuth,
  createIndexedDbPsLiteRuntime,
  createIndexedDbStreamSyncFiles,
} from "@opendatalabs/personal-server-ts-lite";
import { createMockPsLiteGateway } from "../../../lite/src/test-support/gateway.js";
import { createFsStreamSyncFiles } from "./fs-files.js";
import { createFsStreamSyncReadFiles } from "../stream-sync-read/fs-files.js";
import {
  OWNER,
  OWNER_KEY,
  SERVER_KEY,
  SHAPE,
  accountSigner,
  createFakeStreamSyncRegistry,
  interpose,
  startLocalStorage,
  storageBlobs,
} from "./oracle.test-utils.js";

/**
 * The owner's signature over the owner-binding message: what every real host
 * (PS-Lite checks it) derives the stream master key from.
 */
const OWNER_SIGNATURE = await privateKeyToAccount(OWNER_KEY).signMessage({
  message: buildPersonalServerLiteOwnerBindingMessage(OWNER),
});

const CONNECTOR = "skeleton";
const STREAM = "items";
const ACCOUNT_ID = "skeleton-account";
const T0 = Date.UTC(2026, 10, 1);
const silent = { info() {}, warn() {}, error() {} };

export interface Hop {
  readonly name: string;
  readonly pass: boolean;
  readonly detail: string;
}

const hash = (value: unknown): string =>
  createHash("sha256").update(canonicalJson(value)).digest("hex").slice(0, 12);

// ----------------------------------------------------------- stub counter

/**
 * Every stub registers itself when it is constructed or first used, so the
 * count reflects what ran, not what a grep finds. Keyed by name: a stub
 * built once per host counts once. The value says who removes it.
 */
const usedStubs = new Map<string, string>();

function registerStub(name: string, removedBy: string): void {
  usedStubs.set(name, removedBy);
}

export function stubReport(): { count: number; lines: string[] } {
  const lines = [...usedStubs].map(([name, by]) => `  ${name} -> ${by}`);
  return { count: usedStubs.size, lines };
}

// ---------------------------------------------------------------- intake

/**
 * SKELETON STUB (lane P6 replaces it with the real `begin/batches/end`
 * adapter in `packages/core/src/stream-sync/intake.ts`): the same three calls
 * over the writer's own beginRun/append/finishRun, without START issue,
 * binding checks, ordinals or tombstones.
 */
class StubIntake {
  constructor(private readonly writer: StreamSyncWriter) {
    registerStub("intake adapter (StubIntake)", "lane P6");
  }

  begin(runId: string, observedAt: number): Promise<void> {
    // SKELETON STUB: identity is always required and `wantFull` is not modelled.
    return this.writer.beginRun({
      runId,
      connector: CONNECTOR,
      userConnect: false,
      observedAt,
      identity: "required",
      checkpointUsed: null,
    });
  }

  async batch(
    runId: string,
    records: readonly Record<string, unknown>[],
  ): Promise<void> {
    // SKELETON STUB: stream name and shape come from constants, not from a
    // declaration resolved from the connector artifact digest.
    await this.writer.declareStream(runId, STREAM, SHAPE);
    for (const record of records) {
      await this.writer.append(runId, STREAM, record);
    }
  }

  async end(runId: string, checkpoint: JsonValue): Promise<void> {
    await this.writer.setAccountIdentity(runId, ACCOUNT_ID);
    await this.writer.finishRun(runId, { checkpointCandidate: checkpoint });
  }
}

/** SKELETON STUB (lane P6): one fixture connector run of one stream. */
async function fixtureRun(
  intake: StubIntake,
  runId: string,
  observedAt: number,
  records: readonly Record<string, unknown>[],
): Promise<void> {
  registerStub("connector fixture (fixtureRun)", "lane P6");
  await intake.begin(runId, observedAt);
  await intake.batch(runId, records);
  await intake.end(runId, { cursor: runId });
}

// ----------------------------------------------------------------- hosts

interface Host {
  readonly name: string;
  readonly writer: StreamSyncWriter;
  readonly intake: StubIntake;
  /** The host's records for the skeleton stream, read as an app would. */
  readonly read: () => Promise<{
    kind: string;
    records: Record<string, unknown>[];
  }>;
  /** One sync pass: the host's own listing loop. */
  readonly sync: (listing: RegistryListing) => Promise<void>;
}

/**
 * The registry's listing as a gateway serves it: `GET /v1/data?user=..` over
 * the rows the shared in-memory registry accepted. Only the HTTP origin is
 * faked; every host reads it through the production `createGatewayDataPointFeed`
 * and `downloadAll` loop (see `syncFullHost` and the Lite sync manager).
 */
class RegistryListing {
  private readonly rows = new Map<string, Record<string, unknown>>();
  private clock = T0;

  wrap(inner: StreamSyncRegistry): StreamSyncRegistry {
    return interpose(inner, {
      afterPost: async (request, result) => {
        if (result.kind !== "committed") return;
        this.clock += 1000;
        this.rows.set(request.scope, {
          id: computeDataPointId(OWNER, request.scope),
          ownerAddress: OWNER,
          scope: request.scope,
          dataHash: request.dataHash,
          metadataHash: request.metadataHash,
          expectedVersion: request.expectedVersion,
          addedAt: new Date(this.clock).toISOString(),
          deletedAt: null,
        });
      },
    });
  }

  readonly fetch: typeof fetch = async (input) => {
    const url = new URL(String(input));
    if (url.pathname !== "/v1/data") return new Response("{}", { status: 404 });
    return Response.json({
      data: { dataPoints: [...this.rows.values()] },
      pagination: { hasMore: false, nextCursor: null },
    });
  };
}

/** One sync pass of the full server: the production `downloadAll` listing loop. */
async function syncFullHost(
  reader: StreamSyncReadService,
  listing: RegistryListing,
): Promise<void> {
  let stored: string | null = null;
  const storage = createMemoryDataStorage();
  await downloadAll({
    storage,
    storageAdapter: {} as StorageAdapter,
    gateway: {} as GatewayClient,
    dataPointFeed: createGatewayDataPointFeed({
      gatewayUrl: "http://registry.invalid",
      fetch: listing.fetch,
    }),
    cursor: {
      read: async () => stored,
      write: async (value) => {
        stored = value;
      },
    },
    masterKey: new Uint8Array(65),
    serverOwner: OWNER,
    logger: { ...silent, debug() {} } as unknown as Logger,
    streamSync: reader,
  });
}

type HostKind = "full" | "phone" | "frame";

async function makeHost(input: {
  kind: HostKind;
  config: ReturnType<typeof ServerConfigSchema.parse>;
  registry: StreamSyncRegistry;
  storageUrl: string;
  root: string;
  listing: RegistryListing;
}): Promise<Host> {
  // The flag gate, as the hosts apply it: no flag, no writer.
  if (!input.config.streamSync.write) {
    throw new Error("streamSync.write is off: the skeleton needs it on");
  }
  const blobs = storageBlobs(input.storageUrl);
  if (input.kind === "full") {
    const writer = new StreamSyncWriter({
      ownerAddress: OWNER,
      registry: input.registry,
      blobs,
      files: createFsStreamSyncFiles(join(input.root, "full-write")),
      keys: createStreamSyncKeyPorts(OWNER_SIGNATURE),
      signer: accountSigner(SERVER_KEY),
    });
    const reader = await StreamSyncReadService.open({
      files: createFsStreamSyncReadFiles(join(input.root, "full-read")),
      blobs,
      keys: await createStreamSyncReadKeys(
        streamMasterKeyFromSignature(OWNER_SIGNATURE),
      ),
      logger: silent,
    });
    return {
      name: input.kind,
      writer,
      intake: new StubIntake(writer),
      read: () => readFromService(reader),
      sync: (listing) => syncFullHost(reader, listing),
    };
  }
  // Phone and frame READ through the real PS-Lite startup code, flag from
  // config, listing through its sync manager. Only the registry origin
  // (listing feed) is injected.
  // SKELETON STUB (lanes U6 phone, U7 frame): the WRITER is still built by
  // hand, because Lite's own writer talks to the registry over HTTP and the
  // in-memory registry has no origin. The design (DESIGN-V4.1) says the frame
  // uses OPFS, else IndexedDB; both use IndexedDB here, differing by name.
  registerStub(
    "phone/frame host writer recipe",
    "lanes U6 (phone), U7 (frame)",
  );
  const files = createIndexedDbStreamSyncFiles({
    dbName: `skeleton-${input.kind}`,
    factory: new IDBFactory(),
    keyRange: IDBKeyRange,
  });
  const writer = new StreamSyncWriter({
    ownerAddress: OWNER,
    registry: input.registry,
    blobs,
    files,
    keys: createStreamSyncKeyPorts(OWNER_SIGNATURE),
    signer: accountSigner(OWNER_KEY),
  });
  // The runtime opens IndexedDB through the global; stub it once for all hosts
  // (each host has its own database name).
  const globals = globalThis as { indexedDB?: unknown; IDBKeyRange?: unknown };
  globals.indexedDB ??= new IDBFactory();
  globals.IDBKeyRange ??= IDBKeyRange;
  const lite = await createIndexedDbPsLiteRuntime({
    ownerAddress: OWNER,
    ownerSignature: OWNER_SIGNATURE,
    dbName: `skeleton-lite-${input.kind}`,
    gateway: {
      ...createMockPsLiteGateway(),
      getServer: async () => ({ id: "server-1" }),
    } as never,
    dataPointFeed: createGatewayDataPointFeed({
      gatewayUrl: "http://registry.invalid",
      fetch: input.listing.fetch,
    }),
    auth: createBearerTokenPsLiteAuth({ ownerToken: "t", builderToken: "b" }),
    active: true,
    logger: { ...silent, debug() {} } as never,
    configDefaults: {
      gateway: { url: "http://registry.invalid" },
      storage: {
        backend: "vana",
        config: { vana: { apiUrl: input.storageUrl } },
      },
      sync: { enabled: true },
      streamSync: { write: false, read: input.config.streamSync.read },
    } as never,
  });
  return {
    name: input.kind,
    writer,
    intake: new StubIntake(writer),
    read: async () => {
      const res = await lite.runtime.fetch(
        new Request(`https://ps.local/v1/data/pdpp.${CONNECTOR}.${STREAM}`, {
          headers: { Authorization: "Bearer t" },
        }),
      );
      if (res.status !== 200)
        return { kind: `HTTP ${res.status}`, records: [] };
      const body = (await res.json()) as {
        data: { records: Record<string, unknown>[] };
      };
      return { kind: "view", records: body.data.records };
    },
    sync: async () => {
      await lite.syncManager!.trigger();
    },
  };
}

// ----------------------------------------------------------------- checks

async function readFromService(
  reader: StreamSyncReadService,
): Promise<{ kind: string; records: Record<string, unknown>[] }> {
  const decision = await reader.resolve({
    scope: `pdpp.${CONNECTOR}.${STREAM}`,
    connection: null,
    cursor: null,
    legacyFile: false,
  });
  if (decision.kind !== "view") return { kind: decision.kind, records: [] };
  const body = JSON.parse(await new Response(decision.body).text()) as {
    data: { records: Record<string, unknown>[] };
  };
  return { kind: "view", records: body.data.records };
}

function sorted(records: readonly Record<string, unknown>[]): string[] {
  return records.map((r) => hash(r)).sort();
}

export async function runSkeleton(): Promise<Hop[]> {
  const config = ServerConfigSchema.parse({
    streamSync: { write: true, read: true },
  });
  const root = await mkdtemp(join(tmpdir(), "stream-sync-skeleton-"));
  const storage = await startLocalStorage();
  const listing = new RegistryListing();
  // With STREAM_SYNC_ORACLE_GATEWAY_URL set the registry is the real
  // data-gateway. Otherwise it is an in-memory registry with the gateway's
  // exclusive-version rules, which counts as a stub.
  const gatewayUrl = process.env.STREAM_SYNC_ORACLE_GATEWAY_URL;
  if (!gatewayUrl) {
    registerStub(
      "in-memory registry (set STREAM_SYNC_ORACLE_GATEWAY_URL for the real data-gateway)",
      "durable-registry lane (CI default until CI can start the gateway)",
    );
  }
  registerStub(
    "registry listing origin",
    "stubs-burn lane (real registry feed)",
  );
  const registry = listing.wrap(
    gatewayUrl
      ? createGatewayStreamSyncRegistry({ gatewayUrl, ownerAddress: OWNER })
      : createFakeStreamSyncRegistry(),
  );
  process.stdout.write(
    `registry: ${gatewayUrl ? "real data-gateway" : "in-memory STUB"}\n`,
  );
  const hops: Hop[] = [];
  const hop = (name: string, pass: boolean, detail: string) =>
    hops.push({ name, pass, detail });
  try {
    const make = (kind: HostKind) =>
      makeHost({
        kind,
        config,
        registry,
        storageUrl: storage.url,
        root,
        listing,
      });
    const full = await make("full");
    const phone = await make("phone");
    const frame = await make("frame");

    const first = { id: "skeleton-1", value: "written by the full server" };
    const second = { id: "skeleton-2", value: "written by PS-Lite" };

    const check = async (name: string, host: Host, want: unknown[]) => {
      await host.sync(listing);
      const got = await host.read();
      const ok =
        got.kind === "view" &&
        JSON.stringify(sorted(got.records)) ===
          JSON.stringify(sorted(want as Record<string, unknown>[]));
      hop(
        name,
        ok,
        got.kind === "view"
          ? `records=${got.records.length} hashes=${sorted(got.records).join(",")}`
          : `read answered ${got.kind}`,
      );
    };

    // Forward: the full server writes, three hosts read.
    await full.writer.refreshControls();
    await fixtureRun(full.intake, "skeleton-run-1", T0, [first]);
    const report = await full.writer.cycle();
    const run1 = report.runs.find((r) => r.runId === "skeleton-run-1");
    hop(
      "write: full server publishes run 1",
      run1?.outcome?.kind === "checkpointed",
      `outcome=${run1?.outcome?.kind ?? "none"} expected=${hash(first)}`,
    );
    await check("read: full server sees the record", full, [first]);
    await check("read: PS-Lite (phone) sees the record", phone, [first]);
    await check("read: PS-Lite (Account frame) sees the record", frame, [
      first,
    ]);

    // Reverse: PS-Lite (phone) writes, the full server and the frame read.
    await phone.writer.refreshControls();
    await fixtureRun(phone.intake, "skeleton-run-2", T0 + 60_000, [second]);
    const report2 = await phone.writer.cycle();
    const run2 = report2.runs.find((r) => r.runId === "skeleton-run-2");
    hop(
      "write: PS-Lite (phone) publishes run 2",
      run2?.outcome?.kind === "checkpointed",
      `outcome=${run2?.outcome?.kind ?? "none"} expected=${hash(second)}`,
    );
    await check("read: full server sees both records", full, [first, second]);
    await check("read: PS-Lite (Account frame) sees both records", frame, [
      first,
      second,
    ]);
    await check("read: PS-Lite (phone) sees both records", phone, [
      first,
      second,
    ]);
    return hops;
  } finally {
    await storage.close();
    await rm(root, { recursive: true, force: true });
  }
}

export function formatStubs(): string {
  const { count, lines } = stubReport();
  return [`stubs: ${count}`, ...lines].join("\n");
}

export function formatHops(hops: readonly Hop[]): string {
  return hops
    .map((h) => `${h.pass ? "PASS" : "FAIL"} ${h.name} (${h.detail})`)
    .join("\n");
}
