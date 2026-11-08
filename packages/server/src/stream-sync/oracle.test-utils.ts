/**
 * Oracle support for the stream-sync writer (§5.2, lane P1).
 *
 * Backends:
 * - `fake`: an in-memory registry with the exclusive-version rules of the
 *   data-gateway (`feat/registry-exclusive-version`). It runs in CI.
 * - `gateway`: the real gateway at `STREAM_SYNC_ORACLE_GATEWAY_URL`
 *   (Postgres-backed), through the production registry adapter.
 *
 * Storage is always a local write-once HTTP blob store behind the
 * production Vana storage adapter.
 */

import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { privateKeyToAccount } from "viem/accounts";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import {
  controlHashes,
  controlScope,
  decodeHead,
  linesOfParts,
  deriveKeyCheck,
  keccakHex,
  parseScope,
  partBlobName,
  streamScope,
  utf8,
  TOMBSTONE_DATA_LABEL,
  TOMBSTONE_METADATA_LABEL,
  type ControlRead,
  type Head,
  type HeadProfile,
  type JsonValue,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  StreamSyncWriter,
  createGatewayStreamSyncRegistry,
  createStorageStreamSyncBlobs,
  createStreamSyncKeyPorts,
  streamSyncHashes,
  type RegistryPostResult,
  type SignedRegistryPost,
  type StreamSyncBlobs,
  type StreamSyncFiles,
  bindStreamSyncHome,
  type StreamSyncRegistry,
  type StreamSyncSeedSource,
  type StreamSyncSigner,
  type IntakeDeclarations,
  type ResolveArtifact,
  type StreamSyncWriterOptions,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { createServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import { computeDataPointId } from "@opendatalabs/personal-server-ts-core/sync";
import { createVanaSyncStorageAdapter } from "@opendatalabs/personal-server-ts-core/storage/adapters";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createIndexedDbStreamSyncFiles } from "@opendatalabs/personal-server-ts-lite";
import { createFsStreamSyncFiles } from "./fs-files.js";

/** Anvil's well-known test accounts #0 (owner) and #2 (registered server). */
export const OWNER_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
export const SERVER_KEY =
  "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
export const OWNER = privateKeyToAccount(OWNER_KEY).address;
/** OWNER_KEY's signature over the master-key message (deterministic). */
export const OWNER_SIGNATURE =
  "0x1f5c9b3bafc291e8ea7aa4e0c5700a109e68aa2431fdbea08b49f9bf91b5c7db2aaa192de5cdf866e5f9f5f39502a66bd696a1399a537eac8ffb826c00e4e1d51b";
const CONFIG = ServerConfigSchema.parse({});
const GATEWAY_CONFIG = {
  chainId: CONFIG.gateway.chainId,
  contracts: CONFIG.gateway.contracts,
};

export const PROFILE: HeadProfile = { key: null, version: "1.0.0" };
export const SHAPE = { primaryKey: ["id"], profile: PROFILE } as const;

export function accountSigner(key: `0x${string}`): StreamSyncSigner {
  const account = privateKeyToAccount(key);
  return createServerSigner(
    {
      address: account.address,
      publicKey: account.publicKey,
      signTypedData: (params) =>
        account.signTypedData(
          params as Parameters<typeof account.signTypedData>[0],
        ),
      signMessage: (message) => account.signMessage({ message }),
    },
    GATEWAY_CONFIG,
  );
}

// ---------------------------------------------------------------- registry

interface Version {
  readonly dataHash: string;
  readonly metadataHash: string;
}

export async function tombstoneHashes(): Promise<{
  dataHash: `0x${string}`;
  metadataHash: `0x${string}`;
}> {
  return {
    dataHash: await keccakHex(
      streamSyncHashes.keccak256,
      utf8(TOMBSTONE_DATA_LABEL),
    ),
    metadataHash: await keccakHex(
      streamSyncHashes.keccak256,
      utf8(TOMBSTONE_METADATA_LABEL),
    ),
  };
}

/**
 * Exclusive-version semantics of the gateway: POST at `current + 1` writes;
 * the identical row at an existing version answers 2xx and writes nothing
 * (replay); anything else is 409 with the latest version.
 */
export function createFakeStreamSyncRegistry(): StreamSyncRegistry {
  const rows = new Map<string, Version[]>();
  let tombstone: Version | null = null;
  const read = async (scope: string): Promise<ControlRead> => {
    const versions = rows.get(scope);
    if (!versions || versions.length === 0) return { found: false };
    const head = versions[versions.length - 1]!;
    tombstone ??= await tombstoneHashes();
    return {
      found: true,
      version: versions.length,
      dataHash: head.dataHash,
      metadataHash: head.metadataHash,
      deleted:
        head.dataHash === tombstone.dataHash &&
        head.metadataHash === tombstone.metadataHash,
    };
  };
  return {
    read,
    async post(request: SignedRegistryPost): Promise<RegistryPostResult> {
      const versions = rows.get(request.scope) ?? [];
      const version = Number(request.expectedVersion);
      const existing = versions[version - 1];
      if (
        existing &&
        existing.dataHash === request.dataHash &&
        existing.metadataHash === request.metadataHash
      ) {
        return { kind: "committed" };
      }
      if (version !== versions.length + 1) {
        return { kind: "conflict", latestVersion: String(versions.length) };
      }
      versions.push({
        dataHash: request.dataHash,
        metadataHash: request.metadataHash,
      });
      rows.set(request.scope, versions);
      return { kind: "committed" };
    },
    async listControlRows() {
      const out: { scope: string; read: ControlRead }[] = [];
      for (const scope of rows.keys()) {
        if (parseScope(scope)?.kind === "control") {
          out.push({ scope, read: await read(scope) });
        }
      }
      return out;
    },
  };
}

export interface Interposer {
  beforeRead?(scope: string): Promise<void>;
  beforePost?(request: SignedRegistryPost): Promise<void>;
  afterPost?(
    request: SignedRegistryPost,
    result: RegistryPostResult,
  ): Promise<void>;
}

/** Run test actions between a writer's registry calls. */
export function interpose(
  inner: StreamSyncRegistry,
  hooks: Interposer,
): StreamSyncRegistry {
  return {
    async read(scope) {
      await hooks.beforeRead?.(scope);
      return inner.read(scope);
    },
    async post(request) {
      await hooks.beforePost?.(request);
      const result = await inner.post(request);
      await hooks.afterPost?.(request, result);
      return result;
    },
    listControlRows: () => inner.listControlRows(),
  };
}

// ----------------------------------------------------------------- storage

/** A write-once blob store with the Vana storage HTTP shape. */
export async function startLocalStorage(): Promise<{
  url: string;
  objects: () => number;
  close: () => Promise<void>;
}> {
  const blobs = new Map<string, Buffer>();
  const server: Server = createServer((req, res) => {
    const path = decodeURIComponent(
      new URL(req.url ?? "/", "http://x").pathname,
    );
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      if (req.method === "PUT") {
        const existing = blobs.get(path);
        if (existing && !existing.equals(body)) {
          res.statusCode = 409;
          res.end("different bytes");
          return;
        }
        blobs.set(path, body);
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            url: path,
            size: body.length,
            key: path,
            etag: "e",
          }),
        );
        return;
      }
      if (req.method === "GET") {
        const blob = blobs.get(path);
        res.statusCode = blob ? 200 : 404;
        res.end(blob ?? "not found");
        return;
      }
      if (req.method === "DELETE") {
        res.statusCode = blobs.delete(path) ? 200 : 404;
        res.end();
        return;
      }
      res.statusCode = 405;
      res.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("no port");
  return {
    url: `http://127.0.0.1:${address.port}`,
    objects: () => blobs.size,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

export function storageBlobs(storageUrl: string): StreamSyncBlobs {
  const config = ServerConfigSchema.parse({
    storage: { backend: "vana", config: { vana: { apiUrl: storageUrl } } },
  });
  const account = privateKeyToAccount(OWNER_KEY);
  return createStorageStreamSyncBlobs(
    createVanaSyncStorageAdapter({
      config,
      serverOwner: OWNER,
      serverAccount: {
        address: account.address,
        signMessage: (message) => account.signMessage({ message }),
      },
    }),
  );
}

// ---------------------------------------------------------------- surfaces

export type Surface = "full" | "lite";
export type Backend = "fake" | "gateway";

export interface OracleEnv {
  readonly surface: Surface;
  readonly backend: Backend;
  readonly gatewayUrl: string | undefined;
  readonly blobs: StreamSyncBlobs;
  /** A registry handle for test actions and assertions. */
  readonly registry: StreamSyncRegistry;
  /** A new registry adapter instance (each writer gets its own). */
  newRegistry(): StreamSyncRegistry;
  /** Durable files for one device; the same `device` reopens the same files. */
  files(device: string): Promise<StreamSyncFiles>;
  writer(
    device: string,
    extra?: Partial<Omit<StreamSyncWriterOptions, "home">> & {
      registry?: StreamSyncRegistry;
      /** Replaces the device's files (a wrapper that holds or fails calls). */
      files?: StreamSyncFiles;
    },
  ): Promise<StreamSyncWriter>;
  cleanup(): Promise<void>;
}

/** A home for tests: the device's files, bound to the test owner. */
export function testStreamSyncHome(
  files: StreamSyncFiles,
  ownerAddress: `0x${string}` = OWNER,
) {
  return bindStreamSyncHome({
    ownerAddress,
    network: "test",
    open: () => files,
  });
}

export async function createOracleEnv(input: {
  surface: Surface;
  backend: Backend;
  storageUrl: string;
  gatewayUrl?: string;
}): Promise<OracleEnv> {
  const root = await mkdtemp(
    join(tmpdir(), `stream-sync-oracle-${input.surface}-`),
  );
  const idb = new IDBFactory();
  const fake = createFakeStreamSyncRegistry();
  const newRegistry = (): StreamSyncRegistry =>
    input.backend === "fake"
      ? fake
      : createGatewayStreamSyncRegistry({
          gatewayUrl: input.gatewayUrl!,
          ownerAddress: OWNER,
        });
  const blobs = storageBlobs(input.storageUrl);
  const files = async (device: string): Promise<StreamSyncFiles> =>
    input.surface === "full"
      ? createFsStreamSyncFiles(join(root, device))
      : createIndexedDbStreamSyncFiles({
          dbName: device,
          factory: idb,
          keyRange: IDBKeyRange,
        });
  return {
    surface: input.surface,
    backend: input.backend,
    gatewayUrl: input.gatewayUrl,
    blobs,
    registry: newRegistry(),
    newRegistry,
    files,
    async writer(device, { files: override, ...extra } = {}) {
      return new StreamSyncWriter({
        ownerAddress: OWNER,
        registry: newRegistry(),
        blobs,
        home: testStreamSyncHome(
          override ?? (await files(device)),
          extra.ownerAddress,
        ),
        keys: createStreamSyncKeyPorts(OWNER_SIGNATURE),
        // Full server signs with its registered server key; Lite with the owner.
        signer: accountSigner(
          input.surface === "full" ? SERVER_KEY : OWNER_KEY,
        ),
        ...extra,
      });
    },
    async cleanup() {
      await rm(root, { recursive: true, force: true });
    },
  };
}

// ------------------------------------------------------------ test actions

const keys = createStreamSyncKeyPorts(OWNER_SIGNATURE);
const ownerSigner = accountSigner(OWNER_KEY);

async function ownHashes() {
  const keyCheck = await deriveKeyCheck((m) => keys.namespaceHmac(m));
  return {
    keyCheck,
    control: await controlHashes(streamSyncHashes.keccak256, keyCheck),
  };
}

async function postNext(
  registry: StreamSyncRegistry,
  scope: string,
  dataHash: `0x${string}`,
  metadataHash: `0x${string}`,
): Promise<number> {
  const row = await registry.read(scope);
  const version = row.found ? row.version + 1 : 1;
  const signature = await ownerSigner.signAddData({
    ownerAddress: OWNER,
    scope,
    dataHash,
    metadataHash,
    expectedVersion: BigInt(version),
  });
  const result = await registry.post({
    ownerAddress: OWNER,
    scope,
    dataHash,
    metadataHash,
    expectedVersion: String(version),
    signature,
  });
  if (result.kind !== "committed")
    throw new Error(`post ${scope} lost: ${version}`);
  return version;
}

/** Owner-signed ACTIVE control row at the next version (a create or reconnect). */
export async function activateControl(
  registry: StreamSyncRegistry,
  connector: string,
  ns: string,
): Promise<number> {
  const { control } = await ownHashes();
  return postNext(
    registry,
    controlScope(connector, ns),
    control.activeData,
    control.activeMetadata,
  );
}

/**
 * A control row whose hashes are neither the active nor the tombstone pair:
 * a foreign row (§2.4). Posted at the next version like any other write.
 */
export async function foreignControl(
  registry: StreamSyncRegistry,
  connector: string,
  ns: string,
): Promise<number> {
  const hash = (byte: string) => `0x${byte.repeat(32)}` as `0x${string}`;
  return postNext(
    registry,
    controlScope(connector, ns),
    hash("ab"),
    hash("cd"),
  );
}

/** Owner-signed connection delete: tombstone the control row and the given streams. */
export async function deleteConnection(
  registry: StreamSyncRegistry,
  connector: string,
  ns: string,
  streams: readonly string[],
): Promise<number> {
  const tomb = await tombstoneHashes();
  const version = await postNext(
    registry,
    controlScope(connector, ns),
    tomb.dataHash,
    tomb.metadataHash,
  );
  for (const stream of streams) {
    const scope = streamScope(connector, ns, stream);
    const row = await registry.read(scope);
    if (row.found && !row.deleted) {
      await postNext(registry, scope, tomb.dataHash, tomb.metadataHash);
    }
  }
  return version;
}

/**
 * An old, non-exclusive legacy DELETE of one scope (limitation L11, ruling
 * M3): a tombstone signed at the next version. On the gateway it goes through
 * `DELETE /v1/data/:id` exactly as the legacy delete port sends it.
 */
export async function oldDelete(
  env: OracleEnv,
  scope: string,
): Promise<number> {
  const tomb = await tombstoneHashes();
  if (env.backend === "fake") {
    return postNext(env.registry, scope, tomb.dataHash, tomb.metadataHash);
  }
  const row = await env.registry.read(scope);
  const version = row.found ? row.version + 1 : 1;
  const signature = await ownerSigner.signAddData({
    ownerAddress: OWNER,
    scope,
    dataHash: tomb.dataHash,
    metadataHash: tomb.metadataHash,
    expectedVersion: BigInt(version),
  });
  const res = await fetch(
    `${env.gatewayUrl}/v1/data/${computeDataPointId(OWNER, scope)}`,
    {
      method: "DELETE",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Web3Signed ${signature}`,
      },
      body: JSON.stringify({
        ownerAddress: OWNER,
        scope,
        expectedVersion: String(version),
        signature,
      }),
    },
  );
  if (!res.ok)
    throw new Error(
      `old DELETE of ${scope}: ${res.status} ${await res.text()}`,
    );
  return version;
}

export interface StreamView {
  readonly version: number;
  readonly head: Head;
  readonly records: ReadonlyMap<string, JsonValue>;
}

/** Read a stream back through the registry and storage, as a reader would. */
export async function readStream(
  registry: StreamSyncRegistry,
  blobs: StreamSyncBlobs,
  connector: string,
  ns: string,
  stream: string,
): Promise<StreamView | null | "tombstoned"> {
  const scope = streamScope(connector, ns, stream);
  const row = await registry.read(scope);
  if (!row.found) return null;
  const tomb = await tombstoneHashes();
  if (row.deleted || row.dataHash.toLowerCase() === tomb.dataHash) {
    return "tombstoned";
  }
  const hex = row.dataHash.toLowerCase().replace(/^0x/, "");
  const cipher = await blobs.get(`${scope}/h-${hex}`);
  if (!cipher) throw new Error(`head of ${scope} is missing`);
  const decoded = decodeHead(await keys.decrypt(scope, cipher));
  if (decoded.kind !== "ok")
    throw new Error(`head of ${scope}: ${decoded.kind}`);
  const head = decoded.head;
  const records = new Map<string, JsonValue>();
  for await (const line of linesOfParts(
    streamSyncHashes.sha256,
    head,
    async (part) => {
      const partCipher = await blobs.get(
        `${scope}/${partBlobName(head.generation, part.hash)}`,
      );
      if (!partCipher)
        throw new Error(`part ${part.hash} of ${scope} is missing`);
      return keys.decrypt(scope, partCipher);
    },
  )) {
    const value = line.v as { id: string };
    records.set(value.id, line.v);
  }
  return { version: row.version, head, records };
}

/** A collected run: begin, append, finish. */
export async function collect(
  writer: StreamSyncWriter,
  input: {
    runId: string;
    connector: string;
    observedAt: number;
    userConnect?: boolean;
    checkpointUsed?: { ns: string; generation: number } | null;
    streams: Record<string, readonly Record<string, unknown>[]>;
    checkpoint?: JsonValue;
  },
) {
  await writer.beginRun({
    runId: input.runId,
    connector: input.connector,
    userConnect: input.userConnect ?? false,
    observedAt: input.observedAt,
    identity: "none",
    checkpointUsed: input.checkpointUsed ?? null,
  });
  for (const [stream, records] of Object.entries(input.streams)) {
    await writer.declareStream(input.runId, stream, SHAPE);
    for (const record of records)
      await writer.append(input.runId, stream, record);
  }
  return writer.finishRun(input.runId, {
    checkpointCandidate: input.checkpoint ?? { cursor: input.runId },
  });
}

/** A seed source over fixed rows (the Desktop retained snapshot). */
export function fixedSeed(
  installId: string,
  rows: Record<string, readonly Record<string, unknown>[]>,
): StreamSyncSeedSource {
  return {
    installId,
    async streams() {
      return Object.keys(rows).map((stream) => ({ stream, ...SHAPE }));
    },
    async *records(_connector, stream) {
      for (const row of rows[stream] ?? []) yield row;
    },
  };
}

let counter = 0;
/** A connector key no earlier oracle run used (the gateway DB persists). */
export function freshConnector(tag: string): string {
  counter += 1;
  return `oracle-${tag}-${Date.now().toString(36)}-${counter}`;
}

export function finishedOutcome(
  status: Awaited<ReturnType<StreamSyncWriter["status"]>>,
  runId: string,
) {
  return status.finished.find((r) => r.runId === runId) ?? null;
}

const artifactTable = new Map<string, IntakeDeclarations>();
/**
 * A digest that resolves, through `resolveTestArtifact`, to `declarations`
 * bound to `connector`. One digest per connector and shape, so concurrent
 * runs of different tests never share a binding.
 */
export function artifactFor(
  connector: string,
  declarations: Omit<IntakeDeclarations, "connector">,
): string {
  const digest = `sha256:${createHash("sha256")
    .update(connector)
    .update("\0")
    .update(JSON.stringify(declarations))
    .digest("hex")}`;
  artifactTable.set(digest, { connector, ...declarations });
  return digest;
}
export const resolveTestArtifact: ResolveArtifact = (digest) =>
  artifactTable.get(digest) ?? null;
