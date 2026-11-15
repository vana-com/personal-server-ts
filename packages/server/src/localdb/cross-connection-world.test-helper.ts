// A world of several connections in one local database, committed to a fake
// gateway (fake-gateway.ts) through the real gateway adapter, the real publish
// driver, the real SQLite driver and the real connection queue. Shared by the
// cross-connection batch test and its workload.
import { keccak_256 } from "@noble/hashes/sha3";
import {
  controlHashes,
  controlScope,
  deriveKeyCheck,
  streamScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  connectionQueue,
  createLocalSync,
  openLocalDb,
  runCycle,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createGatewayStreamSyncRegistry,
  createMemoryStreamSyncBlobs,
  type StreamSyncBlobs,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { createFakeGateway, type FakeGatewayOptions } from "./fake-gateway.js";

export const OWNER = `0x${"11".repeat(20)}` as const;
export const connectorOf = (c: number) => `fixture${c}`;
export const controlOf = (c: number) => controlScope(connectorOf(c), "");
export const connectionIdOf = (c: number) => `pdpp.${connectorOf(c)}~`;
const sName = (i: number) => `s${i}`;
export const scopeOf = (c: number, i: number) =>
  streamScope(connectorOf(c), "", sName(i));

/** Every database a world opened; the caller closes them with `closeWorlds`. */
const drivers: SqlDriver[] = [];
export async function closeWorlds(): Promise<void> {
  for (const db of drivers.splice(0)) await db.close();
}

/** Poll until `check` stops throwing. */
export async function until(
  check: () => void,
  timeoutMs = 5_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      return check();
    } catch (error) {
      if (Date.now() > deadline) throw error;
      await new Promise((r) => setTimeout(r, 5));
    }
  }
}

export type Options = {
  /** Streams of each connection: `[3, 2]` is two connections. */
  readonly streams: readonly number[];
  readonly crossConnectionBatch?: boolean;
  readonly hold?: boolean;
  readonly gateway?: Partial<FakeGatewayOptions>;
};

export async function world(options: Options) {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: OWNER,
    network: "test",
    deviceId: "d",
  });
  drivers.push(db);
  const keyCheck = await deriveKeyCheck(async () => new Uint8Array(32));
  const hashes = await controlHashes(async (b) => keccak_256(b), keyCheck);
  const gateway = createFakeGateway({
    owner: OWNER,
    isTombstone: (v) =>
      v.dataHash === hashes.tombstoneData &&
      v.metadataHash === hashes.tombstoneMetadata,
    ...options.gateway,
  });
  // Parked parts hold the send gate's byte budget (8 parts by default); a world
  // that parks every part of 32 streams needs room for all of them.
  const innerBlobs = createMemoryStreamSyncBlobs({
    maxBytesInFlight: 1024 * 1024 * 1024,
  });
  const putsDone: string[] = [];
  const parked: { key: string; release: () => void }[] = [];
  const blobs: StreamSyncBlobs = {
    governor: innerBlobs.governor,
    get: (key) => innerBlobs.get(key),
    exists: (key) => innerBlobs.exists(key),
    async put(key, bytes) {
      if (options.hold && /-p-/.test(key)) {
        await new Promise<void>((release) => parked.push({ key, release }));
      }
      await innerBlobs.put(key, bytes);
      putsDone.push(key);
    },
  };
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    queue: connectionQueue(),
    registry: createGatewayStreamSyncRegistry({
      gatewayUrl: "https://gateway.test",
      ownerAddress: OWNER,
      fetch: gateway.fetch,
    }),
    blobs,
    ownerAddress: OWNER,
    keys: {
      namespaceHmac: async () => new Uint8Array(32),
      encrypt: async (_s, b) => b,
      encryptPart: async (_s, b) => b,
      decrypt: async (_s, b) => b,
    },
    signer: { signAddData: async () => "0x00" },
    logger: { info: () => {}, warn: () => {} },
    now: () => 1000,
    newOp: () => `op-${++op}`,
    ...(options.crossConnectionBatch ? { crossConnectionBatch: true } : {}),
  };
  const most = Math.max(...options.streams);
  const names = Array.from({ length: most }, (_, i) => sName(i));
  const sync = createLocalSync(deps, {
    resolveArtifact: (digest) => ({
      connector: digest,
      version: "1",
      streams: names.map((name) => ({
        name,
        semantics: "mutable_state" as const,
        primaryKey: ["id"],
      })),
    }),
    declaredStreams: () => names,
    olderVersionReads: () => true,
  });
  for (const [c, count] of options.streams.entries()) {
    const covered = names.slice(0, count);
    const runId = `run-${c}`;
    await sync.intake.begin(runId, {
      connector: connectorOf(c),
      artifactDigest: connectorOf(c),
      wantFull: true,
      owner: { address: OWNER, leaseId: null },
    });
    await sync.intake.batch(runId, {
      batch: 0,
      records: covered.map((stream) => ({
        stream,
        data: { id: `${stream}-1` },
      })),
    });
    await sync.intake.end(runId, {
      outcome: "succeeded",
      coveredStreams: covered,
      lastBatch: 0,
    });
  }
  const total = options.streams.reduce((a, b) => a + b, 0);
  /**
   * Run one cycle in which the first request is held in flight until every
   * other commit is waiting, so exactly the commits that "finish together"
   * are in the second turn.
   */
  async function cycleWithFirstHeld(
    beforeReply?: (first: { rows: { scope: string }[] }) => void,
  ) {
    let sent!: () => void;
    const firstSent = new Promise<void>((r) => (sent = r));
    let reply!: () => void;
    const firstHeld = new Promise<void>((r) => (reply = r));
    gateway.beforeBatch = async () => {
      gateway.beforeBatch = undefined;
      sent();
      await firstHeld;
    };
    const cycling = runCycle(deps);
    await until(() => {
      if (parked.length !== total)
        throw new Error(`parked ${parked.length} of ${total}`);
    });
    parked[0]!.release();
    await firstSent;
    for (const part of parked.slice(1)) part.release();
    await until(() => {
      const heads = putsDone.filter((k) => !/-p-/.test(k)).length;
      if (heads !== total) throw new Error(`head blobs ${heads} of ${total}`);
    });
    await new Promise((r) => setTimeout(r, 25));
    beforeReply?.(gateway.batches()[0]!.body);
    reply();
    return cycling;
  }
  /** Another device deletes connection `c`. */
  const tombstone = (c: number) =>
    gateway.write(controlOf(c), {
      dataHash: hashes.tombstoneData,
      metadataHash: hashes.tombstoneMetadata,
    });
  return { deps, gateway, cycleWithFirstHeld, tombstone, total };
}
