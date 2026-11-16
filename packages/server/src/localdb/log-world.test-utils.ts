// A shared world for log-protocol tests: one fake gateway and one blob store,
// and any number of devices of one owner, each with its own real SQLite and the
// real publish and apply drivers (see log-protocol.test.ts).
import { keccak_256 } from "@noble/hashes/sha3";
import {
  controlHashes,
  controlScope,
  decodeSegment,
  decodeSnapshotPart,
  deriveKeyCheck,
  logScope,
  pkHash,
  type Segment,
  type SnapshotPart,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { sha256 } from "@noble/hashes/sha2";
import {
  connectionQueue,
  createLocalSync,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "../../../core/src/localdb/index.js";
import {
  createGatewayStreamSyncRegistry,
  createMemoryStreamSyncBlobs,
} from "../../../core/src/stream-sync/index.js";
import {
  createStorageAccess,
  DEFAULT_STORAGE_ACCESS_POLICY,
} from "../../../core/src/stream-sync/storage-retry.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { createFakeGateway } from "./fake-gateway.js";

export const OWNER = `0x${"11".repeat(20)}` as const;
export const CONNECTOR = "fixture";
export const CONNECTION_ID = `pdpp.${CONNECTOR}~`;
export const CONTROL = controlScope(CONNECTOR, "");
export const LOG = logScope(CONNECTOR, "");
export const sName = (i: number) => `s${i}`;
export const idHash = (id: string | number) =>
  pkHash(async (b) => sha256(b), { id }, ["id"]);

const drivers: SqlDriver[] = [];
/** Closes the databases of the devices a test opened; call it from `afterEach`. */
export async function closeWorldDrivers(): Promise<void> {
  for (const db of drivers.splice(0)) await db.close();
}

export async function world(options: {
  streams: number;
  logProtocol: boolean;
  partTargetBytes?: number;
  /** The key types every stream's schema declares (none: undeclared). */
  keyTypes?: readonly ("string" | "number" | "integer" | "boolean" | null)[];
}) {
  const keyCheck = await deriveKeyCheck(async () => new Uint8Array(32));
  const hashes = await controlHashes(async (b) => keccak_256(b), keyCheck);
  const gateway = createFakeGateway({
    owner: OWNER,
    isTombstone: (v) =>
      v.dataHash === hashes.tombstoneData &&
      v.metadataHash === hashes.tombstoneMetadata,
  });
  const store = new Map<string, Uint8Array>();
  const innerBlobs = {
    governor: createMemoryStreamSyncBlobs().governor,
    put: async (key: string, bytes: Uint8Array) => {
      store.set(key, bytes.slice());
    },
    get: async (key: string) => store.get(key) ?? null,
    exists: async (key: string) => store.has(key),
    keys: () => [...store.keys()],
    delete: (key: string) => store.delete(key),
  };
  const names = Array.from({ length: options.streams }, (_, i) => sName(i));
  let clock = 1000;

  async function device(
    deviceId: string,
    logProtocol = options.logProtocol,
    hooks: {
      beforePut?: (key: string) => Promise<void>;
      /** Awaited before a blob is returned: stops an apply where it fetches. */
      beforeGet?: (key: string) => Promise<void>;
      /** A host that serves a first load's applied parts while it fills. */
      progressiveFirstLoad?: boolean;
      /**
       * The byte budget of this device's transfers. A budget below one
       * segment makes an apply fetch and commit one segment at a time.
       */
      maxBytesInFlight?: number;
    } = {},
  ) {
    const db = await openLocalDb(openBetterSqlite3(":memory:"), {
      owner: OWNER,
      network: "test",
      deviceId,
    });
    drivers.push(db);
    const puts: string[] = [];
    const gets: string[] = [];
    let op = 0;
    const deps: LocalSyncDeps = {
      db,
      queue: connectionQueue(),
      registry: createGatewayStreamSyncRegistry({
        gatewayUrl: "https://gateway.test",
        ownerAddress: OWNER,
        fetch: gateway.fetch,
      }),
      blobs: {
        governor:
          hooks.maxBytesInFlight === undefined
            ? innerBlobs.governor
            : createStorageAccess({
                ...DEFAULT_STORAGE_ACCESS_POLICY,
                maxBytesInFlight: hooks.maxBytesInFlight,
              }),
        async get(key) {
          gets.push(key);
          await hooks.beforeGet?.(key);
          return innerBlobs.get(key);
        },
        exists: (key) => innerBlobs.exists(key),
        async put(key, bytes) {
          await hooks.beforePut?.(key);
          await innerBlobs.put(key, bytes);
          puts.push(key);
        },
      },
      ownerAddress: OWNER,
      keys: {
        namespaceHmac: async () => new Uint8Array(32),
        encrypt: async (_s, b) => b,
        encryptPart: async (_s, b) => b,
        decrypt: async (_s, b) => b,
      },
      signer: { signAddData: async () => "0x00" },
      logger: { info: () => {}, warn: () => {} },
      now: () => clock,
      newOp: () => `${deviceId}-${++op}`,
      ...(logProtocol ? { logProtocol: true } : {}),
      ...(hooks.progressiveFirstLoad ? { progressiveFirstLoad: true } : {}),
      ...(options.partTargetBytes !== undefined
        ? { partTargetBytes: options.partTargetBytes }
        : {}),
    };
    const sync = createLocalSync(deps, {
      resolveArtifact: (digest) => ({
        connector: digest,
        version: "1",
        streams: names.map((name) => ({
          name,
          semantics: "mutable_state" as const,
          primaryKey: ["id"],
          coverageStrategy: "full_inventory" as const,
          ...(options.keyTypes ? { keyTypes: options.keyTypes } : {}),
        })),
      }),
      declaredStreams: () => names,
      olderVersionReads: () => true,
    });
    /** One run that writes `records` and ends covering `covered`. */
    const run = async (
      runId: string,
      records: readonly {
        stream: string;
        id: string | number;
        v?: number;
        pad?: number;
        blobId?: string;
        remove?: boolean;
      }[],
      opts: {
        covered?: readonly string[];
        full?: boolean;
        observedAt?: number;
        /** Bytes the record named by `blobId` carries, sent before the run ends. */
        blob?: { hash: string; bytes: Uint8Array };
      } = {},
    ) => {
      clock++;
      await sync.intake.begin(runId, {
        connector: CONNECTOR,
        artifactDigest: CONNECTOR,
        wantFull: opts.full ?? true,
        observedAt: opts.observedAt,
        owner: { address: OWNER, leaseId: null },
      });
      await sync.intake.batch(runId, {
        batch: 0,
        records: records.map(({ stream, id, v, pad, blobId, remove }) => ({
          stream,
          ...(remove ? { op: "delete" as const } : {}),
          data: {
            id,
            ...(v === undefined ? {} : { v }),
            ...(pad === undefined ? {} : { pad: "p".repeat(pad) }),
            ...(blobId === undefined ? {} : { blob_ref: { blob_id: blobId } }),
          },
        })),
      });
      if (opts.blob)
        await sync.blobs.put({
          runId,
          sha256: opts.blob.hash,
          mimeType: "application/octet-stream",
          bytes: opts.blob.bytes,
        });
      await sync.intake.end(runId, {
        outcome: "succeeded",
        coveredStreams: opts.covered ?? names,
        lastBatch: 0,
        ...(opts.full === false ? {} : { provenFullStreams: names }),
      });
    };
    const cycle = async () => {
      const report = await sync.cycle();
      const failed = report.connections.find((c) => c.error !== null);
      if (failed) throw new Error(`cycle failed: ${failed.error}`);
      return report;
    };
    const records = async () =>
      (
        await db.query<{ stream: string; record_key: string; body: string }>(
          "SELECT stream, record_key, body FROM records ORDER BY stream, record_key",
        )
      ).map((r) => `${r.stream}/${r.record_key}=${r.body}`);
    /** Every column the log promises a caught-up reader agrees on. */
    const rows = async () =>
      (
        await db.query<{
          stream: string;
          record_key: string;
          body: string;
          stamp_o: number;
          stamp_r: string;
          first_o: number | null;
        }>(
          "SELECT stream, record_key, body, stamp_o, stamp_r, first_o FROM records ORDER BY stream, record_key",
        )
      ).map((r) => JSON.stringify(r));
    const position = async () =>
      (
        await db.query<{ position: number }>(
          "SELECT position FROM log_state WHERE connection_id = ?",
          [CONNECTION_ID],
        )
      )[0]?.position ?? 0;
    return { db, deps, sync, run, cycle, records, rows, position, puts, gets };
  }

  /** The decoded segments in the blob store, by position. */
  const segments = async () => {
    const out = new Map<number, Segment>();
    for (const key of innerBlobs.keys()) {
      if (!key.startsWith(`${LOG}/s-`)) continue;
      const bytes = await innerBlobs.get(key);
      const decoded = decodeSegment(bytes!);
      if (decoded.kind === "ok")
        out.set(decoded.segment.position, decoded.segment);
    }
    return out;
  };
  /** Segment blob keys by position. */
  const segmentKeys = async () => {
    const out = new Map<number, string>();
    for (const key of innerBlobs.keys()) {
      if (!key.startsWith(`${LOG}/s-`)) continue;
      const decoded = decodeSegment((await innerBlobs.get(key))!);
      if (decoded.kind === "ok") out.set(decoded.segment.position, key);
    }
    return out;
  };
  /** The snapshot parts a head points at, decoded, in pointer order. */
  const snapshotParts = async (head: Segment) => {
    const parts: SnapshotPart[] = [];
    for (const ref of head.snapshot!.parts) {
      const decoded = decodeSnapshotPart(
        (await innerBlobs.get(`${LOG}/q-${ref.dataHash.slice(2)}`))!,
      );
      if (decoded.kind !== "ok")
        throw new Error("snapshot part did not decode");
      parts.push(decoded.part);
    }
    return parts;
  };
  const writes = () => ({
    batches: gateway.batches().length,
    posts: gateway.calls.filter((c) => c.kind === "post").length,
  });
  return {
    device,
    gateway,
    names,
    innerBlobs,
    segments,
    segmentKeys,
    snapshotParts,
    writes,
    setClock: (t: number) => (clock = t),
  };
}
