// A shared world for log-protocol tests: one fake gateway and one blob store,
// and any number of devices of one owner, each with its own real SQLite and the
// real publish and apply drivers (see log-protocol.test.ts).
import { AsyncLocalStorage } from "node:async_hooks";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { keccak_256 } from "@noble/hashes/sha3";
import type { StreamCryptoPort } from "../../../core/src/stream-sync/crypto-port.js";
import {
  controlHashes,
  controlScope,
  decodeSegment,
  decodeSnapshotPart,
  deriveKeyCheck,
  logScope,
  pkHash,
  type JsonValue,
  type WireSegment,
  type WireSnapshotPart,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { sha256 } from "@noble/hashes/sha2";
import {
  connectionQueue,
  createLocalSync,
  openLocalDb,
  type LocalSyncDeps,
  type LogErasurePorts,
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
import { endRequest } from "../../../core/src/test-utils/run-end.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { createFakeGateway, type FakeGatewayOptions } from "./fake-gateway.js";
import type { RequestTrace } from "./request-trace.test-utils.js";

export const OWNER = `0x${"11".repeat(20)}` as const;
export const CONNECTOR = "fixture";
export const CONNECTION_ID = `pdpp.${CONNECTOR}~`;
export const CONTROL = controlScope(CONNECTOR, "");
export const LOG = logScope(CONNECTOR, "");
export const sName = (i: number) => `s${i}`;
export const idHash = (id: string | number) =>
  pkHash(async (b) => sha256(b), { id }, ["id"]);

const drivers: SqlDriver[] = [];
/**
 * Closes the databases of the devices a test opened; call it from `afterEach`.
 * A database its test already closed is skipped.
 */
export async function closeWorldDrivers(): Promise<void> {
  for (const db of drivers.splice(0)) {
    // A test may have closed its device's sync, which closes the database.
    await db.close().catch((error: unknown) => {
      if (!(error instanceof Error && error.message === "sqlite_driver_closed"))
        throw error;
    });
  }
  for (const dir of tempDirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
}
const tempDirs: string[] = [];
/**
 * A database file of one test, on disk, for a device that restarts
 * (`dbFile`). Removed by `closeWorldDrivers`. Under the system's temporary
 * directory: a home-relative path exists on one machine only.
 */
export function tempDbFile(): string {
  const dir = mkdtempSync(join(tmpdir(), "ps-restart-"));
  tempDirs.push(dir);
  return join(dir, "device.sqlite");
}

export async function world(options: {
  streams: number;
  publishWhileCollecting?: boolean;
  /** The registry's rule that refuses a stream row write beside a log row (default on). */
  connectionLogFence?: boolean;
  partTargetBytes?: number;
  /** The key types every stream's schema declares (none: undeclared). */
  keyTypes?: readonly ("string" | "number" | "integer" | "boolean" | null)[];
  /** Every gateway and storage request of every device goes through this trace. */
  trace?: RequestTrace;
  /** The `Batch-Policy` the gateway advertises and enforces (`FakeGatewayOptions.policy`). */
  policy?: FakeGatewayOptions["policy"];
  /** Each stream's declared state parents (none: no parents). */
  stateParents?: Readonly<Record<string, readonly string[]>>;
}) {
  const keyCheck = await deriveKeyCheck(async () => new Uint8Array(32));
  const hashes = await controlHashes(async (b) => keccak_256(b), keyCheck);
  const gateway = createFakeGateway({
    owner: OWNER,
    refresh: true,
    connectionLogFence: options.connectionLogFence ?? true,
    ...(options.policy && { policy: options.policy }),
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
  const trace = options.trace;
  const names = Array.from({ length: options.streams }, (_, i) => sName(i));
  let clock = 1000;

  async function device(
    deviceId: string,
    hooks: {
      beforePut?: (key: string) => Promise<void>;
      /** Awaited before a blob is returned: stops an apply where it fetches. */
      beforeGet?: (key: string) => Promise<void>;
      /** Test-only arrival barrier, before entering the real listing coalescer. */
      beforeListStreamRows?: (connector: string) => Promise<void>;
      /** A host that serves a first load's applied parts while it fills. */
      progressiveFirstLoad?: boolean;
      /**
       * `false` applies a first load segment by segment, never key by key
       * (`LocalSyncDeps.keyedFirstLoad`): the result a keyed load is compared with.
       */
      keyedFirstLoad?: boolean;
      /**
       * The byte budget of this device's transfers. A budget below one
       * segment makes an apply fetch and commit one segment at a time.
       */
      maxBytesInFlight?: number;
      /** The host's hash and cipher port (`LocalSyncDeps.streamCrypto`). */
      streamCrypto?: StreamCryptoPort;
      /** The host's ports for erasing a deleted connection's log objects. */
      erasure?: () => LogErasurePorts | undefined;
      /** The host's ports for retiring a deleted connection's legacy copy. */
      legacyDelete?: () => LegacyDeletePorts | undefined;
      /** Waits between retries of a delete or erasure (shortened for tests). */
      deleteRetryMs?: { first: number; max: number };
      /**
       * A database file for this device (default: in memory). With a file the
       * device can `restart`: a new process over the same database.
       */
      dbFile?: string;
    } = {},
  ) {
    const identity = { owner: OWNER, network: "test", deviceId };
    const db = await openLocalDb(
      openBetterSqlite3(hooks.dbFile ?? ":memory:"),
      identity,
    );
    drivers.push(db);
    const puts: string[] = [];
    const gets: string[] = [];
    let op = 0;
    const logicalCall = new AsyncLocalStorage<string>();
    const registry = createGatewayStreamSyncRegistry({
      gatewayUrl: "https://gateway.test",
      ownerAddress: OWNER,
      fetch: trace
        ? (((input: string, init?: RequestInit) => {
            const url = new URL(input);
            const method = init?.method ?? "GET";
            const kind =
              url.pathname === "/v1/data/batch"
                ? "batch"
                : url.pathname === "/v1/data"
                  ? method === "GET"
                    ? "list"
                    : "post"
                  : "read";
            const label =
              kind === "list"
                ? `${logicalCall.getStore() ?? "unlabelled"} limit=${url.searchParams.get("limit") ?? ""} cursor=${url.searchParams.get("cursor") ?? "<first>"}`
                : "";
            return trace.track(kind, label, () => gateway.fetch(input, init));
          }) as unknown as typeof fetch)
        : gateway.fetch,
    });
    const deps: LocalSyncDeps = {
      db,
      // Ordinary-path reference fixtures opt out; bootstrap tests opt in.
      bootstrapFirstLoad: false,
      queue: connectionQueue(),
      registry: {
        ...registry,
        listControlRows: () =>
          logicalCall.run("listControlRows", () => registry.listControlRows()),
        listOwnerRows: () =>
          logicalCall.run("listOwnerRows", () => registry.listOwnerRows()),
        listStreamRows: async (connector) => {
          if (hooks.beforeListStreamRows)
            await hooks.beforeListStreamRows(connector);
          return logicalCall.run(`listStreamRows(${connector})`, () =>
            registry.listStreamRows(connector),
          );
        },
        ...(registry.probeChange && {
          probeChange: (signal?: AbortSignal) =>
            logicalCall.run("probeChange", () => registry.probeChange!(signal)),
        }),
      },
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
          return trace
            ? trace.track("get", "", () => innerBlobs.get(key))
            : innerBlobs.get(key);
        },
        exists: (key) =>
          trace
            ? trace.track("exists", "", () => innerBlobs.exists(key))
            : innerBlobs.exists(key),
        async put(key, bytes) {
          await hooks.beforePut?.(key);
          if (trace)
            await trace.track("put", "", () => innerBlobs.put(key, bytes));
          else await innerBlobs.put(key, bytes);
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
      ...(options.publishWhileCollecting
        ? { publishWhileCollecting: true }
        : {}),
      ...(hooks.progressiveFirstLoad ? { progressiveFirstLoad: true } : {}),
      ...(hooks.keyedFirstLoad === false ? { keyedFirstLoad: false } : {}),
      ...(hooks.streamCrypto ? { streamCrypto: hooks.streamCrypto } : {}),
      ...(options.partTargetBytes !== undefined
        ? { partTargetBytes: options.partTargetBytes }
        : {}),
    };
    const syncOptions = {
      ...(hooks.erasure ? { erasure: hooks.erasure } : {}),
      ...(hooks.legacyDelete ? { legacyDelete: hooks.legacyDelete } : {}),
      ...(hooks.deleteRetryMs ? { deleteRetryMs: hooks.deleteRetryMs } : {}),
      // A digest `<connector>@<version>` names a connector version; a bare
      // connector name is version 1.
      resolveArtifact: (digest) => ({
        connector: digest.split("@")[0]!,
        version: digest.split("@")[1] ?? "1",
        streams: names.map((name) => ({
          name,
          semantics: "mutable_state" as const,
          primaryKey: ["id"],
          coverageStrategy: "full_inventory" as const,
          ...(options.keyTypes ? { keyTypes: options.keyTypes } : {}),
          ...(options.stateParents?.[name]
            ? { stateParents: options.stateParents[name] }
            : {}),
        })),
      }),
    };
    const sync = createLocalSync(deps, syncOptions);
    /**
     * The process ends and starts again over the same database file: a new
     * handle, a new queue and a new sync, with this device's ports. Nothing
     * the old process held in memory is left.
     */
    let live: { db: typeof db; sync: typeof sync } = { db, sync };
    const restart = async () => {
      if (!hooks.dbFile) throw new Error("a restart needs a dbFile");
      await live.sync.close();
      const at = drivers.indexOf(live.db);
      if (at >= 0) drivers.splice(at, 1);
      const reopened = await openLocalDb(
        openBetterSqlite3(hooks.dbFile),
        identity,
      );
      drivers.push(reopened);
      const next: LocalSyncDeps = {
        ...deps,
        db: reopened,
        queue: connectionQueue(),
      };
      const restarted = createLocalSync(next, syncOptions);
      live = { db: reopened, sync: restarted };
      return { db: reopened, deps: next, sync: restarted };
    };
    /** A run's begin: the mode and state the connector starts from. */
    const begin = (
      runId: string,
      opts: {
        full?: boolean;
        observedAt?: number;
        connect?: boolean;
        connector?: string;
        version?: string;
        join?: boolean;
      } = {},
    ) => {
      clock++;
      const connector = opts.connector ?? CONNECTOR;
      return sync.intake.begin(runId, {
        connector,
        artifactDigest:
          opts.version === undefined
            ? connector
            : `${connector}@${opts.version}`,
        wantFull: opts.full ?? true,
        ...(opts.connect ? { connect: true } : {}),
        ...(opts.join === false ? {} : { join: true as const }),
        observedAt: opts.observedAt,
        owner: { address: OWNER, leaseId: null },
      });
    };
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
        /** The streams the run selected (default: every stream). */
        selected?: readonly string[];
        /** The selected streams it covers; the others were skipped. */
        covered?: readonly string[];
        full?: boolean;
        observedAt?: number;
        /** An explicit connect by the owner: the only start of a deleted connection. */
        connect?: boolean;
        /** Bytes the record named by `blobId` carries, sent before the run ends. */
        blob?: { hash: string; bytes: Uint8Array };
        /** The connector the run collects for (default: the world's one connector). */
        connector?: string;
        /** The connector version the run's artifact declares (default "1"). */
        version?: string;
        /**
         * The host's accepted join prompt. On by default, so a second device
         * collects as it did before the join gate; `false` is a device the
         * user has not asked to continue the connection.
         */
        join?: boolean;
        /** The connector cursor the run ends with, per stream. */
        checkpoints?: Readonly<Record<string, JsonValue>>;
        /** What the run observed per stream (for example a retryable skip). */
        observe?: Readonly<Record<string, { retryableSkip?: boolean }>>;
        /** What happens on the device while the run collects, before it ends. */
        during?: () => Promise<unknown>;
      } = {},
    ) => {
      const begun = await begin(runId, opts);
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
      await opts.during?.();
      const selected = opts.selected ?? names;
      const covered = opts.covered ?? selected;
      await sync.intake.end(
        runId,
        endRequest({
          lastBatch: 0,
          streams: selected,
          live: records
            .filter((record) => !record.remove)
            .map((record) => record.stream),
          deleted: records
            .filter((record) => record.remove)
            .map((record) => record.stream),
          skipped: selected.filter((name) => !covered.includes(name)),
          ...(opts.full === false ? {} : { provenFullStreams: selected }),
          ...(opts.checkpoints ? { checkpoints: opts.checkpoints } : {}),
          ...(opts.observe ? { observe: opts.observe } : {}),
        }),
      );
      return begun;
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
          stamp_n: number;
          first_o: number | null;
        }>(
          "SELECT stream, record_key, body, stamp_o, stamp_r, stamp_n, first_o FROM records ORDER BY stream, record_key",
        )
      ).map((r) => JSON.stringify(r));
    const position = async () =>
      (
        await db.query<{ position: number }>(
          "SELECT position FROM log_state WHERE connection_id = ?",
          [CONNECTION_ID],
        )
      )[0]?.position ?? 0;
    return {
      db,
      deps,
      sync,
      begin,
      run,
      cycle,
      records,
      rows,
      position,
      puts,
      gets,
      restart,
    };
  }

  /** The decoded segments in the blob store, by position. */
  const segments = async () => {
    const out = new Map<number, WireSegment>();
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
  const snapshotParts = async (head: WireSegment) => {
    const parts: WireSnapshotPart[] = [];
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
