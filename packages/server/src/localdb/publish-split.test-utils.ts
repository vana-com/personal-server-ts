// Fixture for the publish snapshot/transfer/commit tests: devices that share
// one registry and one blob store, with deterministic gates on storage and on
// the per-connection queue. No timers: a gate is a promise the test resolves.
import { vi } from "vitest";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  classifyStreamRow,
  controlHashes,
  controlScope,
  deriveKeyCheck,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  connectionQueue,
  createLocalSync,
  openLocalDb,
  type LocalSyncDeps,
  type OperationKind,
  type SqlValue,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createMemoryStreamSyncBlobs,
  createMemoryStreamSyncRegistry,
  type StreamSyncBlobs,
  type StreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

export const owner = `0x${"11".repeat(20)}` as const;

/** A point the code under test reaches and the test releases. */
export type Gate = {
  /** Resolves when the code under test is waiting at the gate. */
  readonly reached: Promise<void>;
  release(): void;
};

function gate(): Gate & { arrive(): Promise<void> } {
  let reach!: () => void;
  let open!: () => void;
  const reached = new Promise<void>((resolve) => (reach = resolve));
  const released = new Promise<void>((resolve) => (open = resolve));
  return {
    reached,
    release: open,
    arrive() {
      reach();
      return released;
    },
  };
}

type StorageOp = "get" | "put";

/** Blob storage whose next matching operation can be held or failed. */
export type FakeStorage = StreamSyncBlobs & {
  readonly puts: string[];
  /** Hold the next operation `when` accepts until the test releases it. */
  holdNext(when?: (op: StorageOp, key: string) => boolean): Gate;
  /** Fail the next put once. */
  failNextPut(): void;
};

function fakeStorage(inner: StreamSyncBlobs): FakeStorage {
  const puts: string[] = [];
  let held: {
    when: (op: StorageOp, key: string) => boolean;
    gate: ReturnType<typeof gate>;
  } | null = null;
  let failing = false;
  const pause = async (op: StorageOp, key: string) => {
    if (held?.when(op, key)) {
      const { gate: pending } = held;
      held = null;
      await pending.arrive();
    }
  };
  return {
    puts,
    holdNext(when = () => true) {
      const next = gate();
      held = { when, gate: next };
      return next;
    },
    failNextPut() {
      failing = true;
    },
    async get(key) {
      await pause("get", key);
      return inner.get(key);
    },
    async exists(key) {
      // A probe was a GET before it became a HEAD; a hold on gets still holds it.
      await pause("get", key);
      return inner.exists(key);
    },
    async put(key, bytes) {
      if (failing) {
        failing = false;
        throw new Error("put failed");
      }
      await pause("put", key);
      puts.push(key);
      await inner.put(key, bytes);
    },
  };
}

export type Device = Awaited<ReturnType<typeof makeDevice>>;

const drivers: SqlDriver[] = [];
export async function closeDrivers(): Promise<void> {
  for (const db of drivers.splice(0)) await db.close();
}

export type FaultyRegistry = StreamSyncRegistry & {
  /**
   * Fail the next stream post once. `before`: the registry never saw it.
   * `after`: the registry accepted it and the caller got an error (a crash
   * between the CAS and the local commit looks the same).
   */
  failNextStreamPost(when: "before" | "after"): void;
};

function faultyRegistry(inner: StreamSyncRegistry): FaultyRegistry {
  let fault: "before" | "after" | null = null;
  const control = controlScope("fixture", "");
  return {
    read: (scope) => inner.read(scope),
    listControlRows: () => inner.listControlRows(),
    listStreamRows: (connector) => inner.listStreamRows(connector),
    failNextStreamPost(when) {
      fault = when;
    },
    async post(request) {
      if (fault && request.scope !== control) {
        const when = fault;
        fault = null;
        if (when === "before") throw new Error("post lost");
        await inner.post(request);
        throw new Error("post reply lost");
      }
      return inner.post(request);
    },
  };
}

export function sharedStores() {
  return {
    registry: faultyRegistry(createMemoryStreamSyncRegistry()),
    storage: fakeStorage(createMemoryStreamSyncBlobs()),
  };
}

type Stores = ReturnType<typeof sharedStores>;

export async function makeDevice(
  stores: Stores,
  deviceId: string,
  connector = "fixture",
) {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner,
    network: "test",
    deviceId,
  });
  drivers.push(db);
  let op = 0;
  let now = 1000;
  const real = connectionQueue();
  // The slot, observed. `pending` counts operations requested and not yet
  // finished, so a request that sees `pending > 0` waits behind another.
  let pending = 0;
  const requests: { kind: OperationKind; behind: number }[] = [];
  const requestWaiters: (() => void)[] = [];
  const publishPauses = new Map<number, ReturnType<typeof gate>>();
  let publishCount = 0;
  const queue = {
    async run<T>(id: string, kind: OperationKind, fn: () => Promise<T>) {
      requests.push({ kind, behind: pending });
      for (const wake of requestWaiters.splice(0)) wake();
      if (kind === "publish") {
        const pause = publishPauses.get(++publishCount);
        if (pause) await pause.arrive();
      }
      pending++;
      try {
        return await real.run(id, kind, fn);
      } finally {
        pending--;
      }
    },
  };
  const deps: LocalSyncDeps = {
    db,
    queue,
    registry: stores.registry,
    blobs: stores.storage,
    ownerAddress: owner,
    keys: {
      namespaceHmac: async () => new Uint8Array(32),
      encrypt: async (_s, b) => b,
      encryptPart: async (_s, b) => b,
      decrypt: async (_s, b) => b,
    },
    signer: { signAddData: async () => "0x00" },
    logger: { info: vi.fn(), warn: vi.fn() },
    now: () => now,
    newOp: () => `${deviceId}-${++op}`,
  };
  const sync = createLocalSync(deps, {
    resolveArtifact: (digest) => ({
      connector: digest,
      version: "1",
      streams: [
        {
          name: "items",
          semantics: "mutable_state" as const,
          primaryKey: ["id"],
        },
      ],
    }),
    declaredStreams: () => ["items"],
    olderVersionReads: () => true,
  });
  /** One connection's run helpers and local reads. */
  const connection = (connector: string) => {
    const connectionId = `pdpp.${connector}~`;
    const begin = (id: string, connect = false) => {
      now++;
      return sync.intake.begin(id, {
        connector,
        artifactDigest: connector,
        wantFull: true,
        ...(connect ? { connect: true } : {}),
        owner: { address: owner, leaseId: null },
      });
    };
    const end = (id: string) =>
      sync.intake.end(id, {
        outcome: "succeeded",
        coveredStreams: ["items"],
        lastBatch: 0,
      });
    const stream = async <T>(columns: string) =>
      (
        await db.query<T & Record<string, never>>(
          `SELECT ${columns} FROM stream_state WHERE connection_id = ? AND stream = 'items'`,
          [connectionId],
        )
      )[0];
    return {
      connectionId,
      connector,
      begin,
      end,
      async run(id: string, rows: string[], connect = false) {
        await begin(id, connect);
        await sync.intake.batch(id, {
          batch: 0,
          records: rows.map((key) => ({ stream: "items", data: { id: key } })),
        });
        return end(id);
      },
      /** A run that deletes records by key (PDPP `op: "delete"`). */
      async remove(id: string, keys: string[]) {
        await begin(id);
        await sync.intake.batch(id, {
          batch: 0,
          records: keys.map((key) => ({
            stream: "items",
            op: "delete" as const,
            data: { id: key },
          })),
        });
        return end(id);
      },
      /** Local record keys, ordered. */
      async keys(): Promise<string[]> {
        return (
          await db.query<{ record_key: string }>(
            "SELECT record_key FROM records WHERE connection_id = ? ORDER BY record_key",
            [connectionId],
          )
        ).map((r) => r.record_key);
      },
      async watermark(): Promise<number> {
        return (
          (await stream<{ publish_watermark: number }>("publish_watermark"))
            ?.publish_watermark ?? 0
        );
      },
      /** The newest change sequence the connection's stream has logged. */
      async newestChange(): Promise<number> {
        const [row] = await db.query<{ w: number | null }>(
          "SELECT MAX(seq) AS w FROM record_changes WHERE connection_id = ? AND stream = 'items'",
          [connectionId],
        );
        return row?.w ?? 0;
      },
      async head(): Promise<{ version: number; generation: number | null }> {
        const row = await stream<{
          head_version: number;
          head_generation: number | null;
        }>("head_version, head_generation");
        return {
          version: row?.head_version ?? 0,
          generation: row?.head_generation ?? null,
        };
      },
    };
  };
  return {
    db,
    sync,
    deps,
    /** True while any operation holds or awaits the connection's slot. */
    inSlot: () => pending > 0,
    requests,
    /** Resolves when the next queue request arrives; resolves its entry. */
    async nextRequest(): Promise<{ kind: OperationKind; behind: number }> {
      const seen = requests.length;
      await new Promise<void>((resolve) => requestWaiters.push(resolve));
      return requests[seen]!;
    },
    /** Pause the nth "publish" slot request from now, before it enters the queue. */
    pausePublish(nth: number): Gate {
      const pause = gate();
      publishPauses.set(publishCount + nth, pause);
      return pause;
    },
    ...connection(connector),
    query: <T extends Record<string, SqlValue>>(sql: string) =>
      db.query<T>(sql),
    connection,
    cycle: () => sync.cycle(),
    async decisions(): Promise<
      { run_id: string; decision: string; reason: string | null }[]
    > {
      return db.query(
        "SELECT run_id, decision, reason FROM run_streams ORDER BY run_id",
      );
    },
  };
}

/**
 * Another writer (Web) moves the control row: deleted, then active again. A
 * connection that was at generation g is at g + 2 afterwards. The stream rows
 * are left as they are: only the control row decides the lifetime.
 */
export async function webDeleteAndReconnect(
  stores: Stores,
  connector = "fixture",
) {
  const keyCheck = await deriveKeyCheck(async () => new Uint8Array(32));
  const hashes = await controlHashes(async (b) => keccak_256(b), keyCheck);
  const scope = controlScope(connector, "");
  const post = (version: number, kind: "active" | "tombstone") =>
    stores.registry.post({
      ownerAddress: owner,
      scope,
      dataHash: kind === "active" ? hashes.activeData : hashes.tombstoneData,
      metadataHash:
        kind === "active" ? hashes.activeMetadata : hashes.tombstoneMetadata,
      expectedVersion: String(version),
      signature: "0x00",
    });
  const read = await stores.registry.read(scope);
  let version = read.found ? read.version : 0;
  if (!read.found) await post(++version, "active");
  await post(++version, "tombstone");
  await post(++version, "active");
}

/** The registry's stream rows for the connector, as a head or a tombstone. */
export async function streamRows(
  stores: Stores,
  connector = "fixture",
): Promise<{ version: number; state: "head" | "tombstone" }[]> {
  const keyCheck = await deriveKeyCheck(async () => new Uint8Array(32));
  const hashes = await controlHashes(async (b) => keccak_256(b), keyCheck);
  return (await stores.registry.listStreamRows(connector)).flatMap(
    ({ read }) =>
      read.found
        ? [
            {
              version: read.version,
              state:
                classifyStreamRow(read, hashes) === "tombstoned"
                  ? ("tombstone" as const)
                  : ("head" as const),
            },
          ]
        : [],
  );
}

/** Every run id named by a publication receipt in a cycle report. */
export function receiptRunIds(report: {
  readonly connections: readonly {
    readonly published: readonly {
      readonly publication?: { readonly runIds: readonly string[] };
    }[];
  }[];
}): string[] {
  return report.connections.flatMap((c) =>
    c.published.flatMap((p) => [...(p.publication?.runIds ?? [])]),
  );
}
