import { vi, expect } from "vitest";
import {
  createImportLedger,
  createLocalSync,
  importLegacySource,
  openLocalDb,
  connectionQueue,
  syncBeforeBegin,
  type ImportSource,
  type LocalSyncDeps,
  type SqlDriver,
} from "../../../core/src/localdb/index.js";
import {
  createMemoryStreamSyncRegistry,
  createMemoryStreamSyncBlobs,
} from "../../../core/src/stream-sync/index.js";
import { endRequest } from "../../../core/src/test-utils/run-end.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

// Devices for the late-seed tests: real runs, publication and seeds over one
// in-memory registry. A test file closes `drivers` after each test.

export const drivers: SqlDriver[] = [];
export const owner = `0x${"11".repeat(20)}` as const;
export const connectionId = "pdpp.fixture~";

function newDeps(
  db: SqlDriver,
  registry: ReturnType<typeof createMemoryStreamSyncRegistry>,
  blobs: ReturnType<typeof createMemoryStreamSyncBlobs>,
  id: string,
  clock: { now: number },
): LocalSyncDeps {
  let op = 0;
  return {
    db,
    queue: connectionQueue(),
    registry,
    blobs,
    ownerAddress: owner,
    keys: {
      namespaceHmac: async () => new Uint8Array(32),
      encrypt: async (_s, b) => b,
      encryptPart: async (_s, b) => b,
      decrypt: async (_s, b) => b,
    },
    signer: { signAddData: async () => "0x00" },
    logger: { info: vi.fn(), warn: vi.fn() },
    now: () => clock.now,
    newOp: () => `${id}-${++op}`,
  };
}

export async function openDevice(
  registry: ReturnType<typeof createMemoryStreamSyncRegistry>,
  blobs: ReturnType<typeof createMemoryStreamSyncBlobs>,
  deviceId: string,
  clock: { now: number },
  path = ":memory:",
  streams = ["items"],
) {
  const db = await openLocalDb(openBetterSqlite3(path), {
    owner,
    network: "test",
    deviceId,
  });
  drivers.push(db);
  const deps = newDeps(db, registry, blobs, deviceId, clock);
  const sync = createLocalSync(deps, {
    resolveArtifact: () => ({
      connector: "fixture",
      version: "1",
      streams: streams.map((name) => ({
        name,
        semantics: "mutable_state" as const,
        primaryKey: ["id"],
        coverageStrategy: "full_inventory" as const,
      })),
    }),
  });
  const keys = async (stream = "items") =>
    (await sync.query.listRecords({ connectionId, stream, limit: 100 })).records
      .map((r) => r.recordKey)
      .sort();
  return {
    db,
    deps,
    sync,
    keys,
    /** A real run: a proven full refresh, or explicit deletes of `rows`. */
    async run(
      id: string,
      rows: string[],
      options: { remove?: boolean; stream?: string; observedAt?: number } = {},
    ) {
      clock.now++;
      const stream = options.stream ?? "items";
      await sync.intake.begin(id, {
        connector: "fixture",
        artifactDigest: "fixture",
        join: true,
        streams: [{ name: stream }],
        wantFull: !options.remove,
        observedAt: options.observedAt,
        owner: { address: owner, leaseId: null },
      });
      await sync.intake.batch(id, {
        batch: 0,
        records: rows.map((key) => ({
          stream,
          ...(options.remove ? { op: "delete" as const } : {}),
          data: { id: key },
        })),
      });
      await sync.intake.end(
        id,
        endRequest({
          lastBatch: 0,
          streams: [stream],
          ...(rows.length === 0
            ? {}
            : options.remove
              ? { deleted: [stream] }
              : { live: [stream] }),
          ...(options.remove ? {} : { provenFullStreams: [stream] }),
        }),
      );
    },
    async publish() {
      expect(
        (await sync.cycle()).connections.every((c) => c.error === null),
      ).toBe(true);
    },
    /** Seed `rows` the way a host's staged upload from one install would. */
    async seed(
      install: string,
      rows: string[],
      stream = "items",
      extra: Record<string, unknown> = {},
    ): Promise<ReturnType<typeof importLegacySource>> {
      await syncBeforeBegin(deps, "fixture");
      const source: ImportSource = {
        source: JSON.stringify([install, "fixture"]),
        owner,
        network: "test",
        revision: `${install}-upload`,
        target: {
          connectionId,
          connector: "fixture",
          stream,
          primaryKey: ["id"],
          semantics: "mutable_state",
          incremental: true,
        },
        exclusions: [],
        async *records() {
          for (const id of rows) yield { id, ...extra };
        },
      };
      return importLegacySource(deps, createImportLedger(db), source);
    },
    /** Import a source as a host would: the control row first, then the import. */
    async importEntry(
      source: ImportSource,
    ): Promise<ReturnType<typeof importLegacySource>> {
      await syncBeforeBegin(deps, "fixture");
      return importLegacySource(deps, createImportLedger(db), source);
    },
    /** Import a source built from the fixture's own identity, as a host would. */
    async importSource(
      install: string,
      build: (base: Omit<ImportSource, "records">) => ImportSource,
    ): Promise<ReturnType<typeof importLegacySource>> {
      return this.importEntry(
        build({
          source: JSON.stringify([install, "fixture"]),
          owner,
          network: "test",
          revision: `${install}-upload`,
          target: {
            connectionId,
            connector: "fixture",
            stream: "items",
            primaryKey: ["id"],
            semantics: "mutable_state",
            incremental: true,
          },
          exclusions: [],
        }),
      );
    },
    async snapshot(stream = "items") {
      return db.query(
        "SELECT record_key, stamp_o, stamp_r, first_o, body FROM records WHERE stream = ? ORDER BY record_key",
        [stream],
      );
    },
  };
}
export async function world() {
  const registry = createMemoryStreamSyncRegistry();
  const blobs = createMemoryStreamSyncBlobs();
  const clock = { now: 1000 };
  return {
    registry,
    blobs,
    clock,
    device: (id: string, path?: string, streams?: string[]) =>
      openDevice(registry, blobs, id, clock, path, streams),
  };
}

/** Everything a device holds of a stream, for "nothing changed" checks. */
export async function state(device: Awaited<ReturnType<typeof openDevice>>) {
  return {
    rows: await device.db.query(
      "SELECT record_key, stamp_o, stamp_r, first_o, body FROM records ORDER BY stream, record_key",
    ),
    changes: await device.db.query("SELECT * FROM record_changes"),
    tombstones: await device.db.query("SELECT * FROM log_tombstones"),
  };
}
