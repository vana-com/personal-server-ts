// What one sync cycle asks the registry when nothing changed anywhere.
//
// The timer runs this cycle every poll interval on every device, so its
// request count is the load the registry sees from idle devices today. The
// change probe (one request) is sized against it: see D4-SYNC-TRIGGERS.
// Real SQLite and connection queue; the registry and blob store are fakes that
// count calls.
import { afterEach, describe, expect, it } from "vitest";
import {
  connectionQueue,
  createLocalSync,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createMemoryStreamSyncBlobs,
  createMemoryStreamSyncRegistry,
  type MemoryStreamSyncRegistry,
  type StreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const OWNER = `0x${"11".repeat(20)}` as const;
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

async function world(connectors: number, streamsPer: number) {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: OWNER,
    network: "test",
    deviceId: "d",
  });
  drivers.push(db);
  const calls: string[] = [];
  const inner = createMemoryStreamSyncRegistry() as MemoryStreamSyncRegistry;
  const registry: StreamSyncRegistry = {
    async read(scope) {
      calls.push("registry.read");
      return inner.read(scope);
    },
    async post(request) {
      calls.push("registry.post");
      return inner.post(request);
    },
    async listControlRows() {
      calls.push("registry.list");
      return inner.listControlRows();
    },
    async listStreamRows(connector) {
      calls.push("registry.list");
      return inner.listStreamRows(connector);
    },
    async listConnectionRows(connector, ns) {
      calls.push("registry.list");
      return inner.listConnectionRows(connector, ns);
    },
    async probeChange() {
      calls.push("registry.probe");
      return inner.probeChange!();
    },
  };
  const innerBlobs = createMemoryStreamSyncBlobs();
  const blobs = {
    async get(key: string) {
      calls.push("blob.get");
      return innerBlobs.get(key);
    },
    async exists(key: string) {
      calls.push("blob.exists");
      return innerBlobs.exists(key);
    },
    async put(key: string, bytes: Uint8Array) {
      calls.push("blob.put");
      await innerBlobs.put(key, bytes);
    },
  };
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    queue: connectionQueue(),
    registry,
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
  };
  const names = Array.from({ length: streamsPer }, (_, i) => `s${i}`);
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
  let runs = 0;
  for (let c = 0; c < connectors; c++) {
    const connector = `c${c}`;
    const runId = `run-${++runs}`;
    await sync.intake.begin(runId, {
      connector,
      artifactDigest: connector,
      wantFull: true,
      owner: { address: OWNER, leaseId: null },
    });
    await sync.intake.batch(runId, {
      batch: 0,
      records: names.flatMap((stream) => [
        { stream, data: { id: `${stream}-0`, version: 1 } },
      ]),
    });
    await sync.intake.end(runId, {
      outcome: "succeeded",
      coveredStreams: names,
      lastBatch: 0,
    });
  }
  await sync.cycle(); // publishes everything
  await sync.cycle(); // settles: a second pass finds nothing to do
  return { sync, calls };
}

const tally = (calls: readonly string[]) =>
  Object.fromEntries(
    [...new Set(calls)]
      .sort()
      .map((c) => [c, calls.filter((x) => x === c).length]),
  );

describe("an idle sync cycle", () => {
  it.each([
    [1, 6],
    [3, 6],
    [6, 6],
  ])("%i connections of %i streams: registry requests", async (c, s) => {
    const w = await world(c, s);
    w.calls.length = 0;
    await w.sync.cycle();
    const t = tally(w.calls);
    console.log(`IDLE-CYCLE connections=${c} streams=${s}`, JSON.stringify(t));
    expect(w.calls.filter((x) => x === "registry.post")).toHaveLength(0);
    expect(w.calls.filter((x) => x === "blob.put")).toHaveLength(0);
  });
});
