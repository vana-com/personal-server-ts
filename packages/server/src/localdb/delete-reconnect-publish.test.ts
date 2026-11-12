/**
 * Delete, then reconnect, then publish: every input to the publish decision is
 * produced by a production function in the order a user performs it.
 *
 * The delete writer posts an empty stream head (see `delete.ts`); a reconnect
 * raises the connection to a later generation (`run-intake.ts`); the publisher
 * defers a stream whose verified registry head has another generation
 * (`publish.ts`). This file runs that sequence through the real deleter, the
 * real run intake and end stores, the real publisher and the real
 * `classifyStreamRow`, over the in-memory registry and blob store. Nothing
 * writes a head or a generation by hand.
 *
 * Limit: the in-memory registry always reports `deleted: false`. A registry
 * that flags a delete post as deleted would make `classifyStreamRow` answer
 * "tombstoned" and skip the head read.
 */
import { afterEach, expect, it, vi } from "vitest";
import {
  connectionQueue,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createMemoryStreamSyncBlobs,
  createMemoryStreamSyncRegistry,
  type MemoryStreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  classifyStreamRow,
  decodeHead,
  headBlobName,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { applyConnection } from "../../../core/src/localdb/apply.js";
import { bootstrapConnections } from "../../../core/src/localdb/bootstrap.js";
import { createConnectionDeleter } from "../../../core/src/localdb/delete.js";
import { publishConnection } from "../../../core/src/localdb/publish.js";
import { createRunEndStore } from "../../../core/src/localdb/run-end.js";
import { createRunIntakeStore } from "../../../core/src/localdb/run-intake.js";
import { syncConnection } from "../../../core/src/localdb/cycle.js";
import { deleteMetadataHash } from "../../../core/src/stream-sync/delete-metadata.js";
import { remoteFixture } from "./apply-fixture.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const owner = `0x${"12".repeat(20)}`;
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

const declaration = {
  connector: "fixture-source",
  version: "1",
  streams: [
    {
      name: "items",
      semantics: "mutable_state" as const,
      primaryKey: ["id"],
    },
  ],
};

async function world() {
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const fixture = await remoteFixture(keys);
  const registry = createMemoryStreamSyncRegistry() as MemoryStreamSyncRegistry;
  const blobs = createMemoryStreamSyncBlobs();
  // Only the control row is seeded; no stream head exists until a real publish.
  await registry.post({
    ownerAddress: owner,
    scope: fixture.control,
    dataHash: fixture.hashes.activeData as `0x${string}`,
    metadataHash: fixture.hashes.activeMetadata as `0x${string}`,
    expectedVersion: "1",
    signature: "0x00",
  });
  const scope = `${fixture.control}.items`;
  const devices = [];
  for (let n = 0; n < 2; n++) {
    const db = await openLocalDb(openBetterSqlite3(":memory:"), {
      owner,
      network: "test",
      deviceId: `repro-${n}`,
    });
    drivers.push(db);
    let op = 0;
    let now = 1000;
    const deps: LocalSyncDeps = {
      db,
      keys,
      registry,
      blobs,
      queue: connectionQueue(),
      ownerAddress: owner,
      signer: { signAddData: async () => "0x00" },
      logger: { info: vi.fn(), warn: vi.fn() },
      now: () => ++now,
      newOp: () => `repro-${n}-${++op}`,
    };
    await bootstrapConnections(deps);
    await applyConnection(deps, fixture.control);
    devices.push({
      db,
      deps,
      deleter: createConnectionDeleter(deps, {
        declaredStreams: () => ["items"],
      }),
    });
  }
  return { fixture, registry, blobs, scope, a: devices[0]!, b: devices[1]! };
}
type World = Awaited<ReturnType<typeof world>>;
type Device = World["a"];

let runs = 0;
/** One collector run through the real intake and end stores. */
async function collect(
  device: Device,
  ids: string[],
  options: { connect?: boolean } = {},
) {
  const runId = `run-${++runs}`;
  const intake = createRunIntakeStore(device.deps);
  const begun = await intake.begin(
    runId,
    {
      connector: declaration.connector,
      artifactDigest: "fixture",
      owner: { address: owner, leaseId: null },
      observedAt: 2000 + runs,
      ...(options.connect ? { connect: true } : {}),
    },
    declaration,
  );
  await intake.batch(runId, {
    batch: 0,
    records: ids.map((id) => ({ stream: "items", data: { id } })),
  });
  await createRunEndStore(device.deps).end(runId, {
    outcome: "succeeded",
    coveredStreams: ["items"],
    lastBatch: 0,
    provenFullStreams: ["items"],
  });
  return begun.start.collection_mode;
}

/** Delete from `device` until no intent is pending. */
async function deleteConnection(w: World, device: Device) {
  await device.deleter.requestConnectionDelete(declaration.connector);
  for (let i = 0; i < 5; i++) {
    if ((await device.deleter.resumeDeletes()).length === 0) return;
  }
  throw new Error("delete intent still pending");
}

/** What the registry holds for the stream now, decoded and classified. */
async function observeHead(w: World) {
  const row = await w.registry.read(w.scope);
  if (!row.found) return { found: false as const };
  const cipher = await w.blobs.get(`${w.scope}/${headBlobName(row.dataHash)}`);
  const decoded = cipher ? decodeHead(cipher) : null;
  return {
    found: true as const,
    version: row.version,
    classification: classifyStreamRow(row, w.fixture.hashes),
    isDeleteMarker:
      row.metadataHash.toLowerCase() ===
      deleteMetadataHash(w.scope, row.version),
    generation: decoded?.kind === "ok" ? decoded.head.generation : null,
    recordCount: decoded?.kind === "ok" ? decoded.head.recordCount : null,
  };
}

async function generationOf(device: Device) {
  const [row] = await device.db.query<{ generation: number }>(
    "SELECT generation FROM connections",
  );
  return row!.generation;
}

/** delete on `del`, reconnect + collect on `rec`, then the normal cycle. */
async function lifetime(w: World, del: Device, rec: Device, label: string) {
  const afterDelete = (await deleteConnection(w, del), await observeHead(w));
  // The reconnecting device learns the deletion through a normal apply.
  if (rec !== del) await applyConnection(rec.deps, w.fixture.control);
  const mode = await collect(rec, [`${label}-new`], { connect: true });
  const generation = await generationOf(rec);
  const cycle = await syncConnection(rec.deps, w.fixture.control);
  const outcomes = cycle.published.map((p) => p.outcome);
  return {
    afterDelete,
    mode,
    generation,
    outcomes,
    cycleError: cycle.error,
    applied: cycle.applied.map((a) => a.outcome),
    afterCycle: await observeHead(w),
  };
}

async function published(w: World) {
  await collect(w.a, ["old"]);
  expect(
    (await publishConnection(w.a.deps, w.fixture.control))[0]?.outcome,
  ).toBe("published");
  expect(await observeHead(w)).toMatchObject({
    generation: 1,
    recordCount: 1,
    classification: "present",
  });
}

// KNOWN DEFECT (reproduced): the delete writer posts its empty stream head at
// generation 1, `classifyStreamRow` calls that delete-marker row "present", the
// reconnect raises the connection to generation 3 (then 5), and the publisher
// returns "deferred" for every later cycle. `it.fails` turns green when a fix
// makes the stream publish again; then change it to `it`.
const REPRO =
  "delete head generation 1 vs reconnected connection generation (deferred forever)";

it("records the real inputs: delete head is generation 1 and 'present'; reconnect is generation 3", async () => {
  const w = await world();
  await published(w);
  const r = await lifetime(w, w.a, w.a, "one");
  expect(r.afterDelete).toMatchObject({
    version: 2,
    isDeleteMarker: true,
    generation: 1,
    recordCount: 0,
    classification: "present",
  });
  expect(r.mode).toBe("full_refresh");
  expect(r.generation).toBe(3);
});

it.fails(`${REPRO}: same device, two delete/reconnect rounds`, async () => {
  const w = await world();
  await published(w);
  for (const label of ["one", "two"]) {
    const r = await lifetime(w, w.a, w.a, label);
    expect(r.outcomes).toEqual(["published"]);
    expect(r.afterCycle.found && r.afterCycle.generation).toBe(r.generation);
  }
});

it.fails(`${REPRO}: delete on device A, reconnect on device B`, async () => {
  const w = await world();
  await published(w);
  const r = await lifetime(w, w.a, w.b, "one");
  expect(r.generation).toBe(3);
  expect(r.outcomes).toEqual(["published"]);
  expect(r.afterCycle.found && r.afterCycle.generation).toBe(3);
});
