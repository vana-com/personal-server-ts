import { afterEach, describe, expect, it, vi } from "vitest";
import {
  connectionQueue,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import type {
  BeginRequest,
  IntakeDeclarations,
} from "../../../core/src/stream-sync/intake.js";
import {
  applyConnection,
  applyStream,
} from "../../../core/src/localdb/apply.js";
import { createRunIntakeStore } from "../../../core/src/localdb/run-intake.js";
import { createRunEndStore } from "../../../core/src/localdb/run-end.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { remoteFixture } from "./apply-fixture.js";

const owner = `0x${"12".repeat(20)}` as const;
const declaration: IntakeDeclarations = {
  connector: "fixture-source",
  version: "1",
  streams: [{ name: "items", semantics: "mutable_state", primaryKey: ["id"] }],
};
const request: BeginRequest = {
  connector: declaration.connector,
  artifactDigest: "fixture-artifact",
  owner: { address: owner, leaseId: null },
  observedAt: 40,
};
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

/** A connection whose "items" stream tombstone V=2 was already applied. */
async function consumedTombstone() {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner,
    network: "test",
    deviceId: "consumed-tombstone",
  });
  drivers.push(db);
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const remote = await remoteFixture(keys);
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    keys,
    registry: remote.registry,
    blobs: remote.storage,
    queue: connectionQueue(),
    ownerAddress: owner,
    signer: { signAddData: async () => "0x00" },
    logger: { info: vi.fn(), warn: vi.fn() },
    now: () => 100,
    newOp: () => `consumed-${++op}`,
  };
  const id = remote.control;
  await db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?,'fixture-source','',1,'active',1)",
      params: [id],
    },
  ]);
  const h = await remote.head("items", [{ id: "old" }]);
  await applyConnection(deps, id);
  const tombstone = (version: number) =>
    remote.reads.set(h.scope, {
      found: true,
      version,
      dataHash: remote.hashes.tombstoneData,
      metadataHash: remote.hashes.tombstoneMetadata,
      deleted: true,
    });
  tombstone(2);
  expect(await applyStream(deps, id, "items")).toMatchObject({
    outcome: "purged",
  });
  const records = () =>
    db.query<{ record_key: string }>("SELECT record_key FROM records");
  const staged = () =>
    db.query<{ stream: string }>("SELECT stream FROM run_rows");
  return {
    db,
    deps,
    id,
    tombstone,
    records,
    staged,
    store: createRunIntakeStore(deps),
    end: createRunEndStore(deps),
  };
}

describe("a tombstone that is already consumed", () => {
  it("keeps rows staged by an open run when the same tombstone is applied again", async () => {
    const f = await consumedTombstone();
    await f.store.begin("run", request, declaration);
    await f.store.batch("run", {
      batch: 0,
      records: [{ stream: "items", data: { id: "new" } }],
    });
    expect(await f.staged()).toHaveLength(1);
    expect(await applyStream(f.deps, f.id, "items")).not.toMatchObject({
      outcome: "applied",
    });
    expect(await f.staged()).toHaveLength(1);
    // The collector retransmits batch 0: it is a replay, not a lost batch.
    expect(
      await f.store.batch("run", {
        batch: 0,
        records: [{ stream: "items", data: { id: "new" } }],
      }),
    ).toMatchObject({ applied: false });
    expect(await f.staged()).toHaveLength(1);
  });

  it("keeps committed, unpublished rows of an ended run", async () => {
    const f = await consumedTombstone();
    await f.store.begin("run", request, declaration);
    await f.store.batch("run", {
      batch: 0,
      records: [{ stream: "items", data: { id: "new" } }],
    });
    await f.end.end("run", {
      outcome: "retry_pending",
      coveredStreams: [],
      lastBatch: 0,
    });
    expect(await f.records()).toEqual([{ record_key: "new" }]);
    await applyStream(f.deps, f.id, "items");
    expect(await f.records()).toEqual([{ record_key: "new" }]);
  });

  it("still purges for a newer tombstone", async () => {
    const f = await consumedTombstone();
    await f.store.begin("run", request, declaration);
    await f.store.batch("run", {
      batch: 0,
      records: [{ stream: "items", data: { id: "new" } }],
    });
    f.tombstone(3);
    expect(await applyStream(f.deps, f.id, "items")).toMatchObject({
      outcome: "purged",
    });
    expect(await f.staged()).toEqual([]);
    expect(
      await f.db.query("SELECT last_delete_version FROM stream_state"),
    ).toEqual([{ last_delete_version: 3 }]);
  });
});
