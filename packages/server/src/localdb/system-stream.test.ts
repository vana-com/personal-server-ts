import { runCycle, runPublish } from "../../../core/src/localdb/cycle.js";
import { createSystemStreamStore } from "../../../core/src/localdb/system-streams.js";
import { afterEach, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  connectionQueue,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { createRunIntakeStore } from "../../../core/src/localdb/run-intake.js";
import { systemStreamIdentity } from "../../../core/src/localdb/system-stream-descriptor.js";
import { endRequest } from "../../../core/src/test-utils/run-end.js";
import { createRunEndStore } from "../../../core/src/localdb/run-end.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { remoteFixture } from "./apply-fixture.test-utils.js";

const owner = `0x${"12".repeat(20)}` as const;
const descriptor = {
  connector: "vana-system-access-v1",
  stream: "events",
  version: "1",
  primaryKey: ["eventId"],
} as const;
const drivers: SqlDriver[] = [];
const dirs: string[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
  for (const dir of dirs.splice(0))
    await rm(dir, { recursive: true, force: true });
});
async function fixture(path = ":memory:") {
  const db = await openLocalDb(openBetterSqlite3(path), {
    owner,
    network: "test",
    deviceId: "fixture",
  });
  drivers.push(db);
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const remote = await remoteFixture(keys);

  const deps: LocalSyncDeps = {
    db,
    keys,
    registry: remote.registry,
    blobs: remote.storage,
    queue: connectionQueue(),
    ownerAddress: owner,
    signer: { signAddData: async () => "0x00" },
    logger: { info: vi.fn(), warn: vi.fn() },
    now: () => Date.parse("2026-06-01T00:00:00.000Z"),
    newOp: () => crypto.randomUUID(),
  };
  return { db, deps, remote };
}

it("admits a trusted server-produced stream through begin/batch/end without connector registry admission", async () => {
  const f = await fixture();
  const intake = createRunIntakeStore(f.deps, descriptor);
  const identity = systemStreamIdentity(descriptor);
  const req = {
    connector: descriptor.connector,
    artifactDigest: "system:1",
    owner: { address: owner, leaseId: null },
  };
  await expect(
    createRunIntakeStore(f.deps).begin("spoof", req, identity.declarations),
  ).rejects.toMatchObject({ code: "invalid_request" });
  await intake.begin("trusted", req, identity.declarations);
  await intake.batch("trusted", {
    batch: 0,
    records: [{ stream: descriptor.stream, data: { eventId: "one" } }],
  });
  await createRunEndStore(f.deps).end(
    "trusted",
    endRequest({ lastBatch: 0, live: [descriptor.stream] }),
  );
  expect(await f.db.query("SELECT record_key,body FROM records")).toEqual([
    { record_key: "one", body: '{"eventId":"one"}' },
  ]);
  expect(await f.db.query("SELECT op,origin FROM record_changes")).toEqual([
    { op: "upsert", origin: "local" },
  ]);
});

it("restart after enqueue or interrupted staging loses nothing and duplicates nothing", async () => {
  const dir = await mkdtemp(join(tmpdir(), "system-stream-"));
  dirs.push(dir);
  const path = join(dir, "data.db");
  const first = await fixture(path);
  const desc = { ...descriptor, timestampField: "occurredAt" };
  const data = { eventId: "one", occurredAt: "2026-06-01T00:00:00.000Z" };
  const store = createSystemStreamStore(first.deps, desc);
  const instance = await store.instanceId();
  await store.append(data);
  await first.db.close();
  drivers.splice(drivers.indexOf(first.db), 1);
  const second = await fixture(path);
  const restarted = createSystemStreamStore(second.deps, desc);
  expect(await restarted.instanceId()).toBe(instance);
  // Simulate a process that died after batch staging. Runtime recovery may
  // abort this orphan before the durable producer gets to resume it.
  const [pending] = await second.db.query<{
    run_id: string;
    observed_at: number;
  }>("SELECT run_id,observed_at FROM system_stream_outbox");
  const intake = createRunIntakeStore(second.deps, descriptor);
  await intake.begin(
    pending!.run_id,
    {
      connector: descriptor.connector,
      artifactDigest: "system:1",
      owner: { address: owner, leaseId: null },
      observedAt: pending!.observed_at,
    },
    systemStreamIdentity(descriptor).declarations,
  );
  await intake.batch(pending!.run_id, {
    batch: 0,
    records: [{ stream: descriptor.stream, data }],
  });
  await createRunEndStore(second.deps).abort(pending!.run_id, "failed");
  await restarted.drain();
  await restarted.append(data);
  await restarted.drain();
  expect(await second.db.query("SELECT count(*) AS n FROM records")).toEqual([
    { n: 1 },
  ]);
  expect(
    await second.db.query("SELECT count(*) AS n FROM record_changes"),
  ).toEqual([{ n: 1 }]);
  expect(await second.db.query("SELECT * FROM system_stream_outbox")).toEqual(
    [],
  );
});

it("crash after canonical admission before acknowledgement replays without a duplicate", async () => {
  const f = await fixture();
  const desc = { ...descriptor, timestampField: "occurredAt" };
  const store = createSystemStreamStore(f.deps, desc);
  await store.append({
    eventId: "one",
    occurredAt: "2026-06-01T00:00:00.000Z",
  });
  const batch = f.db.batch.bind(f.db);
  const fault = vi
    .spyOn(f.db, "batch")
    .mockImplementation(async (statements) => {
      if (
        statements.some((s) =>
          s.sql.startsWith("DELETE FROM system_stream_outbox"),
        )
      )
        throw new Error("crash before ack");
      return batch(statements);
    });
  await expect(store.drain()).rejects.toThrow("crash before ack");
  fault.mockRestore();
  await createSystemStreamStore(f.deps, desc).drain();
  expect(await f.db.query("SELECT count(*) AS n FROM records")).toEqual([
    { n: 1 },
  ]);
  expect(await f.db.query("SELECT count(*) AS n FROM record_changes")).toEqual([
    { n: 1 },
  ]);
});

it("retains staged rows when canonical admission is refused by a newer profile", async () => {
  const f = await fixture();
  const store = createSystemStreamStore(f.deps, {
    ...descriptor,
    timestampField: "occurredAt",
  });
  await store.append({
    eventId: "one",
    occurredAt: "2026-06-01T00:00:00.000Z",
  });
  const identity = systemStreamIdentity(descriptor);
  await f.db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns) VALUES (?,?,'')",
      params: [identity.connectionId, descriptor.connector],
    },
    {
      sql: "INSERT INTO stream_state(connection_id,stream,primary_key,semantics,incremental,floor_version) VALUES (?,?,'[\"eventId\"]','mutable_state',1,'9')",
      params: [identity.connectionId, descriptor.stream],
    },
  ]);
  await expect(store.drain()).rejects.toThrow("canonical admission refused");
  expect(
    await f.db.query("SELECT count(*) AS n FROM system_stream_outbox"),
  ).toEqual([{ n: 1 }]);
  expect(await f.db.query("SELECT * FROM records")).toEqual([]);
});

it("a full durable outbox refuses new appends without a visible partial insert", async () => {
  const f = await fixture();
  const [trigger] = await f.db.query<{ sql: string }>(
    "SELECT sql FROM sqlite_master WHERE name='system_stream_outbox_capacity'",
  );
  await f.db.batch([
    { sql: "DROP TRIGGER system_stream_outbox_capacity" },
    {
      sql: "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100000) INSERT INTO system_stream_outbox SELECT 'capacity','events',CAST(x AS TEXT),'{}','2026-06-01T00:00:00.000Z',CAST(x AS TEXT),1 FROM n",
    },
    { sql: trigger!.sql },
  ]);
  const store = createSystemStreamStore(f.deps, {
    ...descriptor,
    timestampField: "occurredAt",
  });
  await expect(
    store.append({ eventId: "one", occurredAt: "2026-06-01T00:00:00.000Z" }),
  ).rejects.toThrow("system_stream_outbox_full");
  expect(await f.db.query("SELECT * FROM system_stream_projection")).toEqual(
    [],
  );
});

it("A to B to A replication and repeated projection reads emit no new events", async () => {
  const a = await fixture();
  const b = await fixture();
  const shared = { ...b.deps, registry: a.deps.registry, blobs: a.deps.blobs };
  const desc = { ...descriptor, timestampField: "occurredAt" };
  const first = createSystemStreamStore(a.deps, desc);
  const second = createSystemStreamStore(shared, desc);
  const event = { eventId: "one", occurredAt: "2026-06-01T00:00:00.000Z" };
  await first.append(event);
  await first.drain();
  expect(
    (await runPublish(a.deps)).connections.every((c) => c.error === null),
  ).toBe(true);
  expect(
    (await runCycle(shared)).connections.every((c) => c.error === null),
  ).toBe(true);
  expect(await second.project()).toBe(1);
  expect(await second.project()).toBe(0);
  await runCycle(a.deps);
  await first.project();
  expect(await b.db.query("SELECT body FROM system_stream_projection")).toEqual(
    [{ body: JSON.stringify(event) }],
  );
  for (const f of [a, b]) {
    expect(await f.db.query("SELECT count(*) AS n FROM records")).toEqual([
      { n: 1 },
    ]);
    expect(await f.db.query("SELECT * FROM system_stream_outbox")).toEqual([]);
  }
  expect(
    await b.db.query(
      "SELECT count(*) AS n FROM record_changes WHERE origin='local'",
    ),
  ).toEqual([{ n: 0 }]);
});

it("each served owner or delegated read durably appends one minimized served-start event", async () => {
  const { createLocalSync } = await import("../../../core/src/localdb/sync.js");
  const { handlePersonalServerDataRequest } =
    await import("../../../core/src/api/index.js");
  const { createMemoryDataStorage } =
    await import("../../../core/src/test-utils/memory-storage.js");
  const f = await fixture();
  const local = createLocalSync(f.deps, { resolveArtifact: () => null });
  const scope = "pdpp.fixture-source.items";
  for (const grantId of ["owner", "grant-1"]) {
    const eventId = crypto.randomUUID();
    const response = await handlePersonalServerDataRequest(
      new Request(`https://server.example/${scope}`, {
        headers: {
          "x-forwarded-for": "192.0.2.1",
          "user-agent": "private-agent",
        },
      }),
      {
        storage: createMemoryDataStorage(),
        accountStorageMode: { owner, read: () => "switched" },
        streamSyncRead: {
          resolve: async () => ({
            kind: "view",
            connector: "fixture-source",
            ns: "",
            cursor: "head",
            served: { scope: "pdpp.fixture-source~.items", version: 1 },
            body: new Response('{"data":{"records":[]}}').body!,
          }),
        },
        auth: {
          authorizeBuilderRead: async () => ({ grantId, builder: owner }),
        },
        accessLogWriter: {
          write: (entry) => local.accessActivity.write(entry),
        },
        createLogId: () => eventId,
        now: () => new Date(f.deps.now()),
      } as never,
    );
    expect(response.status).toBe(200);
    const rows = await f.db.query<{ body: string }>(
      "SELECT body FROM system_stream_projection WHERE record_id=?",
      [eventId],
    );
    expect(rows).toHaveLength(1);
    const event = JSON.parse(rows[0]!.body);
    expect(event).toEqual({
      schemaVersion: 1,
      eventId,
      instanceId: expect.any(String),
      occurredAt: "2026-06-01T00:00:00.000Z",
      action: "read",
      scope,
      grantId,
      builder: owner,
      phase: "served-start",
    });
    expect(rows[0]!.body).not.toMatch(
      /192\.0\.2\.1|private-agent|ipAddress|userAgent/,
    );
    await response.body?.cancel();
  }
  await local.accessActivity.drain();
  expect(await f.db.query("SELECT count(*) AS n FROM records")).toEqual([
    { n: 2 },
  ]);
  await local.accessActivity.write({
    logId: crypto.randomUUID(),
    grantId: "owner",
    builder: owner,
    action: "read",
    scope: "pdpp.vana-system-access-v1.events",
    timestamp: "2026-06-01T00:00:00.000Z",
    ipAddress: "",
    userAgent: "",
  });
  expect(await f.db.query("SELECT * FROM system_stream_outbox")).toEqual([]);
});

it("retention deletes old activity canonically and persists its deletion watermark", async () => {
  const { createAccessActivity } =
    await import("../../../core/src/logging/activity-stream.js");
  const f = await fixture();
  const activity = createAccessActivity(f.deps);
  await activity.write({
    logId: crypto.randomUUID(),
    grantId: "owner",
    builder: owner,
    action: "read",
    scope: "fixture.items",
    timestamp: "2026-04-01T00:00:00.000Z",
    ipAddress: "",
    userAgent: "",
  });
  await activity.drain();
  expect(await f.db.query("SELECT count(*) AS n FROM records")).toEqual([
    { n: 1 },
  ]);
  await activity.prune();
  expect(await f.db.query("SELECT * FROM records")).toEqual([]);
  expect(
    await f.db.query("SELECT op FROM record_changes ORDER BY seq"),
  ).toEqual([{ op: "upsert" }, { op: "remove" }]);
  const [deleted] = await f.db.query<{ tombstone_wm_o: number }>(
    "SELECT tombstone_wm_o FROM connections WHERE connector='vana-system-access-v1'",
  );
  expect(deleted!.tombstone_wm_o).toBeGreaterThan(f.deps.now());
});
