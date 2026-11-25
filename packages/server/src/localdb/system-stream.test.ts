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
import { ACCESS_ACTIVITY_DESCRIPTOR } from "../../../core/src/logging/activity-stream.js";

it("rejects an access activity descriptor with an unreadable timestamp", () => {
  const event = {
    schemaVersion: 1,
    eventId: "00000000-0000-4000-8000-000000000001",
    instanceId: "00000000-0000-4000-8000-000000000002",
    occurredAt: "2026-01-02T03:04:05.000Z",
    action: "read",
    scope: "fixture.scope",
    grantId: "fixture-grant",
    builder: "fixture-builder",
    phase: "served-start",
  };
  expect(() => ACCESS_ACTIVITY_DESCRIPTOR.validate(event)).not.toThrow();
  expect(() =>
    ACCESS_ACTIVITY_DESCRIPTOR.validate({
      ...event,
      occurredAt: "not a timestamp",
    }),
  ).toThrow("Invalid access activity timestamp");
});

it.each([{ schemaVersion: 2 }, { phase: "finished" }])(
  "reports a stable activity descriptor error for %j",
  async (change) => {
    const { ACCESS_ACTIVITY_DESCRIPTOR } =
      await import("../../../core/src/logging/activity-stream.js");
    const event = {
      schemaVersion: 1,
      eventId: "00000000-0000-4000-8000-000000000001",
      instanceId: "00000000-0000-4000-8000-000000000002",
      occurredAt: "2026-01-01T00:00:00.000Z",
      action: "read",
      scope: "fixture.scope",
      grantId: "fixture-grant",
      builder: "fixture-builder",
      phase: "served-start",
    };
    expect(() => ACCESS_ACTIVITY_DESCRIPTOR.validate(event)).not.toThrow();
    expect(() =>
      ACCESS_ACTIVITY_DESCRIPTOR.validate({ ...event, ...change }),
    ).toThrow(/^Invalid access activity event$/);
  },
);

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

it("rejects an unsupported access activity schema version", async () => {
  const { ACCESS_ACTIVITY_DESCRIPTOR } =
    await import("../../../core/src/logging/activity-stream.js");
  expect(() =>
    ACCESS_ACTIVITY_DESCRIPTOR.validate({
      schemaVersion: 2,
      eventId: "00000000-0000-4000-8000-000000000001",
      instanceId: "00000000-0000-4000-8000-000000000002",
      occurredAt: "2026-01-01T00:00:00.000Z",
      action: "read",
      scope: "synthetic.entries",
      grantId: "synthetic-grant",
      builder: "synthetic-builder",
      phase: "served-start",
    }),
  ).toThrow("Invalid access activity event");
});

it("rejects an empty scope in an otherwise valid access activity event", async () => {
  const { ACCESS_ACTIVITY_DESCRIPTOR } =
    await import("../../../core/src/logging/activity-stream.js");
  expect(() =>
    ACCESS_ACTIVITY_DESCRIPTOR.validate({
      schemaVersion: 1,
      eventId: "00000000-0000-4000-8000-000000000001",
      instanceId: "00000000-0000-4000-8000-000000000002",
      occurredAt: "2026-01-01T00:00:00.000Z",
      action: "read",
      scope: "",
      grantId: "synthetic-grant",
      builder: "synthetic-builder",
      phase: "served-start",
    }),
  ).toThrow("Invalid access activity field");
});

it("accepts each supported access activity action", async () => {
  const { ACCESS_ACTIVITY_DESCRIPTOR } =
    await import("../../../core/src/logging/activity-stream.js");
  for (const action of ["read", "write", "delete", "lineage"] as const) {
    expect(() =>
      ACCESS_ACTIVITY_DESCRIPTOR.validate({
        schemaVersion: 1,
        eventId: "00000000-0000-4000-8000-000000000001",
        instanceId: "00000000-0000-4000-8000-000000000002",
        occurredAt: "2026-01-01T00:00:00.000Z",
        action,
        scope: "synthetic.entries",
        grantId: "synthetic-grant",
        builder: "synthetic-builder",
        phase: "served-start",
      }),
    ).not.toThrow();
  }
});

it("accepts the maximum access activity scope length but not one character more", async () => {
  const { ACCESS_ACTIVITY_DESCRIPTOR } =
    await import("../../../core/src/logging/activity-stream.js");
  const event = {
    schemaVersion: 1,
    eventId: "00000000-0000-4000-8000-000000000001",
    instanceId: "00000000-0000-4000-8000-000000000002",
    occurredAt: "2026-01-01T00:00:00.000Z",
    action: "read",
    scope: "s".repeat(512),
    grantId: "synthetic-grant",
    builder: "synthetic-builder",
    phase: "served-start",
  };
  expect(() => ACCESS_ACTIVITY_DESCRIPTOR.validate(event)).not.toThrow();
  expect(() =>
    ACCESS_ACTIVITY_DESCRIPTOR.validate({ ...event, scope: event.scope + "s" }),
  ).toThrow("Invalid access activity field");
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

it("rejects incomplete access activity attribution", async () => {
  const { ACCESS_ACTIVITY_DESCRIPTOR } =
    await import("../../../core/src/logging/activity-stream.js");
  const event = {
    schemaVersion: 1,
    eventId: "00000000-0000-4000-8000-000000000001",
    instanceId: "00000000-0000-4000-8000-000000000002",
    occurredAt: "2026-01-01T00:00:00.000Z",
    action: "read",
    scope: "synthetic.entries",
    grantId: "synthetic-grant",
    builder: "synthetic-builder",
    phase: "served-start",
  };
  expect(() => ACCESS_ACTIVITY_DESCRIPTOR.validate(event)).not.toThrow();
  for (const field of ["grantId", "builder"]) {
    expect(() =>
      ACCESS_ACTIVITY_DESCRIPTOR.validate({ ...event, [field]: "" }),
    ).toThrow("Invalid access activity field");
  }
});

it("distinguishes unknown access activity phases from served-start", async () => {
  const { ACCESS_ACTIVITY_DESCRIPTOR } =
    await import("../../../core/src/logging/activity-stream.js");
  const event = {
    schemaVersion: 1,
    eventId: "00000000-0000-4000-8000-000000000001",
    instanceId: "00000000-0000-4000-8000-000000000002",
    occurredAt: "2026-01-01T00:00:00.000Z",
    action: "read",
    scope: "synthetic.entries",
    grantId: "synthetic-grant",
    builder: "synthetic-builder",
    phase: "served-start",
  };
  expect(() => ACCESS_ACTIVITY_DESCRIPTOR.validate(event)).not.toThrow();
  expect(() =>
    ACCESS_ACTIVITY_DESCRIPTOR.validate({ ...event, phase: "served-finish" }),
  ).toThrow("Invalid access activity event");
});

it("owner history pages tied timestamps without skips, duplicate rows or recursive audit", async () => {
  const { createAccessActivity } =
    await import("../../../core/src/logging/activity-stream.js");
  const { handlePersonalServerAccessLogsRequest } =
    await import("../../../core/src/api/index.js");
  const f = await fixture();
  const activity = createAccessActivity(f.deps);
  const ids = [1, 2, 3, 4, 5].map(
    (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`,
  );
  for (const id of ids)
    await activity.write({
      logId: id,
      grantId: "owner",
      builder: owner,
      action: "read",
      scope: "fixture.items",
      timestamp: "2026-06-01T00:00:00.000Z",
      ipAddress: "",
      userAgent: "",
    });
  await activity.drain();
  const seen: string[] = [];
  let cursor: string | null = null;
  do {
    const url = new URL("https://server.example/?limit=2");
    if (cursor) url.searchParams.set("cursor", cursor);
    const response = await handlePersonalServerAccessLogsRequest(
      new Request(url),
      {
        auth: { authorizeOwner: async () => {} },
        accessLogReader: activity,
      } as never,
    );
    expect(response.status).toBe(200);
    const page = await response.json();
    seen.push(...page.logs.map((row: { eventId: string }) => row.eventId));
    cursor = page.nextCursor;
    expect(page).not.toHaveProperty("total");
  } while (cursor);
  expect(seen).toEqual([...ids].reverse());
  expect(await f.db.query("SELECT * FROM system_stream_outbox")).toEqual([]);
  expect(await f.db.query("SELECT count(*) AS n FROM records")).toEqual([
    { n: 5 },
  ]);
});

it("owner history enforces the page cap and rejects malformed or foreign cursors", async () => {
  const { createAccessActivity } =
    await import("../../../core/src/logging/activity-stream.js");
  const f = await fixture();
  const activity = createAccessActivity(f.deps);
  for (let n = 0; n < 205; n++)
    await activity.write({
      logId: crypto.randomUUID(),
      grantId: "owner",
      builder: owner,
      action: "read",
      scope: "fixture.items",
      timestamp: "2026-06-01T00:00:00.000Z",
      ipAddress: "",
      userAgent: "",
    });
  const page = await activity.read({ limit: 1000 });
  expect(page.limit).toBe(200);
  expect(page.logs).toHaveLength(200);
  expect((await activity.read({ cursor: page.nextCursor! })).logs).toHaveLength(
    5,
  );
  await expect(activity.read({ cursor: "bad-cursor" })).rejects.toMatchObject({
    code: 400,
  });
  const foreign = createAccessActivity({
    ...f.deps,
    ownerAddress: `0x${"34".repeat(20)}`,
  });
  await expect(
    foreign.read({ cursor: page.nextCursor! }),
  ).rejects.toMatchObject({ code: 400 });
});

it("imported expired activity stays invisible and duplicate imports produce one history row", async () => {
  const { createAccessActivity } =
    await import("../../../core/src/logging/activity-stream.js");
  const a = await fixture();
  const b = await fixture();
  const shared = { ...b.deps, registry: a.deps.registry, blobs: a.deps.blobs };
  const producer = createAccessActivity(a.deps);
  const consumer = createAccessActivity(shared);
  for (const timestamp of [
    "2026-04-01T00:00:00.000Z",
    "2026-06-01T00:00:00.000Z",
  ])
    await producer.write({
      logId: crypto.randomUUID(),
      grantId: "owner",
      builder: owner,
      action: "read",
      scope: "fixture.items",
      timestamp,
      ipAddress: "",
      userAgent: "",
    });
  await producer.drain();
  await runPublish(a.deps);
  await runCycle(shared);
  await runCycle(shared);
  expect((await consumer.read()).logs).toHaveLength(1);
  expect(await b.db.query("SELECT * FROM system_stream_outbox")).toEqual([]);
  await producer.prune();
  await runPublish(a.deps);
  await runCycle(shared);
  expect((await consumer.read()).logs).toHaveLength(1);
  expect(await b.db.query("SELECT count(*) AS n FROM records")).toEqual([
    { n: 1 },
  ]);
});

it("defers durable producer work while another connection owns bootstrap staging", async () => {
  const f = await fixture();
  const store = createSystemStreamStore(f.deps, {
    ...descriptor,
    timestampField: "occurredAt",
  });
  await store.append({
    eventId: "one",
    occurredAt: "2026-06-01T00:00:00.000Z",
  });
  await f.db.batch([
    {
      sql: "INSERT INTO bootstrap_load(id,connection_id,generation,base) VALUES (1,'pdpp.fixture~',1,0)",
    },
  ]);
  expect(await store.drain()).toBe(0);
  expect(
    await f.db.query("SELECT count(*) AS n FROM system_stream_outbox"),
  ).toEqual([{ n: 1 }]);
  await f.db.batch([{ sql: "DELETE FROM bootstrap_load" }]);
  await store.drain();
  expect(await f.db.query("SELECT count(*) AS n FROM records")).toEqual([
    { n: 1 },
  ]);
});

it("quarantines a conflicting event id even when its imported projection is still pending", async () => {
  const a = await fixture();
  const b = await fixture();
  const shared = { ...b.deps, registry: a.deps.registry, blobs: a.deps.blobs };
  const desc = { ...descriptor, timestampField: "occurredAt" };
  const first = createSystemStreamStore(a.deps, desc);
  const second = createSystemStreamStore(shared, desc);
  const data = { eventId: "one", occurredAt: "2026-06-01T00:00:00.000Z" };
  await first.append(data);
  await first.drain();
  await runPublish(a.deps);
  await runCycle(shared);
  await expect(
    second.append({ ...data, value: "conflicting" }),
  ).rejects.toThrow("Conflicting system stream record");
  expect(
    await b.db.query("SELECT count(*) AS n FROM system_stream_quarantine"),
  ).toEqual([{ n: 1 }]);
  expect(await b.db.query("SELECT * FROM system_stream_outbox")).toEqual([]);
});

it("keeps a first-page upper watermark until the owner refreshes history", async () => {
  const { createAccessActivity } =
    await import("../../../core/src/logging/activity-stream.js");
  const f = await fixture();
  const activity = createAccessActivity(f.deps);
  const entry = (logId: string, timestamp: string) => ({
    logId,
    timestamp,
    grantId: "owner",
    builder: owner,
    action: "read" as const,
    scope: "fixture.items",
  });
  const earlier = [
    crypto.randomUUID(),
    crypto.randomUUID(),
    crypto.randomUUID(),
  ];
  for (const id of earlier)
    await activity.write(entry(id, "2026-06-01T00:00:00.000Z"));
  const first = await activity.read({ limit: 2 });
  const later = crypto.randomUUID();
  await activity.write(entry(later, "2026-06-01T00:00:01.000Z"));
  const next = await activity.read({ limit: 2, cursor: first.nextCursor! });
  expect(next.logs).toHaveLength(1);
  expect([...first.logs, ...next.logs].map((row) => row.logId).sort()).toEqual(
    [...earlier].sort(),
  );
  expect((await activity.read({ limit: 2 })).logs[0]!.logId).toBe(later);
});

it("concurrent producer handles dedupe identical retries and quarantine conflicting ids", async () => {
  const f = await fixture();
  const desc = { ...descriptor, timestampField: "occurredAt" };
  const a = createSystemStreamStore(f.deps, desc);
  const b = createSystemStreamStore(f.deps, desc);
  const data = { eventId: "one", occurredAt: "2026-06-01T00:00:00.000Z" };
  await Promise.all([a.append(data), b.append(data)]);
  const results = await Promise.allSettled([
    a.append({ ...data, eventId: "two" }),
    b.append({ ...data, eventId: "two", value: "conflict" }),
  ]);
  expect(results.map((r) => r.status).sort()).toEqual([
    "fulfilled",
    "rejected",
  ]);
  expect(
    await f.db.query("SELECT count(*) AS n FROM system_stream_outbox"),
  ).toEqual([{ n: 2 }]);
  expect(
    await f.db.query("SELECT count(*) AS n FROM system_stream_quarantine"),
  ).toEqual([{ n: 1 }]);
});

it("a served read can commit its outbox event while drain waits for canonical sync admission", async () => {
  const f = await fixture();
  const desc = { ...descriptor, timestampField: "occurredAt" };
  let intercept = true;
  const queue: LocalSyncDeps["queue"] = {
    async run(id, kind, work) {
      if (intercept && kind === "end") {
        intercept = false;
        // Another served read arrives while the sync admission slot is unavailable.
        await store.append({
          eventId: "two",
          occurredAt: "2026-06-01T00:00:00.000Z",
        });
        throw new Error("sync admission unavailable");
      }
      return f.deps.queue.run(id, kind, work);
    },
  };
  const store = createSystemStreamStore({ ...f.deps, queue }, desc);
  await store.append({
    eventId: "one",
    occurredAt: "2026-06-01T00:00:00.000Z",
  });
  await expect(store.drain()).rejects.toThrow("sync admission unavailable");
  expect(
    await f.db.query("SELECT count(*) AS n FROM system_stream_outbox"),
  ).toEqual([{ n: 2 }]);
  await store.drain();
  expect(await f.db.query("SELECT count(*) AS n FROM records")).toEqual([
    { n: 2 },
  ]);
});

it("projects reserved events installed by the bootstrap table swap without re-emitting them", async () => {
  const { createAccessActivity } =
    await import("../../../core/src/logging/activity-stream.js");
  const a = await fixture();
  const b = await fixture();
  const producer = createAccessActivity(a.deps);
  const eventId = crypto.randomUUID();
  await producer.write({
    logId: eventId,
    grantId: "owner",
    builder: owner,
    action: "read",
    scope: "fixture.items",
    timestamp: "2026-06-01T00:00:00.000Z",
  });
  await producer.drain();
  await runPublish(a.deps);
  const shared = {
    ...b.deps,
    registry: a.deps.registry,
    blobs: a.deps.blobs,
    bootstrapFirstLoad: true,
    progressiveFirstLoad: true,
    keyedFirstLoad: false,
  };
  const batch = b.db.batch.bind(b.db);
  let swapped = false;
  vi.spyOn(b.db, "batch").mockImplementation((statements) => {
    if (statements.some((s) => s.sql === "DROP TABLE records")) swapped = true;
    return batch(statements);
  });
  const report = await runCycle(shared);
  expect(report.connections.every((c) => c.error === null)).toBe(true);
  expect(swapped).toBe(true);
  expect(
    (await createAccessActivity(shared).read()).logs.map((row) => row.logId),
  ).toEqual([eventId]);
  expect(await b.db.query("SELECT * FROM system_stream_outbox")).toEqual([]);
});

it("keeps private access activity out of ordinary imported-data additions", async () => {
  const { createAccessActivity } =
    await import("../../../core/src/logging/activity-stream.js");
  const { createLocalHistory } =
    await import("../../../core/src/localdb/history.js");
  const f = await fixture();
  const activity = createAccessActivity(f.deps);
  await activity.write({
    logId: crypto.randomUUID(),
    grantId: "owner",
    builder: owner,
    action: "read",
    scope: "fixture.items",
    timestamp: "2026-06-01T00:00:00.000Z",
  });
  await activity.drain();
  await runPublish(f.deps);
  expect(
    (
      await createLocalHistory(f.deps, {}).additions({
        timezone: "UTC",
        days: 7,
      })
    ).total,
  ).toBe(0);
  expect((await activity.read()).logs).toHaveLength(1);
});

it("keeps system activity pending for the next publish without waking one", async () => {
  const f = await fixture();
  const recordsCommitted = vi.fn();
  const store = createSystemStreamStore(
    { ...f.deps, recordsCommitted },
    { ...descriptor, timestampField: "occurredAt" },
  );
  await store.append({
    eventId: "one",
    occurredAt: "2026-06-01T00:00:00.000Z",
  });
  expect(recordsCommitted).not.toHaveBeenCalled();
  await store.drain();
  expect(recordsCommitted).not.toHaveBeenCalled();
  expect(await f.db.query("SELECT count(*) AS n FROM records")).toEqual([
    { n: 1 },
  ]);
  expect((await runPublish(f.deps)).connections).toHaveLength(1);
});

it("publishes idle activity on the timer without waking for each record", async () => {
  const { createLocalSync } = await import("../../../core/src/localdb/sync.js");
  const { createSyncManager } =
    await import("../../../core/src/sync/engine/sync-manager.js");
  const f = await fixture();
  const sync = createLocalSync(f.deps, { resolveArtifact: () => null });
  const cycle = vi.fn((scope?: { readonly connections: readonly string[] }) =>
    sync.cycle(scope),
  );
  const pending = vi.spyOn(sync, "hasPendingPublication");
  let handlers!: {
    onHealth(healthy: boolean): void;
    onPosition(position: string): void;
  };
  const posts = vi.spyOn(f.deps.registry, "postBatch");
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
  const manager = createSyncManager(
    {
      logger: f.deps.logger,
      storage: { findUnsynced: () => [] },
      serverOwner: owner,
    } as never,
    { logger: f.deps.logger } as never,
    {
      accountStorageMode: { read: () => "switched" },
      localSync: {
        cycle,
        applyDelta: sync.applyDelta,
        hasPendingPublication: sync.hasPendingPublication,
      },
      pollInterval: 60_000,
      changeProbe: {
        read: async () => "1",
        push: {
          subscribe(h) {
            handlers = h;
            return () => {};
          },
        },
      },
    },
  );
  try {
    manager.start();
    handlers.onPosition("1");
    handlers.onHealth(true);
    await manager.trigger();
    cycle.mockClear();
    posts.mockClear();
    vi.advanceTimersByTime(60_000);
    await vi.waitFor(() => expect(pending).toHaveBeenCalledTimes(1));
    await pending.mock.results[0]!.value;
    expect(cycle).not.toHaveBeenCalled();
    await sync.accessActivity.write({
      logId: crypto.randomUUID(),
      grantId: "owner",
      builder: owner,
      action: "read",
      scope: "fixture.items",
      timestamp: "2026-06-01T00:00:00.000Z",
      ipAddress: "",
      userAgent: "",
    });
    await sync.accessActivity.drain();
    expect(cycle).not.toHaveBeenCalled();
    expect(posts).not.toHaveBeenCalled();
    vi.advanceTimersByTime(60_000);
    await vi.waitFor(() => expect(posts).toHaveBeenCalled());
  } finally {
    await manager.stop();
    vi.useRealTimers();
  }
});
