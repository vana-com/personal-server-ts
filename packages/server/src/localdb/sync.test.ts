import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import type {
  BeginRequest,
  IntakeDeclarations,
} from "../../../core/src/stream-sync/intake.js";
import { createStreamSyncIntake } from "../../../core/src/stream-sync/intake.js";
import { createLocalSync } from "../../../core/src/localdb/sync.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import { remoteFixture } from "./apply-fixture.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const ports = vi.hoisted(() => ({
  cycle: vi.fn(),
  connection: vi.fn(),
  replace: vi.fn(() => false),
  listing: vi.fn(),
  resolver: vi.fn(),
}));
vi.mock("../../../core/src/localdb/cycle.js", () => ({
  runCycle: ports.cycle,
  syncConnection: ports.connection,
}));
vi.mock("../../../core/src/localdb/replace.js", () => ({
  decideReplace: ports.replace,
}));
vi.mock("../../../core/src/localdb/blobs.js", () => ({
  createBlobStore: () => ({ put: vi.fn(), get: vi.fn() }),
}));
vi.mock("../../../core/src/localdb/delete.js", () => ({
  createConnectionDeleter: () => ({
    requestConnectionDelete: vi.fn(),
    resumeDeletes: vi.fn(),
  }),
}));
vi.mock("../../../core/src/localdb/older-versions.js", () => ({
  createOlderVersions: () => ({
    list: vi.fn(),
    read: vi.fn(),
    counts: () => ({ served: 0, gone: 0, off: 0 }),
  }),
}));
vi.mock("../../../core/src/localdb/listing.js", () => ({
  createLocalListing: (...args: unknown[]) => {
    ports.listing(...args);
    return { listScopes: vi.fn(), status: vi.fn(), cacheKey: vi.fn() };
  },
}));
vi.mock("../../../core/src/localdb/resolve.js", () => ({
  createLocalResolver: (...args: unknown[]) => {
    ports.resolver(...args);
    return { resolve: vi.fn() };
  },
}));

const owner = ("0x" + "11".repeat(20)) as `0x${string}`;
const declaration: IntakeDeclarations = {
  connector: "fixture",
  version: "1",
  streams: [{ name: "items", primaryKey: ["id"], semantics: "mutable_state" }],
};
const beginRequest: BeginRequest = {
  connector: declaration.connector,
  artifactDigest: "fixture-artifact",
  owner: { address: owner, leaseId: null },
};

describe("local sync intake adapter", () => {
  const drivers: SqlDriver[] = [];
  beforeEach(() => {
    vi.clearAllMocks();
    ports.replace.mockReturnValue(false);
  });
  afterEach(async () => {
    vi.useRealTimers();
    for (const db of drivers.splice(0)) await db.close();
  });

  async function setup(
    aliases: Pick<
      Parameters<typeof createLocalSync>[1],
      "aliasScopes" | "aliasTargets"
    > = {},
  ) {
    const db = openBetterSqlite3(":memory:");
    drivers.push(db);
    await openLocalDb(db, { owner, network: "test", deviceId: "fixture" });
    await db.batch([
      {
        sql: "INSERT INTO connections(connection_id, connector, ns, control_state) VALUES ('pdpp.fixture~', ?, '', 'active')",
        params: [declaration.connector],
      },
      {
        sql: "INSERT INTO stream_state(connection_id, stream, primary_key, semantics, incremental, profile_key, profile_version) VALUES ('pdpp.fixture~', 'items', ?, 'mutable_state', 1, ?, '1')",
        params: [JSON.stringify(["id"]), declaration.connector],
      },
    ]);
    let op = 0;
    const keys = {
      namespaceHmac: async () => new Uint8Array(32),
      encrypt: async (_s: string, b: Uint8Array) => b,
      encryptPart: async (_s: string, b: Uint8Array) => b,
      decrypt: async (_s: string, b: Uint8Array) => b,
    };
    const remote = await remoteFixture(keys, declaration.connector);
    let now = 0;
    const deps: LocalSyncDeps = {
      db,
      ownerAddress: owner,
      queue: connectionQueue(),
      now: () => ++now,
      newOp: () => String(++op),
      logger: { info: vi.fn(), warn: vi.fn() },
      registry: remote.registry,
      blobs: remote.storage,
      keys,
      signer: { signAddData: async () => "0x00" },
    };
    const sync = createLocalSync(deps, {
      resolveArtifact: () => declaration,
      declaredStreams: () => ["items"],
      olderVersionReads: () => true,
      ...aliases,
    });
    return { db, deps, sync };
  }

  const records = (first: number, last: number) =>
    Array.from({ length: last - first + 1 }, (_, i) => ({
      stream: "items",
      data: { id: `r${first + i}` },
    }));

  it("forwards the host name enumerator to both resolver and pending listing dependency", async () => {
    const aliasScopes = () => new Set(["fixture.alias"]).keys();
    const aliasTargets = () => [];
    await setup({ aliasScopes, aliasTargets });
    const listingDeps = ports.listing.mock.calls[0][0];
    const resolverParts = ports.resolver.mock.calls[0][1];
    expect(listingDeps.aliasScopes).toBe(aliasScopes);
    expect(resolverParts.aliasScopes).toBe(aliasScopes);
    expect(resolverParts.aliasTargets).toBe(aliasTargets);
    expect([...listingDeps.aliasScopes()]).toEqual(["fixture.alias"]);
    expect([...listingDeps.aliasScopes()]).toEqual(["fixture.alias"]);
  });

  it("uses the same HTTP-facing factory for a local intake without a file writer", async () => {
    const { sync } = await setup();
    expect(createStreamSyncIntake({ intake: sync.intake })).toBe(sync.intake);
  });

  it("retry-pending-keeps-progress", async () => {
    const { db, sync } = await setup();
    await sync.intake.begin("A", beginRequest);
    await sync.intake.batch("A", { batch: 0, records: records(1, 50) });
    expect(
      await sync.intake.end("A", {
        outcome: "retry_pending",
        coveredStreams: ["items"],
        lastBatch: 0,
        checkpointCandidate: { items: "C50" },
        provenFullStreams: ["items"],
      }),
    ).toEqual({ result: "queued", stuck: false, updateRequired: false });
    const afterA = await sync.query.listRecords({
      connectionId: "pdpp.fixture~",
      stream: "items",
      limit: 100,
    });
    expect(afterA.records.map((r) => r.recordKey).sort()).toEqual(
      records(1, 50)
        .map((r) => r.data.id)
        .sort(),
    );
    expect(
      await db.query("SELECT replace FROM run_streams WHERE run_id = 'A'"),
    ).toEqual([{ replace: 0 }]);
    expect(
      await db.query(
        "SELECT complete FROM stream_state WHERE connection_id = 'pdpp.fixture~'",
      ),
    ).toEqual([{ complete: 0 }]);

    const b = await sync.intake.begin("B", beginRequest);
    expect(b.start.state).toEqual({ items: "C50" });
    const receivedByB = records(51, 60);
    expect(receivedByB.every((r) => Number(r.data.id.slice(1)) > 50)).toBe(
      true,
    );
    await sync.intake.batch("B", { batch: 0, records: receivedByB });
    expect(
      await db.query<{ record_key: string }>(
        "SELECT record_key FROM run_rows WHERE run_id = 'B' ORDER BY record_key",
      ),
    ).toEqual(receivedByB.map((r) => ({ record_key: r.data.id })));
    expect(
      await sync.intake.end("B", {
        outcome: "succeeded",
        coveredStreams: ["items"],
        lastBatch: 0,
        checkpointCandidate: { items: "C60" },
        provenFullStreams: ["items"],
      }),
    ).toEqual({ result: "queued", stuck: false, updateRequired: false });

    const head = await sync.query.listRecords({
      connectionId: "pdpp.fixture~",
      stream: "items",
      limit: 100,
    });
    expect(head.records.map((r) => r.recordKey).sort()).toEqual(
      records(1, 60)
        .map((r) => r.data.id)
        .sort(),
    );
    const changes = await db.query<{ record_key: string; count: number }>(
      "SELECT record_key, COUNT(*) AS count FROM record_changes WHERE origin = 'local' AND stamp_r = 'A' GROUP BY record_key ORDER BY record_key",
    );
    expect(changes).toEqual(
      records(1, 50)
        .map((r) => ({ record_key: r.data.id, count: 1 }))
        .sort((a, b) => a.record_key.localeCompare(b.record_key)),
    );
    expect(ports.replace).toHaveBeenCalledWith(
      expect.objectContaining({
        outcome: "succeeded",
        provenFullStreams: ["items"],
      }),
    );
  });

  it("returns checkpoint_only for an all-empty retry", async () => {
    const { db, sync } = await setup();
    await sync.intake.begin("empty", beginRequest);
    expect(
      await sync.intake.end("empty", {
        outcome: "retry_pending",
        coveredStreams: [],
        lastBatch: -1,
        checkpointCandidate: { items: "C0" },
      }),
    ).toEqual({
      result: "checkpoint_only",
      stuck: false,
      updateRequired: false,
    });
    expect(
      await db.query(
        "SELECT checkpoint FROM connections WHERE connection_id = 'pdpp.fixture~'",
      ),
    ).toEqual([{ checkpoint: JSON.stringify({ items: "C0" }) }]);
    expect(
      await db.query("SELECT COUNT(*) AS count FROM record_changes"),
    ).toEqual([{ count: 0 }]);
  });

  it("returns no_checkpoint when neither rows nor a checkpoint are merged", async () => {
    const { sync } = await setup();
    await sync.intake.begin("empty", beginRequest);
    expect(
      await sync.intake.end("empty", {
        outcome: "partial",
        coveredStreams: [],
        lastBatch: -1,
      }),
    ).toEqual({ result: "no_checkpoint", stuck: false, updateRequired: false });
  });

  it("discards a tombstoned run and clears its checkpoint before a full recollect", async () => {
    const { db, sync } = await setup();
    await sync.intake.begin("deleted", beginRequest);
    await sync.intake.batch("deleted", { batch: 0, records: records(1, 1) });
    await db.batch([
      {
        sql: "UPDATE connections SET checkpoint = ? WHERE connection_id = 'pdpp.fixture~'",
        params: [JSON.stringify({ items: "old" })],
      },
      {
        sql: "UPDATE stream_state SET last_delete_version = 1 WHERE connection_id = 'pdpp.fixture~'",
      },
    ]);
    expect(
      await sync.intake.end("deleted", {
        outcome: "succeeded",
        coveredStreams: ["items"],
        lastBatch: 0,
        checkpointCandidate: { items: "new" },
      }),
    ).toEqual({ result: "discarded", stuck: false, updateRequired: false });
    expect(await db.query("SELECT COUNT(*) AS count FROM run_rows")).toEqual([
      { count: 0 },
    ]);
    expect(await db.query("SELECT checkpoint FROM connections")).toEqual([
      { checkpoint: null },
    ]);
    expect(
      await db.query("SELECT needs_full, complete FROM stream_state"),
    ).toEqual([{ needs_full: 1, complete: 0 }]);
    expect(await db.query("SELECT COUNT(*) AS count FROM records")).toEqual([
      { count: 0 },
    ]);
  });

  it.each(["failed", "cancelled"] as const)(
    "returns aborted and drops staged rows after %s",
    async (outcome) => {
      const { db, sync } = await setup();
      await sync.intake.begin("aborted", beginRequest);
      await sync.intake.batch("aborted", { batch: 0, records: records(1, 1) });
      expect(
        await sync.intake.end("aborted", {
          outcome,
          coveredStreams: [],
          lastBatch: 0,
        }),
      ).toEqual({ result: "aborted", stuck: false, updateRequired: false });
      expect(await db.query("SELECT COUNT(*) AS count FROM run_rows")).toEqual([
        { count: 0 },
      ]);
      expect(await db.query("SELECT COUNT(*) AS count FROM records")).toEqual([
        { count: 0 },
      ]);
    },
  );

  it("routes explicit abort to the same durable cleanup", async () => {
    const { db, sync } = await setup();
    await sync.intake.begin("aborted", beginRequest);
    await sync.intake.batch("aborted", { batch: 0, records: records(1, 1) });
    await sync.intake.abort("aborted", "cancelled");
    expect(await db.query("SELECT state FROM runs")).toEqual([
      { state: "ended" },
    ]);
    expect(await db.query("SELECT COUNT(*) AS count FROM run_rows")).toEqual([
      { count: 0 },
    ]);
  });

  it("shares the cycle ports for trigger and single-file sync without a new timer", async () => {
    vi.useFakeTimers();
    const { deps, sync } = await setup();
    const connection = {
      connectionId: "c",
      applied: [],
      published: [],
      error: null,
    };
    const report = { connections: [connection] };
    ports.cycle.mockResolvedValue(report);
    ports.connection.mockResolvedValue(connection);
    expect(await sync.cycle()).toBe(report);
    expect(ports.cycle).toHaveBeenCalledTimes(1);
    expect(ports.cycle).toHaveBeenCalledWith(deps);
    expect(await sync.syncConnection("c")).toBe(connection);
    expect(ports.connection).toHaveBeenCalledTimes(1);
    expect(ports.connection).toHaveBeenCalledWith(deps, "c");
    expect(vi.getTimerCount()).toBe(0);
  });
});
