import { createLegacyRetireRemote } from "./legacy-retire-remote.js";
import type { LegacyRetirePipelinePorts } from "./legacy-retire-pipeline.js";
import { legacyStreamsOfScope } from "../legacy-projection/erase-connector.js";
import { FAKE_CHAIN_ID } from "../test-utils/legacy-gateway-fake.js";
// Standalone retirement through the real local sync and its dedicated pipeline,
// with real SQLite and a fake legacy gateway:
// a source whose delete was never sent, connected again while its legacy scopes
// are still listed.
import { afterEach, describe, expect, it, vi } from "vitest";
import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  CONNECTOR as FIXTURE,
  closeWorldDrivers,
  sName,
  tempDbFile,
  world,
} from "../../../server/src/localdb/log-world.test-utils.js";
import { createImportLedger } from "./import-ledger.js";
import { importLegacySource } from "./legacy-import.js";
import type { ImportSource } from "./legacy-import-types.js";
import {
  LegacyRetireNotAdmitted,
  LegacyRetireUnavailable,
} from "./legacy-retire-intent.js";
import { legacyScopesOfConnector } from "../legacy-projection/erase-connector.js";
import { legacyPortsOver } from "../test-utils/legacy-delete-ports.js";
import { createLegacyGatewayFake } from "../test-utils/legacy-gateway-fake.js";
import {
  FAKE_GATEWAY,
  FAKE_STORAGE,
} from "../test-utils/legacy-gateway-fake.js";

afterEach(closeWorldDrivers);

const OWNER = `0x${"11".repeat(20)}` as const;
const RETRY = { first: 5, max: 20 };
const GH = "github";
const SCOPES = legacyScopesOfConnector(GH);
const DONE = { state: "done" } as const;
const PENDING = { state: "pending" } as const;

/** A switched account whose `github` source is connected, with live legacy scopes. */
async function reconnected(
  options: {
    mode?: "on" | "off";
    finality?: Parameters<typeof legacyPortsOver>[1] extends infer O
      ? O extends { finality?: infer F }
        ? F
        : never
      : never;
    wrapLegacy?: (
      ports: LegacyRetirePipelinePorts,
    ) => LegacyRetirePipelinePorts;
    dbFile?: string;
    writeReady?: () => boolean;
    /** Extra options of the fake host's ports (see `legacyPortsOver`). */
    host?: {
      onAdapterHeadRead?: () => void;
      wrapFetch?: (fetch: typeof globalThis.fetch) => typeof globalThis.fetch;
    };
  } = {},
) {
  const w = await world({ streams: 1 });
  const fake = createLegacyGatewayFake({ owner: OWNER, cutover: "v3" });
  for (const scope of SCOPES) fake.seed(scope, 2);
  const legacy = await legacyPortsOver(fake, {
    ...(options.mode && { mode: options.mode }),
    ...(options.finality && { finality: options.finality }),
  });
  const pipelinePorts: LegacyRetirePipelinePorts = {
    ...legacy.ports,
    streamsOf: legacyStreamsOfScope,
    finality: options.finality
      ? legacy.ports.finality
      : {
          tombstoneState: async () => ({
            finalized: "3",
            settling: false,
            rolledBack: null,
          }),
        },
    rows: {
      capture: async (save, check) => {
        check();
        return save(legacy.storage.entries.map((row) => ({ ...row })));
      },
      absent: async (rows, check) => {
        check();
        return rows.every(
          (row) => !legacy.storage.entries.some((entry) => entry.id === row.id),
        );
      },
      erase: async (row, check) => {
        check();
        if (legacy.storage.entries.some((entry) => entry.id === row.id))
          await legacy.storage.deleteVersion(row.scope, row.collectedAt, {
            id: row.id,
            path: row.path,
          });
      },
    },
    ...createLegacyRetireRemote({
      gatewayUrl: FAKE_GATEWAY,
      dataPointFeed: {
        getDataPoint: async (request) => {
          options.host?.onAdapterHeadRead?.();
          return fake.feed.getDataPoint(request);
        },
      } as never,
      serverOwner: OWNER,
      signer: fake.signer,
      storage: {
        endpoint: FAKE_STORAGE,
        chainId: FAKE_CHAIN_ID,
        signMessage: async () => `0x${"ab".repeat(65)}`,
      },
      fetch: options.host?.wrapFetch?.(fake.fetch) ?? fake.fetch,
    }),
  };
  const a = await w.device("a", {
    legacyRetire: () => options.wrapLegacy?.(pipelinePorts) ?? pipelinePorts,
    deleteRetryMs: RETRY,
    ...(options.writeReady && { legacyWriteReady: options.writeReady }),
    ...(options.dbFile && { dbFile: options.dbFile }),
  });
  await a.run("run-1", [{ stream: sName(0), id: "x", v: 0 }], {
    connector: GH,
    observedAt: 1100,
  });
  await a.cycle();
  return { w, a, fake, legacy, pipelinePorts };
}

type Fixture = Awaited<ReturnType<typeof reconnected>>;

/** Everything of the current connection a legacy retirement must leave alone. */
async function currentState(f: Fixture) {
  return {
    records: await f.a.records(),
    connections: await f.a.db.query(
      "SELECT connection_id, generation, control_state, deleted_at FROM connections ORDER BY connection_id",
    ),
    streams: await f.a.db.query(
      "SELECT connection_id, stream, head_version, last_delete_version, publish_watermark FROM stream_state ORDER BY connection_id, stream",
    ),
    changes: await f.a.db.query("SELECT count(*) AS n FROM record_changes"),
    registry: [...f.w.gateway.versions].map(([scope, v]) => [scope, v.length]),
    intents: await f.a.db.query("SELECT * FROM delete_intents"),
  };
}

/** A local legacy entry per scope, as the pre-switch writes left them. */
function placeLocalEntries(f: Fixture) {
  // The seal refuses a new legacy write, so the index rows are placed directly.
  SCOPES.forEach((scope, id) =>
    f.legacy.storage.entries.push({
      id: id + 1,
      fileId: null,
      schemaId: null,
      path: `${scope}/2026-01-01T00:00:00.000Z.json`,
      scope,
      collectedAt: "2026-01-01T00:00:00.000Z",
      createdAt: "2026-01-01T00:00:00.000Z",
      sizeBytes: 1,
      version: 1,
      casRevision: 1,
      dataPointId: null,
    }),
  );
}

const gatewayDeletes = (fake: Fixture["fake"]) =>
  fake.requests.filter(
    (r) => r.url.startsWith(FAKE_GATEWAY) && r.method === "DELETE",
  );

const storageDeletes = (fake: Fixture["fake"]) =>
  fake.requests.filter(
    (r) => r.url.startsWith(FAKE_STORAGE) && r.method === "DELETE",
  );

describe("a standalone legacy retirement after the switch", () => {
  it("retires a pinned legacy scope after reconnect without changing current control, stream head or records", async () => {
    expect(SCOPES.length).toBeGreaterThan(0);
    const f = await reconnected();
    const before = await currentState(f);

    const { retireId } = await f.a.sync.legacyRetirer.request(GH);

    await vi.waitFor(async () =>
      expect(await f.a.sync.legacyRetirer.status(GH)).toEqual({
        retireId,
        legacy: DONE,
      }),
    );
    for (const scope of SCOPES) {
      expect(f.fake.isLive(scope)).toBe(false);
      expect(f.fake.tombstones.get(scope)).toEqual([3]);
      expect(f.fake.blobCount(scope)).toBe(0);
    }
    expect(await currentState(f)).toEqual(before);
    // No connector-wide fence was written, even for a moment.
    expect(await f.a.db.query("SELECT * FROM delete_intents")).toEqual([]);
    // The current connection still collects and publishes (a full run
    // replaces its inventory, so the new row is the one it holds).
    await f.a.run("run-2", [{ stream: sName(0), id: "y", v: 1 }], {
      connector: GH,
      observedAt: 1200,
    });
    await f.a.cycle();
    expect(await f.a.records()).toEqual(['s0/y={"id":"y","v":1}']);
  });

  it("resumes the same intent and scope set after a repeat request and a restart", async () => {
    const finality = {
      finalized: null as string | null,
      settling: true,
      rolledBack: null,
    };
    const dbFile = tempDbFile();
    const f = await reconnected({ finality: () => finality, dbFile });

    const first = await f.a.sync.legacyRetirer.request(GH);
    await vi.waitFor(() =>
      expect(gatewayDeletes(f.fake)).toHaveLength(SCOPES.length),
    );
    expect((await f.a.sync.legacyRetirer.status(GH))?.legacy).toEqual(PENDING);
    // A repeat request is the same intent.
    expect(await f.a.sync.legacyRetirer.request(GH)).toEqual(first);

    const restarted = await f.a.restart();
    // The restarted process knows only the row: same id, still pending.
    expect(await restarted.sync.legacyRetirer.status(GH)).toEqual({
      retireId: first.retireId,
      legacy: PENDING,
    });
    finality.finalized = "3";
    finality.settling = false;
    await restarted.sync.cycle();
    await vi.waitFor(async () =>
      expect(await restarted.sync.legacyRetirer.status(GH)).toEqual({
        retireId: first.retireId,
        legacy: DONE,
      }),
    );
    // One tombstone per scope for the whole journey; a repeat after done sends nothing.
    for (const scope of SCOPES)
      expect(f.fake.tombstones.get(scope)).toEqual([3]);
    expect(await restarted.sync.legacyRetirer.request(GH)).toEqual(first);
    expect(gatewayDeletes(f.fake)).toHaveLength(SCOPES.length);
    expect(
      await restarted.db.query("SELECT retire_id FROM legacy_retirements"),
    ).toEqual([{ retire_id: first.retireId }]);
  });

  it("blocks on a head that moved since the request, tombstones nothing and never widens", async () => {
    // Pin reads pass; later reads wait for the test to move the head.
    const gate = (() => {
      let open!: () => void;
      const opened = new Promise<void>((resolve) => (open = resolve));
      return { opened, open };
    })();
    const read = new Set<string>();
    const f = await reconnected({
      wrapLegacy: (ports) => ({
        ...ports,
        head: async (scope, signal) => {
          if (read.has(scope)) await gate.opened;
          read.add(scope);
          return ports.head(scope, signal);
        },
      }),
    });
    const { retireId } = await f.a.sync.legacyRetirer.request(GH);
    for (const scope of SCOPES) f.fake.moveHead(scope);
    gate.open();

    await vi.waitFor(async () =>
      expect(await f.a.sync.legacyRetirer.status(GH)).toEqual({
        retireId,
        legacy: { state: "blocked", reason: "legacy_head_changed" },
      }),
    );
    expect(gatewayDeletes(f.fake)).toEqual([]);
    for (const scope of SCOPES) expect(f.fake.isLive(scope)).toBe(true);
    // Blocked is not done: the intent stays open and keeps its fence.
    expect(await f.a.db.query("SELECT state FROM legacy_retirements")).toEqual([
      { state: "open" },
    ]);
  });

  // The request pins live v2. Another writer then publishes v3 and tombstones
  // it at v4: that tombstone does not follow the pin, and erasing it would free
  // the slot of v3, which the pin never named.
  it("blocks on a tombstone that does not directly follow the pinned head, and erases nothing", async () => {
    const gate = (() => {
      let open!: () => void;
      const opened = new Promise<void>((resolve) => (open = resolve));
      return { opened, open };
    })();
    const read = new Set<string>();
    const f = await reconnected({
      wrapLegacy: (ports) => ({
        ...ports,
        head: async (scope, signal) => {
          if (read.has(scope)) await gate.opened;
          read.add(scope);
          return ports.head(scope, signal);
        },
      }),
    });
    const { retireId } = await f.a.sync.legacyRetirer.request(GH);
    for (const scope of SCOPES) {
      f.fake.moveHead(scope);
      f.fake.foreignTombstone(scope);
    }
    gate.open();

    await vi.waitFor(async () =>
      expect(await f.a.sync.legacyRetirer.status(GH)).toEqual({
        retireId,
        legacy: { state: "blocked", reason: "legacy_head_changed" },
      }),
    );
    expect(gatewayDeletes(f.fake)).toEqual([]);
    expect(storageDeletes(f.fake)).toEqual([]);
    for (const scope of SCOPES) expect(f.fake.blobCount(scope)).toBe(3);
  });

  // The worker reads the pinned head live, then another device publishes v3
  // and tombstones at v4 before the delete adapter reads the head. The adapter
  // must not take v4 as "already deleted" and clean up through it: that frees
  // v3's blob, which the pin never named. Nothing is cleaned or queued.
  it("cleans nothing and queues nothing when the head moves between the worker's read and the adapter's read", async () => {
    const f = await reconnected({
      wrapLegacy: (ports) => ({
        ...ports,
        tombstone: async (scope, fence, check, signal) => {
          f.fake.moveHead(scope);
          f.fake.foreignTombstone(scope);
          return ports.tombstone(scope, fence, check, signal);
        },
      }),
    });
    const { retireId } = await f.a.sync.legacyRetirer.request(GH);

    await vi.waitFor(async () =>
      expect(await f.a.sync.legacyRetirer.status(GH)).toEqual({
        retireId,
        legacy: { state: "blocked", reason: "legacy_head_changed" },
      }),
    );
    expect(gatewayDeletes(f.fake)).toEqual([]);
    expect(storageDeletes(f.fake)).toEqual([]);
    for (const scope of SCOPES) {
      expect(await f.legacy.ports.pendingBlobs(scope)).toBe(0);
      expect(f.fake.blobCount(scope)).toBe(scope === SCOPES[0] ? 3 : 2);
    }
  });

  // The worker reads the pinned head live; the adapter then finds it absent.
  // The retirement transport must not acknowledge an absent head as its pin.
  // The pipeline blocks without erasing local entries or writing receipts.
  it("a fenced retire whose adapter sees the head absent writes no queue rows and touches no local files", async () => {
    const f = await reconnected({
      wrapLegacy: (ports) => ({
        ...ports,
        tombstone: async (scope, fence, check, signal) => {
          f.fake.dropHead(scope);
          return ports.tombstone(scope, fence, check, signal);
        },
      }),
    });
    // A local legacy entry per scope, as the pre-switch writes left them (the
    // seal refuses a new legacy write, so the index rows are placed directly).
    SCOPES.forEach((scope, id) =>
      f.legacy.storage.entries.push({
        id: id + 1,
        fileId: null,
        schemaId: null,
        path: `${scope}/2026-01-01T00:00:00.000Z.json`,
        scope,
        collectedAt: "2026-01-01T00:00:00.000Z",
        createdAt: "2026-01-01T00:00:00.000Z",
        sizeBytes: 1,
        version: 1,
        casRevision: 1,
        dataPointId: null,
      }),
    );
    const { retireId } = await f.a.sync.legacyRetirer.request(GH);

    await vi.waitFor(async () =>
      expect(await f.a.sync.legacyRetirer.status(GH)).toEqual({
        retireId,
        legacy: { state: "blocked", reason: "legacy_head_changed" },
      }),
    );
    expect(gatewayDeletes(f.fake)).toEqual([]);
    expect(storageDeletes(f.fake)).toEqual([]);
    for (const scope of SCOPES) {
      expect(await f.legacy.ports.pendingBlobs(scope)).toBe(0);
      expect(f.legacy.storage.countVersions(scope)).toBe(1);
    }
  });

  it("releases a connector's memory, verdict and loop once its retirement is done", async () => {
    const f = await reconnected();
    const { retireId } = await f.a.sync.legacyRetirer.request(GH);

    await vi.waitFor(async () =>
      expect(await f.a.sync.legacyRetirer.status(GH)).toEqual({
        retireId,
        legacy: DONE,
      }),
    );
    await vi.waitFor(() => expect(f.a.sync.legacyRetirer.retained()).toBe(0));
  });

  it("accepts a tombstone another writer put directly after the pinned head", async () => {
    const gate = (() => {
      let open!: () => void;
      const opened = new Promise<void>((resolve) => (open = resolve));
      return { opened, open };
    })();
    const read = new Set<string>();
    const f = await reconnected({
      wrapLegacy: (ports) => ({
        ...ports,
        head: async (scope, signal) => {
          if (read.has(scope)) await gate.opened;
          read.add(scope);
          return ports.head(scope, signal);
        },
      }),
    });
    const { retireId } = await f.a.sync.legacyRetirer.request(GH);
    for (const scope of SCOPES) f.fake.foreignTombstone(scope);
    gate.open();

    await vi.waitFor(async () =>
      expect(await f.a.sync.legacyRetirer.status(GH)).toEqual({
        retireId,
        legacy: DONE,
      }),
    );
    expect(gatewayDeletes(f.fake)).toEqual([]);
    for (const scope of SCOPES) expect(f.fake.blobCount(scope)).toBe(0);
  });

  // A status poll reports the verdict. It is not a retry: a blocked intent is
  // not read again, and a pending one keeps its backoff.
  it("does not restart a blocked intent when its status is polled", async () => {
    const gate = (() => {
      let open!: () => void;
      const opened = new Promise<void>((resolve) => (open = resolve));
      return { opened, open };
    })();
    const read = new Set<string>();
    let reads = 0;
    const f = await reconnected({
      wrapLegacy: (ports) => ({
        ...ports,
        head: async (scope, signal) => {
          reads += 1;
          if (read.has(scope)) await gate.opened;
          read.add(scope);
          return ports.head(scope, signal);
        },
      }),
    });
    const { retireId } = await f.a.sync.legacyRetirer.request(GH);
    for (const scope of SCOPES) f.fake.moveHead(scope);
    gate.open();
    const blockedStatus = {
      retireId,
      legacy: { state: "blocked", reason: "legacy_head_changed" },
    };
    await vi.waitFor(async () =>
      expect(await f.a.sync.legacyRetirer.status(GH)).toEqual(blockedStatus),
    );
    // Let any pass the polls above started finish before counting.
    await new Promise((resolve) => setTimeout(resolve, 60));
    const settled = reads;

    for (let poll = 0; poll < 20; poll++)
      expect(await f.a.sync.legacyRetirer.status(GH)).toEqual(blockedStatus);
    await new Promise((resolve) => setTimeout(resolve, 60));

    expect(reads).toBe(settled);
    expect(gatewayDeletes(f.fake)).toEqual([]);
  });

  it("starts a pass on a status poll only when no worker exists for the intent", async () => {
    const dbFile = tempDbFile();
    const f = await reconnected({ dbFile });
    const { retireId } = await f.a.sync.legacyRetirer.request(GH);
    await vi.waitFor(async () =>
      expect((await f.a.sync.legacyRetirer.status(GH))?.legacy).toEqual(DONE),
    );
    // A restart that has not cycled yet has no worker; a poll of an open
    // intent starts one. Reopen the intent to prove it.
    await f.a.db.batch([
      {
        sql: "UPDATE legacy_retirements SET state = 'open' WHERE retire_id = ?",
        params: [retireId],
      },
    ]);
    const restarted = await f.a.restart();
    await vi.waitFor(async () =>
      expect(await restarted.sync.legacyRetirer.status(GH)).toEqual({
        retireId,
        legacy: DONE,
      }),
    );
  });

  // The preflight `importFence` and the merge are two steps. An intent that is
  // persisted between them must still stop the merge: only the guard inside the
  // merge transaction can.
  it("merges no record when the intent is persisted after the import's last preflight check", async () => {
    const f = await reconnected();
    const source: ImportSource = {
      source: "legacy-race",
      owner: OWNER,
      network: "test",
      revision: "r1",
      target: {
        connectionId: controlScope(GH, ""),
        connector: GH,
        stream: sName(0),
        primaryKey: ["id"],
        semantics: "mutable_state",
        incremental: true,
      },
      exclusions: [],
      async *records() {
        yield { id: "raced" };
      },
    };
    const recordsBefore = await f.a.records();
    const changesBefore = await f.a.db.query(
      "SELECT count(*) AS n FROM record_changes",
    );
    let persisted = false;
    const db = new Proxy(f.a.deps.db, {
      get(target, key, receiver) {
        if (key !== "batch") return Reflect.get(target, key, receiver);
        return async (statements: { sql: string }[]) => {
          // The merge transaction is the batch that carries the guard.
          if (
            !persisted &&
            statements.some((s) => s.sql.includes("INSERT INTO import_guard"))
          ) {
            persisted = true;
            await f.a.db.batch([
              {
                sql: "INSERT INTO legacy_retirements (owner, connector, retire_id, state, scopes, created_at) VALUES (?, ?, 'race', 'open', '[]', 1)",
                params: [OWNER.toLowerCase(), GH],
              },
            ]);
          }
          return target.batch(statements as never);
        };
      },
    });

    await importLegacySource(
      { ...f.a.deps, db },
      createImportLedger(f.a.db),
      source,
    ).catch(() => undefined);

    expect(persisted).toBe(true);
    expect(await f.a.records()).toEqual(recordsBefore);
    expect(
      await f.a.db.query("SELECT count(*) AS n FROM record_changes"),
    ).toEqual(changesBefore);
  });

  // `done` must not lift the fence of a retired scope: a batch read before the
  // retirement finished would merge the records the retirement deleted.
  it("an import batch read before retirement completes merges nothing after the retirement is done", async () => {
    const f = await reconnected();
    const source: ImportSource = {
      source: "legacy-stale",
      owner: OWNER,
      network: "test",
      revision: "r1",
      target: {
        connectionId: controlScope(GH, ""),
        connector: GH,
        // A stream the connector's retired scope `github.repositories` feeds.
        stream: "repositories",
        primaryKey: ["id"],
        semantics: "mutable_state",
        incremental: true,
      },
      exclusions: [],
      async *records() {
        yield { id: "deleted-upstream" };
      },
    };
    const recordsBefore = await f.a.records();
    let retired = false;
    const db = new Proxy(f.a.deps.db, {
      get(target, key, receiver) {
        if (key !== "batch") return Reflect.get(target, key, receiver);
        return async (statements: { sql: string }[]) => {
          if (
            !retired &&
            statements.some((s) => s.sql.includes("INSERT INTO import_guard"))
          ) {
            retired = true;
            await f.a.sync.legacyRetirer.request(GH);
            await vi.waitFor(async () =>
              expect((await f.a.sync.legacyRetirer.status(GH))?.legacy).toEqual(
                DONE,
              ),
            );
          }
          return target.batch(statements as never);
        };
      },
    });

    await importLegacySource(
      { ...f.a.deps, db },
      createImportLedger(f.a.db),
      source,
    ).catch(() => undefined);

    expect(retired).toBe(true);
    expect(await f.a.records()).toEqual(recordsBefore);
    // And a later import of the retired scope's stream is refused too.
    expect(
      await importLegacySource(f.a.deps, createImportLedger(f.a.db), {
        ...source,
        source: "legacy-later",
        revision: "r2",
      }),
    ).toEqual({ kind: "refused", reason: "legacy_retired" });
  });

  it("refuses an account that has not switched, and writes nothing", async () => {
    const f = await reconnected({ mode: "off" });

    await expect(f.a.sync.legacyRetirer.request(GH)).rejects.toBeInstanceOf(
      LegacyRetireNotAdmitted,
    );
    await expect(f.a.sync.legacyRetirer.request(GH)).rejects.toMatchObject({
      mode: "unswitched",
    });
    expect(await f.a.sync.legacyRetirer.status(GH)).toBeNull();
    expect(await f.a.db.query("SELECT * FROM legacy_retirements")).toEqual([]);
    expect(f.fake.requests).toEqual([]);
  });

  // Without the streams of each scope the intent could not hold back a later
  // import of them, so the permanent fence would silently hold nothing.
  it("writes no done verdict when the account mode stopped reading as switched during the pass", async () => {
    let mode: "switched" | "unknown" = "switched";
    let retired = 0;
    const f = await reconnected({
      wrapLegacy: (ports) => ({
        ...ports,
        mode: () => (mode === "switched" ? ports.mode() : "unknown"),
        tombstone: async (scope, fence, check, signal) => {
          const result = await ports.tombstone(scope, fence, check, signal);
          retired += 1;
          mode = "unknown";
          return result;
        },
      }),
    });
    const doneWrites: string[] = [];
    const batch = f.a.db.batch.bind(f.a.db);
    f.a.db.batch = async (statements) => {
      for (const { sql } of statements)
        if (sql.includes("legacy_retirements SET state = 'done'"))
          doneWrites.push(sql);
      return batch(statements);
    };
    await f.a.sync.legacyRetirer.request(GH);

    // The pass stops at the next host call once the mode reads unknown.
    await vi.waitFor(() => expect(retired).toBe(1));
    // The pass ends; its verdict is pending, never done.
    await vi.waitFor(async () =>
      expect(await f.a.sync.legacyRetirer.status(GH)).toMatchObject({
        legacy: PENDING,
      }),
    );
    await f.a.sync.legacyRetirer.close();
    expect(doneWrites).toEqual([]);
  });

  it("a persisted retirement polled during a registration hold does no destructive work", async () => {
    let ready = true;
    const f = await reconnected({ writeReady: () => ready });
    f.fake.requests.length = 0;

    // The DELETE records the intent and answers pending; a GET reads it.
    const { retireId } = await f.a.sync.legacyRetirer.request(GH);
    ready = false;
    expect(await f.a.sync.legacyRetirer.status(GH)).toEqual({
      retireId,
      legacy: PENDING,
    });
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(await f.a.sync.legacyRetirer.status(GH)).toMatchObject({
      legacy: PENDING,
    });
    expect(gatewayDeletes(f.fake)).toEqual([]);
    expect(storageDeletes(f.fake)).toEqual([]);
    for (const scope of SCOPES) expect(f.fake.isLive(scope)).toBe(true);

    ready = true;
    await vi.waitFor(async () =>
      expect(await f.a.sync.legacyRetirer.status(GH)).toEqual({
        retireId,
        legacy: DONE,
      }),
    );
    for (const scope of SCOPES) expect(f.fake.isLive(scope)).toBe(false);
  });

  it("refuses admission when the host cannot name the streams of a scope, and writes nothing", async () => {
    const f = await reconnected({
      wrapLegacy: ({ streamsOf: _streamsOf, ...ports }) => ports,
    });

    await expect(f.a.sync.legacyRetirer.request(GH)).rejects.toBeInstanceOf(
      LegacyRetireUnavailable,
    );
    expect(await f.a.sync.legacyRetirer.status(GH)).toBeNull();
    expect(await f.a.db.query("SELECT * FROM legacy_retirements")).toEqual([]);
    expect(gatewayDeletes(f.fake)).toEqual([]);
  });

  // Closing the sync closes the database. A pass with a storage call in flight
  // would write its verdict to a closed database, so close waits for it.
  it("close waits for an in-flight legacy retirement before closing its database", async () => {
    let entered!: () => void;
    const inFlight = new Promise<void>((resolve) => (entered = resolve));
    let release!: () => void;
    const released = new Promise<void>((resolve) => (release = resolve));
    let storageReturned = false;
    const f = await reconnected({
      wrapLegacy: (ports) => ({
        ...ports,
        eraseBlob: async (scope, version, check, signal) => {
          const outcome = await ports.eraseBlob(scope, version, check, signal);
          if (scope === SCOPES.at(-1)) {
            storageReturned = false;
            entered();
            await released;
          }
          storageReturned = true;
          return outcome;
        },
      }),
    });
    await f.a.sync.legacyRetirer.request(GH);
    await inFlight;

    // Rows the pass writes after close began would land on a closing database.
    const doneWrites: string[] = [];
    const batch = f.a.db.batch.bind(f.a.db);
    f.a.db.batch = async (statements) => {
      for (const { sql } of statements)
        if (sql.includes("legacy_retirements SET state = 'done'"))
          doneWrites.push(sql);
      return batch(statements);
    };
    let closed = false;
    const closing = f.a.sync.close().then(() => (closed = true));
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(closed).toBe(false);

    release();
    await closing;
    expect(storageReturned).toBe(true);
    expect(doneWrites).toEqual([]);
  });

  it("refuses while the account mode is unknown, and writes nothing", async () => {
    const f = await reconnected({
      wrapLegacy: (ports) => ({ ...ports, mode: () => "unknown" }),
    });

    await expect(f.a.sync.legacyRetirer.request(GH)).rejects.toMatchObject({
      mode: "unknown",
    });
    expect(await f.a.db.query("SELECT * FROM legacy_retirements")).toEqual([]);
    expect(gatewayDeletes(f.fake)).toEqual([]);
  });

  it("refuses a legacy import of the connector while the intent is open, and admits it again once done", async () => {
    const finality = {
      finalized: null as string | null,
      settling: true,
      rolledBack: null,
    };
    const f = await reconnected({ finality: () => finality });
    const importOf = (revision: string, id: string) => {
      const source: ImportSource = {
        source: `legacy-${revision}`,
        owner: OWNER,
        network: "test",
        revision,
        target: {
          connectionId: controlScope(GH, ""),
          connector: GH,
          stream: sName(0),
          primaryKey: ["id"],
          semantics: "mutable_state",
          incremental: true,
        },
        exclusions: [],
        async *records() {
          yield { id };
        },
      };
      return importLegacySource(f.a.deps, createImportLedger(f.a.db), source);
    };
    expect((await importOf("r1", "before")).kind).toBe("imported");

    await f.a.sync.legacyRetirer.request(GH);
    await vi.waitFor(() =>
      expect(gatewayDeletes(f.fake)).toHaveLength(SCOPES.length),
    );

    expect(await importOf("r2", "during")).toEqual({
      kind: "refused",
      reason: "legacy_retiring",
    });
    expect(await f.a.records()).not.toContainEqual(
      expect.stringContaining("during"),
    );

    finality.finalized = "3";
    finality.settling = false;
    await vi.waitFor(async () =>
      expect((await f.a.sync.legacyRetirer.status(GH))?.legacy).toEqual(DONE),
    );
    expect((await importOf("r3", "after")).kind).toBe("imported");
  });
});

// The fixture's own connector is not bound to a legacy scope: a retirement of
// it pins nothing and is done at once, without a gateway read.
describe("a retirement's destructive steps run only under live write authority and the pinned version", () => {
  it("revoking write authority during the adapter's head read sends no tombstone and erases nothing", async () => {
    let ready = true;
    let armed = false;
    const f = await reconnected({
      writeReady: () => ready,
      host: {
        onAdapterHeadRead: () => {
          if (armed) ready = false;
        },
      },
    });
    placeLocalEntries(f);
    f.fake.requests.length = 0;
    armed = true;
    const { retireId } = await f.a.sync.legacyRetirer.request(GH);

    await vi.waitFor(() => expect(ready).toBe(false));
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(gatewayDeletes(f.fake)).toEqual([]);
    expect(storageDeletes(f.fake)).toEqual([]);
    for (const scope of SCOPES) {
      expect(f.fake.isLive(scope)).toBe(true);
      expect(await f.legacy.ports.pendingBlobs(scope)).toBe(0);
      expect(f.legacy.storage.countVersions(scope)).toBe(1);
    }
    expect(await f.a.sync.legacyRetirer.status(GH)).toEqual({
      retireId,
      legacy: PENDING,
    });

    // The authority comes back: the same pass finishes, locally too.
    armed = false;
    ready = true;
    await vi.waitFor(async () =>
      expect(await f.a.sync.legacyRetirer.status(GH)).toEqual({
        retireId,
        legacy: DONE,
      }),
    );
    for (const scope of SCOPES)
      expect(f.legacy.storage.countVersions(scope)).toBe(0);
  });

  it("a fenced delete whose 2xx echoes a later version cleans nothing past the pinned version", async () => {
    const f = await reconnected({
      host: {
        wrapFetch: (fetchImpl) =>
          (async (input, init) => {
            const res = await fetchImpl(input, init);
            if (
              init?.method !== "DELETE" ||
              !String(input).startsWith(FAKE_GATEWAY)
            )
              return res;
            const body = (await res.json()) as {
              data: Record<string, unknown>;
            };
            return new Response(
              JSON.stringify({ data: { ...body.data, expectedVersion: "9" } }),
              {
                status: res.status,
                headers: { "content-type": "application/json" },
              },
            );
          }) as typeof fetch,
      },
    });
    placeLocalEntries(f);
    const { retireId } = await f.a.sync.legacyRetirer.request(GH);

    await vi.waitFor(async () =>
      expect(await f.a.sync.legacyRetirer.status(GH)).toEqual({
        retireId,
        legacy: DONE,
      }),
    );
    // The pins named version 2: its tombstone is 3. No blob above it is asked for.
    const versions = storageDeletes(f.fake).map((r) =>
      Number(decodeURIComponent(r.url).split("/").pop()),
    );
    expect(versions.length).toBeGreaterThan(0);
    expect(Math.max(...versions)).toBeLessThanOrEqual(3);
  });

  it("resumes local cleanup when the process stopped after the tombstone landed", async () => {
    const dbFile = tempDbFile();
    let crashed = true;
    const f = await reconnected({ dbFile });
    placeLocalEntries(f);
    const deleteVersion = f.legacy.storage.deleteVersion.bind(f.legacy.storage);
    f.legacy.storage.deleteVersion = async (...args) => {
      if (crashed)
        throw new Error("the process stopped before the local erase");
      return deleteVersion(...args);
    };
    const { retireId } = await f.a.sync.legacyRetirer.request(GH);
    await vi.waitFor(() =>
      expect(gatewayDeletes(f.fake)).toHaveLength(SCOPES.length),
    );
    await f.a.sync.legacyRetirer.close();
    for (const scope of SCOPES) {
      expect(f.fake.isLive(scope)).toBe(false);
      expect(f.legacy.storage.countVersions(scope)).toBe(1);
    }

    // A new process: no memory, a deleted head, local files left behind.
    crashed = false;
    const restarted = await f.a.restart();
    await vi.waitFor(async () =>
      expect(await restarted.sync.legacyRetirer.status(GH)).toEqual({
        retireId,
        legacy: DONE,
      }),
    );
    for (const scope of SCOPES)
      expect(f.legacy.storage.countVersions(scope)).toBe(0);
    // Still one tombstone per scope: the retry cleaned, it did not delete again.
    expect(gatewayDeletes(f.fake)).toHaveLength(SCOPES.length);
  });

  it("a failed local erase keeps the retirement pending", async () => {
    const f = await reconnected();
    placeLocalEntries(f);
    let failing = true;
    const deleteVersion = f.legacy.storage.deleteVersion.bind(f.legacy.storage);
    f.legacy.storage.deleteVersion = async (...args) => {
      if (failing) throw new Error("disk error");
      return deleteVersion(...args);
    };
    const { retireId } = await f.a.sync.legacyRetirer.request(GH);

    await vi.waitFor(() =>
      expect(gatewayDeletes(f.fake)).toHaveLength(SCOPES.length),
    );
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(await f.a.sync.legacyRetirer.status(GH)).toEqual({
      retireId,
      legacy: PENDING,
    });
    for (const scope of SCOPES)
      expect(f.legacy.storage.countVersions(scope)).toBe(1);

    failing = false;
    await vi.waitFor(async () =>
      expect(await f.a.sync.legacyRetirer.status(GH)).toEqual({
        retireId,
        legacy: DONE,
      }),
    );
    for (const scope of SCOPES)
      expect(f.legacy.storage.countVersions(scope)).toBe(0);
  });
});

describe("a connector with no bound legacy scope", () => {
  it("is done at once and sends nothing", async () => {
    const f = await reconnected();
    expect(legacyScopesOfConnector(FIXTURE)).toEqual([]);
    const { retireId } = await f.a.sync.legacyRetirer.request(FIXTURE);
    await vi.waitFor(async () =>
      expect(await f.a.sync.legacyRetirer.status(FIXTURE)).toEqual({
        retireId,
        legacy: DONE,
      }),
    );
    expect(f.fake.requests).toEqual([]);
  });
});
