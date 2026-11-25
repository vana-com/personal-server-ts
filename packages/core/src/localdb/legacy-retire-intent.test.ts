// The standalone legacy retirement through the real local sync, the real seal,
// the real `deleteScope` worker and real SQLite, over a fake legacy gateway:
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
import { LegacyRetireNotAdmitted } from "./legacy-retire-intent.js";
import { legacyScopesOfConnector } from "../legacy-projection/erase-connector.js";
import { legacyPortsOver } from "../test-utils/legacy-delete-ports.js";
import { createLegacyGatewayFake } from "../test-utils/legacy-gateway-fake.js";
import {
  FAKE_GATEWAY,
  FAKE_STORAGE,
} from "../test-utils/legacy-gateway-fake.js";
import type { LegacyDeletePorts } from "./legacy-delete.js";

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
    wrapLegacy?: (ports: LegacyDeletePorts) => LegacyDeletePorts;
    dbFile?: string;
  } = {},
) {
  const w = await world({ streams: 1 });
  const fake = createLegacyGatewayFake({ owner: OWNER, cutover: "v3" });
  for (const scope of SCOPES) fake.seed(scope, 2);
  const legacy = await legacyPortsOver(fake, {
    ...(options.mode && { mode: options.mode }),
    ...(options.finality && { finality: options.finality }),
  });
  const a = await w.device("a", {
    legacyDelete: () => options.wrapLegacy?.(legacy.ports) ?? legacy.ports,
    deleteRetryMs: RETRY,
    ...(options.dbFile && { dbFile: options.dbFile }),
  });
  await a.run("run-1", [{ stream: sName(0), id: "x", v: 0 }], {
    connector: GH,
    observedAt: 1100,
  });
  await a.cycle();
  return { w, a, fake, legacy };
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
    finality.finalized = "99";
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

    finality.finalized = "99";
    finality.settling = false;
    await vi.waitFor(async () =>
      expect((await f.a.sync.legacyRetirer.status(GH))?.legacy).toEqual(DONE),
    );
    expect((await importOf("r3", "after")).kind).toBe("imported");
  });
});

// The fixture's own connector is not bound to a legacy scope: a retirement of
// it pins nothing and is done at once, without a gateway read.
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
