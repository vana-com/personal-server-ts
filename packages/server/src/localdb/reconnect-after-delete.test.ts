/**
 * A source deleted and then connected again, with the stream-sync log on: the
 * delete must leave the registry in a state a reconnect can begin on.
 *
 * Real gateway adapter, real intake, deleter, publish and apply drivers, real
 * SQLite, against the fake gateway. The fake refuses a stream row write while
 * the connection's log row exists (409), as the registry does.
 */
import { afterEach, describe, expect, it } from "vitest";
import {
  controlScope,
  logScope,
  streamScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "../../../core/src/api/index.js";
import { applyConnection } from "../../../core/src/localdb/apply.js";
import {
  RegistryUnavailableBeforeWriteError,
  RegistryUnavailableError,
} from "../../../core/src/stream-sync/ports.js";
import { createLocalResolver } from "../../../core/src/localdb/resolve.js";
import { createRecordQuery } from "../../../core/src/localdb/query.js";
import type { DeleteIntent } from "../../../core/src/localdb/delete.js";
import {
  CONNECTOR,
  CONNECTION_ID,
  OWNER,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const LOG = logScope(CONNECTOR, "");
const connect = (runId: string) => ({
  runId,
  request: {
    connector: CONNECTOR,
    artifactDigest: CONNECTOR,
    connect: true,
    observedAt: 3000,
    owner: { address: OWNER, leaseId: null },
  },
});

describe.each([
  { name: "registry refuses stream rows beside a log", fence: true },
  { name: "registry accepts stream rows beside a log", fence: false },
])("delete then reconnect, log protocol on: $name", ({ fence }) => {
  it("lands the delete, leaves the log row alone and begins the reconnect run", async () => {
    const w = await world({
      streams: 3,
      connectionLogFence: fence,
    });
    const a = await w.device("a");
    await a.run("run-1", [
      { stream: sName(0), id: "1" },
      { stream: sName(1), id: "2" },
    ]);
    await a.cycle();
    const logVersions = w.gateway.versions.get(LOG)!.length;

    await a.sync.deleter.requestConnectionDelete(CONNECTOR);
    // The delete finishes: nothing is left pending behind it.
    expect(await a.sync.deleter.resumeDeletes()).toEqual([]);
    expect(await a.db.query("SELECT 1 FROM delete_intents")).toEqual([]);
    // The log row is the connection's own, not a stream's: no delete head
    // lands on it, so a reader still finds a segment at every position.
    expect(w.gateway.versions.get(LOG)).toHaveLength(logVersions);

    const { runId, request } = connect("reconnect-1");
    const begun = await a.sync.intake.begin(runId, request);
    expect(begun.status).toBe("collecting");
  });

  it("publishes the new lifetime and a second device sees only it", async () => {
    const w = await world({
      streams: 3,
      connectionLogFence: fence,
    });
    const a = await w.device("a");
    const b = await w.device("b");
    await a.run("run-1", [{ stream: sName(0), id: "old" }]);
    await a.cycle();
    await b.cycle();
    expect(await b.records()).toHaveLength(1);

    await a.sync.deleter.requestConnectionDelete(CONNECTOR);
    expect(await a.sync.deleter.resumeDeletes()).toEqual([]);
    await b.cycle();
    expect(await b.records()).toEqual([]);

    // A second device, which never saw the delete, reconnects.
    const { runId, request } = connect("reconnect-b");
    expect((await b.sync.intake.begin(runId, request)).status).toBe(
      "collecting",
    );
    await b.sync.intake.abort(runId, "cancelled");
    await a.run("run-2", [{ stream: sName(1), id: "new" }]);
    await a.cycle();
    await b.cycle();
    const rows = await b.records();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toContain(`${sName(1)}/`);
  });
});

it("a delete leaves the connection log as it is, whatever the listing showed", async () => {
  const w = await world({ streams: 3 });
  const a = await w.device("a");
  await a.run("run-1", [{ stream: sName(0), id: "1" }]);
  await a.cycle();
  // A listing that misses the log row changes nothing: the delete writes the
  // fence only.
  const registry = a.deps.registry;
  const listStreamRows = registry.listStreamRows.bind(registry);
  registry.listStreamRows = async (connector) =>
    (await listStreamRows(connector)).filter((row) => row.scope !== LOG);
  await a.sync.deleter.requestConnectionDelete(CONNECTOR);
  expect(await a.sync.deleter.resumeDeletes()).toEqual([]);
  expect(w.gateway.versions.get(LOG)).toHaveLength(1);
});

it("planning names the control pins only: no listed or declared stream, and not the log", async () => {
  const w = await world({ streams: 3 });
  const a = await w.device("plan-guard");
  await a.run("run-plan", [{ stream: sName(0), id: "old" }]);
  await a.cycle();
  const registry = a.deps.registry;
  const list = registry.listStreamRows.bind(registry);
  const listed = await list(CONNECTOR);
  const log = listed.find((row) => row.scope === LOG);
  expect(log).toBeDefined();
  // Model a listing retaining an old stream head beside the connection log.
  // Only plan reads this hint: landing is deliberately never started.
  registry.listStreamRows = async (connector) => [
    ...(await list(connector)),
    { ...log!, scope: streamScope(CONNECTOR, "", "old-listed-stream") },
  ];
  const batch = a.db.batch.bind(a.db);
  const stop = new Error("test captured plan before persistence");
  let planned: DeleteIntent | undefined;
  a.db.batch = async (statements) => {
    const save = statements.find((statement) =>
      statement.sql.startsWith("INSERT OR REPLACE INTO delete_intents("),
    );
    if (save) {
      planned = JSON.parse(String(save.params![2])) as DeleteIntent;
      throw stop;
    }
    return batch(statements);
  };
  try {
    await expect(
      a.sync.deleter.requestConnectionDelete(CONNECTOR),
    ).rejects.toBe(stop);
    expect(planned).toBeDefined();
    // The plan names control pins only: no stream, listed or declared, and
    // not the log.
    expect(planned).toEqual({
      id: expect.any(String),
      pins: [expect.anything()],
    });
    expect(await a.db.query("SELECT 1 FROM delete_intents")).toEqual([]);
  } finally {
    a.db.batch = batch;
    registry.listStreamRows = list;
  }
});

it.each(
  ["active v1", "deleted v2", "absent"].flatMap((stale) =>
    [false, true].map((withHint) => ({ stale, withHint })),
  ),
)(
  "retries $stale control after reconnect (observed hint: $withHint)",
  async ({ stale, withHint }) => {
    const w = await world({ streams: 3 });
    const a = await w.device("lagging-control");
    const registry = a.deps.registry;
    const control = controlScope(CONNECTOR, "");
    await a.run("before-delete", [{ stream: sName(0), id: "old" }]);
    await a.cycle();
    const activeControl = await registry.read(control);
    const staleLog = await registry.read(LOG);
    if (!activeControl.found || !staleLog.found)
      throw new Error("missing old lifetime");
    expect(activeControl.version).toBe(1);

    await a.sync.deleter.requestConnectionDelete(CONNECTOR);
    expect(await a.sync.deleter.resumeDeletes()).toEqual([]);
    expect(await a.records()).toEqual([]);
    const deletedControl = await registry.read(control);
    if (!deletedControl.found) throw new Error("missing deletion control");
    expect(deletedControl.version).toBe(2);
    const staleControl =
      stale === "active v1"
        ? activeControl
        : stale === "deleted v2"
          ? deletedControl
          : { found: false as const };
    await a.run("after-reconnect", [{ stream: sName(1), id: "new" }], {
      connect: true,
    });
    await a.cycle();
    const rows = await a.records();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toContain(`${sName(1)}/`);
    const records = await a.db.query(
      "SELECT * FROM records ORDER BY stream, record_key",
    );
    const [before] = await a.db.query<{
      connection_id: string;
      generation: number;
      control_version: number;
    }>("SELECT * FROM connections WHERE connector=?", [CONNECTOR]);
    expect(before.generation).toBe(3);
    expect(before.control_version).toBe(3);
    const heads = await a.db.query(
      "SELECT * FROM stream_state ORDER BY stream",
    );
    expect(heads.length).toBeGreaterThan(0);

    const registryBefore = structuredClone([...w.gateway.versions]);
    const batch = a.db.batch.bind(a.db);
    let partialMarks = 0;
    a.db.batch = async (statements) => {
      partialMarks += statements.filter((statement) =>
        statement.sql.includes("SET apply_partial=1"),
      ).length;
      return batch(statements);
    };
    const read = registry.read.bind(registry);
    let controlReads = 0;
    registry.read = async (scope) => {
      if (scope === control) {
        controlReads++;
        return staleControl;
      }
      if (scope === LOG) return staleLog;
      return read(scope);
    };
    try {
      await expect(
        applyConnection(
          a.deps,
          before.connection_id,
          undefined,
          withHint ? staleControl : undefined,
        ),
      ).rejects.toBeInstanceOf(RegistryUnavailableBeforeWriteError);
      expect(controlReads).toBe(1);
      expect(partialMarks).toBe(0);
      expect([...w.gateway.versions]).toEqual(registryBefore);
      expect(
        await a.db.query("SELECT * FROM records ORDER BY stream, record_key"),
      ).toEqual(records);
      expect(
        await a.db.query("SELECT * FROM connections WHERE connector=?", [
          CONNECTOR,
        ]),
      ).toEqual([before]);
      expect(
        await a.db.query("SELECT * FROM stream_state ORDER BY stream"),
      ).toEqual(heads);
    } finally {
      registry.read = read;
      a.db.batch = batch;
    }
    let retryControlReads = 0;
    registry.read = async (scope) => {
      const result = await read(scope);
      if (scope === control) {
        retryControlReads++;
        expect(result.found && result.version).toBe(before.control_version);
      }
      return result;
    };
    try {
      await applyConnection(a.deps, before.connection_id);
      expect(retryControlReads).toBe(1);
      const [after] = await a.db.query<{
        generation: number;
        control_version: number;
      }>(
        "SELECT generation, control_version FROM connections WHERE connector=?",
        [CONNECTOR],
      );
      expect(after).toEqual({
        generation: before.generation,
        control_version: before.control_version,
      });
      expect(await a.records()).toEqual(rows);
      expect(
        await a.db.query("SELECT * FROM stream_state ORDER BY stream"),
      ).toEqual(heads);
    } finally {
      registry.read = read;
    }
    await a.cycle();
    expect(await a.records()).toEqual(rows);
  },
);

it.each(
  ["older control", "registry unavailable"].flatMap((failure) =>
    [false, true].map((progressive) => ({ failure, progressive })),
  ),
)(
  "serves local rows when apply fails before writing: $failure (progressive: $progressive)",
  async ({ failure, progressive }) => {
    const w = await world({ streams: 1 });
    const a = await w.device("read-local", {
      progressiveFirstLoad: progressive,
    });
    await a.run("first", [{ stream: sName(0), id: "local" }]);
    await a.cycle();
    if (failure === "older control") {
      await a.db.batch([
        { sql: "UPDATE connections SET control_version = control_version + 1" },
      ]);
    } else {
      const read = a.deps.registry.read.bind(a.deps.registry);
      a.deps.registry.read = (scope) =>
        scope === controlScope(CONNECTOR, "")
          ? Promise.reject(new RegistryUnavailableError("offline"))
          : read(scope);
    }
    const resolver = createLocalResolver(a.deps, {
      query: createRecordQuery(a.db),
    });
    const result = await resolver.resolve({
      scope: streamScope(CONNECTOR, "", sName(0)),
      connection: null,
      cursor: null,
      legacyFile: false,
      isOwnerView: true,
    });
    expect(result.kind).toBe("view");
    if (result.kind !== "view") throw new Error("missing local view");
    const body = (await new Response(result.body).json()) as {
      data: { records: { id: string }[] };
    };
    expect(body.data.records.map((r) => r.id)).toEqual(["local"]);
  },
);

it.each([false, true])(
  "refuses a first read when the registry is unavailable (old deleted connection: %s)",
  async (withDeleted) => {
    const w = await world({ streams: 1 });
    const a = await w.device("read-empty");
    await a.db.batch([
      {
        sql: "INSERT INTO connections(connection_id, connector, ns, generation, control_state, control_version) VALUES (?, ?, '', 1, 'active', 1)",
        params: [CONNECTION_ID, CONNECTOR],
      },
      ...(withDeleted
        ? [
            {
              sql: "INSERT INTO connections(connection_id, connector, ns, generation, control_state, control_version) VALUES (?, ?, ?, 1, 'deleted', 1)",
              params: ["deleted-connection", CONNECTOR, "0123456789abcdef"],
            },
          ]
        : []),
    ]);
    a.deps.registry.read = () =>
      Promise.reject(new RegistryUnavailableError("offline"));
    const resolver = createLocalResolver(a.deps, {
      query: createRecordQuery(a.db),
    });
    expect(
      await resolver.resolve({
        scope: streamScope(CONNECTOR, "", sName(0)),
        connection: null,
        cursor: null,
        legacyFile: false,
        isOwnerView: true,
      }),
    ).toEqual({ kind: "busy", retryAfterSeconds: 5 });
    const deps = {
      accountMode: { read: () => "switched" },
      streamSyncRead: resolver,
      auth: {
        authorizeOwner: async () => undefined,
        authorizeBuilderList: async () => undefined,
        authorizeBuilderRead: async () => ({ grantId: "owner" }),
      },
      accessLogWriter: { write: async () => undefined },
      logger: { debug() {}, error() {}, warn() {}, info() {} },
      serverOwner: OWNER,
      createLogId: () => "read-1",
    } as unknown as PersonalServerDataApiDeps;
    const response = await handlePersonalServerDataRequest(
      new Request(
        `https://server.example/v1/data/${streamScope(CONNECTOR, "", sName(0))}`,
      ),
      deps,
      { basePath: "/v1/data" },
    );
    expect(response.status).toBe(503);
    expect(response.headers.get("Retry-After")).toBe("5");
    expect((await response.json()).error.errorCode).toBe(
      "STREAM_SYNC_READ_BUSY",
    );
    if (withDeleted)
      expect(
        await resolver.resolve({
          scope: streamScope(CONNECTOR, "", sName(0)),
          connection: "0123456789abcdef",
          cursor: null,
          legacyFile: false,
          isOwnerView: true,
        }),
      ).toEqual({ kind: "unavailable", reason: "deleted" });
  },
);
