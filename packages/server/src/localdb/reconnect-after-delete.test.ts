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
import type { DeleteIntent } from "../../../core/src/localdb/delete.js";
import {
  CONNECTOR,
  OWNER,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const LOG = logScope(CONNECTOR, "");
const CONTROL = controlScope(CONNECTOR, "");
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

it("an intent an older build saved with a log pin resumes without planning or advancing the log version", async () => {
  // A permissive gateway makes a write to the log observable as a successful
  // destructive write, not an incidental conflict-based exit.
  const w = await world({
    streams: 3,
    connectionLogFence: false,
  });
  const a = await w.device("legacy-intent");
  await a.run("run-legacy", [{ stream: sName(0), id: "old" }]);
  await a.cycle();
  const before = await a.deps.registry.read(LOG);
  const control = await a.deps.registry.read(CONTROL);
  expect(before.found).toBe(true);
  expect(control.found).toBe(true);
  if (!before.found || !control.found) throw new Error("missing fixture rows");
  const versions = w.gateway.versions.get(LOG)!.length;
  // An older build saved stream pins beside the control pins.
  const intent = {
    id: "saved-before-log-guard",
    pins: [{ ns: "", version: control.version }],
    streams: [
      {
        ns: "",
        stream: "~log",
        pin: before.version + 1,
        control: { kind: "active", generation: control.version },
      },
    ],
  };
  await a.db.batch([
    {
      sql: "INSERT OR REPLACE INTO delete_intents(connector,delete_id,intent) VALUES (?,?,?)",
      params: [CONNECTOR, intent.id!, JSON.stringify(intent)],
    },
  ]);
  const list = a.deps.registry.listControlRows.bind(a.deps.registry);
  a.deps.registry.listControlRows = async () => {
    throw new Error("resuming a stored intent must not plan");
  };
  try {
    expect(await a.sync.deleter.resumeDeletes()).toEqual([]);
    a.deps.registry.listControlRows = list;
    expect(await a.db.query("SELECT 1 FROM delete_intents")).toEqual([]);
    expect(await a.deps.registry.read(LOG)).toEqual(before);
    expect(w.gateway.versions.get(LOG)).toHaveLength(versions);
    expect(await a.deps.registry.read(CONTROL)).toMatchObject({
      found: true,
      version: control.version + 1,
    });
    const { runId, request } = connect("reconnect-legacy");
    expect((await a.sync.intake.begin(runId, request)).status).toBe(
      "collecting",
    );
    await a.sync.intake.abort("reconnect-legacy", "cancelled");
  } finally {
    a.deps.registry.listControlRows = list;
  }
});
