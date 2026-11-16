/**
 * A source deleted and then connected again, with the stream-sync log on: the
 * delete must leave the registry in a state a reconnect can begin on.
 *
 * Real gateway adapter, real intake, deleter, publish and apply drivers, real
 * SQLite, against the fake gateway. The fake refuses a stream row write while
 * the connection's log row exists (409), as the registry does.
 */
import { afterEach, describe, expect, it } from "vitest";
import { logScope } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  CONNECTOR,
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
      logProtocol: true,
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
      logProtocol: true,
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

it("a log row that appears after the delete was planned ends the stream cleanup", async () => {
  const w = await world({ streams: 3, logProtocol: true });
  const a = await w.device("a");
  await a.run("run-1", [{ stream: sName(0), id: "1" }]);
  await a.cycle();
  // The plan listed the connection before the log row existed: it names the
  // declared streams, and the registry now refuses each write to one.
  const registry = a.deps.registry;
  const listStreamRows = registry.listStreamRows.bind(registry);
  registry.listStreamRows = async (connector) =>
    (await listStreamRows(connector)).filter((row) => row.scope !== LOG);
  await a.sync.deleter.requestConnectionDelete(CONNECTOR);
  expect(await a.sync.deleter.resumeDeletes()).toEqual([]);
  expect(w.gateway.versions.get(LOG)).toHaveLength(1);
});
