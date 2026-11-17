/**
 * A connection delete fences every stream of the lifetime it ends, including a
 * stream the manifest declares and no run ever published.
 *
 * The fence is the control tombstone (docs/261114-connection-delete-fence.md):
 * admission re-reads the control row and the gateway conditions each publish
 * on it. Neither reads a list of streams, so a second device needs no record
 * that a stream exists in order to be refused a write to it. These tests pin
 * that with real intake, publish and apply drivers and the fake gateway.
 */
import { afterEach, describe, expect, it } from "vitest";
import { endRequest } from "../../../core/src/test-utils/run-end.js";
import {
  CONNECTOR,
  CONTROL,
  LOG,
  OWNER,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const NEVER_PUBLISHED = sName(1);
const connect = (observedAt: number) => ({
  connector: CONNECTOR,
  artifactDigest: CONNECTOR,
  connect: true,
  observedAt,
  owner: { address: OWNER, leaseId: null },
});
const request = (observedAt: number) => ({
  connector: CONNECTOR,
  artifactDigest: CONNECTOR,
  wantFull: true,
  observedAt,
  owner: { address: OWNER, leaseId: null },
});

describe("a stream declared and never published", () => {
  it("is refused to a second device that has not yet applied the delete", async () => {
    const w = await world({ streams: 2 });
    const a = await w.device("a");
    const b = await w.device("b");
    // A publishes `s0` only. `s1` is declared by the manifest and no run covers it.
    await a.run("run-a", [{ stream: sName(0), id: "1" }], {
      covered: [sName(0)],
    });
    await a.cycle();
    await b.cycle();
    expect(await b.sync.declarations.streamsOf(CONNECTOR)).toEqual([sName(0)]);

    await a.sync.deleter.requestConnectionDelete(CONNECTOR);
    expect(await a.sync.deleter.resumeDeletes()).toEqual([]);

    // B holds no record of `s1` and has not applied the delete.
    await expect(
      b.run("run-b", [{ stream: NEVER_PUBLISHED, id: "late" }]),
    ).rejects.toMatchObject({ message: "connection_stopped" });
    // The refused begin read the registry and applied the delete.
    await b.cycle();
    expect(await b.records()).toEqual([]);
    expect(await a.records()).toEqual([]);
    // Nothing was written for the stream: the log row and the control row are
    // the only registry rows, and the log row has its one pre-delete version.
    expect([...w.gateway.versions.keys()].sort()).toEqual([CONTROL, LOG]);
    expect(w.gateway.versions.get(LOG)).toHaveLength(1);
  });

  describe("a run that began before the delete and ends after it", () => {
    const setup = async () => {
      const w = await world({ streams: 2 });
      const a = await w.device("a");
      const b = await w.device("b");
      await a.run("run-a", [{ stream: sName(0), id: "1" }], {
        covered: [sName(0)],
      });
      await a.cycle();
      await b.cycle();
      // B is collecting `s1` and has staged a record for it.
      await b.sync.intake.begin("run-b", request(5000));
      await b.sync.intake.batch("run-b", {
        batch: 0,
        records: [{ stream: NEVER_PUBLISHED, data: { id: "late" } }],
      });
      const end = () =>
        b.sync.intake.end(
          "run-b",
          endRequest({
            lastBatch: 0,
            streams: [NEVER_PUBLISHED],
            live: [NEVER_PUBLISHED],
            provenFullStreams: [NEVER_PUBLISHED],
          }),
        );
      // The control row as the registry holds it now, before any delete. This
      // is read from the fake gateway's store, not from the code under test.
      const controlRows = w.gateway.versions.get(CONTROL)!;
      const head = controlRows[controlRows.length - 1]!;
      const observed = {
        scope: CONTROL,
        expectedVersion: String(controlRows.length),
        notDeleted: true,
        expectedDataHash: head.dataHash,
      };
      const logPublishes = (from: number) =>
        w.gateway.calls
          .slice(from)
          .filter((call) => call.kind === "batch")
          .filter((call) =>
            call.body.rows.some((row) => String(row.scope).includes("~log")),
          );
      return { w, a, b, end, logPublishes, observed };
    };

    it("publishes when nothing was deleted (positive control)", async () => {
      const { w, a, b, end, logPublishes } = await setup();
      const before = w.gateway.calls.length;
      await end();
      await b.cycle();
      await a.cycle();

      expect(logPublishes(before)).toHaveLength(1);
      expect(w.gateway.versions.get(LOG)).toHaveLength(2);
      expect(await a.records()).toContain(
        `${NEVER_PUBLISHED}/late={"id":"late"}`,
      );
    });

    it("is refused by the gateway's control condition after the delete", async () => {
      const { w, a, b, end, logPublishes, observed } = await setup();
      await a.sync.deleter.requestConnectionDelete(CONNECTOR);
      expect(await a.sync.deleter.resumeDeletes()).toEqual([]);
      const before = w.gateway.calls.length;

      await end();
      await b.cycle();

      // B did attempt the publish. It named the control row with the whole
      // condition: the version and data hash the registry held when B began.
      const attempts = logPublishes(before);
      expect(attempts).toHaveLength(1);
      expect(attempts[0]?.body.requires).toEqual([observed]);
      // The gateway refused it: no new log version, nothing written for `s1`.
      expect(w.gateway.versions.get(LOG)).toHaveLength(1);
      expect([...w.gateway.versions.keys()].sort()).toEqual([CONTROL, LOG]);
      expect(await b.records()).toEqual([]);
      await a.cycle();
      expect(await a.records()).toEqual([]);
    });

    it("is refused after the connection is deleted and connected again before the commit", async () => {
      const { w, a, b, end, logPublishes, observed } = await setup();
      await a.sync.deleter.requestConnectionDelete(CONNECTOR);
      expect(await a.sync.deleter.resumeDeletes()).toEqual([]);
      // The connection is connected again: a new lifetime begins on the same
      // control row, so the row is no longer deleted.
      const reconnect = await a.sync.intake.begin("reconnect", connect(6000));
      expect(reconnect.status).toBe("collecting");
      await a.sync.intake.abort("reconnect", "cancelled");
      const controlRows = w.gateway.versions.get(CONTROL)!;
      const head = controlRows[controlRows.length - 1]!;
      // Setup: the delete and the reconnect each wrote a control version, and
      // the head carries the same data hash as the one B observed. Of the
      // condition's three parts only the version can now refuse the old run.
      expect(controlRows).toHaveLength(Number(observed.expectedVersion) + 2);
      expect(head.dataHash).toBe(observed.expectedDataHash);
      const logVersions = w.gateway.versions.get(LOG)!.length;
      const before = w.gateway.calls.length;

      await end();
      await b.cycle();

      const attempts = logPublishes(before);
      expect(attempts).toHaveLength(1);
      expect(attempts[0]?.body.requires).toEqual([observed]);
      // The old lifetime's publish is refused: no new log version, no record.
      expect(w.gateway.versions.get(LOG)).toHaveLength(logVersions);
      expect(await b.records()).toEqual([]);
      await a.cycle();
      expect(await a.records()).toEqual([]);
    });
  });

  it("is refused after a connection that never published anything is deleted", async () => {
    const w = await world({ streams: 2 });
    const a = await w.device("a");
    const b = await w.device("b");
    await a.run("run-a", [], { covered: [] });
    await a.cycle();
    await b.cycle();
    // No run published: the registry holds the control row only.
    expect([...w.gateway.versions.keys()]).toEqual([CONTROL]);

    await a.sync.deleter.requestConnectionDelete(CONNECTOR);
    expect(await a.sync.deleter.resumeDeletes()).toEqual([]);

    await expect(
      b.run("run-b", [{ stream: NEVER_PUBLISHED, id: "late" }]),
    ).rejects.toMatchObject({ message: "connection_stopped" });
    await b.cycle();
    expect(await b.records()).toEqual([]);
  });
});

/**
 * A device that never held the connector's manifest can delete the connection.
 * Delete planning reads the registry's control rows and nothing else, so it
 * needs no list of streams from the host.
 */
describe("a connection deleted from a device that never held it", () => {
  it("lands the fence for a connection that never published, and refuses the creator's later run", async () => {
    const w = await world({ streams: 2 });
    const a = await w.device("a");
    const b = await w.device("b");
    // A connects and its first run covers nothing: no log row, no stream row.
    await a.run("run-a", [], { covered: [] });
    await a.cycle();
    expect([...w.gateway.versions.keys()]).toEqual([CONTROL]);

    // B has applied nothing: no connection, no stream row, no manifest.
    expect(await b.db.query("SELECT 1 FROM connections")).toEqual([]);
    const request = await b.sync.deleter.requestConnectionDelete(CONNECTOR);
    expect(request.fenced).toBe(true);
    expect(await b.sync.deleter.resumeDeletes()).toEqual([]);

    // The control tombstone is the only registry write.
    expect([...w.gateway.versions.keys()]).toEqual([CONTROL]);
    expect(w.gateway.versions.get(CONTROL)).toHaveLength(2);

    // A has not applied the delete. Its next run is refused at admission.
    await expect(
      a.run("run-a2", [{ stream: NEVER_PUBLISHED, id: "late" }]),
    ).rejects.toMatchObject({ message: "connection_stopped" });
    await a.cycle();
    expect(await a.records()).toEqual([]);
    expect(await b.records()).toEqual([]);
    expect([...w.gateway.versions.keys()]).toEqual([CONTROL]);
    expect(w.gateway.versions.get(CONTROL)).toHaveLength(2);
  });
});

/**
 * What a second device lacks. The writing device keeps a `stream_state` row for
 * every stream its manifest declares; a replica gets one only from a segment
 * that touched the stream, and a segment is written for a stream a run covers.
 * So a stream no run covered is named on the writer and not on the replica.
 * This pins today's behavior as a characterisation, not a wish: if a replica
 * ever learns such a stream, this test fails and its expectation changes with
 * the decision. Each precondition below can fail on its own.
 */
it("a second device names only the streams a run covered", async () => {
  const w = await world({ streams: 2 });
  const a = await w.device("a");
  const b = await w.device("b");
  await a.run("run-a", [{ stream: sName(0), id: "1" }], {
    covered: [sName(0)],
  });
  await a.cycle();
  await b.cycle();

  // Setup: the run published, and B applied it.
  expect(w.gateway.versions.get(LOG)).toHaveLength(1);
  expect(await b.records()).toEqual(await a.records());
  expect(await b.records()).toHaveLength(1);
  // Writer: A names both manifest streams, one of them never covered.
  expect(await a.sync.declarations.streamsOf(CONNECTOR)).toEqual([
    sName(0),
    NEVER_PUBLISHED,
  ]);
  // Replica: B names the covered stream only.
  expect(await b.sync.declarations.streamsOf(CONNECTOR)).toEqual([sName(0)]);
});
