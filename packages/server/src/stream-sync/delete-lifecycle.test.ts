/**
 * Lane P4 (design 4.1 §2.4, §2.11; PLAN B8): a connection delete on one host
 * stops the others, with no resurrection and no cleanup race.
 *
 * The scenarios use the two-host oracle harness. A delete is the production
 * `StreamSyncWriter.deleteConnection`: it tombstones every control row of the
 * connector at the version it pinned, durably, so a crash resumes the same
 * pins on the next boot.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  controlScope,
  eligible,
  streamScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  activateControl,
  collect,
  createOracleEnv,
  deleteConnection,
  finishedOutcome,
  freshConnector,
  interpose,
  readStream,
  SHAPE,
  startLocalStorage,
  type Backend,
  type OracleEnv,
  type Surface,
} from "./oracle.test-utils.js";

const GATEWAY_URL = process.env.STREAM_SYNC_ORACLE_GATEWAY_URL;
const NS = "";
const NS_OTHER = "0123456789abcdef";
const T0 = Date.UTC(2026, 10, 1);

const backends: Backend[] = GATEWAY_URL ? ["fake", "gateway"] : ["fake"];
const surfaces: Surface[] = ["full", "lite"];
const matrix = backends.flatMap((backend) =>
  surfaces.map((surface) => ({ backend, surface })),
);

const rows = (ids: string[], tag: string) => ids.map((id) => ({ id, n: tag }));

/** A scheduled (not user-initiated) run start, for the `stopped` gate. */
function scheduled(
  writer: { beginRun(input: Record<string, unknown>): Promise<unknown> },
  connector: string,
  runId: string,
) {
  return writer.beginRun({
    runId,
    connector,
    userConnect: false,
    observedAt: T0,
    checkpointUsed: null,
  });
}

describe.each(matrix)(
  "stream-sync P4 delete lifecycle: $surface on $backend",
  ({ backend, surface }) => {
    let storage: Awaited<ReturnType<typeof startLocalStorage>>;
    let env: OracleEnv;

    beforeAll(async () => {
      storage = await startLocalStorage();
      env = await createOracleEnv({
        surface,
        backend,
        storageUrl: storage.url,
        gatewayUrl: GATEWAY_URL,
      });
    });

    afterAll(async () => {
      await env.cleanup();
      await storage.close();
    });

    // S1
    it("delete on one host during a publish on the other: the racing run does not checkpoint, and a reconnect carries only the fresh records", async () => {
      const c = freshConnector("p4-delete-race");
      await activateControl(env.registry, c, NS); // active(1)
      const b = await env.writer("p4-race-b");
      const sScope = streamScope(c, NS, "s");
      let deleted = false;
      const a = await env.writer("p4-race-a", {
        registry: interpose(env.newRegistry(), {
          // A has already admitted at generation 1. B deletes now, before
          // A's stream commit reaches the registry.
          async beforePost(request) {
            if (deleted || request.scope !== sScope) return;
            deleted = true;
            await b.refreshControls();
            await b.deleteConnection(c);
          },
        }),
      });
      await a.refreshControls();
      await collect(a, {
        runId: "race-a",
        connector: c,
        observedAt: T0,
        streams: { s: rows(["1"], "a") },
      });
      await a.publishPending();

      expect(deleted).toBe(true);
      expect(await env.registry.read(controlScope(c, NS))).toMatchObject({
        found: true,
        version: 2,
        deleted: true,
      });
      expect(finishedOutcome(await a.status(), "race-a")?.outcome).not.toEqual({
        kind: "checkpointed",
        generation: 1,
      });

      // Reconnect (active(3)) and a fresh full run: the racing record must
      // not come back, because the base of the new generation is empty.
      await activateControl(env.registry, c, NS);
      await b.refreshControls();
      await collect(b, {
        runId: "fresh",
        connector: c,
        observedAt: T0 + 5000,
        userConnect: true,
        streams: { s: rows(["2"], "b") },
      });
      await b.publishPending();
      const view = await readStream(env.registry, env.blobs, c, NS, "s");
      if (!view || view === "tombstoned") throw new Error("stream missing");
      expect(view.head.generation).toBe(3);
      expect([...view.records.keys()]).toEqual(["2"]);
    });

    // S2
    it("reconnect during cleanup: a resumed delete tombstones only its pinned version and never the reconnect", async () => {
      const c = freshConnector("p4-reconnect-cleanup");
      await activateControl(env.registry, c, NS); // active(1)
      const tombScope = controlScope(c, NS);
      let crashed = false;
      const a = await env.writer("p4-cleanup-a", {
        registry: interpose(env.newRegistry(), {
          // The control tombstone (version 2) commits, then the process dies
          // before the delete's cleanup finishes.
          async afterPost(request) {
            if (crashed || request.scope !== tombScope) return;
            crashed = true;
            throw new Error("crash during cleanup");
          },
        }),
      });
      await a.refreshControls();
      await expect(a.deleteConnection(c)).rejects.toThrow(
        "crash during cleanup",
      );
      expect(await env.registry.read(tombScope)).toMatchObject({
        version: 2,
        deleted: true,
      });

      // Elsewhere: reconnect (active(3)).
      await activateControl(env.registry, c, NS);

      // The rebooted device resumes its delete. It must not tombstone the
      // reconnect at version 4.
      const rebooted = await env.writer("p4-cleanup-a");
      await rebooted.publishPending();
      expect(await env.registry.read(tombScope)).toMatchObject({
        found: true,
        version: 3,
        deleted: false,
      });
    });

    // S3
    it("crash between the delete intent and the tombstones: the next boot resumes and tombstones the connection", async () => {
      const c = freshConnector("p4-intent-crash");
      await activateControl(env.registry, c, NS); // active(1)
      const tombScope = controlScope(c, NS);
      const a = await env.writer("p4-intent-a", {
        registry: interpose(env.newRegistry(), {
          async beforePost(request) {
            if (request.scope === tombScope) {
              throw new Error("crash before tombstone");
            }
          },
        }),
      });
      await a.refreshControls();
      await expect(a.deleteConnection(c)).rejects.toThrow(
        "crash before tombstone",
      );
      expect(await env.registry.read(tombScope)).toMatchObject({
        version: 1,
        deleted: false,
      });

      const booted = await env.writer("p4-intent-a");
      await booted.publishPending();
      expect(await env.registry.read(tombScope)).toMatchObject({
        found: true,
        version: 2,
        deleted: true,
      });
    });

    // S4
    it("stopped survives a restart: scheduled runs refuse until a reconnect is observed, explicit connect is not blocked", async () => {
      const c = freshConnector("p4-stopped");
      await activateControl(env.registry, c, NS); // active(1)
      const a = await env.writer("p4-stopped-a");
      await a.refreshControls();
      await a.deleteConnection(c); // deleted(2), seen here

      const restarted = await env.writer("p4-stopped-a");
      await restarted.refreshControls();
      await expect(scheduled(restarted, c, "sched-1")).rejects.toThrow(
        /stopped/,
      );

      // A second restart, no refresh: the stop is durable.
      const again = await env.writer("p4-stopped-a");
      await expect(scheduled(again, c, "sched-2")).rejects.toThrow(/stopped/);

      // Reconnect elsewhere (active(3)) is observed: the stop clears.
      await activateControl(env.registry, c, NS);
      await again.refreshControls();
      await expect(scheduled(again, c, "sched-3")).resolves.toBeDefined();
    });

    // R1 (review P1, Q2): a resume that fails holds only its own connector.
    it("a failed resume holds only its connector: another connector still publishes, and the resume is retried on the next pass", async () => {
      const c = freshConnector("p4r2-resume-fail");
      const other = freshConnector("p4r2-resume-other");
      await activateControl(env.registry, c, NS);
      await activateControl(env.registry, other, NS);
      const tombScope = controlScope(c, NS);
      const crashing = await env.writer("p4r2-resume-a", {
        registry: interpose(env.newRegistry(), {
          async beforePost(request) {
            if (request.scope === tombScope) throw new Error("crash first");
          },
        }),
      });
      await crashing.refreshControls();
      await expect(crashing.deleteConnection(c)).rejects.toThrow("crash first");

      let down = true;
      const booted = await env.writer("p4r2-resume-a", {
        registry: interpose(env.newRegistry(), {
          async beforePost(request) {
            if (down && request.scope === tombScope) {
              throw new Error("still down");
            }
          },
        }),
      });
      await booted.refreshControls();
      await collect(booted, {
        runId: "p4r2-other",
        connector: other,
        observedAt: T0,
        streams: { s: rows(["1"], "other") },
      });
      await expect(booted.publishPending()).resolves.toBeDefined();
      const otherView = await readStream(
        env.registry,
        env.blobs,
        other,
        NS,
        "s",
      );
      if (!otherView || otherView === "tombstoned") {
        throw new Error("the other connector did not publish");
      }
      expect([...otherView.records.keys()]).toEqual(["1"]);

      down = false;
      await booted.publishPending();
      expect(await env.registry.read(tombScope)).toMatchObject({
        found: true,
        version: 2,
        deleted: true,
      });
    });

    // R2 (review P2-1): an explicit connect finishes a pending delete first.
    it("an explicit connect with a pending delete finishes the delete, then reconnects; a later boot does not delete the new connection", async () => {
      const c = freshConnector("p4r2-connect-pending");
      await activateControl(env.registry, c, NS); // active(1)
      const tombScope = controlScope(c, NS);
      let down = true;
      const a = await env.writer("p4r2-connect-a", {
        registry: interpose(env.newRegistry(), {
          async beforePost(request) {
            if (down && request.scope === tombScope) throw new Error("offline");
          },
        }),
      });
      await a.refreshControls();
      await expect(a.deleteConnection(c)).rejects.toThrow("offline");

      down = false;
      await collect(a, {
        runId: "p4r2-connect",
        connector: c,
        observedAt: T0,
        userConnect: true,
        streams: { s: rows(["9"], "new") },
      });
      await a.publishPending();

      const boot = await env.writer("p4r2-connect-a");
      await boot.publishPending();
      expect(await env.registry.read(tombScope)).toMatchObject({
        found: true,
        version: 3,
        deleted: false,
      });
    });

    // R3 (review P2-2): a delete decided from a stale listing must not be a silent no-op.
    it("a delete decided from a stale listing lands on the current row: the connection is deleted, not left active", async () => {
      const c = freshConnector("p4r2-stale-listing");
      await activateControl(env.registry, c, NS); // active(1)
      const stale = await env.registry.listControlRows();
      await deleteConnection(env.registry, c, NS, []); // deleted(2)
      await activateControl(env.registry, c, NS); // active(3), reconnected elsewhere
      const a = await env.writer("p4r2-stale-a", {
        registry: { ...env.newRegistry(), listControlRows: async () => stale },
      });
      await a.deleteConnection(c);
      expect(await env.registry.read(controlScope(c, NS))).toMatchObject({
        found: true,
        version: 4,
        deleted: true,
      });
    });

    // R4 (review P3-1): a deleted namespace does not stop the active one.
    it("a deleted row in another namespace does not stop scheduled runs of the identity-less namespace", async () => {
      const c = freshConnector("p4r2-ns-isolation");
      await activateControl(env.registry, c, NS);
      await activateControl(env.registry, c, NS_OTHER);
      await deleteConnection(env.registry, c, NS_OTHER, []);
      const a = await env.writer("p4r2-ns-a");
      await a.refreshControls();
      await expect(scheduled(a, c, "sched-ns")).resolves.toBeDefined();
    });

    // R5 (review P3-2): an explicit connect right after the device's own delete.
    it("an explicit connect right after this device's own delete is accepted, without a listing in between", async () => {
      const c = freshConnector("p4r2-connect-after-delete");
      await activateControl(env.registry, c, NS); // active(1)
      const a = await env.writer("p4r2-after-a");
      await a.refreshControls();
      await a.deleteConnection(c); // deleted(2)
      await collect(a, {
        runId: "p4r2-after-connect",
        connector: c,
        observedAt: T0,
        userConnect: true,
        streams: { s: rows(["1"], "n") },
      });
      await a.publishPending();
      expect(await env.registry.read(controlScope(c, NS))).toMatchObject({
        found: true,
        version: 3,
        deleted: false,
      });
    });

    // S4b (review m8): a user connect on a stopped connector reconnects; a second device that saw the delete is stopped until then.
    it("a second device stays stopped until the explicit connect reconnects, then runs again", async () => {
      const c = freshConnector("p4r2-second-device");
      await activateControl(env.registry, c, NS); // active(1)
      const first = await env.writer("p4r2-second-a");
      await first.refreshControls();
      await first.deleteConnection(c); // deleted(2)

      const second = await env.writer("p4r2-second-b");
      await second.refreshControls();
      await expect(scheduled(second, c, "sched-b1")).rejects.toThrow(/stopped/);

      await first.refreshControls();
      await collect(first, {
        runId: "p4r2-second-connect",
        connector: c,
        observedAt: T0,
        userConnect: true,
        streams: { s: rows(["5"], "again") },
      });
      await first.publishPending();

      await second.refreshControls();
      await expect(scheduled(second, c, "sched-b2")).resolves.toBeDefined();
    });

    // R7 (owinteg #567 gap): a run collected before a deletion must neither
    // stay readable nor publish after it, whether it is still in flight or
    // already finished locally.
    it("a run collected before a scope delete: nothing deleted is readable or published by the next publish cycle", async () => {
      const c = freshConnector("p4r2-purge-pending");
      await activateControl(env.registry, c, NS); // active(1)
      const a = await env.writer("p4r2-purge-a");
      await a.refreshControls();
      // In flight: begun and appended, never finished.
      await a.beginRun({
        runId: "p4r2-purge-inflight",
        connector: c,
        userConnect: false,
        observedAt: T0,
        identity: "none",
        checkpointUsed: null,
      });
      await a.declareStream("p4r2-purge-inflight", "s", SHAPE);
      await a.append("p4r2-purge-inflight", "s", { id: "1", n: "inflight" });
      // Finished locally, not yet published.
      await collect(a, {
        runId: "p4r2-purge-finished",
        connector: c,
        observedAt: T0 + 1000,
        streams: { s: rows(["2"], "finished") },
      });
      await a.deleteConnection(c); // deleted(2)
      // The in-flight run finishes after the delete, then a publish cycle runs.
      await a.finishRun("p4r2-purge-inflight", {
        checkpointCandidate: { cursor: "x" },
      });
      await a.publishPending();
      await a.publishPending();

      const view = await readStream(env.registry, env.blobs, c, NS, "s");
      expect(view === null || view === "tombstoned").toBe(true);
      expect(
        finishedOutcome(await a.status(), "p4r2-purge-finished")?.outcome,
      ).not.toMatchObject({ kind: "checkpointed" });
      expect(
        finishedOutcome(await a.status(), "p4r2-purge-inflight")?.outcome,
      ).not.toMatchObject({ kind: "checkpointed" });
    });

    // R6 (review P2-2): a fresh delete overtaken by a reconnect fails typed, not silently.
    it("a fresh delete overtaken by a reconnect before it reads back fails with ConnectionDeleteSuperseded", async () => {
      const c = freshConnector("p4r2-superseded");
      await activateControl(env.registry, c, NS); // active(1)
      const tombScope = controlScope(c, NS);
      let overtaken = false;
      const a = await env.writer("p4r2-superseded-a", {
        registry: interpose(env.newRegistry(), {
          async afterPost(request) {
            if (overtaken || request.scope !== tombScope) return;
            overtaken = true;
            await activateControl(env.registry, c, NS); // active(3) lands first
          },
        }),
      });
      await a.refreshControls();
      await expect(a.deleteConnection(c)).rejects.toMatchObject({
        name: "ConnectionDeleteSuperseded",
      });
      expect(overtaken).toBe(true);
    });

    // S6: a run collected before the delete publishes nothing after it.
    it("a run collected before the delete publishes nothing once the delete has landed", async () => {
      const c = freshConnector("p4r2-collecting-run");
      await activateControl(env.registry, c, NS); // active(1)
      const a = await env.writer("p4r2-collecting-a");
      await a.refreshControls();
      await a.beginRun({
        runId: "p4r2-collecting",
        connector: c,
        userConnect: false,
        observedAt: T0,
        identity: "none",
        checkpointUsed: null,
      });
      await a.declareStream("p4r2-collecting", "s", SHAPE);
      await a.append("p4r2-collecting", "s", { id: "1", n: "early" });
      await a.deleteConnection(c); // deleted(2)
      await a.finishRun("p4r2-collecting", {
        checkpointCandidate: { cursor: "x" },
      });
      await a.publishPending();
      const view = await readStream(env.registry, env.blobs, c, NS, "s");
      expect(view === null || view === "tombstoned").toBe(true);
    });

    // S5
    it("an old-install legacy write after a delete stays hidden", () => {
      const deletedConnection = {
        ns: NS,
        control: { kind: "deleted", version: 2 } as const,
        latestHeadRegistration: null,
        streams: {},
      };
      expect(
        eligible({
          connections: [deletedConnection],
          target: { kind: "logical", streams: ["s"] },
          legacyFile: true,
        }),
      ).toEqual({ kind: "unavailable", reason: "deleted" });
    });
  },
);
