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
  finishedOutcome,
  freshConnector,
  interpose,
  readStream,
  startLocalStorage,
  type Backend,
  type OracleEnv,
  type Surface,
} from "./oracle.test-utils.js";

const GATEWAY_URL = process.env.STREAM_SYNC_ORACLE_GATEWAY_URL;
const NS = "";
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
