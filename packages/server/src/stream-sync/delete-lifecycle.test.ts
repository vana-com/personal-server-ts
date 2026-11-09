/**
 * Lane P4 (design 4.1 §2.4, §2.11; PLAN B8): a connection delete on one host
 * stops the others, with no resurrection and no cleanup race.
 *
 * The scenarios use the two-host oracle harness. A delete is the production
 * `StreamSyncWriter.deleteConnection`: it tombstones every control row of the
 * connector at the version it pinned, durably, so a crash resumes the same
 * pins on the next boot.
 */

import { mkdir, mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { join, relative } from "node:path";
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
  foreignControl,
  freshConnector,
  interpose,
  oldDelete,
  readStream,
  SHAPE,
  type StreamView,
  startLocalStorage,
  type Backend,
  type OracleEnv,
  type Surface,
} from "./oracle.test-utils.js";
import { createFsStreamSyncFiles } from "./fs-files.js";

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

/**
 * Every file under `dir` whose path or bytes contain a needle. Bytes are read
 * as latin1 so a binary file is searched as well as a text one.
 */
async function leftoverFiles(
  dir: string,
  needles: string[],
): Promise<string[]> {
  const found: string[] = [];
  const walk = async (current: string): Promise<void> => {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) {
        await walk(path);
        continue;
      }
      const rel = relative(dir, path);
      const text = (await readFile(path)).toString("latin1");
      if (needles.some((n) => rel.includes(n) || text.includes(n))) {
        found.push(rel);
      }
    }
  };
  await walk(dir);
  return found;
}

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
      await expect(
        a.finishRun("p4r2-purge-inflight", {
          checkpointCandidate: { cursor: "x" },
        }),
      ).rejects.toThrow(/gone/);
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
      // The delete purged the run: it is gone and cannot finish.
      await expect(
        a.finishRun("p4r2-collecting", {
          checkpointCandidate: { cursor: "x" },
        }),
      ).rejects.toThrow(/gone/);
      await a.publishPending();
      const view = await readStream(env.registry, env.blobs, c, NS, "s");
      expect(view === null || view === "tombstoned").toBe(true);
    });

    // L11 (ruling M3): an old install's non-exclusive DELETE tombstones one
    // stream row. An unobserved delete discards the next incremental run and
    // clears its checkpoint; the full re-collection ends complete.
    it("L11: an old DELETE tombstones one stream row; the next run is full and the head ends complete", async () => {
      const c = freshConnector("p4r2-l11-full");
      await activateControl(env.registry, c, NS); // control active(1)
      const scope = streamScope(c, NS, "s");
      const d = await env.writer("p4r2-l11-full-d");
      await d.refreshControls();
      await collect(d, {
        runId: "p4r2-l11-full-0",
        connector: c,
        observedAt: T0,
        streams: { s: rows(["r1", "r2", "r3"], "base") },
      });
      await d.publishPending();
      await oldDelete(env, scope); // L11: the stream row is tombstoned

      // Incremental run from the old checkpoint, publishing onto the tombstone.
      await d.refreshControls();
      await collect(d, {
        runId: "p4r2-l11-full-1",
        connector: c,
        observedAt: T0 + 1000,
        checkpointUsed: { ns: NS, generation: 1 },
        streams: { s: rows(["r4"], "incremental") },
      });
      const discarded = await d.publishPending();
      expect(
        discarded.runs.find((r) => r.runId === "p4r2-l11-full-1")?.outcome,
      ).toMatchObject({
        kind: "discarded",
        clearCheckpoints: true,
        restartFull: true,
      });
      expect(await readStream(env.registry, env.blobs, c, NS, "s")).toBe(
        "tombstoned",
      );
      expect((await d.issueStart(c, false)).start.collectionMode).toBe(
        "full_refresh",
      );

      // The next run is full: it re-collects everything upstream returns.
      await d.refreshControls();
      await collect(d, {
        runId: "p4r2-l11-full-2",
        connector: c,
        observedAt: T0 + 2000,
        checkpointUsed: null,
        streams: { s: rows(["r1", "r2", "r3", "r4"], "full") },
      });
      await d.publishPending();
      const view = await readStream(env.registry, env.blobs, c, NS, "s");
      expect(view).not.toBeNull();
      expect(view).not.toBe("tombstoned");
      expect((view as StreamView).head.complete).toBe(true);
      expect([...(view as StreamView).records.keys()].sort()).toEqual([
        "r1",
        "r2",
        "r3",
        "r4",
      ]);
    });

    // L11, late arrival: a partial run started before the tombstone publishes
    // after the relive. The head must stay complete and keep the relive's rows.
    it("L11: an old partial run published after the relive leaves the head complete and keeps the relive's rows", async () => {
      const c = freshConnector("p4r2-l11-late");
      await activateControl(env.registry, c, NS); // control active(1)
      const scope = streamScope(c, NS, "s");
      const old = await env.writer("p4r2-l11-late-old");
      await old.refreshControls();
      await collect(old, {
        runId: "p4r2-l11-late-old",
        connector: c,
        observedAt: T0,
        checkpointUsed: { ns: NS, generation: 1 },
        streams: { s: rows(["o1"], "old") },
      });
      await oldDelete(env, scope); // the stream row is tombstoned
      const relive = await env.writer("p4r2-l11-late-relive");
      await relive.refreshControls();
      await collect(relive, {
        runId: "p4r2-l11-late-relive",
        connector: c,
        observedAt: T0 + 1000,
        streams: { s: rows(["r1", "r2"], "relive") },
      });
      const first = await relive.publishPending();
      expect(first.runs[0]?.outcome?.kind).toBe("discarded");
      await collect(relive, {
        runId: "p4r2-l11-late-recollect",
        connector: c,
        observedAt: T0 + 2000,
        streams: { s: rows(["r1", "r2"], "relive") },
      });
      await relive.publishPending();
      const stale = await old.publishPending();
      expect(stale.runs[0]?.outcome?.kind).toBe("discarded");

      const view = await readStream(env.registry, env.blobs, c, NS, "s");
      expect(view).not.toBeNull();
      expect(view).not.toBe("tombstoned");
      expect((view as StreamView).head.complete).toBe(true);
      expect([...(view as StreamView).records.keys()]).toEqual(
        expect.arrayContaining(["r1", "r2"]),
      );
    });

    // S1-stream, no relive: a stream row tombstoned after collect and not
    // written again. The old run must not publish over the tombstone.
    it("collect, tombstone stream row, publish: nothing from the old run is readable or published", async () => {
      const c = freshConnector("p4r2-stream-tomb-only");
      await activateControl(env.registry, c, NS); // control active(1)
      const scope = streamScope(c, NS, "s");
      const a = await env.writer("p4r2-stream-tomb-only-a");
      await a.refreshControls();
      await collect(a, {
        runId: "p4r2-stream-tomb-only-old",
        connector: c,
        observedAt: T0,
        streams: { s: rows(["1"], "old") },
      });
      await oldDelete(env, scope); // the stream row is tombstoned
      await a.publishPending();

      const view = await readStream(env.registry, env.blobs, c, NS, "s");
      expect(view === null || view === "tombstoned").toBe(true);
      expect(
        finishedOutcome(await a.status(), "p4r2-stream-tomb-only-old")?.outcome,
      ).not.toMatchObject({ kind: "checkpointed" });
    });

    // Guard for the stream-row stamp: a second run of the same connector,
    // collected before the first publishes, is an ordinary overlay and not a
    // delete. Both runs publish and neither is lost.
    it("two runs of one connector collected before either publishes: both publish, neither is lost", async () => {
      const c = freshConnector("p4r2-two-runs");
      await activateControl(env.registry, c, NS); // control active(1)
      const a = await env.writer("p4r2-two-runs-a");
      await a.refreshControls();
      await collect(a, {
        runId: "p4r2-two-first",
        connector: c,
        observedAt: T0,
        streams: { s: rows(["1"], "first") },
      });
      await collect(a, {
        runId: "p4r2-two-second",
        connector: c,
        observedAt: T0 + 1000,
        streams: { s: rows(["2"], "second") },
      });
      await a.publishPending();
      await a.publishPending();

      const view = await readStream(env.registry, env.blobs, c, NS, "s");
      expect(view).not.toBeNull();
      expect(view).not.toBe("tombstoned");
      expect([...(view as StreamView).records.keys()].sort()).toEqual([
        "1",
        "2",
      ]);
      for (const runId of ["p4r2-two-first", "p4r2-two-second"]) {
        expect(finishedOutcome(await a.status(), runId)?.outcome).toMatchObject(
          { kind: "checkpointed" },
        );
      }
    });

    // R8 (item 1): after a delete and a pass, no file of the scope remains.
    it("collect, delete, run a pass: no file of that scope remains under the home", async () => {
      const c = freshConnector("p4r2-purge-files");
      await activateControl(env.registry, c, NS); // active(1)
      const tmpParent = join(homedir(), ".tmp");
      await mkdir(tmpParent, { recursive: true });
      const root = await mkdtemp(join(tmpParent, "p4r2-purge-"));
      try {
        const a = await env.writer("p4r2-purge-device", {
          files: createFsStreamSyncFiles(join(root, "home")),
        });
        await a.refreshControls();
        await collect(a, {
          runId: "purge-done",
          connector: c,
          observedAt: T0,
          streams: { s: rows(["PURGE-DONE-MARKER"], "done") },
        });
        await a.beginRun({
          runId: "purge-inflight",
          connector: c,
          userConnect: false,
          observedAt: T0 + 1000,
          identity: "none",
          checkpointUsed: null,
        });
        await a.declareStream("purge-inflight", "s", SHAPE);
        await a.append("purge-inflight", "s", { id: "PURGE-INFLIGHT-MARKER" });
        await a.deleteConnection(c); // deleted(2)
        await a.publishPending();
        expect(
          await leftoverFiles(join(root, "home"), [
            "purge-done",
            "purge-inflight",
            "PURGE-DONE-MARKER",
            "PURGE-INFLIGHT-MARKER",
          ]),
        ).toEqual([]);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });

    // R9 (m6): a resumed delete whose tombstone version a reconnect took resolves without throwing.
    it("a resumed delete whose tombstone version a reconnect took resolves without throwing, and the reconnect stays active", async () => {
      const c = freshConnector("p4r2-conflict");
      await activateControl(env.registry, c, NS); // active(1)
      const tombScope = controlScope(c, NS);
      const crashing = await env.writer("p4r2-conflict-a", {
        registry: interpose(env.newRegistry(), {
          async beforePost(request) {
            if (request.scope === tombScope) throw new Error("crash first");
          },
        }),
      });
      await crashing.refreshControls();
      await expect(crashing.deleteConnection(c)).rejects.toThrow("crash first");
      await activateControl(env.registry, c, NS); // active(2): the reconnect takes pin+1

      const booted = await env.writer("p4r2-conflict-a");
      // The conflicting tombstone post is not an error: the resume finishes
      // without reporting the connector as a pending delete.
      await expect(booted.publishPending()).resolves.toMatchObject({
        deletesPending: [],
      });
      expect(await env.registry.read(tombScope)).toMatchObject({
        found: true,
        version: 2,
        deleted: false,
      });
      await expect(booted.publishPending()).resolves.toBeDefined();
    });

    // R10 (m3): two namespaces; the resume finishes every pin, not only the first.
    it("a delete of two namespaces that fails after the first pin is finished for both by the resume", async () => {
      const c = freshConnector("p4r2-multi-pin");
      await activateControl(env.registry, c, NS);
      await activateControl(env.registry, c, NS_OTHER);
      let crashed = false;
      const a = await env.writer("p4r2-multi-a", {
        registry: interpose(env.newRegistry(), {
          async afterPost(request) {
            if (crashed || !request.scope.startsWith(controlScope(c, "")))
              return;
            crashed = true;
            throw new Error("crash after one pin");
          },
        }),
      });
      await a.refreshControls();
      await expect(a.deleteConnection(c)).rejects.toThrow(
        "crash after one pin",
      );

      const booted = await env.writer("p4r2-multi-a");
      await booted.publishPending();
      expect(await env.registry.read(controlScope(c, NS))).toMatchObject({
        deleted: true,
      });
      expect(await env.registry.read(controlScope(c, NS_OTHER))).toMatchObject({
        deleted: true,
      });
    });

    // R11 (m4): a foreign control row of the connector is pinned and tombstoned with the rest.
    it("a foreign control row of the connector is tombstoned with the connector's other rows", async () => {
      const c = freshConnector("p4r2-foreign-pin");
      await activateControl(env.registry, c, NS); // active(1)
      await foreignControl(env.registry, c, NS_OTHER); // foreign(1)
      const a = await env.writer("p4r2-foreign-a");
      await a.refreshControls();
      await a.deleteConnection(c);
      expect(await env.registry.read(controlScope(c, NS))).toMatchObject({
        version: 2,
        deleted: true,
      });
      expect(await env.registry.read(controlScope(c, NS_OTHER))).toMatchObject({
        version: 2,
        deleted: true,
      });
    });

    // R12 (m5): two connectors with open deletes; a resume that still fails for one does not hold the other.
    it("two connectors with open deletes: the one still failing is reported and does not hold the other", async () => {
      const one = freshConnector("p4r2-two-a");
      const two = freshConnector("p4r2-two-b");
      await activateControl(env.registry, one, NS);
      await activateControl(env.registry, two, NS);
      let blockOne = true;
      let blockTwo = true;
      const a = await env.writer("p4r2-two-device", {
        registry: interpose(env.newRegistry(), {
          async beforePost(request) {
            if (blockOne && request.scope === controlScope(one, NS)) {
              throw new Error("one down");
            }
            if (blockTwo && request.scope === controlScope(two, NS)) {
              throw new Error("two down");
            }
          },
        }),
      });
      await a.refreshControls();
      await expect(a.deleteConnection(one)).rejects.toThrow("one down");
      await expect(a.deleteConnection(two)).rejects.toThrow("two down");

      blockOne = false;
      const report = await a.publishPending();
      expect(report.deletesPending.map((p) => p.connector)).toEqual([two]);
      expect(await env.registry.read(controlScope(one, NS))).toMatchObject({
        deleted: true,
      });
      expect(await env.registry.read(controlScope(two, NS))).toMatchObject({
        deleted: false,
      });

      blockTwo = false;
      await a.publishPending();
      expect(await env.registry.read(controlScope(two, NS))).toMatchObject({
        deleted: true,
      });
    });

    // R13: delete, reconnect, delete, reconnect: each lands at its own version; only the last generation's records show.
    it("delete, reconnect, delete, reconnect: each lands at its own version and only the last generation's records are visible", async () => {
      const c = freshConnector("p4r2-twice");
      await activateControl(env.registry, c, NS); // active(1)
      const a = await env.writer("p4r2-twice-a");
      await a.refreshControls();
      await a.deleteConnection(c); // deleted(2)
      await activateControl(env.registry, c, NS); // active(3)
      await a.refreshControls();
      await collect(a, {
        runId: "twice-1",
        connector: c,
        observedAt: T0,
        userConnect: true,
        streams: { s: rows(["old"], "gen3") },
      });
      await a.publishPending();

      await a.deleteConnection(c); // deleted(4)
      await activateControl(env.registry, c, NS); // active(5)
      await a.refreshControls();
      await collect(a, {
        runId: "twice-2",
        connector: c,
        observedAt: T0 + 10000,
        userConnect: true,
        streams: { s: rows(["new"], "gen5") },
      });
      await a.publishPending();

      expect(await env.registry.read(controlScope(c, NS))).toMatchObject({
        version: 5,
        deleted: false,
      });
      const view = await readStream(env.registry, env.blobs, c, NS, "s");
      if (!view || view === "tombstoned") throw new Error("stream missing");
      expect([...view.records.keys()]).toEqual(["new"]);
    });

    // R14: a stream first written by a run collected before the delete never appears.
    it("a stream first written by a run collected before the delete never appears after it", async () => {
      const c = freshConnector("p4r2-first-stream");
      await activateControl(env.registry, c, NS); // active(1)
      const a = await env.writer("p4r2-first-a");
      await a.refreshControls();
      await collect(a, {
        runId: "first-stream",
        connector: c,
        observedAt: T0,
        streams: { brandnew: rows(["1"], "new") },
      });
      await a.deleteConnection(c); // deleted(2)
      await a.publishPending();
      const view = await readStream(env.registry, env.blobs, c, NS, "brandnew");
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
