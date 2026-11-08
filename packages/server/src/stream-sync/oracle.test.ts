/**
 * Lane P1 oracle (§5.2): the stream-sync writer on the full-server and Lite
 * file adapters, with the production storage and registry adapters.
 *
 * Every case runs against an in-memory registry with the gateway's
 * exclusive-version rules. With `STREAM_SYNC_ORACLE_GATEWAY_URL` set, every
 * case also runs against that data-gateway (real Postgres). The gateway must
 * know the server key of `SERVER_KEY` as a registered server of `OWNER`.
 */

import { writeFile } from "node:fs/promises";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  AmbiguousRegistryReplyError,
  type StreamSyncFaultPoint,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  canonicalJson,
  controlScope,
  FRAME_PIECE_BYTES,
  streamScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  activateControl,
  collect,
  createOracleEnv,
  deleteConnection,
  finishedOutcome,
  fixedSeed,
  freshConnector,
  interpose,
  oldDelete,
  readStream,
  startLocalStorage,
  type Backend,
  type OracleEnv,
  type Surface,
} from "./oracle.test-utils.js";

const GATEWAY_URL = process.env.STREAM_SYNC_ORACLE_GATEWAY_URL;
const REPORT = process.env.STREAM_SYNC_ORACLE_REPORT;
const NS = "";
const T0 = Date.UTC(2026, 10, 1);

const backends: Backend[] = GATEWAY_URL ? ["fake", "gateway"] : ["fake"];
const surfaces: Surface[] = ["full", "lite"];
const matrix = backends.flatMap((backend) =>
  surfaces.map((surface) => ({ backend, surface })),
);

const report: Record<string, unknown> = {};

const rows = (ids: string[], tag: string) => ids.map((id) => ({ id, n: tag }));

const MiB = 1024 * 1024;

/** A record whose canonical JSON body is exactly `bodyBytes` bytes long. */
function recordOfBodyBytes(
  id: string,
  bodyBytes: number,
  filler = "a",
): { id: string; pad: string } {
  const shell = canonicalJson({ id, pad: "" }).length;
  return { id, pad: filler.repeat(bodyBytes - shell) };
}

describe.each(matrix)(
  "stream-sync oracle: $surface on $backend",
  ({ backend, surface }) => {
    let storage: Awaited<ReturnType<typeof startLocalStorage>>;
    let env: OracleEnv;
    const note = (name: string, value: unknown) => {
      report[`${surface}/${backend}/${name}`] = value;
    };

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

    it("two concurrent writers: one commits per version, the other re-overlays and commits next", async () => {
      const c = freshConnector("concurrent");
      const a = await env.writer("concurrent-a");
      const b = await env.writer("concurrent-b");
      await a.refreshControls();
      await b.refreshControls();
      await collect(a, {
        runId: "run-a",
        connector: c,
        observedAt: T0,
        streams: { s: rows(["1", "2"], "a") },
      });
      await collect(b, {
        runId: "run-b",
        connector: c,
        observedAt: T0 + 1000,
        streams: { s: rows(["2", "3"], "b") },
      });
      await Promise.all([a.publishPending(), b.publishPending()]);
      const view = await readStream(env.registry, env.blobs, c, NS, "s");
      if (!view || view === "tombstoned") throw new Error("stream missing");
      expect(view.version).toBe(2);
      expect(view.head.generation).toBe(1);
      expect(Object.fromEntries(view.records)).toEqual({
        "1": { id: "1", n: "a" },
        "2": { id: "2", n: "b" },
        "3": { id: "3", n: "b" },
      });
      const control = await env.registry.read(controlScope(c, NS));
      expect(control).toMatchObject({ found: true, version: 1 });
      for (const [w, runId] of [
        [a, "run-a"],
        [b, "run-b"],
      ] as const) {
        expect(finishedOutcome(await w.status(), runId)?.outcome).toEqual({
          kind: "checkpointed",
          generation: 1,
        });
      }
      note("concurrent", {
        streamVersion: view.version,
        controlVersion: 1,
        records: view.records.size,
      });
    });

    it("forced interleaving: the loser gets 409, refetches the winner's head and commits at the next version", async () => {
      const c = freshConnector("race");
      const b = await env.writer("race-b");
      const conflicts: string[] = [];
      let raced = false;
      const a = await env.writer("race-a", {
        registry: interpose(env.newRegistry(), {
          async beforePost(request) {
            if (raced || request.scope !== streamScope(c, NS, "s")) return;
            raced = true;
            await b.publishPending();
          },
          async afterPost(request, result) {
            if (result.kind === "conflict") {
              conflicts.push(
                `${request.expectedVersion}->${result.latestVersion}`,
              );
            }
          },
        }),
      });
      await a.refreshControls();
      await b.refreshControls();
      await collect(a, {
        runId: "run-a",
        connector: c,
        observedAt: T0 + 2000,
        streams: { s: rows(["1", "2"], "a") },
      });
      await collect(b, {
        runId: "run-b",
        connector: c,
        observedAt: T0,
        streams: { s: rows(["2", "3"], "b") },
      });
      await a.publishPending();
      const view = await readStream(env.registry, env.blobs, c, NS, "s");
      if (!view || view === "tombstoned") throw new Error("stream missing");
      expect(conflicts).toEqual(["1->1"]);
      expect(view.version).toBe(2);
      expect(Object.fromEntries(view.records)).toEqual({
        "1": { id: "1", n: "a" },
        "2": { id: "2", n: "a" },
        "3": { id: "3", n: "b" },
      });
      note("race", { conflicts, streamVersion: view.version });
    });

    const faultPoints: StreamSyncFaultPoint[] = [
      "after_control_write",
      "after_parts_upload",
      "after_head_upload",
      "after_request_persisted",
      "after_post_reply",
      "after_commit_recorded",
      "after_checkpoint_saved",
    ];

    it.each(faultPoints)(
      "crash at %s, then resume: one commit, no lost run",
      async (point) => {
        const c = freshConnector(`crash-${point.replaceAll("_", "-")}`);
        const device = `crash-${point}`;
        const crashing = await env.writer(device, {
          fault: (p) => {
            if (p === point) throw new Error(`crash at ${p}`);
          },
        });
        await crashing.refreshControls();
        await collect(crashing, {
          runId: "run-1",
          connector: c,
          observedAt: T0,
          streams: { s: rows(["1", "2", "3"], "x") },
        });
        await expect(crashing.publishPending()).rejects.toThrow(
          `crash at ${point}`,
        );
        const resumed = await env.writer(device);
        await resumed.cycle();
        const status = await resumed.status();
        expect(status.pending).toEqual([]);
        expect(finishedOutcome(status, "run-1")?.outcome).toEqual({
          kind: "checkpointed",
          generation: 1,
        });
        expect(status.checkpoints[c]).toEqual({
          ns: NS,
          generation: 1,
          value: { cursor: "run-1" },
        });
        const view = await readStream(env.registry, env.blobs, c, NS, "s");
        if (!view || view === "tombstoned") throw new Error("stream missing");
        expect(view.version).toBe(1);
        expect([...view.records.keys()].sort()).toEqual(["1", "2", "3"]);
        expect(await env.registry.read(controlScope(c, NS))).toMatchObject({
          version: 1,
        });
        note(`crash/${point}`, { streamVersion: view.version, records: 3 });
      },
    );

    it("crash while collecting: the partial run is failed, nothing is published", async () => {
      const c = freshConnector("crash-collecting");
      const first = await env.writer("crash-collecting");
      await first.refreshControls();
      await first.beginRun({
        runId: "run-1",
        connector: c,
        userConnect: false,
        observedAt: T0,
        identity: "none",
      });
      await first.declareStream("run-1", "s", {
        primaryKey: ["id"],
        profile: { key: null, version: "1.0.0" },
      });
      await first.append("run-1", "s", { id: "1" });
      const resumed = await env.writer("crash-collecting");
      await resumed.cycle();
      const status = await resumed.status();
      expect(finishedOutcome(status, "run-1")?.outcome).toMatchObject({
        kind: "failed",
      });
      expect(await env.registry.read(streamScope(c, NS, "s"))).toEqual({
        found: false,
      });
    });

    it("lost POST reply, then resend: replayed, no second version", async () => {
      const c = freshConnector("lost-reply");
      let lost = 0;
      const replies: string[] = [];
      const registry = interpose(env.newRegistry(), {
        async afterPost(request, result) {
          if (request.scope !== streamScope(c, NS, "s")) return;
          replies.push(`${request.expectedVersion}:${result.kind}`);
          if (lost === 0) {
            lost += 1;
            throw new AmbiguousRegistryReplyError("reply lost");
          }
        },
      });
      const w = await env.writer("lost-reply", { registry });
      await w.refreshControls();
      await collect(w, {
        runId: "run-1",
        connector: c,
        observedAt: T0,
        streams: { s: rows(["1", "2"], "x") },
      });
      await w.publishPending();
      const pending = (await w.status()).pending[0]!;
      expect(pending.streams.s).toMatchObject({
        state: "request_persisted",
        problem: "ambiguous_reply",
      });
      await w.publishPending();
      expect(replies).toEqual(["1:committed", "1:committed"]);
      const view = await readStream(env.registry, env.blobs, c, NS, "s");
      if (!view || view === "tombstoned") throw new Error("stream missing");
      expect(view.version).toBe(1);
      expect(finishedOutcome(await w.status(), "run-1")?.outcome).toEqual({
        kind: "checkpointed",
        generation: 1,
      });
      note("lost-reply", { replies, streamVersion: view.version });
    });

    it("trace A: a create replayed after a delete is not published", async () => {
      const c = freshConnector("trace-a");
      let raced = false;
      const registry = interpose(env.newRegistry(), {
        async beforePost(request) {
          if (raced || request.scope !== controlScope(c, NS)) return;
          raced = true;
          // Another device creates the connection, then it is deleted.
          await activateControl(env.registry, c, NS);
          await deleteConnection(env.registry, c, NS, ["s"]);
        },
      });
      const w = await env.writer("trace-a", { registry });
      await w.refreshControls();
      await collect(w, {
        runId: "run-1",
        connector: c,
        observedAt: T0,
        streams: { s: rows(["1"], "x") },
      });
      await w.publishPending();
      const outcome = finishedOutcome(await w.status(), "run-1")?.outcome;
      expect(outcome).toMatchObject({
        kind: "discarded",
        why: "control reads deleted(2)",
      });
      expect(await env.registry.read(streamScope(c, NS, "s"))).toEqual({
        found: false,
      });
      expect(await env.registry.read(controlScope(c, NS))).toMatchObject({
        version: 2,
        deleted: true,
      });
      note("trace-a", outcome);
    });

    it("trace B: a stale userConnect entry over a later delete and reconnect is discarded", async () => {
      const c = freshConnector("trace-b");
      await activateControl(env.registry, c, NS);
      await deleteConnection(env.registry, c, NS, []);
      const w = await env.writer("trace-b");
      await w.refreshControls(); // start: deleted(2)
      await collect(w, {
        runId: "run-1",
        connector: c,
        observedAt: T0,
        userConnect: true,
        streams: { s: rows(["1"], "x") },
      });
      // Elsewhere: reconnect (3), delete (4), reconnect (5).
      await activateControl(env.registry, c, NS);
      await deleteConnection(env.registry, c, NS, []);
      await activateControl(env.registry, c, NS);
      await w.publishPending();
      const outcome = finishedOutcome(await w.status(), "run-1")?.outcome;
      expect(outcome).toMatchObject({
        kind: "discarded",
        restartFull: false,
        why: "control reads active(5)",
      });
      expect(await env.registry.read(streamScope(c, NS, "s"))).toEqual({
        found: false,
      });
      note("trace-b", outcome);
    });

    it("split run: stream 1 commits at gen 1, delete and reconnect, stream 2 sees gen 3: discarded, then a fresh full run", async () => {
      const c = freshConnector("split-run");
      let raced = false;
      const registry = interpose(env.newRegistry(), {
        async afterPost(request, result) {
          if (raced || request.scope !== streamScope(c, NS, "s1")) return;
          if (result.kind !== "committed") return;
          raced = true;
          await deleteConnection(env.registry, c, NS, ["s1"]);
          await activateControl(env.registry, c, NS);
        },
      });
      const w = await env.writer("split-run", { registry });
      await w.refreshControls();
      await collect(w, {
        runId: "run-1",
        connector: c,
        observedAt: T0,
        streams: { s1: rows(["1"], "x"), s2: rows(["2"], "x") },
      });
      await w.publishPending();
      const status = await w.status();
      const run = finishedOutcome(status, "run-1")!;
      expect(run.outcome).toMatchObject({
        kind: "discarded",
        why: "control reads active(3)",
      });
      expect(run.streams.s1).toMatchObject({
        state: "committed",
        generation: 1,
      });
      expect(run.streams.s2).toMatchObject({ state: "discarded" });
      expect(await env.registry.read(streamScope(c, NS, "s2"))).toEqual({
        found: false,
      });
      expect(await readStream(env.registry, env.blobs, c, NS, "s1")).toBe(
        "tombstoned",
      );
      const plan = await w.runPlan(c);
      expect(plan.checkpoint).toBeNull();

      // The next run uses no checkpoint, so it is full and publishes at gen 3.
      await w.refreshControls();
      await collect(w, {
        runId: "run-2",
        connector: c,
        observedAt: T0 + 1000,
        checkpointUsed: plan.checkpoint,
        streams: { s1: rows(["1"], "y"), s2: rows(["2"], "y") },
      });
      await w.publishPending();
      const next = finishedOutcome(await w.status(), "run-2")!;
      expect(next.outcome).toEqual({ kind: "checkpointed", generation: 3 });
      for (const s of ["s1", "s2"]) {
        const view = await readStream(env.registry, env.blobs, c, NS, s);
        if (!view || view === "tombstoned") throw new Error(`${s} missing`);
        expect(view.head.generation).toBe(3);
        expect(view.head.complete).toBe(true);
      }
      note("split-run", { first: run.outcome, next: next.outcome });
    });

    it("F1 late head: a run admitted at gen 1 meets a gen-3 head: stale_generation, nothing published, gen-3 keys intact", async () => {
      const c = freshConnector("late-head");
      const elsewhere = await env.writer("late-head-elsewhere");
      let raced = false;
      let streamReads = 0;
      const registry = interpose(env.newRegistry(), {
        async beforeRead(scope) {
          if (raced || scope !== streamScope(c, NS, "s")) return;
          // The first read is the stream-row stamp taken at collection; the
          // race is the publish-time read after admission.
          streamReads += 1;
          if (streamReads < 2) return;
          raced = true;
          // After this run was admitted at gen 1: delete, then a reconnect
          // elsewhere commits gen 3.
          await deleteConnection(env.registry, c, NS, []);
          await elsewhere.refreshControls();
          await collect(elsewhere, {
            runId: "reconnect",
            connector: c,
            observedAt: T0 + 5000,
            userConnect: true,
            streams: { s: rows(["g3-a", "g3-b"], "gen3") },
          });
          await elsewhere.publishPending();
        },
      });
      const w = await env.writer("late-head", { registry });
      await w.refreshControls();
      await collect(w, {
        runId: "run-1",
        connector: c,
        observedAt: T0,
        streams: { s: rows(["old"], "gen1") },
      });
      await w.publishPending();
      expect(
        finishedOutcome(await elsewhere.status(), "reconnect")?.outcome,
      ).toEqual({
        kind: "checkpointed",
        generation: 3,
      });
      const outcome = finishedOutcome(await w.status(), "run-1")?.outcome;
      expect(outcome).toMatchObject({
        kind: "discarded",
        why: "stale_generation: control reads active(3)",
      });
      const view = await readStream(env.registry, env.blobs, c, NS, "s");
      if (!view || view === "tombstoned") throw new Error("stream missing");
      expect(view.version).toBe(1);
      expect(view.head.generation).toBe(3);
      expect([...view.records.keys()].sort()).toEqual(["g3-a", "g3-b"]);
      note("late-head", {
        outcome,
        streamVersion: view.version,
        generation: 3,
      });
    });

    it.each([
      ["7.9 MiB", Math.floor(7.9 * MiB)],
      ["8 MiB + 1", 8 * MiB + 1],
      ["30 MiB", 30 * MiB],
    ])(
      "keeps a record of %s byte-exact through publish and read",
      async (_name, bodyBytes) => {
        const c = freshConnector(`big-${bodyBytes}`);
        const w = await env.writer(`big-${bodyBytes}`);
        await w.refreshControls();
        const huge = recordOfBodyBytes("huge", bodyBytes);
        await collect(w, {
          runId: "run-1",
          connector: c,
          observedAt: T0,
          streams: { s: [{ id: "small", n: "x" }, huge] },
        });
        await w.publishPending();
        const run = finishedOutcome(await w.status(), "run-1")!;
        expect(run.outcome).toEqual({ kind: "checkpointed", generation: 1 });
        const view = await readStream(env.registry, env.blobs, c, NS, "s");
        if (!view || view === "tombstoned") throw new Error("stream missing");
        expect([...view.records.keys()].sort()).toEqual(["huge", "small"]);
        expect(canonicalJson(view.records.get("huge"))).toBe(
          canonicalJson(huge),
        );
        expect(view.head.format).toBe(2);
        expect(view.head.recordCount).toBe(2);
        // The long record is alone in parts of at most the piece size.
        for (const part of view.head.parts) {
          expect(part.bytes).toBeLessThanOrEqual(FRAME_PIECE_BYTES);
        }
      },
    );

    it("carries a long record unchanged through a later run that updates another record", async () => {
      const c = freshConnector("big-carry");
      const w = await env.writer("big-carry");
      await w.refreshControls();
      const huge = recordOfBodyBytes("huge", 9 * MiB);
      await collect(w, {
        runId: "run-1",
        connector: c,
        observedAt: T0,
        streams: { s: [{ id: "small", n: "x" }, huge] },
      });
      await w.publishPending();
      const first = (await readStream(env.registry, env.blobs, c, NS, "s"))!;
      if (first === "tombstoned") throw new Error("tombstoned");
      await collect(w, {
        runId: "run-2",
        connector: c,
        observedAt: T0 + 1000,
        checkpointUsed: { ns: NS, generation: 1 },
        streams: { s: [{ id: "small", n: "y" }] },
      });
      await w.publishPending();
      const second = (await readStream(env.registry, env.blobs, c, NS, "s"))!;
      if (second === "tombstoned") throw new Error("tombstoned");
      expect(second.version).toBe(first.version + 1);
      expect(second.records.get("small")).toEqual({ id: "small", n: "y" });
      expect(canonicalJson(second.records.get("huge"))).toBe(
        canonicalJson(huge),
      );
      // The long record's pieces are the same blobs: nothing was re-encoded.
      const longHashes = (head: typeof first.head) =>
        head.parts
          .filter((p) => p.bytes === FRAME_PIECE_BYTES)
          .map((p) => p.hash);
      expect(longHashes(second.head)).toEqual(longHashes(first.head));
      expect(longHashes(first.head).length).toBeGreaterThan(0);
    });

    it("replaces a long record when a later run updates it, to a long or a small one", async () => {
      const c = freshConnector("big-update");
      const w = await env.writer("big-update");
      await w.refreshControls();
      await collect(w, {
        runId: "run-1",
        connector: c,
        observedAt: T0,
        streams: { s: [recordOfBodyBytes("huge", 9 * MiB)] },
      });
      await w.publishPending();
      const longer = recordOfBodyBytes("huge", 10 * MiB, "b");
      await collect(w, {
        runId: "run-2",
        connector: c,
        observedAt: T0 + 1000,
        checkpointUsed: { ns: NS, generation: 1 },
        streams: { s: [longer] },
      });
      await w.publishPending();
      let view = (await readStream(env.registry, env.blobs, c, NS, "s"))!;
      if (view === "tombstoned") throw new Error("tombstoned");
      expect(canonicalJson(view.records.get("huge"))).toBe(
        canonicalJson(longer),
      );
      await collect(w, {
        runId: "run-3",
        connector: c,
        observedAt: T0 + 2000,
        checkpointUsed: { ns: NS, generation: 1 },
        streams: { s: [{ id: "huge", n: "now small" }] },
      });
      await w.publishPending();
      view = (await readStream(env.registry, env.blobs, c, NS, "s"))!;
      if (view === "tombstoned") throw new Error("tombstoned");
      expect(view.records.get("huge")).toEqual({ id: "huge", n: "now small" });
      expect(view.head.parts).toHaveLength(1);
    });

    it("drops a long record when the stream is deleted and published again", async () => {
      const c = freshConnector("big-delete");
      const w = await env.writer("big-delete");
      await w.refreshControls();
      await collect(w, {
        runId: "run-1",
        connector: c,
        observedAt: T0,
        streams: { s: [recordOfBodyBytes("huge", 9 * MiB)] },
      });
      await w.publishPending();
      await oldDelete(env, streamScope(c, NS, "s"));
      expect(await readStream(env.registry, env.blobs, c, NS, "s")).toBe(
        "tombstoned",
      );
      await w.refreshControls();
      await collect(w, {
        runId: "run-2",
        connector: c,
        observedAt: T0 + 1000,
        streams: { s: [{ id: "after", n: "z" }] },
      });
      await w.publishPending();
      const view = (await readStream(env.registry, env.blobs, c, NS, "s"))!;
      if (view === "tombstoned") throw new Error("tombstoned");
      expect([...view.records.keys()]).toEqual(["after"]);
    });

    it("Q9: a no-op onto a complete:false base keeps needsFull and blocks the checkpoint", async () => {
      const c = freshConnector("noop-incomplete");
      // Another device publishes an incremental run onto the empty stream:
      // its head is complete:false.
      const other = await env.writer("noop-incomplete-other");
      await other.refreshControls();
      await collect(other, {
        runId: "other-run",
        connector: c,
        observedAt: T0,
        checkpointUsed: { ns: NS, generation: 1 },
        streams: { s: rows(["1"], "x") },
      });
      await other.publishPending();
      // This device's incremental run finds nothing new: a no-op onto that base.
      const w = await env.writer("noop-incomplete");
      await w.refreshControls();
      await collect(w, {
        runId: "run-1",
        connector: c,
        observedAt: T0 + 1000,
        checkpointUsed: { ns: NS, generation: 1 },
        streams: { s: [] },
      });
      await w.publishPending();
      const status = await w.status();
      const run = finishedOutcome(status, "run-1")!;
      expect(run.streams.s).toMatchObject({ state: "noop", complete: false });
      expect(run.outcome).toEqual({
        kind: "no_checkpoint",
        generation: 1,
        reason: "published_incomplete",
      });
      expect(status.needsFull).toEqual([{ connector: c, ns: NS, stream: "s" }]);
      expect(status.checkpoints[c]).toBeUndefined();
      expect(await w.runPlan(c)).toEqual({
        mustBeFull: true,
        checkpoint: null,
      });
      const view = await readStream(env.registry, env.blobs, c, NS, "s");
      if (!view || view === "tombstoned") throw new Error("stream missing");
      expect(view.version).toBe(1);
      expect(view.head.complete).toBe(false);
      note("q9-noop", {
        outcome: run.outcome,
        needsFull: status.needsFull.length,
      });
    });

    it("R3 (Muse Q9): old DELETE, an empty complete:false head from a device that left, then two quiet incremental runs", async () => {
      const c = freshConnector("muse-q9");
      const scope = streamScope(c, NS, "s");
      const R = rows(["r1", "r2", "r3"], "desktop");
      const desktop = await env.writer("muse-q9-desktop", {
        seed: fixedSeed("desktop-install", { s: rows(["r1"], "seed") }),
      });
      await desktop.refreshControls();
      await collect(desktop, {
        runId: "d-0",
        connector: c,
        observedAt: T0,
        streams: { s: R },
      });
      await desktop.publishPending();
      let status = await desktop.status();
      expect(finishedOutcome(status, "d-0")?.outcome).toEqual({
        kind: "checkpointed",
        generation: 1,
      });
      expect(status.receipts[`desktop-install|${c}|${NS}|s`]).toBe("merged");
      const live = await readStream(env.registry, env.blobs, c, NS, "s");
      if (!live || live === "tombstoned") throw new Error("stream missing");
      expect(live.head.complete).toBe(true);
      expect([...live.records.keys()].sort()).toEqual(["r1", "r2", "r3"]);

      // An old install's non-exclusive DELETE tombstones s (L11).
      await oldDelete(env, scope);
      expect(await readStream(env.registry, env.blobs, c, NS, "s")).toBe(
        "tombstoned",
      );

      // Device P runs incrementally with nothing new, publishes an empty
      // complete:false head, and never runs again.
      const phone = await env.writer("muse-q9-phone");
      await phone.refreshControls();
      await collect(phone, {
        runId: "p-1",
        connector: c,
        observedAt: T0 + 1000,
        checkpointUsed: { ns: NS, generation: 1 },
        streams: { s: [] },
      });
      await phone.publishPending();
      const empty = await readStream(env.registry, env.blobs, c, NS, "s");
      if (!empty || empty === "tombstoned") throw new Error("stream missing");
      expect(empty.head.complete).toBe(false);
      expect(empty.records.size).toBe(0);

      // D, first quiet incremental run: a no-op onto the incomplete base.
      let plan = await desktop.runPlan(c);
      expect(plan).toEqual({
        mustBeFull: false,
        checkpoint: { ns: NS, generation: 1, value: { cursor: "d-0" } },
      });
      await desktop.refreshControls();
      await collect(desktop, {
        runId: "d-1",
        connector: c,
        observedAt: T0 + 2000,
        checkpointUsed: { ns: NS, generation: 1 },
        streams: { s: [] },
      });
      await desktop.publishPending();
      status = await desktop.status();
      const first = finishedOutcome(status, "d-1")!;
      expect(first.streams.s).toMatchObject({ state: "noop", complete: false });
      expect(first.outcome).toEqual({
        kind: "no_checkpoint",
        generation: 1,
        reason: "published_incomplete",
      });
      expect(status.needsFull).toEqual([{ connector: c, ns: NS, stream: "s" }]);
      expect(status.checkpoints[c]).toBeUndefined();
      const afterNoop = await env.registry.read(scope);

      // D, next run: needsFull makes it full, so it re-emits R.
      plan = await desktop.runPlan(c);
      expect(plan).toEqual({ mustBeFull: true, checkpoint: null });
      await desktop.refreshControls();
      await collect(desktop, {
        runId: "d-2",
        connector: c,
        observedAt: T0 + 3000,
        checkpointUsed: plan.checkpoint,
        streams: { s: R },
      });
      await desktop.publishPending();
      status = await desktop.status();
      expect(finishedOutcome(status, "d-2")?.outcome).toEqual({
        kind: "checkpointed",
        generation: 1,
      });
      expect(status.needsFull).toEqual([]);
      const healed = await readStream(env.registry, env.blobs, c, NS, "s");
      if (!healed || healed === "tombstoned") throw new Error("stream missing");
      expect(healed.head.complete).toBe(true);
      expect([...healed.records.keys()].sort()).toEqual(["r1", "r2", "r3"]);
      expect(afterNoop).toMatchObject({ version: empty.version });
      expect(healed.version).toBe(empty.version + 1);
      note("r3-muse-q9", {
        versions: {
          live: live.version,
          empty: empty.version,
          healed: healed.version,
        },
        noop: first.outcome,
        healedRecords: healed.records.size,
      });
    });

    it("R3 (dot): A decides T=1 and pauses before its stream-row read; B deletes, reconnects and commits H3; A gets stale_generation and posts nothing", async () => {
      const c = freshConnector("dot-interleave");
      const scope = streamScope(c, NS, "s");
      await activateControl(env.registry, c, NS); // active(1)
      const b = await env.writer("dot-b");
      const postsAfterPause: string[] = [];
      let h3: string | null = null;
      let paused = false;
      let streamReads = 0;
      const a = await env.writer("dot-a", {
        registry: interpose(env.newRegistry(), {
          async beforeRead(read) {
            if (paused || read !== scope) return;
            // The first read is the stream-row stamp taken at collection; the
            // pause is before the publish-time read.
            streamReads += 1;
            if (streamReads < 2) return;
            paused = true;
            // While A is paused: B deletes (control v2), reconnects (v3),
            // commits H3 with record x and checkpoints.
            await deleteConnection(env.registry, c, NS, []);
            await b.refreshControls();
            await collect(b, {
              runId: "b-reconnect",
              connector: c,
              observedAt: T0 + 5000,
              userConnect: true,
              streams: { s: rows(["x"], "b") },
            });
            await b.publishPending();
            const row = await env.registry.read(scope);
            h3 = row.found ? row.dataHash : null;
          },
          async beforePost(request) {
            if (paused)
              postsAfterPause.push(
                `${request.scope}@${request.expectedVersion}`,
              );
          },
        }),
      });
      await a.refreshControls(); // start: active(1)
      await collect(a, {
        runId: "a-1",
        connector: c,
        observedAt: T0,
        streams: { s: rows(["a"], "a") },
      });
      await a.publishPending();
      expect(finishedOutcome(await b.status(), "b-reconnect")?.outcome).toEqual(
        {
          kind: "checkpointed",
          generation: 3,
        },
      );
      const outcome = finishedOutcome(await a.status(), "a-1")?.outcome;
      expect(outcome).toEqual({
        kind: "discarded",
        recollect: false,
        clearCheckpoints: true,
        restartFull: false,
        why: "stale_generation: control reads active(3)",
      });
      expect(postsAfterPause).toEqual([]);
      const row = await env.registry.read(scope);
      expect(row.found && row.dataHash).toBe(h3);
      const view = await readStream(env.registry, env.blobs, c, NS, "s");
      if (!view || view === "tombstoned") throw new Error("stream missing");
      expect(view.head.generation).toBe(3);
      expect(Object.fromEntries(view.records)).toEqual({
        x: { id: "x", n: "b" },
      });
      note("r3-dot", {
        outcome,
        postsAfterPause: postsAfterPause.length,
        version: view.version,
      });
    });

    it("M7: the phone publishes first, then a Desktop seed adds Desktop-only rows", async () => {
      const c = freshConnector("phone-first");
      const phone = await env.writer("phone-first-phone");
      await phone.refreshControls();
      await collect(phone, {
        runId: "phone-run",
        connector: c,
        observedAt: T0 + 1000,
        streams: { s: rows(["a", "b"], "phone") },
      });
      await phone.publishPending();
      const desktop = await env.writer("phone-first-desktop", {
        seed: fixedSeed("desktop-install", {
          s: rows(["a", "x", "y"], "seed"),
        }),
      });
      await desktop.refreshControls();
      // Fingerprint suppression: Desktop's run re-emits only a changed row.
      await collect(desktop, {
        runId: "desktop-run",
        connector: c,
        observedAt: T0 + 2000,
        streams: { s: rows(["c"], "desktop") },
      });
      await desktop.publishPending();
      const status = await desktop.status();
      expect(finishedOutcome(status, "desktop-run")?.outcome).toEqual({
        kind: "checkpointed",
        generation: 1,
      });
      expect(status.receipts).toEqual({
        [`desktop-install|${c}|${NS}|s`]: "merged",
      });
      const view = await readStream(env.registry, env.blobs, c, NS, "s");
      if (!view || view === "tombstoned") throw new Error("stream missing");
      expect(Object.fromEntries(view.records)).toEqual({
        a: { id: "a", n: "phone" },
        b: { id: "b", n: "phone" },
        c: { id: "c", n: "desktop" },
        x: { id: "x", n: "seed" },
        y: { id: "y", n: "seed" },
      });
      expect(view.head.complete).toBe(true);
      note("m7", { records: view.records.size, streamVersion: view.version });
    });
  },
);

afterAll(async () => {
  if (REPORT) await writeFile(REPORT, JSON.stringify(report, null, 2));
});
