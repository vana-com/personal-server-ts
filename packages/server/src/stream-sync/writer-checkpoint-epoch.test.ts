/**
 * A checkpoint save that finishes late must not overwrite or restore a
 * checkpoint that an invalidation (a control change, or a deliberate clear)
 * overtook while the save waited for its final control read.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { StreamSyncRegistry } from "@opendatalabs/personal-server-ts-core/stream-sync";
import { parseScope } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  activateControl,
  collect,
  createOracleEnv,
  deleteConnection,
  finishedOutcome,
  freshConnector,
  type OracleEnv,
  startLocalStorage,
} from "./oracle.test-utils.js";

const NS = "";
const T0 = Date.UTC(2026, 10, 1);
const rows = (ids: string[], tag: string) => ids.map((id) => ({ id, n: tag }));

let storage: Awaited<ReturnType<typeof startLocalStorage>>;
let env: OracleEnv;

beforeAll(async () => {
  storage = await startLocalStorage();
  env = await createOracleEnv({
    surface: "full",
    backend: "fake",
    storageUrl: storage.url,
  });
});
afterAll(async () => {
  await env.cleanup();
  await storage.close();
});

/**
 * A registry with two test hooks on control reads, once armed:
 * - `arm`: one control read returns the row as it was when the read began,
 *   but is delivered only after `release` (a save's final control read). With
 *   `afterStreamPost` it waits for a stream post first; `skip` lets that many
 *   control reads pass.
 * - `beforeRead`: runs an action before the Nth control read after it is set.
 */
function controlReadHooks(inner: StreamSyncRegistry) {
  let held: { skip: number; afterStreamPost: boolean } | null = null;
  let postSeen = false;
  let before: { skip: number; action: () => Promise<void> } | null = null;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => (release = resolve));
  let reached!: () => void;
  const atRead = new Promise<void>((resolve) => (reached = resolve));
  const registry: StreamSyncRegistry = {
    ...inner,
    async post(request) {
      const result = await inner.post(request);
      if (held && parseScope(request.scope)?.kind === "stream") {
        postSeen = true;
      }
      return result;
    },
    async read(scope) {
      const control = parseScope(scope)?.kind === "control";
      if (control && before) {
        if (before.skip > 0) before.skip -= 1;
        else {
          const { action } = before;
          before = null;
          await action();
        }
      }
      const result = await inner.read(scope);
      if (control && held && (!held.afterStreamPost || postSeen)) {
        if (held.skip > 0) held.skip -= 1;
        else {
          held = null;
          reached();
          await gate;
        }
      }
      return result;
    },
  };
  return {
    registry,
    arm: (options: { skip?: number; afterStreamPost?: boolean } = {}) => {
      held = {
        skip: options.skip ?? 0,
        afterStreamPost: options.afterStreamPost ?? false,
      };
    },
    beforeRead: (skip: number, action: () => Promise<void>) => {
      before = { skip, action };
    },
    atRead,
    release,
  };
}

const checkpointOf = async (
  w: Awaited<ReturnType<OracleEnv["writer"]>>,
  c: string,
) => (await w.status()).checkpoints[c];

/** Run `body`, always releasing the held read so a failure cannot hang. */
async function guarded(
  held: ReturnType<typeof controlReadHooks>,
  body: () => Promise<void>,
) {
  try {
    await body();
  } finally {
    held.release();
  }
}

/**
 * Run A (g1) commits its streams and starts its checkpoint step with a delayed
 * control read. The owner deletes and reconnects (g3 active). Run B at g3 then
 * saves `bCursors`. A resumes with its stale active(g1) read.
 */
async function lateSaveAfterInvalidation(
  tag: string,
  bCursors: Record<string, string>,
) {
  const c = freshConnector(tag);
  const held = controlReadHooks(env.newRegistry());
  const w = await env.writer(tag, { registry: held.registry });
  await w.refreshControls();
  await collect(w, {
    runId: "r0",
    connector: c,
    observedAt: T0,
    streams: { s1: rows(["1"], "a") },
    checkpoint: { s1: "T0" },
  });
  await w.publishPending();
  expect(await checkpointOf(w, c)).toEqual({
    ns: NS,
    generation: 1,
    value: { s1: "T0" },
  });

  held.arm({ afterStreamPost: true });
  await collect(w, {
    runId: "rA",
    connector: c,
    observedAt: T0 + 1000,
    checkpointUsed: { ns: NS, generation: 1 },
    streams: { s1: rows(["2"], "a") },
    checkpoint: { s1: "T1" },
  });
  const publishing = w.publishPending();
  await guarded(held, async () => {
    await held.atRead;
    await deleteConnection(env.registry, c, NS, ["s1"]);
    await activateControl(env.registry, c, NS);
    await w.refreshControls();
    await w.beginRun({
      runId: "rB",
      connector: c,
      userConnect: false,
      observedAt: T0 + 2000,
      identity: "none",
      checkpointUsed: null,
    });
    await w.saveCheckpointOnly("rB", bCursors);
  });
  await publishing;
  expect(finishedOutcome(await w.status(), "rA")).not.toBeNull();
  return { w, c };
}

describe("checkpoint save against an invalidation", { timeout: 30_000 }, () => {
  it("a late save of the old generation leaves the newer checkpoint", async () => {
    const { w, c } = await lateSaveAfterInvalidation("ckpt-epoch", {
      s1: "U2",
    });
    const expected = { ns: NS, generation: 3, value: { s1: "U2" } };
    expect(await checkpointOf(w, c)).toEqual(expected);
    expect((await w.runPlan(c)).checkpoint).toEqual(expected);
  });

  it("a late save of the old generation does not replace a newer null checkpoint", async () => {
    const { w, c } = await lateSaveAfterInvalidation("ckpt-epoch-null", {});
    const plan = await w.runPlan(c);
    expect(plan.checkpoint?.value ?? null).toBeNull();
    expect(plan.checkpoint?.generation ?? 3).toBe(3);
  });

  // Only the invalidation count protects this case: no checkpoint is stored,
  // so the generation guard has nothing to compare.
  it("an invalidation seen while no checkpoint is stored still stops a late save", async () => {
    const c = freshConnector("ckpt-epoch-empty");
    const held = controlReadHooks(env.newRegistry());
    const w = await env.writer("ckpt-epoch-empty", { registry: held.registry });
    await w.refreshControls();

    held.arm({ afterStreamPost: true });
    await collect(w, {
      runId: "rA",
      connector: c,
      observedAt: T0,
      streams: { s1: rows(["1"], "a") },
      checkpoint: { s1: "T1" },
    });
    const publishing = w.publishPending();
    await guarded(held, async () => {
      await held.atRead;
      await deleteConnection(env.registry, c, NS, ["s1"]);
      await activateControl(env.registry, c, NS);
      await w.refreshControls();
      await w.beginRun({
        runId: "rB",
        connector: c,
        userConnect: false,
        observedAt: T0 + 1000,
        identity: "none",
        checkpointUsed: null,
      });
      // B sees active(3) at admission, then the connection is deleted again
      // before its final read, so B saves nothing.
      held.beforeRead(1, () =>
        deleteConnection(env.registry, c, NS, []).then(() => undefined),
      );
      const b = await w.saveCheckpointOnly("rB", { s1: "U2" });
      expect(b.outcome.kind).toBe("no_checkpoint");
      expect(await checkpointOf(w, c)).toBeUndefined();
    });
    await publishing;
    expect(finishedOutcome(await w.status(), "rA")?.outcome.kind).toBe(
      "no_checkpoint",
    );
    expect(await checkpointOf(w, c)).toBeUndefined();
    expect((await w.runPlan(c)).checkpoint).toBeNull();
  });

  // Only the generation guard protects this case: the checkpoint appears in
  // state without any invalidation, as if written by a writer that keeps no
  // invalidation count.
  it("a late save never replaces a newer generation's checkpoint", async () => {
    const c = freshConnector("ckpt-epoch-gen");
    const held = controlReadHooks(env.newRegistry());
    const files = await env.files("ckpt-epoch-gen");
    const w = await env.writer("ckpt-epoch-gen", {
      registry: held.registry,
      files,
    });
    await w.refreshControls();
    held.arm({ afterStreamPost: true });
    await collect(w, {
      runId: "rA",
      connector: c,
      observedAt: T0,
      streams: { s1: rows(["1"], "a") },
      checkpoint: { s1: "T1" },
    });
    const publishing = w.publishPending();
    await guarded(held, async () => {
      await held.atRead;
      const state = JSON.parse(
        new TextDecoder().decode((await files.read("state.json"))!),
      );
      state.checkpoints[c] = { ns: NS, generation: 3, value: { s1: "U2" } };
      await files.write(
        "state.json",
        new TextEncoder().encode(JSON.stringify(state)),
      );
    });
    await publishing;
    expect(await checkpointOf(w, c)).toEqual({
      ns: NS,
      generation: 3,
      value: { s1: "U2" },
    });
  });

  it("a late save does not restore a checkpoint that a published incomplete head cleared", async () => {
    const c = freshConnector("ckpt-epoch-aftercommit");
    // Another device leaves stream `s` incomplete at g1.
    const other = await env.writer("ckpt-epoch-aftercommit-other");
    await other.refreshControls();
    await collect(other, {
      runId: "other-run",
      connector: c,
      observedAt: T0,
      checkpointUsed: { ns: NS, generation: 1 },
      streams: { s: rows(["1"], "x") },
    });
    await other.publishPending();

    const held = controlReadHooks(env.newRegistry());
    const w = await env.writer("ckpt-epoch-aftercommit", {
      registry: held.registry,
    });
    await w.refreshControls();
    await collect(w, {
      runId: "r0",
      connector: c,
      observedAt: T0 + 1000,
      streams: { ok: rows(["1"], "a") },
      checkpoint: { ok: "T0" },
    });
    await w.publishPending();
    expect((await checkpointOf(w, c))?.generation).toBe(1);

    // B is a no-op onto the incomplete head: publishing it clears the checkpoint.
    await collect(w, {
      runId: "rB",
      connector: c,
      observedAt: T0 + 2000,
      checkpointUsed: { ns: NS, generation: 1 },
      streams: { s: [] },
    });
    // A, a checkpoint-only run, holds its final control read.
    await w.beginRun({
      runId: "rA",
      connector: c,
      userConnect: false,
      observedAt: T0 + 3000,
      identity: "none",
      checkpointUsed: null,
    });
    held.arm({ skip: 1 });
    const saving = w.saveCheckpointOnly("rA", { ok: "T1" });
    await guarded(held, async () => {
      await held.atRead;
      await w.publishPending();
      expect(await checkpointOf(w, c)).toBeUndefined();
    });
    await saving;
    expect(await checkpointOf(w, c)).toBeUndefined();
  });

  it("a late save does not restore a checkpoint that a discard cleared", async () => {
    const c = freshConnector("ckpt-epoch-discard");
    const held = controlReadHooks(env.newRegistry());
    const w = await env.writer("ckpt-epoch-discard", {
      registry: held.registry,
    });
    await w.refreshControls();
    await collect(w, {
      runId: "r0",
      connector: c,
      observedAt: T0,
      streams: { s1: rows(["1"], "a") },
      checkpoint: { s1: "T0" },
    });
    await w.publishPending();

    // D starts at g1 and is ready to publish.
    await w.refreshControls();
    await collect(w, {
      runId: "rD",
      connector: c,
      observedAt: T0 + 3000,
      checkpointUsed: { ns: NS, generation: 1 },
      streams: { s1: rows(["9"], "d") },
      checkpoint: { s1: "TD" },
    });
    await deleteConnection(env.registry, c, NS, ["s1"]);
    await activateControl(env.registry, c, NS);
    await w.refreshControls();
    // C runs at g3 and saves a checkpoint there.
    await collect(w, {
      runId: "rC",
      connector: c,
      observedAt: T0 + 1000,
      streams: { s1: rows(["3"], "c") },
      checkpoint: { s1: "TC" },
    });
    // A, a checkpoint-only run at g3, holds its final control read.
    await w.beginRun({
      runId: "rA",
      connector: c,
      userConnect: false,
      observedAt: T0 + 4000,
      identity: "none",
      checkpointUsed: null,
    });
    held.arm({ skip: 1 });
    const saving = w.saveCheckpointOnly("rA", { s1: "TA" });
    await guarded(held, async () => {
      await held.atRead;
      // C publishes and saves g3; D, started at g1, is discarded and clears it.
      await w.publishPending();
      expect(finishedOutcome(await w.status(), "rD")?.outcome).toMatchObject({
        kind: "discarded",
        clearCheckpoints: true,
      });
      expect(await checkpointOf(w, c)).toBeUndefined();
    });
    await saving;
    expect(await checkpointOf(w, c)).toBeUndefined();
  });
});
