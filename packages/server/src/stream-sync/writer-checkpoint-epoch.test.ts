/**
 * A checkpoint save that finishes late must not replace the checkpoint a newer
 * generation saved after the connection was invalidated.
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
 * A registry whose first control read after a stream post, once armed, returns
 * the row as it was when the read began but is delivered only after `release`
 * is called: the checkpoint step of a run whose streams have committed.
 */
function delayedControlRead(inner: StreamSyncRegistry) {
  let armed = false;
  let postSeen = false;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => (release = resolve));
  let reached!: () => void;
  const atRead = new Promise<void>((resolve) => (reached = resolve));
  const registry: StreamSyncRegistry = {
    ...inner,
    async post(request) {
      const result = await inner.post(request);
      if (armed && parseScope(request.scope)?.kind === "stream") {
        postSeen = true;
      }
      return result;
    },
    async read(scope) {
      const result = await inner.read(scope);
      if (armed && postSeen && parseScope(scope)?.kind === "control") {
        armed = false;
        reached();
        await gate;
      }
      return result;
    },
  };
  return {
    registry,
    arm: () => (armed = true),
    atRead,
    release,
  };
}

/**
 * Run A (g1) commits its streams and starts its checkpoint step with a delayed
 * control read. The owner deletes and reconnects (g2 active). Run B at g2 then
 * saves `bCursors` (or nothing). A resumes with its stale active(g1) read.
 */
async function lateSaveAfterInvalidation(
  tag: string,
  bCursors: Record<string, string>,
) {
  const c = freshConnector(tag);
  const held = delayedControlRead(env.newRegistry());
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
  expect((await w.status()).checkpoints[c]).toEqual({
    ns: NS,
    generation: 1,
    value: { s1: "T0" },
  });

  held.arm();
  await collect(w, {
    runId: "rA",
    connector: c,
    observedAt: T0 + 1000,
    checkpointUsed: { ns: NS, generation: 1 },
    streams: { s1: rows(["2"], "a") },
    checkpoint: { s1: "T1" },
  });
  const publishing = w.publishPending();
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

  held.release();
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
    expect((await w.status()).checkpoints[c]).toEqual(expected);
    expect((await w.runPlan(c)).checkpoint).toEqual(expected);
  });

  it("a late save of the old generation saves nothing when the newer one saved nothing", async () => {
    const { w, c } = await lateSaveAfterInvalidation("ckpt-epoch-none", {});
    const plan = await w.runPlan(c);
    expect(plan.checkpoint?.value ?? null).toBeNull();
    expect(plan.checkpoint?.generation ?? 3).toBe(3);
  });
});
