/**
 * A run that is finishing while the first publish pass of a new process runs
 * recovery. Recovery must not mistake it for a run a dead process left behind.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { StreamSyncFiles } from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  createOracleEnv,
  finishedOutcome,
  freshConnector,
  readStream,
  startLocalStorage,
  type OracleEnv,
} from "./oracle.test-utils.js";

const T0 = Date.UTC(2026, 10, 1);
const SHAPE = { primaryKey: ["id"], profile: { key: null, version: "1.0.0" } };

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

/** Files whose `sync` of a run directory waits until `release` is called. */
async function heldSync(device: string) {
  const inner = await env.files(device);
  let release!: () => void;
  const gate = new Promise<void>((resolve) => (release = resolve));
  let reached!: () => void;
  const atSync = new Promise<void>((resolve) => (reached = resolve));
  const files: StreamSyncFiles = {
    ...inner,
    async sync(prefix) {
      if (prefix.startsWith("runs/")) {
        reached();
        await gate;
      }
      return inner.sync(prefix);
    },
  };
  return { files, atSync, release };
}

describe(
  "finishRun against the first publish pass",
  { timeout: 30_000 },
  () => {
    it("keeps the finishing run and publishes every record", async () => {
      const c = freshConnector("finish-race");
      const held = await heldSync("finish-race");
      const writer = await env.writer("finish-race", { files: held.files });
      await writer.refreshControls();
      await writer.beginRun({
        runId: "r1",
        connector: c,
        userConnect: false,
        observedAt: T0,
        identity: "none",
        checkpointUsed: null,
      });
      await writer.declareStream("r1", "items", SHAPE);
      await writer.append("r1", "items", { id: "a" });
      await writer.append("r1", "items", { id: "b" });

      const finishing = writer.finishRun("r1", {
        checkpointCandidate: { cursor: "c1" },
      });
      await held.atSync;
      // The first publish pass of the process runs recovery while the run is
      // between its intake flush and its durable `ready` write.
      await writer.publishPending();
      held.release();
      await finishing;

      await writer.publishPending();
      const status = await writer.status();
      expect(finishedOutcome(status, "r1")?.outcome.kind).toBe("checkpointed");
      const view = await readStream(env.registry, env.blobs, c, "", "items");
      expect(view).not.toBeNull();
      expect(
        [...(view as { records: Map<string, unknown> }).records.keys()].sort(),
      ).toEqual(["a", "b"]);
    });
  },
);
