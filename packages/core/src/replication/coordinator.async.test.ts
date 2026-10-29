import assert from "node:assert/strict";
import { it } from "vitest";
import {
  createAsyncReplicaCoordinator,
  createReplicaCoordinator,
  ReplicaAsyncCheckpointError,
  ReplicaCoordinatorConflict,
  type AsyncReplicaCoordinatorStatePort,
  type AsyncReplicaPhaseHandler,
  type ReplicaCoordinatorState,
  type ReplicaCoordinatorStatePort,
  type ReplicaPhaseHandler,
} from "./coordinator.js";
import type { ReplicaPhase } from "./outcome.js";
import { initialReplicaWorkState } from "./schedule.js";

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

/** An asynchronous port whose transaction is a receipts buffer. */
function asyncMemory() {
  let disk: ReplicaCoordinatorState = { owner: "a", version: 0, writers: {} };
  const receipts: string[] = [];
  const port: AsyncReplicaCoordinatorStatePort<string[]> = {
    async: true,
    async load() {
      await tick();
      return structuredClone(disk);
    },
    async commit(expected, next, checkpoint) {
      await tick();
      if (expected.owner !== disk.owner || expected.version !== disk.version)
        throw new ReplicaCoordinatorConflict();
      const tx: string[] = [];
      const result = await checkpoint(tx);
      await tick();
      receipts.push(...tx);
      disk = {
        ...structuredClone(next),
        owner: disk.owner,
        version: disk.version + 1,
      };
      return { state: structuredClone(disk), result };
    },
  };
  return { port, receipts, disk: () => disk };
}

function asyncPhase(
  name: ReplicaPhase,
  writers: string[],
  opts: { failCommit?: boolean } = {},
): AsyncReplicaPhaseHandler<
  {
    id: string;
    phase: ReplicaPhase;
    writer: string;
    state: typeof initialReplicaWorkState;
  },
  string[]
> {
  const done = new Set<string>();
  return {
    phase: name,
    async due(_eligibility, limit) {
      await tick();
      return writers
        .filter((writer) => !done.has(writer))
        .slice(0, limit.total)
        .map((writer) => ({
          id: writer,
          phase: name,
          writer,
          state: { ...initialReplicaWorkState },
        }));
    },
    run: async (item) => ({
      outcome: { tag: "progress", receipt: { phase: name, key: item.writer } },
    }),
    async commit(item, attempt, settle, tx) {
      await tick();
      const result = settle(attempt.outcome);
      tx.push(`${name}:${item.writer}:${result.outcome.tag}`);
      if (opts.failCommit) throw new Error("commit failed");
      done.add(item.writer);
      return result.outcome;
    },
    async earliest() {
      await tick();
      return done.size === writers.length ? undefined : 0;
    },
    async wake() {
      await tick();
      return 1;
    },
  };
}

it("steps asynchronous handlers through an asynchronous port, rotation and receipts together", async () => {
  const memory = asyncMemory();
  const co = createAsyncReplicaCoordinator({
    phases: [asyncPhase("publish", ["A", "B"]), asyncPhase("import", ["Z"])],
    state: memory.port,
  });
  const report = await co.step({ now: 1, budget: { units: 10 } });
  assert.deepEqual(
    report.receipts.map((r) => `${r.phase}:${r.key}`),
    ["publish:A", "publish:B", "import:Z"],
  );
  assert.deepEqual(memory.receipts, [
    "publish:A:progress",
    "publish:B:progress",
    "import:Z:progress",
  ]);
  assert.equal(memory.disk().version, 3);
  assert.equal(report.nextWake, undefined);
  assert.equal(await co.onDependencyChanged("blob:x", 1), 2);
});

it("a failed asynchronous commit leaves no receipt and no rotation", async () => {
  const memory = asyncMemory();
  const co = createAsyncReplicaCoordinator({
    phases: [asyncPhase("publish", ["A"], { failCommit: true })],
    state: memory.port,
  });
  await assert.rejects(
    co.step({ now: 1, budget: { units: 1 } }),
    /commit failed/,
  );
  assert.deepEqual(memory.receipts, []);
  assert.equal(memory.disk().version, 0);
});

it("a synchronous port refuses an asynchronous checkpoint inside its transaction", async () => {
  let disk: ReplicaCoordinatorState = { owner: "a", version: 0, writers: {} };
  const port: ReplicaCoordinatorStatePort = {
    load: () => structuredClone(disk),
    commit(expected, next, checkpoint) {
      const result = checkpoint();
      disk = { ...next, owner: "a", version: disk.version + 1 };
      return { state: structuredClone(disk), result };
    },
  };
  const co = createAsyncReplicaCoordinator({
    phases: [asyncPhase("publish", ["A"])],
    state: port,
  });
  await assert.rejects(
    co.step({ now: 1, budget: { units: 1 } }),
    ReplicaAsyncCheckpointError,
  );
  assert.equal(disk.version, 0);
});

it("the synchronous factory keeps onDependencyChanged synchronous", () => {
  const handler: ReplicaPhaseHandler = {
    phase: "import",
    due: () => [],
    run: async () => ({ outcome: { tag: "retry", problem: "unknown" } }),
    commit: (_item, attempt, settle) => settle(attempt.outcome).outcome,
    earliest: () => undefined,
    wake: () => 3,
  };
  const co = createReplicaCoordinator({ phases: [handler] });
  assert.equal(co.onDependencyChanged("blob:x", 1), 3);
});
