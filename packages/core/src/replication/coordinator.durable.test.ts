import assert from "node:assert/strict";
import { it } from "vitest";
import {
  createReplicaCoordinator,
  ReplicaCoordinatorConflict,
  REPLICA_REPORT_LIMIT,
  REPLICA_STEP_BYTES,
  type ReplicaAttempt,
  type ReplicaCoordinatorState,
  type ReplicaCoordinatorStatePort,
  type ReplicaPhaseHandler,
} from "./coordinator.js";
import type { ReplicaPhase } from "./outcome.js";
import { initialReplicaWorkState } from "./schedule.js";

function memory() {
  let disk: ReplicaCoordinatorState = { owner: "a", version: 0, writers: {} };
  const receipts: string[] = [];
  const port: ReplicaCoordinatorStatePort = {
    load: () => structuredClone(disk),
    commit(expected, next, checkpoint) {
      if (expected.owner !== disk.owner || expected.version !== disk.version)
        throw new ReplicaCoordinatorConflict();
      const before = [...receipts];
      try {
        const result = checkpoint();
        disk = structuredClone({
          ...next,
          owner: disk.owner,
          version: disk.version + 1,
        });
        return { state: structuredClone(disk), result };
      } catch (error) {
        receipts.splice(0, receipts.length, ...before);
        throw error;
      }
    },
  };
  return {
    port,
    receipts,
    recover: (owner: string) => {
      disk.owner = owner;
    },
  };
}

function phase(
  name: ReplicaPhase,
  writers: string[],
  receipts: string[],
): ReplicaPhaseHandler {
  return {
    phase: name,
    due(_eligibility, limit) {
      return [...writers]
        .sort(
          (a, b) =>
            Number(a <= (limit.after ?? "")) -
              Number(b <= (limit.after ?? "")) || a.localeCompare(b),
        )
        .slice(0, limit.total)
        .map((writer) => ({
          id: writer,
          phase: name,
          writer,
          state: { ...initialReplicaWorkState },
          bytes: 1,
        }));
    },
    run: async (item) => ({
      outcome: { tag: "progress", receipt: { phase: name, key: item.writer } },
    }),
    commit(item, attempt, settle) {
      const result = settle(attempt.plan?.() ?? attempt.outcome);
      receipts.push(`${name}:${item.writer}:${result.outcome.tag}`);
      return result.outcome;
    },
    earliest: () => 0,
  };
}

it("restart before every one-unit turn preserves phase and writer service", async () => {
  const h = memory();
  const trace: { served: string; cursor: ReplicaCoordinatorState }[] = [];
  // retain:A is continuously replenished; B and the later phases must not starve.
  for (let turn = 0; turn < 6; turn++) {
    const co = createReplicaCoordinator({
      state: h.port,
      phases: [
        phase("retain", ["A", "B"], h.receipts),
        phase("publish", ["A"], h.receipts),
        phase("import", ["Z"], h.receipts),
      ],
    });
    const report = await co.step({
      now: 1000 + turn,
      budget: { units: 1, bytes: 1 },
    });
    trace.push({
      served: `${report.receipts[0].phase}:${report.receipts[0].key}`,
      cursor: h.port.load(),
    });
  }
  assert.deepEqual(
    trace.map((row) => row.served),
    ["retain:A", "publish:A", "import:Z", "retain:B", "publish:A", "import:Z"],
  );
  assert.deepEqual(
    trace.map((row) => row.cursor.nextPhase),
    ["publish", "import", "retain", "publish", "import", "retain"],
  );
  assert.deepEqual(
    trace.map((row) => row.cursor.version),
    [1, 2, 3, 4, 5, 6],
  );
  assert.equal(trace[3].cursor.writers.retain, "B");
  assert.equal(trace[5].cursor.writers.import, "Z");
});

it("cyclic-after selection wraps after a writer which is absent from the page", async () => {
  const h = memory();
  h.port.commit(
    h.port.load(),
    { writers: { publish: "B" }, nextPhase: "publish" },
    () => undefined,
  );
  const co = createReplicaCoordinator({
    state: h.port,
    phases: [phase("publish", ["A", "C", "D"], h.receipts)],
  });
  const report = await co.step({ now: 1000, budget: { units: 1 } });
  assert.equal(report.receipts[0].key, "C");
});

it("abort discards the whole attempt and leaves the durable turn unchanged", async () => {
  const h = memory();
  const controller = new AbortController();
  const handler = phase("publish", ["A"], h.receipts);
  let release!: (attempt: ReplicaAttempt) => void;
  handler.run = async () =>
    new Promise((resolve) => {
      release = resolve;
      controller.abort();
    });
  const co = createReplicaCoordinator({ state: h.port, phases: [handler] });
  await co.step({ now: 1000, signal: controller.signal, budget: { units: 1 } });
  release({
    outcome: { tag: "progress", receipt: { phase: "publish", key: "late" } },
    plan: () => {
      h.receipts.push("late");
    },
  });
  await Promise.resolve();
  assert.equal(h.port.load().version, 0);
  assert.deepEqual(h.receipts, []);
});

it("a deadline Retry advances cursor and checkpoint together; a late plan cannot overwrite it", async () => {
  const h = memory();
  const handler = phase("publish", ["A"], h.receipts);
  let release!: (attempt: ReplicaAttempt) => void;
  handler.run = async () =>
    new Promise((resolve) => {
      release = resolve;
    });
  const co = createReplicaCoordinator({
    state: h.port,
    phases: [handler, phase("import", ["Z"], h.receipts)],
    deadlineMs: 5,
  });
  const report = await co.step({ now: 1000, budget: { units: 1 } });
  assert.equal(report.problems[0].problem, "deadline_exceeded");
  assert.equal(h.port.load().nextPhase, "import");
  assert.equal(h.port.load().writers.publish, "A");
  assert.equal(h.port.load().version, 1);
  release({
    outcome: { tag: "progress", receipt: { phase: "publish", key: "late" } },
    plan: () => {
      h.receipts.push("late");
    },
  });
  await Promise.resolve();
  const restarted = createReplicaCoordinator({
    state: h.port,
    phases: [handler, phase("import", ["Z"], h.receipts)],
  });
  await restarted.step({ now: 1001, budget: { units: 1 } });
  assert.deepEqual(h.receipts, ["publish:A:retry", "import:Z:progress"]);
});

it("a failed plan rolls back its effect and commits exactly one Retry/cursor revision", async () => {
  const h = memory();
  const handler = phase("publish", ["A"], h.receipts);
  handler.run = async () => ({
    outcome: { tag: "progress", receipt: { phase: "publish", key: "A" } },
    plan: () => {
      h.receipts.push("rolled-back");
      throw new Error("plan");
    },
  });
  const report = await createReplicaCoordinator({
    state: h.port,
    phases: [handler],
  }).step({ now: 1000, budget: { units: 1 } });
  assert.equal(report.problems[0].problem, "storage_failed");
  assert.deepEqual(h.receipts, ["publish:A:retry"]);
  assert.equal(h.port.load().version, 1);
});

it("rejects invalid budgets and clocks before hints, load, selection or effects", async () => {
  let reads = 0;
  const h = memory();
  const port = {
    ...h.port,
    load: () => {
      reads++;
      return h.port.load();
    },
  };
  const co = createReplicaCoordinator({
    state: port,
    phases: [],
    hint: {
      head: async () => {
        reads++;
        return 1n;
      },
    },
  });
  for (const invalid of [
    0,
    -1,
    0.5,
    NaN,
    Infinity,
    -Infinity,
    Number.MAX_SAFE_INTEGER + 1,
    null,
    "1",
  ] as number[]) {
    await assert.rejects(
      co.step({ now: 1, budget: { units: invalid } }),
      RangeError,
    );
    await assert.rejects(
      co.step({ now: 1, budget: { units: 1, bytes: invalid } }),
      RangeError,
    );
  }
  for (const invalid of [-1, 0.5, NaN, Infinity])
    await assert.rejects(
      co.step({ now: invalid, budget: { units: 1 } }),
      RangeError,
    );
  assert.equal(reads, 0);
});

it("rejects zero/fractional/nonfinite quanta, polling intervals and timeouts", () => {
  for (const value of [0, -1, 0.5, NaN, Infinity]) {
    assert.throws(
      () =>
        createReplicaCoordinator({ phases: [], quantum: { publish: value } }),
      RangeError,
    );
    assert.throws(
      () => createReplicaCoordinator({ phases: [], perWriter: value }),
      RangeError,
    );
    assert.throws(
      () => createReplicaCoordinator({ phases: [], hintRefreshMs: value }),
      RangeError,
    );
    assert.throws(
      () => createReplicaCoordinator({ phases: [], deadlineMs: value }),
      RangeError,
    );
  }
  assert.throws(
    () => createReplicaCoordinator({ phases: [], deadlineMs: 2_147_483_648 }),
    RangeError,
  );
});

it("omitted bytes has a finite bound and idle uses undefined, not null", async () => {
  const h = memory();
  const handler = phase("publish", ["A"], h.receipts);
  const due = handler.due;
  handler.due = (e, limit) =>
    due(e, limit).map((item) => ({ ...item, bytes: REPLICA_STEP_BYTES + 1 }));
  const report = await createReplicaCoordinator({ phases: [handler] }).step({
    now: 1000,
    budget: { units: 1 },
  });
  assert.deepEqual(report.receipts, []);
  assert.equal(report.nextWake, 1000);
  const idle = await createReplicaCoordinator({ phases: [] }).step({
    now: 1000,
    budget: { units: 1 },
  });
  assert.equal(idle.nextWake, undefined);
});

it("bounds diagnostics without losing checkpoint or cursor commits", async () => {
  const h = memory();
  const names: ReplicaPhase[] = [
    "retain",
    "publish",
    "import",
    "discover",
    "download",
    "fetch",
  ];
  const writers = Array.from({ length: 50 }, (_, n) =>
    String(n).padStart(3, "0"),
  );
  const report = await createReplicaCoordinator({
    state: h.port,
    phases: names.map((name) => phase(name, writers, h.receipts)),
  }).step({ now: 1000, budget: { units: 300 } });
  assert.equal(report.receipts.length, REPLICA_REPORT_LIMIT);
  assert.equal(report.diagnosticsTruncated, true);
  assert.equal(h.receipts.length, 300);
  assert.equal(h.port.load().version, 300);
});

it("a concurrent step on the same coordinator is rejected without corrupting its clock", async () => {
  const h = memory();
  const handler = phase("publish", ["A"], h.receipts);
  let release!: () => void;
  handler.run = async () => {
    await new Promise<void>((resolve) => {
      release = resolve;
    });
    return { outcome: { tag: "retry", problem: "download_failed" } };
  };
  const co = createReplicaCoordinator({ state: h.port, phases: [handler] });
  const first = co.step({ now: 1000, budget: { units: 1 } });
  await Promise.resolve();
  await assert.rejects(
    co.step({ now: 9000, budget: { units: 1 } }),
    ReplicaCoordinatorConflict,
  );
  release();
  assert.equal((await first).problems[0].nextEligible, 2000);
});

it("a late attempt from a lost owner cannot commit a plan or fallback Retry", async () => {
  const h = memory();
  const handler = phase("publish", ["A"], h.receipts);
  let release!: (attempt: ReplicaAttempt) => void;
  handler.run = async () =>
    new Promise((resolve) => {
      release = resolve;
    });
  const old = createReplicaCoordinator({ state: h.port, phases: [handler] });
  const pending = old.step({ now: 1000, budget: { units: 1 } });
  await Promise.resolve();
  h.recover("b");
  const next = createReplicaCoordinator({
    state: h.port,
    phases: [phase("import", ["Z"], h.receipts)],
  });
  await next.step({ now: 1001, budget: { units: 1 } });
  release({
    outcome: { tag: "progress", receipt: { phase: "publish", key: "stale" } },
    plan: () => {
      h.receipts.push("stale");
    },
  });
  await assert.rejects(pending, ReplicaCoordinatorConflict);
  assert.deepEqual(h.receipts, ["import:Z:progress"]);
  assert.equal(h.port.load().owner, "b");
  assert.equal(h.port.load().version, 1);
});
