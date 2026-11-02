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
  /** Byte estimate per writer's item; 1 when absent. */
  bytes: Record<string, number> = {},
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
          bytes: bytes[writer] ?? 1,
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

it("an item larger than the explicit byte budget does not block another writer's item that fits", async () => {
  // Review of #513 (P2): A needs 2 bytes, B needs 1, the budget is 1 byte.
  // A due() bounded by total=1 returns A only; B must still be served.
  const h = memory();
  const runs: string[] = [];
  for (let turn = 0; turn < 4; turn++) {
    // A new coordinator each turn: a process restart between steps.
    const handler = phase("publish", ["A", "B"], h.receipts, { A: 2, B: 1 });
    const run = handler.run;
    handler.run = (item, signal) => {
      runs.push(item.writer);
      return run(item, signal);
    };
    const co = createReplicaCoordinator({ state: h.port, phases: [handler] });
    const now = 1000 + turn;
    const report = await co.step({ now, budget: { units: 1, bytes: 1 } });
    assert.deepEqual(
      report.receipts.map((r) => r.key),
      ["B"],
      `turn ${turn}`,
    );
    // A is deferred intact: never run, never settled, due again now.
    assert.equal(report.nextWake, now);
    assert.equal(h.port.load().writers.publish, "B");
  }
  assert.deepEqual(runs, ["B", "B", "B", "B"]);
  assert.deepEqual(h.receipts, Array(4).fill("publish:B:progress"));
});

it("items deferred for bytes stay bounded: a backlog of oversized items is not scanned whole", async () => {
  const h = memory();
  const writers = Array.from(
    { length: 500 },
    (_, i) => `W${String(i).padStart(3, "0")}`,
  );
  const sizes = Object.fromEntries(writers.map((w) => [w, 2]));
  const handler = phase("publish", [...writers, "Z"], h.receipts, sizes);
  const pages: number[] = [];
  const due = handler.due;
  handler.due = (eligibility, limit) => {
    pages.push(limit.total);
    return due(eligibility, limit);
  };
  const co = createReplicaCoordinator({
    state: h.port,
    phases: [handler],
    quantum: { publish: 4 },
  });
  const report = await co.step({ now: 1000, budget: { units: 1, bytes: 1 } });
  // Z sits behind 500 oversized items: not reached within the bound this step.
  assert.deepEqual(report.receipts, []);
  assert.equal(report.nextWake, 1000);
  assert.ok(Math.max(...pages) <= 1 + 4 + 1, `pages ${pages.join(",")}`);
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

it("rejects zero/fractional/nonfinite polling intervals and timeouts, and invalid quanta", () => {
  // A zero quantum stays valid, as on main: it leaves its phase idle.
  assert.doesNotThrow(() =>
    createReplicaCoordinator({ phases: [], quantum: { publish: 0 } }),
  );
  for (const value of [0, -1, 0.5, NaN, Infinity]) {
    if (value !== 0)
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
  const handler = phase("publish", ["A", "B"], h.receipts);
  const due = handler.due;
  handler.due = (e, limit) =>
    due(e, limit).map((item) => ({ ...item, bytes: REPLICA_STEP_BYTES + 1 }));
  // Each item is over the default bound: one runs alone, the other waits.
  const report = await createReplicaCoordinator({ phases: [handler] }).step({
    now: 1000,
    budget: { units: 2 },
  });
  assert.equal(report.receipts.length, 1);
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

it("an abort between run settlement and checkpoint dispatch discards and releases the result", async () => {
  for (let depth = 1; depth <= 12; depth++) {
    const controller = new AbortController();
    const h = memory();
    const handler = phase("publish", ["A"], h.receipts);
    let releases = 0;
    let committedAfterAbort = false;
    const abortAfter = (remaining: number): void => {
      if (remaining) queueMicrotask(() => abortAfter(remaining - 1));
      else controller.abort();
    };
    handler.run = async () => {
      abortAfter(depth);
      return {
        outcome: { tag: "progress", receipt: { phase: "publish", key: "A" } },
        release: () => {
          releases++;
        },
      };
    };
    const commit = handler.commit;
    handler.commit = (item, attempt, settle) => {
      committedAfterAbort = controller.signal.aborted;
      return commit(item, attempt, settle);
    };
    await createReplicaCoordinator({ state: h.port, phases: [handler] }).step({
      now: 1000,
      budget: { units: 1 },
      signal: controller.signal,
    });
    await new Promise<void>((resolve) => queueMicrotask(resolve));
    assert.equal(committedAfterAbort, false, `microtask depth ${depth}`);
    assert.equal(releases, 1, `release at depth ${depth}`);
  }
});

it("abort after the durable commit does not erase its receipt or cursor", async () => {
  const h = memory();
  const controller = new AbortController();
  const handler = phase("publish", ["A"], h.receipts);
  handler.run = async () => ({
    outcome: { tag: "progress", receipt: { phase: "publish", key: "A" } },
    // Resource release is after the port transaction returned successfully.
    release: () => controller.abort(),
  });
  const report = await createReplicaCoordinator({
    state: h.port,
    phases: [handler],
  }).step({ now: 1000, budget: { units: 1 }, signal: controller.signal });
  assert.equal(controller.signal.aborted, true);
  assert.equal(report.receipts.length, 1);
  assert.equal(h.port.load().version, 1);
  assert.deepEqual(h.receipts, ["publish:A:progress"]);
});
