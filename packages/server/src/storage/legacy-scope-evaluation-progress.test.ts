import type * as Threads from "node:worker_threads";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { afterEach, expect, it, vi } from "vitest";
import { initializeDatabase } from "./index-schema.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import {
  trackLegacyScopeMutations,
  type LegacyRevalidationState,
} from "./legacy-scope-revalidation-state.js";
import {
  createLegacyEvaluationWorker,
  type LegacyEvaluationJob,
} from "./legacy-scope-evaluation.js";

// Only projection time is modeled: the production host, timers, SQLite recovery
// and revision-fenced marker publication run unchanged.
const control = vi.hoisted(() => ({
  delays: new Map<string, number>(),
  finish: (_scope: string) => {},
  starts: [] as string[],
}));
vi.mock("node:worker_threads", async (original) => ({
  ...(await original<typeof Threads>()),
  Worker: class extends EventEmitter {
    timer?: ReturnType<typeof setTimeout>;
    stopped = false;
    postMessage(job: LegacyEvaluationJob) {
      const run = (index: number) => {
        const scope = job.scopes[index];
        if (!scope) {
          this.emit("message", { wallMs: 0, peakRssKiB: 1, refused: [] });
          return;
        }
        control.starts.push(scope);
        this.timer = setTimeout(
          () => {
            if (this.stopped) return;
            control.finish(scope);
            run(index + 1);
          },
          control.delays.get(scope) ?? 20_000,
        );
      };
      run(0);
    }
    async terminate() {
      this.stopped = true;
      clearTimeout(this.timer);
      return 0;
    }
  },
}));
const closers: (() => Promise<void> | void)[] = [];
afterEach(async () => {
  for (const close of closers.splice(0).reverse()) await close();
  vi.useRealTimers();
  control.delays.clear();
  control.starts = [];
});
function fixture() {
  vi.useFakeTimers({ toFake: ["Date", "setTimeout", "clearTimeout"] });
  vi.setSystemTime(1000);
  const root = mkdtempSync(join(homedir(), ".tmp", "swr-progress-"));
  closers.push(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, "index.db");
  const raw = initializeDatabase(path);
  const store = createSqliteRecordStore(raw);
  store.registerConnection({
    instance: "i",
    sourceId: "synthetic",
    method: "synthetic",
    label: "",
  });
  const scopes = ["synthetic.a", "synthetic.b", "synthetic.c", "synthetic.d"];
  for (const scope of scopes) {
    raw
      .prepare(
        "INSERT INTO data_files(path,scope,collected_at) VALUES (?,?,'2026-01-01')",
      )
      .run(scope, scope);
    raw
      .prepare(
        "INSERT INTO legacy_scope_takeovers(scope,instance,generation,method,superseded_path,superseded_version,superseded_cas_revision,superseded_collected_at) VALUES (?,'i',1,'synthetic',?,1,1,'2026-01-01')",
      )
      .run(scope, scope);
  }
  let state = trackLegacyScopeMutations(raw, { ceilingMs: 180_000 });
  state.ensureDirty();
  let db = raw;
  closers.push(() => db.close());
  // Model the worker's successful revision-fenced confirmation, not host progress.
  let captured = state.revision("i");
  control.finish = (scope) => {
    state.complete("i", scope, captured);
  };
  const job = {
    database: path,
    dataDir: root,
    owner: "synthetic",
    replication: false,
    declarations: [],
    configuredMethods: [],
    optInMethods: [],
    coverageThresholds: undefined,
    instance: "i",
    scopes,
  };
  function openWorker() {
    const worker = createLegacyEvaluationWorker({ state });
    closers.push(() => worker.stop());
    return worker;
  }
  return {
    scopes,
    job,
    openWorker,
    get state() {
      return state;
    },
    restart() {
      db.close();
      db = initializeDatabase(path);
      state = trackLegacyScopeMutations(db, { ceilingMs: 180_000 });
      captured = state.revision("i");
      state.ensureDirty();
    },
  };
}
it("gives each scope its own budget so four slow scopes finish within the ceiling", async () => {
  const f = fixture();
  const result = f.openWorker().evaluate(f.job);
  const settled = result.catch((error: unknown) => error);
  await vi.advanceTimersByTimeAsync(80_001);
  expect(await settled).not.toBeInstanceOf(Error);
  for (const scope of f.scopes)
    expect(f.state.status("i", scope)?.dirty_since).toBeNull();
  expect(f.state.diagnostics()).toEqual([]);
});
it("persists progress so restart starts the unfinished tail before the completed prefix", async () => {
  const f = fixture();
  const worker = f.openWorker();
  const interrupted = worker.evaluate(f.job).catch(() => {});
  await vi.advanceTimersByTimeAsync(45_000);
  await worker.stop();
  await interrupted;
  f.restart();
  control.starts = [];
  const candidate = f.state.candidates()[0];
  const result = f
    .openWorker()
    .evaluate({ ...f.job, scopes: candidate.scopes });
  const settled = result.catch((error: unknown) => error);
  await vi.advanceTimersByTimeAsync(40_001);
  expect(control.starts.slice(0, 2)).toEqual(f.scopes.slice(2));
  for (const scope of f.scopes.slice(2))
    expect(f.state.status("i", scope)?.dirty_since).toBeNull();
  expect(f.state.diagnostics()).toEqual([]);
  await vi.advanceTimersByTimeAsync(40_000);
  expect(await settled).not.toBeInstanceOf(Error);
});
it("continues after a scope times out and acknowledges only the attempted revision", async () => {
  const f = fixture();
  control.delays.set(f.scopes[0], 75_000);
  const result = f
    .openWorker()
    .evaluate(f.job)
    .catch((error: unknown) => error);
  await vi.advanceTimersByTimeAsync(120_001);
  expect(await result).toBeInstanceOf(Error);
  expect(f.state.status("i", f.scopes[0])?.dirty_since).toBe(1000);
  expect(f.state.status("i", f.scopes[3])?.dirty_since).toBeNull();
  expect(f.state.candidates()[0].scopes.at(-1)).toBe(f.scopes[3]);
});
it("does not acknowledge work interrupted by a newer dependency revision", async () => {
  const f = fixture();
  const result = f.openWorker().evaluate({ ...f.job, scopes: [f.scopes[0]] });
  await vi.advanceTimersByTimeAsync(10_000);
  f.state.markDirty();
  await vi.advanceTimersByTimeAsync(10_001);
  await result;
  expect(f.state.status("i", f.scopes[0])?.dirty_since).toBe(1000);
  expect(
    f.state.db
      .prepare(
        "SELECT attempted_revision FROM legacy_scope_revalidation_scopes WHERE scope=?",
      )
      .pluck()
      .get(f.scopes[0]),
  ).toBeNull();
});
it("measures boot invalidation for ten thousand tracked scopes", () => {
  const root = mkdtempSync(join(homedir(), ".tmp", "swr-boot-"));
  closers.push(() => rmSync(root, { recursive: true, force: true }));
  const path = join(root, "index.db");
  const raw = initializeDatabase(path);
  trackLegacyScopeMutations(raw, { ceilingMs: 1_800_000 });
  raw.transaction(() => {
    const insert = raw.prepare(
      "INSERT INTO legacy_scope_revalidation_scopes(instance,scope,dirty_since,ceiling_ms,confirmed_revision) VALUES (?,?,NULL,1800000,0)",
    );
    for (let i = 0; i < 10_000; i++)
      insert.run(`instance-${i % 100}`, `scope-${i}`);
  })();
  raw.close();
  const db = initializeDatabase(path);
  try {
    const started = performance.now();
    const state: LegacyRevalidationState = trackLegacyScopeMutations(db, {
      ceilingMs: 1_800_000,
    });
    const wallMs = performance.now() - started;
    expect(
      state.db
        .prepare(
          "SELECT count(*) FROM legacy_scope_revalidation_scopes WHERE dirty_since IS NOT NULL",
        )
        .pluck()
        .get(),
    ).toBe(10_000);
    console.log(
      JSON.stringify({ bootDirtyScopes: 10_000, instances: 100, wallMs }),
    );
  } finally {
    db.close();
  }
});
