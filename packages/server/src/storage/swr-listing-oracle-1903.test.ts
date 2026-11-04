// Independent oracle: oracles/swr-listing-oracle-tests-1903.md, main 2df2ae99.
// Case IDs retain the independent design's numbering. Only explicit Lead rulings
// change that design; each such change is marked beside its assertions.
import type * as WorkerThreads from "node:worker_threads";
import { EventEmitter } from "node:events";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import pino from "pino";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createLegacyScopeView,
  type LegacyCoverageVerdict,
} from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "@opendatalabs/personal-server-ts-core/api";
import { createNodeDataStorage } from "./node-data-storage.js";
import { createScopeDeletionTracker } from "@opendatalabs/personal-server-ts-core/sync";
import { createApp, type AppDeps } from "../app.js";
import { initializeDatabase } from "./index-schema.js";
import { createIndexManager } from "./index-manager.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createLegacyScopeAuthority } from "./legacy-scope-authority.js";
import { trackLegacyScopeMutations } from "./legacy-scope-revalidation-state.js";
import { createLegacyScopeRevalidator } from "./legacy-scope-revalidator.js";
import {
  createLegacyEvaluationWorker,
  freshCoverageAuthority,
} from "./legacy-scope-evaluation.js";

// The production worker host and its deadline run unchanged. This port models a
// CPU worker that never replies, then a responsive replacement, without sleeps.
const workerControl = vi.hoisted(() => ({
  block: true,
  bodies: 0,
  active: 0,
  max: 0,
}));
vi.mock("node:worker_threads", async (original) => {
  const actual = await original<typeof WorkerThreads>();
  return {
    ...actual,
    Worker: class extends EventEmitter {
      busy = false;
      postMessage() {
        this.busy = true;
        workerControl.bodies++;
        workerControl.active++;
        workerControl.max = Math.max(workerControl.max, workerControl.active);
        if (!workerControl.block)
          queueMicrotask(() => {
            if (!this.busy) return;
            this.busy = false;
            workerControl.active--;
            this.emit("message", { wallMs: 0, peakRssKiB: 0, refused: [] });
          });
      }
      async terminate() {
        if (this.busy) {
          this.busy = false;
          workerControl.active--;
        }
        return 0;
      }
    },
  };
});
const S = "chatgpt.conversations",
  I = "oracle-instance",
  G = 7;
const SOURCE = "https://registry.pdpp.dev/sources/chatgpt";
const S_MIN = 900_000,
  CEILING = 1_800_000;
const T0 = Date.parse("2026-10-01T00:00:00.000Z");
const text = "Synthetic oracle text";
const closers: (() => Promise<void>)[] = [];
const releases: (() => void)[] = [];
function barrier() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  releases.push(release);
  return { promise, release };
}
beforeEach(() => {
  vi.useFakeTimers({
    toFake: [
      "Date",
      "setInterval",
      "clearInterval",
      "setTimeout",
      "clearTimeout",
    ],
  });
  vi.setSystemTime(T0);
});
afterEach(async () => {
  while (releases.length) releases.pop()!();
  while (closers.length) await closers.pop()!();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

async function fixture() {
  const parent = join(homedir(), ".tmp");
  await mkdir(parent, { recursive: true });
  const root = await mkdtemp(join(parent, "swr-oracle-1903-"));
  const path = join(root, "index.db");
  let db = initializeDatabase(path);
  let state = trackLegacyScopeMutations(db, { ceilingMs: CEILING });
  let store = createSqliteRecordStore(state.db);
  const loader = vi.fn(async (head: { path: string }) =>
    JSON.parse(await readFile(join(root, head.path), "utf8")),
  );
  const configured = (source: string) =>
    source === SOURCE ? ["chatgpt"] : ["oura"];
  let declarationVersion = 1;
  const declarations = {
    forInstance: (_instance: string, stream: string) => ({
      name: stream,
      semantics: "mutable_state" as const,
      primaryKey: ["id"],
      cursorField: "emitted_at",
      requiredFields: ["id"],
      schema: { type: "object", $id: `oracle/${stream}/${declarationVersion}` },
    }),
  };
  let authority = createLegacyScopeAuthority(state.db, state);
  let view = createLegacyScopeView({
    authority,
    declarations,
    records: store,
    configuredMethods: configured,
    readLegacyHead: loader,
  });
  const deletion = createScopeDeletionTracker();
  const charge = vi.fn();
  function app() {
    return createApp({
      logger: pino({ level: "silent" }),
      version: "oracle",
      startedAt: new Date(),
      indexManager: createIndexManager(state.db),
      hierarchyOptions: { dataDir: root },
      serverOrigin: "http://localhost:8080",
      serverOwner: "0x1111111111111111111111111111111111111111",
      devToken: "oracle-owner",
      gateway: { payForOperation: charge },
      accessLogWriter: { write: async () => {} },
      accessLogReader: {
        read: async () => ({ logs: [], total: 0, limit: 50, offset: 0 }),
      },
      legacyScopeView: view,
      scopeDeletions: deletion,
    } as unknown as AppDeps);
  }
  const request = (uri: string) =>
    app().request(uri, { headers: { authorization: "Bearer oracle-owner" } });
  async function listed(uri = "/v1/data") {
    const response = await request(uri);
    expect(response.status).toBe(200);
    return response.json();
  }
  function register(
    instance = I,
    generation = G,
    source = SOURCE,
    method = "chatgpt",
  ) {
    store.registerConnection({
      instance,
      sourceId: source,
      method,
      label: "Synthetic",
    });
    for (let g = 1; g < generation; g++)
      store.resetInstanceBinding({
        instance,
        expectedMethod: method,
        expectedGeneration: g,
        nextMethod: method,
      });
  }
  function put(
    stream: string,
    data: Record<string, unknown>,
    instance = I,
    generation = G,
    method = "chatgpt",
  ) {
    const result = store.ingestBatch(
      [
        {
          instance,
          stream,
          key: String(data.id),
          data,
          emitted_at: "2026-09-01T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method, generation },
    );
    expect(result.rejected).toEqual([]);
  }
  const conversation = (id: string) => ({
    id,
    title: `${text} ${id}`,
    create_time: "2026-09-01T00:00:00Z",
    update_time: "2026-09-01T00:00:00Z",
    current_node: `m-${id}`,
    message_count_on_current_branch: 1,
  });
  const message = (id: string, content: string | null = text) => ({
    id: `m-${id}`,
    conversation_id: id,
    parent_id: null,
    role: "assistant",
    content_type: "text",
    content,
    create_time: "2026-09-01T00:00:00Z",
    model_slug: "synthetic",
    on_current_branch: true,
  });
  function recordTime() {
    // The fixture supplies deterministic time to SQLite's persisted timestamp
    // field as well as JS timers. No coverage value or fence is replaced.
    db.function("oracle_now", () => new Date().toISOString());
    db.exec(`CREATE TEMP TRIGGER oracle_insert_clock AFTER INSERT ON legacy_scope_takeover_verdicts BEGIN UPDATE legacy_scope_takeover_verdicts SET evaluated_at=oracle_now() WHERE scope=NEW.scope AND instance=NEW.instance AND generation=NEW.generation; END;
      CREATE TEMP TRIGGER oracle_update_clock AFTER UPDATE ON legacy_scope_takeover_verdicts WHEN NEW.evaluated_at<>oracle_now() BEGIN UPDATE legacy_scope_takeover_verdicts SET evaluated_at=oracle_now() WHERE scope=NEW.scope AND instance=NEW.instance AND generation=NEW.generation; END;`);
  }
  recordTime();
  register();
  for (const id of ["A", "B"]) {
    put("conversations", conversation(id));
    put("messages", message(id));
  }
  const initial = await view.readLatest(S);
  expect(initial.kind).toBe("canonical");
  if (initial.kind !== "canonical") throw Error("oracle fixture projection");
  await writeFile(join(root, "legacy.json"), JSON.stringify(initial.envelope));
  state.db
    .prepare(
      "INSERT INTO data_files(path,scope,collected_at,size_bytes) VALUES ('legacy.json',?,?,1)",
    )
    .run(S, "2026-09-01T00:00:00.000Z");
  expect((await view.readLatest(S)).kind).toBe("canonical");
  const origin = () => authority.verdictFor(S)[0]!.evaluatedAt;
  const head = () => authority.eligibleLegacyHead(S)!;
  function snapshot(covered = true) {
    const verdict = authority.verdictFor(S)[0]!;
    const coverage = authority.cachedVerdict(
      S,
      I,
      G,
      verdict.legacyVersionId,
      verdict.canonicalCursor,
    )!;
    return {
      head: head(),
      method: "chatgpt",
      proof: {
        instance: I,
        generation: G,
        writeClock: authority.writeClock(),
        arrivalRevision: authority.arrivalRevision(),
        dependencyRevision: state.revision(I),
        canonicalCursor: verdict.canonicalCursor,
        coverage: {
          ...coverage,
          covered,
          reason: covered ? null : "missing_entity",
          missingEntityCount: covered ? 0 : 1,
        } as LegacyCoverageVerdict,
        cached: false as const,
      },
    };
  }
  async function fresh(scope = S, instance = I) {
    const revision = state.revision(instance);
    const current = createLegacyScopeView({
      authority: freshCoverageAuthority(
        authority,
        () => state.revision(instance) === revision,
      ),
      records: store,
      declarations,
      configuredMethods: configured,
      readLegacyHead: loader,
    });
    const result = await current.readLatest(scope);
    state.complete(instance, scope, revision);
    return result;
  }
  function scheduler(
    evaluate: (instance: string, scopes: readonly string[]) => Promise<void>,
    options: { policy?: () => string; failure?: () => void } = {},
  ) {
    let policy = options.policy?.() ?? "";
    const scheduler = createLegacyScopeRevalidator({
      evaluate,
      candidates: () => state.candidates(),
      fingerprint: () => {
        const next = options.policy?.() ?? "";
        if (next !== policy) {
          state.markDirty();
          policy = next;
        }
        return `${state.fingerprint()}:${policy}`;
      },
      onSweep: () => state.ensureDirty(),
      onFailure: (instance, scopes) => {
        state.fail(instance, scopes);
        options.failure?.();
      },
      intervalMs: S_MIN,
      logger: { warn: vi.fn() },
    });
    closers.push(() => scheduler.stop());
    return scheduler;
  }
  async function reopen() {
    db.close();
    db = initializeDatabase(path);
    state = trackLegacyScopeMutations(db, { ceilingMs: CEILING });
    store = createSqliteRecordStore(state.db);
    authority = createLegacyScopeAuthority(state.db, state);
    view = createLegacyScopeView({
      authority,
      records: store,
      declarations,
      configuredMethods: configured,
      readLegacyHead: loader,
    });
    recordTime();
  }
  closers.push(async () => {
    if (db.open) db.close();
    await rm(root, { recursive: true, force: true });
  });
  return {
    get db() {
      return state.db;
    },
    get state() {
      return state;
    },
    get store() {
      return store;
    },
    get authority() {
      return authority;
    },
    get view() {
      return view;
    },
    root,
    path,
    loader,
    register,
    put,
    message,
    conversation,
    origin,
    head,
    snapshot,
    fresh,
    scheduler,
    reopen,
    request,
    listed,
    deletion,
    charge,
    declarationKey: () => String(declarationVersion),
    changeDeclaration: () => {
      declarationVersion++;
    },
  };
}

// Every test below corresponds to an oracle case, not a local implementation test.
describe("independent SWR listing oracle 1903", () => {
  it("01 unrelated_write_keeps_taken_over_scope", async () => {
    const h = await fixture(),
      before = h.origin(),
      reads = h.loader.mock.calls.length;
    h.register(
      "unrelated",
      1,
      "https://registry.pdpp.dev/sources/oura",
      "oura",
    );
    vi.setSystemTime(T0 + 60_000);
    h.put(
      "activity",
      { id: "o", day: "2026-09-01", score: 80 },
      "unrelated",
      1,
      "oura",
    );
    const gate = barrier(),
      evaluate = vi.fn(() => gate.promise),
      q = h.scheduler(evaluate);
    q.start();
    await Promise.resolve();
    expect(
      (await h.listed()).scopes.filter((s: { scope: string }) => s.scope === S),
    ).toHaveLength(1);
    expect(h.view.listingFor(S).kind).toBe("canonical");
    expect(evaluate).toHaveBeenCalledTimes(1);
    expect(h.loader).toHaveBeenCalledTimes(reads);
    expect(h.origin()).toBe(before);
    gate.release();
    await q.idle();
  });
  it("02 real_loss_unlists_after_committed_recheck", async () => {
    const h = await fixture();
    vi.setSystemTime(T0 + 60_000);
    h.put("messages", h.message("B", null));
    expect(
      (await h.listed()).scopes.some((s: { scope: string }) => s.scope === S),
    ).toBe(true);
    expect((await h.fresh()).kind).toBe("refused");
    expect(h.authority.verdictFor(S)[0]).toMatchObject({
      verdict: "not_covered",
    });
    expect(
      h.authority.verdictFor(S)[0]!.reason!.missingEntityCount,
    ).toBeGreaterThan(0);
    expect(
      (await h.listed()).scopes.some((s: { scope: string }) => s.scope === S),
    ).toBe(false);
    expect(h.view.listingFor(S).kind).toBe("refused");
    expect((await h.request(`/v1/data/${S}`)).status).toBe(503);
  });
  it("03 two_same_instance_triggers_single_flight", async () => {
    const h = await fixture(),
      before = barrier(),
      captured: string[][] = [];
    let active = 0,
      max = 0;
    const other = "chatgpt.other";
    h.db
      .prepare(
        "INSERT INTO data_files(path,scope,collected_at,size_bytes) VALUES ('other.json',?,'2026-09-01T00:00:00.000Z',1)",
      )
      .run(other);
    const proof = h.snapshot().proof;
    expect(
      h.authority.confirmRead(
        other,
        h.authority.eligibleLegacyHead(other),
        () => true,
        "chatgpt",
        proof,
      ),
    ).toBe(true);
    const q = h.scheduler(async (_instance, scopes) => {
      active++;
      max = Math.max(max, active);
      await before.promise;
      captured.push([...scopes]);
      for (const scope of scopes) {
        const covered = scope === S;
        expect(
          h.authority.confirmRead(
            scope,
            h.authority.eligibleLegacyHead(scope),
            () => true,
            "chatgpt",
            {
              ...proof,
              coverage: {
                ...proof.coverage,
                covered,
                reason: covered ? null : "missing_entity",
                missingEntityCount: covered ? 0 : 1,
              },
            },
          ),
        ).toBe(true);
      }
      active--;
    });
    q.enqueue(I, [S]);
    q.enqueue(I, ["chatgpt.other"]);
    await Promise.resolve();
    expect(active).toBe(1);
    before.release();
    await q.idle();
    expect(max).toBe(1);
    expect(captured).toEqual([[S, other]]);
    expect(h.authority.verdictFor(S)[0]?.verdict).toBe("covered");
    expect(h.authority.verdictFor(other)[0]?.verdict).toBe("not_covered");
  });
  it("04 trigger_during_evaluation_requires_one_followup", async () => {
    const h = await fixture(),
      gate = barrier(),
      seen: number[] = [],
      published: boolean[] = [];
    const q = h.scheduler(async () => {
      const revision = h.state.revision(I);
      seen.push(revision);
      if (seen.length === 1) await gate.promise;
      published.push(h.state.complete(I, S, revision));
    });
    q.enqueue(I, [S]);
    await Promise.resolve();
    for (let n = 0; n < 3; n++) {
      h.put("messages", h.message("A", `${text} ${n}`));
      q.enqueue(I, [S]);
    }
    const latest = h.state.revision(I);
    gate.release();
    await q.idle();
    expect(seen).toHaveLength(2);
    expect(seen[1]).toBe(latest);
    expect(published).toEqual([false, true]);
  });
  it("05 timed_out_instance_preserves_verdict_and_cannot_defeat_ceiling", async () => {
    // ruled by lead 11-03: retain serialization; require deadline, no fabricated
    // promotion on timeout, and listing expiry independent of worker completion.
    const h = await fixture(),
      original = h.authority.verdictFor(S);
    h.state.markDirty();
    Object.assign(workerControl, { block: true, bodies: 0, active: 0, max: 0 });
    const worker = createLegacyEvaluationWorker({ timeoutMs: 100 });
    closers.push(() => worker.stop());
    const finished: string[] = [],
      failed = vi.fn();
    const q = h.scheduler(
      async (instance) => {
        await worker.evaluate({
          database: h.path,
          dataDir: h.root,
          owner: "synthetic-owner",
          replication: false,
          declarations: [],
          configuredMethods: [[SOURCE, ["chatgpt"]]],
          optInMethods: [],
          coverageThresholds: undefined,
          instance,
          scopes: [S],
        });
        finished.push(instance);
      },
      { failure: failed },
    );
    q.enqueue(I, [S]);
    q.enqueue("I2", ["other.scope"]);
    await Promise.resolve();
    expect(workerControl.bodies).toBe(1);
    workerControl.block = false;
    await vi.advanceTimersByTimeAsync(100);
    await q.idle();
    expect(failed).toHaveBeenCalledTimes(1);
    expect(finished).toEqual(["I2"]);
    expect(workerControl.max).toBe(1);
    expect(h.authority.verdictFor(S)).toEqual(original);
    expect(h.state.status(I, S)?.dirty_since).toBe(T0);
    vi.setSystemTime(T0 + CEILING - 1);
    expect(h.view.listingFor(S).kind).toBe("canonical");
    vi.setSystemTime(T0 + CEILING);
    expect(h.view.listingFor(S).kind).toBe("refused");
    h.put("messages", h.message("B", null));
    expect((await h.fresh()).kind).toBe("refused");
    const negative = h.authority.verdictFor(S);
    workerControl.block = true;
    q.enqueue(I, [S]);
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(100);
    await q.idle();
    expect(h.authority.verdictFor(S)).toEqual(negative);
    expect(h.authority.verdictFor(S)[0]?.verdict).toBe("not_covered");
    expect(finished).toEqual(["I2"]);
  });
  it("06 restart_preserves_stale_since_and_deadline", async () => {
    // ruled by lead 11-03: deadline is first stale mutation + 30 min, not proof age.
    const h = await fixture(),
      proof = h.origin();
    vi.setSystemTime(T0 + 5 * 60_000);
    h.put("messages", h.message("A"));
    const dirty = h.state.status(I, S)?.dirty_since;
    vi.setSystemTime(T0 + 20 * 60_000);
    await h.reopen();
    vi.setSystemTime(T0 + 29 * 60_000);
    const gate = barrier(),
      run = vi.fn(() => gate.promise),
      q = h.scheduler(run);
    q.start();
    await Promise.resolve();
    expect(h.view.listingFor(S).kind).toBe("canonical");
    expect(h.origin()).toBe(proof);
    expect(h.state.status(I, S)?.dirty_since).toBe(dirty);
    expect(run).toHaveBeenCalledTimes(1);
    await h.listed();
    await h.listed();
    expect(run).toHaveBeenCalledTimes(1);
    vi.setSystemTime(T0 + 35 * 60_000);
    expect(h.view.listingFor(S).kind).toBe("refused");
    gate.release();
    await q.idle();
  });
  it("07 no_mutation_does_not_expire_a_clean_proof", async () => {
    // ruled by lead 11-03: no mutation means no stale window and no age expiry.
    const h = await fixture(),
      original = h.authority.verdictFor(S);
    for (const delta of [CEILING - 1, CEILING, CEILING + 1]) {
      vi.setSystemTime(T0 + delta);
      expect(h.view.listingFor(S).kind).toBe("canonical");
    }
    expect(h.authority.verdictFor(S)).toEqual(original);
    expect(h.state.status(I, S)?.dirty_since).toBeNull();
  });
  it("08 repeated_dirty_events_do_not_slide_deadline", async () => {
    // ruled by lead 11-03: first stale mutation at +1 min anchors expiry at +31 min.
    const h = await fixture(),
      proof = h.origin();
    for (const minute of [1, 10, 20, 29]) {
      vi.setSystemTime(T0 + minute * 60_000);
      h.put("messages", h.message("A"));
    }
    expect(h.state.status(I, S)?.dirty_since).toBe(T0 + 60_000);
    expect(h.origin()).toBe(proof);
    vi.setSystemTime(T0 + 31 * 60_000);
    expect(h.view.listingFor(S).kind).toBe("refused");
    await h.reopen();
    expect(h.view.listingFor(S).kind).toBe("refused");
  });
  it("09 successful_revalidation_clears_staleness_until_the_next_mutation", async () => {
    // ruled by lead 11-03: success clears stale-since; the next mutation, not
    // successful-proof age, starts a new 30-minute budget.
    const h = await fixture();
    vi.setSystemTime(T0 + 60_000);
    h.put("messages", h.message("A"));
    vi.setSystemTime(T0 + 14 * 60_000);
    expect((await h.fresh()).kind).toBe("canonical");
    expect(h.state.status(I, S)?.dirty_since).toBeNull();
    expect(h.origin()).toBe(new Date(T0 + 14 * 60_000).toISOString());
    vi.setSystemTime(T0 + 44 * 60_000);
    expect(h.view.listingFor(S).kind).toBe("canonical");
    h.put("messages", h.message("A"));
    vi.setSystemTime(T0 + 74 * 60_000 - 1);
    expect(h.view.listingFor(S).kind).toBe("canonical");
    vi.setSystemTime(T0 + 74 * 60_000);
    expect(h.view.listingFor(S).kind).toBe("refused");
  });
  it("10 failed_or_cancelled_recheck_does_not_renew", async () => {
    // ruled by lead 11-03: failure budget ends 30 min after first stale mutation.
    const h = await fixture(),
      proof = h.origin(),
      first = barrier(),
      second = barrier();
    h.state.markDirty();
    const run = vi
      .fn()
      .mockImplementationOnce(async () => {
        await first.promise;
        throw Error("synthetic unavailable storage");
      })
      .mockImplementationOnce(async () => {
        await second.promise;
        throw Error("synthetic unavailable storage");
      });
    const q = h.scheduler(run);
    q.start();
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(14 * 60_000);
    first.release();
    await q.idle();
    expect(run).toHaveBeenCalledTimes(1);
    expect(h.origin()).toBe(proof);
    expect(h.state.status(I, S)?.dirty_since).toBe(T0);
    expect(h.authority.verdictFor(S)[0]?.verdict).toBe("covered");
    await vi.advanceTimersByTimeAsync(14 * 60_000);
    second.release();
    await q.idle();
    expect(run).toHaveBeenCalledTimes(2);
    expect(h.origin()).toBe(proof);
    expect(h.state.status(I, S)?.dirty_since).toBe(T0);
    vi.setSystemTime(T0 + CEILING - 1);
    expect(h.view.listingFor(S).kind).toBe("canonical");
    vi.setSystemTime(T0 + CEILING);
    expect(h.view.listingFor(S).kind).toBe("refused");
    expect(h.state.diagnostics()).toMatchObject([
      { reason: "evaluation_failing", error_count: 2 },
    ]);
  });
  it("11 sweep_runs_with_no_gets", async () => {
    const h = await fixture(),
      run = vi.fn(async () => {}),
      q = h.scheduler(run);
    q.start();
    await q.idle();
    run.mockClear();
    await vi.advanceTimersByTimeAsync(S_MIN);
    await q.idle();
    expect(run).toHaveBeenCalledTimes(1);
    q.enqueue(I, [S]);
    await vi.advanceTimersByTimeAsync(S_MIN);
    await q.idle();
    expect(run.mock.calls.length).toBeGreaterThanOrEqual(2);
    expect(h.loader).toHaveBeenCalledTimes(1);
  });
  it.each([
    [12, false, true],
    [13, true, false],
  ] as const)(
    "%i late_old_result_cannot_overwrite_newer_evidence",
    async (_id, oldCovered, newCovered) => {
      const h = await fixture(),
        old = h.snapshot(oldCovered);
      h.put("messages", newCovered ? h.message("A") : h.message("B", null));
      expect((await h.fresh()).kind).toBe(newCovered ? "canonical" : "refused");
      const accepted = h.authority.verdictFor(S);
      expect(accepted[0]?.canonicalCursor).not.toBe(old.proof.canonicalCursor);
      expect(accepted[0]?.verdict).toBe(newCovered ? "covered" : "not_covered");
      expect(
        h.authority.confirmRead(S, old.head, () => true, old.method, old.proof),
      ).toBe(false);
      expect(h.authority.verdictFor(S)).toEqual(accepted);
      expect(h.view.listingFor(S).kind).toBe(
        newCovered ? "canonical" : "refused",
      );
    },
  );
  it("14 new_legacy_head_invalidates_kept_verdict", async () => {
    const h = await fixture(),
      old = h.snapshot();
    h.db
      .prepare(
        "UPDATE data_files SET id=id+100,version=version+1,cas_revision=cas_revision+1 WHERE scope=?",
      )
      .run(S);
    expect(h.view.listingFor(S).kind).not.toBe("canonical");
    expect(
      h.authority.confirmRead(S, old.head, () => true, old.method, old.proof),
    ).toBe(false);
    expect(h.authority.eligibleLegacyHead(S)?.id).not.toBe(old.head.id);
    expect(h.authority.eligibleLegacyHead(S)?.casRevision).not.toBe(
      old.head.casRevision,
    );
  });
  it.each(["reset", "generation", "connection"] as const)(
    "15 reset_generation_and_connection_invalidate: %s",
    async (kind) => {
      const h = await fixture(),
        old = h.snapshot();
      if (kind === "reset") h.view.resetTakeover(S);
      else if (kind === "generation")
        h.store.resetInstanceBinding({
          instance: I,
          expectedMethod: "chatgpt",
          expectedGeneration: G,
          nextMethod: "chatgpt",
        });
      else {
        h.store.deleteConnection(I);
        h.register("replacement");
      }
      expect(h.view.listingFor(S).kind).not.toBe("canonical");
      expect(
        h.authority.confirmRead(S, old.head, () => true, old.method, old.proof),
      ).toBe(false);
    },
  );
  it.each(["blob", "replica", "quarantine", "receipt", "declaration"] as const)(
    "16 all_required_events_enqueue_without_waiting_for_sweep: %s",
    async (cause) => {
      const h = await fixture();
      // Real reader dependency tables, through the same tracked Database port as
      // their production writers. Separate parameters exercise separate writes.
      h.db
        .exec(`CREATE TABLE IF NOT EXISTS pdpp_replica_pending_bytes(batch_id TEXT,blob_id TEXT,bytes BLOB,PRIMARY KEY(batch_id,blob_id));
      CREATE TABLE IF NOT EXISTS pdpp_replica_quarantined_keys(instance TEXT,generation INTEGER,stream TEXT,record_key TEXT,PRIMARY KEY(instance,generation,stream,record_key));`);
      const gate = barrier(),
        events: string[] = [],
        run = vi.fn(async () => {
          events.push(cause);
          await gate.promise;
        });
      const q = h.scheduler(async () => {}, { policy: h.declarationKey });
      q.start();
      await q.idle();
      await q.stop();
      const live = h.scheduler(run, { policy: h.declarationKey });
      // No startup job obscures the event job. Start, release its first body, then
      // block the independent event's body at its immutable-snapshot boundary.
      gate.release();
      live.start();
      await live.idle();
      run.mockClear();
      events.length = 0;
      const pending = barrier();
      run.mockImplementation(async () => {
        events.push(cause);
        await pending.promise;
      });
      const writeClock = h.authority.writeClock(),
        arrivals = h.authority.arrivalRevision(),
        reads = h.loader.mock.calls.length;
      if (cause === "blob")
        h.store.storeBlobBytesForInstance({
          instance: I,
          method: "chatgpt",
          generation: G,
          bytes: new TextEncoder().encode("synthetic source bytes"),
          mimeType: "application/json",
        });
      if (cause === "replica")
        h.db.exec(
          "INSERT INTO pdpp_replica_pending_bytes VALUES ('batch','blob',X'00')",
        );
      if (cause === "quarantine")
        h.db
          .prepare("INSERT INTO pdpp_replica_quarantined_keys VALUES (?,?,?,?)")
          .run(I, G, "messages", "m-A");
      if (cause === "receipt")
        h.db
          .prepare(
            "INSERT INTO pdpp_stream_completion(instance,stream,method,generation,source_collected_at,write_seq,live_count) VALUES (?,?,?,?,?,?,?)",
          )
          .run(
            I,
            "messages",
            "chatgpt",
            G,
            "2026-09-02T00:00:00Z",
            writeClock,
            2,
          );
      if (cause === "declaration") h.changeDeclaration();
      await vi.advanceTimersByTimeAsync(1000);
      expect(run).toHaveBeenCalledTimes(1);
      expect(events).toEqual([cause]);
      expect(h.state.status(I, S)?.dirty_since).not.toBeNull();
      expect(h.authority.writeClock()).toBe(writeClock);
      expect(h.authority.arrivalRevision()).toBe(arrivals);
      expect(h.loader).toHaveBeenCalledTimes(reads);
      pending.release();
      await live.idle();
    },
  );
  it("17 same_scope_other_account_cannot_reuse_proof", async () => {
    const a = await fixture(),
      b = await fixture();
    b.db.exec(
      "DELETE FROM legacy_scope_takeovers; DELETE FROM legacy_scope_takeover_verdicts",
    );
    expect(a.head().id).toBe(b.head().id);
    expect(a.path).not.toBe(b.path);
    const before = b.authority.verdictFor(S),
      dirty = b.state.status(I, S);
    workerControl.block = false;
    const workerA = createLegacyEvaluationWorker({ timeoutMs: 100 });
    closers.push(() => workerA.stop());
    // Deliver A's worker response to B's scheduler adapter. Worker responses are
    // metrics, not portable admission proofs; publication stays in A's DB.
    const qB = b.scheduler(async () => {
      await workerA.evaluate({
        database: a.path,
        dataDir: a.root,
        owner: "owner-A",
        replication: false,
        declarations: [],
        configuredMethods: [[SOURCE, ["chatgpt"]]],
        optInMethods: [],
        coverageThresholds: undefined,
        instance: I,
        scopes: [S],
      });
    });
    qB.enqueue(I, [S]);
    await qB.idle();
    expect(b.authority.verdictFor(S)).toEqual(before);
    expect(b.state.status(I, S)).toEqual(dirty);
    expect(b.view.listingFor(S).kind).not.toBe("canonical");
  });
  it("18 retryable_transient_read_error_contract", async () => {
    // ruled by lead 11-03: retain retryable + reason only; no retryAfterMs,
    // action, scope or Retry-After contract belongs in this bridge.
    const h = await fixture();
    h.put("messages", h.message("A"));
    h.loader.mockRejectedValue(Error("synthetic unavailable file"));
    expect(
      (await h.listed()).scopes.some((s: { scope: string }) => s.scope === S),
    ).toBe(true);
    const response = await h.request(`/v1/data/${S}`);
    const body = await response.json();
    expect(response.status).toBe(503);
    expect(body).toMatchObject({
      error: "CANONICAL_VIEW_UNAVAILABLE",
      status: "unavailable",
      reason: "store_inconsistent_read",
      retryable: true,
    });
    expect(JSON.stringify(body)).not.toContain(text);
    expect(JSON.stringify(body)).not.toContain(I);
    expect(body.message).not.toMatch(/reimport|delete/i);
  });
  it.each(["ambiguous", "deleted", "paid"] as const)(
    "19 nonretryable_refusals_not_mislabeled: %s",
    async (kind) => {
      const h = await fixture();
      if (kind === "ambiguous") {
        h.register("second-account");
        h.put("conversations", h.conversation("C"), "second-account");
        h.put("messages", h.message("C"), "second-account");
      }
      if (kind === "deleted")
        h.deletion.markDeleted(S, {
          deletedAt: new Date().toISOString(),
          version: null,
        });
      let response: Response;
      if (kind === "paid") {
        const authorizeBuilderRead = vi.fn(async () => ({
          builder: "0x2222222222222222222222222222222222222222",
          grantId: "synthetic-grant",
        }));
        response = await handlePersonalServerDataRequest(
          new Request(`http://localhost/v1/data/${S}`),
          {
            storage: createNodeDataStorage({
              indexManager: createIndexManager(h.db),
              hierarchyOptions: { dataDir: h.root },
            }),
            legacyScopeView: h.view,
            auth: {
              authorizeOwner: async () => {},
              authorizeBuilderList: async () => {},
              authorizeBuilderRead,
            },
            accessLogWriter: { write: async () => {} },
            serverOwner: "0x1111111111111111111111111111111111111111",
            paymentEnabled: true,
            gateway: { getGrant: h.charge },
            gatewayConfig: {} as PersonalServerDataApiDeps["gatewayConfig"],
            gatewayUrl: "https://gateway.invalid",
            logger: pino({ level: "silent" }),
          },
          { basePath: "/v1/data" },
        );
      } else response = await h.request(`/v1/data/${S}`);
      const body = await response.json();
      expect(response.status).toBe(
        kind === "ambiguous" ? 409 : kind === "deleted" ? 410 : 503,
      );
      if (kind === "ambiguous")
        expect(body.reason).toBe("ambiguous_connection");
      if (kind === "paid") expect(body.reason).toBe("paid_read_unsupported");
      expect(body.retryable).not.toBe(true);
      expect(JSON.stringify(body)).not.toContain(text);
      expect(h.charge).not.toHaveBeenCalled();
      if (kind !== "paid")
        expect(
          (await h.listed()).scopes.some(
            (s: { scope: string }) => s.scope === S,
          ),
        ).toBe(false);
    },
  );
  it("20 negative_is_not_stale_covered_fallback", async () => {
    const h = await fixture();
    h.put("messages", h.message("B", null));
    expect((await h.fresh()).kind).toBe("refused");
    const negative = h.authority.verdictFor(S);
    const gate = barrier(),
      q = h.scheduler(() => gate.promise);
    q.start();
    await Promise.resolve();
    expect(h.view.listingFor(S).kind).toBe("refused");
    expect(
      (await h.listed()).scopes.some((s: { scope: string }) => s.scope === S),
    ).toBe(false);
    gate.release();
    await q.stop();
    await h.reopen();
    expect(h.authority.verdictFor(S)).toEqual(negative);
    expect(h.view.listingFor(S).kind).toBe("refused");
  });
  it("21 listing_never_serves_cached_body_as_read_proof", async () => {
    const h = await fixture(),
      scope = "claude.projects",
      source = "https://registry.pdpp.dev/sources/claude",
      instance = "claude-blob";
    h.store.registerConnection({
      instance,
      sourceId: source,
      method: "anthropic",
      label: "Synthetic",
    });
    const profile = {
      id: "org",
      organization_id: "org",
      full_name: "Synthetic reader",
      plan: null,
      name_source: "users_json",
      metadata_status: "valid",
    };
    const payload = { uuid: "p", name: "Synthetic private source", docs: [] };
    const meta = h.store.storeBlobBytesForInstance({
      instance,
      method: "anthropic",
      generation: 1,
      mimeType: "application/json",
      bytes: new TextEncoder().encode(
        JSON.stringify({
          format: "anthropic-source-record-v1",
          stream: "projects",
          record_key: "p",
          payload,
        }),
      ),
    });
    const project = {
      id: "p",
      blob_ref: {
        blob_id: meta.blobId,
        mime_type: meta.mimeType,
        size_bytes: meta.sizeBytes,
        sha256: meta.sha256,
      },
    };
    for (const [stream, rows] of [
      ["account_profile", [profile]],
      ["projects", [project]],
      ["project_documents", []],
    ] as const)
      h.store.replaceStream({
        instance,
        stream,
        method: "anthropic",
        generation: 1,
        primaryKey: ["id"],
        emittedAt: "2026-09-01T00:00:00Z",
        sourceCollectedAt: "2026-09-01T00:00:00Z",
        envelopes: rows.map((data) => ({
          instance,
          stream,
          key: data.id,
          data,
          emitted_at: "2026-09-01T00:00:00Z",
        })),
      });
    const authority = h.authority;
    const view = createLegacyScopeView({
      authority,
      records: h.store,
      configuredMethods: (id) => (id === source ? ["anthropic"] : ["chatgpt"]),
      readLegacyHead: h.loader,
    });
    const first = await view.readLatest(scope);
    expect(first.kind).toBe("canonical");
    if (first.kind !== "canonical") throw Error("blob fixture");
    await writeFile(
      join(h.root, "claude.json"),
      JSON.stringify(first.envelope),
    );
    h.db
      .prepare(
        "INSERT INTO data_files(path,scope,collected_at,size_bytes) VALUES ('claude.json',?,'2026-09-01T00:00:00Z',1)",
      )
      .run(scope);
    expect((await view.readLatest(scope)).kind).toBe("canonical");
    expect((await view.readLatest(scope)).kind).toBe("canonical");
    // A normal sync makes the read cursor stale; required source-byte access
    // then fails. This is an availability fault, not out-of-band SQL deletion.
    h.store.ingestBatch(
      [
        {
          instance,
          stream: "projects",
          key: "p",
          data: project,
          emitted_at: "2026-09-01T00:00:00Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "anthropic", generation: 1 },
    );
    vi.spyOn(h.store, "getBlobBytes").mockReturnValue(undefined);
    expect(view.listingFor(scope).kind).toBe("canonical");
    const response = await handlePersonalServerDataRequest(
      new Request(`http://localhost/v1/data/${scope}`),
      {
        storage: createNodeDataStorage({
          indexManager: createIndexManager(h.db),
          hierarchyOptions: { dataDir: h.root },
        }),
        legacyScopeView: view,
        auth: {
          authorizeOwner: async () => {},
          authorizeBuilderList: async () => {},
          authorizeBuilderRead: async () => ({ grantId: "owner" }),
        },
        accessLogWriter: { write: async () => {} },
        serverOwner: "0x1111111111111111111111111111111111111111",
      },
      { basePath: "/v1/data" },
    );
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({
      error: "CANONICAL_VIEW_UNAVAILABLE",
      retryable: true,
      reason: expect.any(String),
    });
  });
  it("22 list_pagination_and_metadata_stay_coherent", async () => {
    const h = await fixture(),
      instance = "oura-pages";
    h.register(instance, 1, "https://registry.pdpp.dev/sources/oura", "oura");
    for (const stream of ["activity", "readiness", "sleep"]) {
      const scope = `oura.${stream}`;
      h.put(
        stream,
        { id: stream, day: "2026-09-01", score: 80, sleep_score: 80 },
        instance,
        1,
        "oura",
      );
      const body = await h.view.readLatest(scope);
      expect(body.kind).toBe("canonical");
      if (body.kind !== "canonical") throw Error("page fixture");
      const path = `${stream}.json`;
      await writeFile(join(h.root, path), JSON.stringify(body.envelope));
      h.db
        .prepare(
          "INSERT INTO data_files(path,scope,collected_at,size_bytes) VALUES (?,?,'2026-09-01T00:00:00.000Z',1)",
        )
        .run(path, scope);
      expect((await h.view.readLatest(scope)).kind).toBe("canonical");
    }
    h.state.markDirty();
    vi.setSystemTime(T0 + 29 * 60_000);
    expect((await h.fresh()).kind).toBe("canonical");
    h.put("messages", h.message("A"));
    expect((await h.fresh("oura.activity", instance)).kind).toBe("canonical");
    h.deletion.markDeleted("oura.sleep", {
      deletedAt: new Date().toISOString(),
      version: null,
    });
    vi.setSystemTime(T0 + 31 * 60_000);
    const pages = [];
    for (let offset = 0; offset < 3; offset++) {
      const page = await h.listed(`/v1/data?limit=1&offset=${offset}`);
      expect(page.total).toBe(2);
      pages.push(...page.scopes);
      expect(await h.listed(`/v1/data?limit=1&offset=${offset}`)).toEqual(page);
    }
    expect(pages.map((s: { scope: string }) => s.scope).sort()).toEqual(
      [S, "oura.activity"].sort(),
    );
    expect(new Set(pages.map((s: { scope: string }) => s.scope)).size).toBe(2);
    for (const page of pages)
      expect(page.latestCollectedAt).toBe("2026-09-01T00:00:00.000Z");
  });
  // Case 23 is deliberately not implemented.
  // ruled by lead 11-03: drop case 23; accept wall-clock rollback extending the window.
});
