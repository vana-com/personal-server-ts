// The delete retry timer, driven through the retry loop with the order of
// events forced: a tick finds a connector's erasure in flight and reports
// that, the connector's run then ends owing work, and only then does the tick
// go on. The timer must follow the work that is owed when the tick goes on,
// not what the tick learned earlier.
import { afterEach, describe, expect, it, vi } from "vitest";
import { logScope } from "@opendatalabs/personal-server-ts-stream-sync";
import type { createConnectionDeleter } from "../../../core/src/localdb/delete.js";
import type { LogErasurePorts } from "../../../core/src/localdb/log-erase.js";
import {
  CONNECTOR,
  CONTROL,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

// What the tick does between learning its answer and returning it.
const gap: {
  afterErasures?: () => Promise<void>;
  /** Runs the tick is handed besides its own (a test's failing run). */
  extraRuns?: () => Promise<void>[];
  deleter?: ReturnType<typeof createConnectionDeleter>;
} = {};
vi.mock("../../../core/src/localdb/delete.js", async (importOriginal) => {
  const original = await importOriginal<{
    createConnectionDeleter: typeof createConnectionDeleter;
  }>();
  return {
    ...original,
    createConnectionDeleter: (
      ...args: Parameters<typeof createConnectionDeleter>
    ) => {
      const deleter = original.createConnectionDeleter(...args);
      const startErasures = deleter.startErasures.bind(deleter);
      gap.deleter = deleter;
      deleter.startErasures = async () => {
        const answer = await startErasures();
        await gap.afterErasures?.();
        return [...answer, ...(gap.extraRuns?.() ?? [])];
      };
      return deleter;
    },
  };
});

// Every device made here is closed after its test: a loop left running over a
// closed database keeps failing, and arms timers in the tests that follow.
const devices: { sync: { close(): Promise<void> } }[] = [];
async function device(
  w: Awaited<ReturnType<typeof world>>,
  ...args: Parameters<Awaited<ReturnType<typeof world>>["device"]>
) {
  const made = await w.device(...args);
  devices.push(made);
  return made;
}
afterEach(async () => {
  gap.afterErasures = undefined;
  gap.extraRuns = undefined;
  await Promise.all(devices.splice(0).map((device) => device.sync.close()));
  vi.useRealTimers();
  await closeWorldDrivers();
});

const LOG = logScope(CONNECTOR, "");
const RETRY = { first: 5, max: 20 };
const nextTask = () => new Promise<void>((resolve) => setImmediate(resolve));
/** Wait on state with real macrotasks only: the timers under test are faked. */
async function until(done: () => boolean | Promise<boolean>) {
  // Real time, not a count of tasks: a loaded host runs the database slowly.
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (await done()) return;
    await nextTask();
  }
  throw new Error("state never reached");
}

describe("the delete retry timer follows the work owed when it is decided", () => {
  it("stays armed when a connector's run ends owing work between a tick's answer and its return", async () => {
    const w = await world({ streams: 1, partTargetBytes: 65536 });
    const logKeys = () =>
      w.innerBlobs.keys().filter((key) => key.startsWith(`${LOG}/`));
    // What the erasure must leave: no log object but a version's own marker.
    const left = () => logKeys().filter((key) => !key.includes("/v-"));
    let erased!: () => void;
    const erasedSignal = new Promise<void>((resolve) => (erased = resolve));
    // The finality read waits on the test, then says "not final" once: the
    // erasure is unfinished after its first pass and finishes on a retry.
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    let asked = 0;
    let inFlight = false;
    const erasure: LogErasurePorts = {
      versions: {
        list: async (scope) => ({
          complete: true,
          versions: (w.gateway.versions.get(scope) ?? []).map((v, i) => ({
            expectedVersion: String(i + 1),
            dataHash: v.dataHash,
            isTombstone: false,
          })),
        }),
      },
      finality: {
        tombstoneState: async () => {
          asked += 1;
          if (asked === 1) {
            inFlight = true;
            await gate;
          }
          return { finalized: asked > 1 ? "99" : null, rolledBack: null };
        },
      },
      objects: {
        deleteBlobVersions: async (scope, names) => {
          const out = {
            deleted: [] as string[],
            missing: [] as string[],
            failed: [] as { version: string; error: string }[],
          };
          for (const name of names)
            (w.innerBlobs.delete(`${scope}/${name}`)
              ? out.deleted
              : out.missing
            ).push(name);
          if (left().length === 0) erased();
          return out;
        },
      },
    };
    const a = await device(w, "a", {
      erasure: () => erasure,
      deleteRetryMs: RETRY,
    });
    await a.run("run-1", [{ stream: sName(0), id: "x", v: 0 }], {
      observedAt: 1100,
    });
    await a.cycle();
    expect(logKeys().length).toBeGreaterThan(0);

    // From here the retry timer is the test's: it fires only when advanced.
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    await a.sync.deleter.requestConnectionDelete(CONNECTOR);
    // The delete has landed and the erasure waits on storage's finality read.
    await until(() => inFlight);
    // The request armed the timer; its tick finds the erasure in flight and
    // owes nothing, so the loop goes quiet.
    await vi.advanceTimersByTimeAsync(RETRY.max);
    await until(() => vi.getTimerCount() === 0);

    // The forced order. A tick reads its answer while the erasure is in
    // flight (nothing queued). Then the run ends owing work and arms the
    // retry. Only then does the tick go on.
    gap.afterErasures = async () => {
      gap.afterErasures = undefined;
      release();
      // The run ends while the tick is still on its way out.
      await until(() => gap.deleter!.erasureOwed());
    };
    await a.sync.deleter.resumeDeletes();

    // The erasure is owed, and the loop looked again after the tick: the
    // timer is armed.
    await until(() => vi.getTimerCount() === 1);
    expect(logKeys().length).toBeGreaterThan(0);

    // And the retry it fires finishes the erasure.
    // The storage port says when it is done; the test's own timeout bounds it.
    let done = false;
    void erasedSignal.then(() => (done = true));
    while (!done) {
      await vi.advanceTimersByTimeAsync(RETRY.max);
      await nextTask();
    }
    expect(left()).toEqual([]);
  });
});

describe("an in-memory retry marker is cleared when the durable fact it mirrors goes away", () => {
  /** A device that collected the connector, with the retry timer faked. */
  async function collected() {
    const w = await world({ streams: 1, partTargetBytes: 65536 });
    const a = await device(w, "a", { deleteRetryMs: RETRY });
    await a.run("run-1", [{ stream: sName(0), id: "x", v: 0 }], {
      observedAt: 1100,
    });
    await a.cycle();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    return { w, a };
  }
  const intents = (a: Awaited<ReturnType<typeof collected>>["a"]) =>
    a.db.query("SELECT 1 FROM delete_intents");
  /** Let the database reads of a tick under way finish. */
  const settle = async () => {
    for (let spins = 0; spins < 60; spins += 1) await nextTask();
  };
  it("arms no timer after a delete is superseded while it lands: its intent is cleared, so nothing is left to retry", async () => {
    const { a } = await collected();
    // Another writer moves the connection's control row past the delete's pin
    // just before the delete's fence post.
    const post = a.deps.registry.post.bind(a.deps.registry);
    const postBatch = a.deps.registry.postBatch!.bind(a.deps.registry);
    let rival = false;
    a.deps.registry.postBatch = async (request, signal) => {
      if (!rival && request.rows.some((row) => row.scope === CONTROL)) {
        rival = true;
        const row = request.rows.find((r) => r.scope === CONTROL)!;
        await post({
          ownerAddress: request.ownerAddress,
          scope: CONTROL,
          expectedVersion: row.expectedVersion,
          dataHash: `0x${"ab".repeat(32)}`,
          metadataHash: `0x${"cd".repeat(32)}`,
          signature: "0x01",
        });
      }
      return postBatch(request, signal);
    };

    await a.sync.deleter.requestConnectionDelete(CONNECTOR);
    await until(async () => (await intents(a)).length === 0);
    expect(rival).toBe(true);
    await settle();

    // The next tick owes nothing: the delete is gone, so no timer is armed.
    await a.sync.deleter.resumeDeletes();
    await settle();
    expect(await gap.deleter!.retryOwed()).toBe(false);
    // The loop decides at the end of its last pass, and stays decided.
    await until(() => vi.getTimerCount() === 0);
    await settle();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("arms no timer when a failed landing's intent is gone by the time the retry looks", async () => {
    const { a } = await collected();
    const post = a.deps.registry.post.bind(a.deps.registry);
    const postBatch = a.deps.registry.postBatch!.bind(a.deps.registry);
    a.deps.registry.post = async (request, signal) => {
      if (request.scope === CONTROL) throw new Error("registry down");
      return post(request, signal);
    };
    a.deps.registry.postBatch = async (request, signal) => {
      if (request.rows.some((row) => row.scope === CONTROL))
        throw new Error("registry down");
      return postBatch(request, signal);
    };
    await a.sync.deleter.requestConnectionDelete(CONNECTOR);
    await until(async () => (await intents(a)).length === 1);
    // The landing keeps failing: the loop is armed, as it should be.
    await vi.advanceTimersByTimeAsync(RETRY.max);
    await settle();
    expect(await gap.deleter!.retryOwed()).toBe(true);

    // The intent goes (another process finished or replaced the delete). The
    // next tick finds nothing to land and nothing owed.
    await a.db.batch([{ sql: "DELETE FROM delete_intents" }]);
    await a.sync.deleter.resumeDeletes();
    expect(await gap.deleter!.retryOwed()).toBe(false);
    // The loop decides at the end of its last pass, and stays decided.
    await until(() => vi.getTimerCount() === 0);
    await settle();
    expect(vi.getTimerCount()).toBe(0);
  });

  /** The registry refuses every control post while `registry.down`. */
  function registryDown(a: Awaited<ReturnType<typeof collected>>["a"]) {
    const registry = { down: true };
    const post = a.deps.registry.post.bind(a.deps.registry);
    const postBatch = a.deps.registry.postBatch!.bind(a.deps.registry);
    a.deps.registry.post = async (request, signal) => {
      if (registry.down && request.scope === CONTROL)
        throw new Error("registry down");
      return post(request, signal);
    };
    a.deps.registry.postBatch = async (request, signal) => {
      if (registry.down && request.rows.some((row) => row.scope === CONTROL))
        throw new Error("registry down");
      return postBatch(request, signal);
    };
    return registry;
  }
  /** Fire the retry timer and let what it starts run. */
  const fire = async () => {
    await vi.advanceTimersByTimeAsync(RETRY.max);
    await settle();
  };

  it("keeps the retry armed when a delete for the connector fails to land while a scan that found none is still being applied", async () => {
    const { a } = await collected();
    const registry = registryDown(a);
    await a.sync.deleter.requestConnectionDelete(CONNECTOR);
    await until(async () => (await intents(a)).length === 1);
    await settle();
    // Another process finished the delete: the next scan will find no row.
    await a.db.batch([{ sql: "DELETE FROM delete_intents" }]);

    // The scan reads its rows (none) and is held before it applies them.
    const query = a.db.query.bind(a.db);
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    let scanned = false;
    a.db.query = (async (sql: string, params?: readonly unknown[]) => {
      const rows = await query(sql, params);
      if (!scanned && sql.includes("FROM delete_intents ORDER BY connector")) {
        scanned = true;
        await held;
      }
      return rows;
    }) as typeof a.db.query;
    await vi.advanceTimersByTimeAsync(RETRY.max);
    await until(() => scanned);

    // A new delete for the connector fails to land before the scan's rows are
    // applied: its intent is durable, and it is owed a retry.
    await a.sync.deleter.requestConnectionDelete(CONNECTOR);
    await until(async () => (await intents(a)).length === 1);
    await settle();
    release();
    // The loop looks again after the scan and arms the timer for the intent.
    await until(() => vi.getTimerCount() === 1);
    await settle();

    expect((await intents(a)).length).toBe(1);
    expect(vi.getTimerCount()).toBe(1);

    // The registry comes back: the retry it armed lands the delete.
    registry.down = false;
    for (let rounds = 0; rounds < 50 && (await intents(a)).length > 0;) {
      await fire();
      rounds += 1;
    }
    expect(await intents(a)).toEqual([]);
  });

  it("keeps the retry armed when a resume that scanned earlier ends after a later resume's scan failed", async () => {
    const { a } = await collected();
    // Resume A has scanned and is on its way out when resume B's scan fails.
    const query = a.db.query.bind(a.db);
    let failScan = false;
    a.db.query = (async (sql: string, params?: readonly unknown[]) => {
      if (failScan && sql.includes("FROM delete_intents ORDER BY connector")) {
        failScan = false;
        throw new Error("database busy");
      }
      return query(sql, params);
    }) as typeof a.db.query;
    let second: Promise<unknown> = Promise.resolve();
    gap.afterErasures = async () => {
      gap.afterErasures = undefined;
      failScan = true;
      second = a.sync.deleter.resumeDeletes().catch(() => undefined);
      await settle();
    };
    await a.sync.deleter.resumeDeletes();
    await second;
    await settle();

    // B's scan failed after A's: what B did not get to is still owed.
    expect(vi.getTimerCount()).toBe(1);

    // The retry scans again, succeeds and has nothing left: it stops.
    await fire();
    // The loop decides at the end of its last pass, and stays decided.
    await until(() => vi.getTimerCount() === 0);
    await settle();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("retries a delete that fails to land while another connector's landing is stuck", async () => {
    const w = await world({ streams: 1, partTargetBytes: 65536 });
    const a = await device(w, "a", { deleteRetryMs: RETRY });
    const STUCK = "stuck-source";
    for (const connector of [CONNECTOR, STUCK])
      await a.run(`run-${connector}`, [{ stream: sName(0), id: "x", v: 0 }], {
        observedAt: 1100,
        connector,
      });
    await a.cycle();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });

    // The stuck connector's landing never ends: its last write, clearing the
    // intent, waits on the test. (A registry call is bounded by a deadline;
    // a database write is not.)
    let free!: () => void;
    const gate = new Promise<void>((resolve) => (free = resolve));
    const batch = a.db.batch.bind(a.db);
    a.db.batch = (async (statements: Parameters<typeof a.db.batch>[0]) => {
      if (
        statements.some(
          (statement) =>
            statement.sql.startsWith("DELETE FROM delete_intents") &&
            statement.params?.[0] === STUCK,
        )
      )
        await gate;
      return batch(statements);
    }) as typeof a.db.batch;
    // The registry refuses the other connector's fence; the test counts the
    // attempts (one per single post).
    let attempts = 0;
    const post = a.deps.registry.post.bind(a.deps.registry);
    a.deps.registry.post = async (request, signal) => {
      if (request.scope === CONTROL) {
        attempts += 1;
        throw new Error("registry down");
      }
      return post(request, signal);
    };
    const postBatch = a.deps.registry.postBatch!.bind(a.deps.registry);
    a.deps.registry.postBatch = async (request, signal) => {
      if (request.rows.some((row) => row.scope === CONTROL))
        throw new Error("registry down");
      return postBatch(request, signal);
    };
    try {
      await a.sync.deleter.requestConnectionDelete(STUCK);
      await a.sync.deleter.requestConnectionDelete(CONNECTOR);
      await until(() => attempts === 1);

      // The stuck landing does not hold the loop: each tick that fires retries
      // the failed delete, and the loop arms the next one. Tick until it has
      // retried twice more (a loop held by the stuck landing stops at the
      // first: it never decides the timer again).
      const tick = (count: number) =>
        until(async () => {
          await fire();
          return attempts >= count;
        });
      await tick(2);
      await tick(3);
    } finally {
      free();
    }
  });

  it("answers a resume only once the loop has decided the timer after the erasure it started has ended", async () => {
    const w = await world({ streams: 1, partTargetBytes: 65536 });
    // The erasure's first pass is unfinished; the second waits on the test.
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    let asked = 0;
    const erasure: LogErasurePorts = {
      versions: {
        list: async (scope) => ({
          complete: true,
          versions: (w.gateway.versions.get(scope) ?? []).map((v, i) => ({
            expectedVersion: String(i + 1),
            dataHash: v.dataHash,
            isTombstone: false,
          })),
        }),
      },
      finality: {
        tombstoneState: async () => {
          asked += 1;
          if (asked === 2) await gate;
          return { finalized: asked > 1 ? "99" : null, rolledBack: null };
        },
      },
      objects: {
        deleteBlobVersions: async (scope, names) => {
          const out = {
            deleted: [] as string[],
            missing: [] as string[],
            failed: [] as { version: string; error: string }[],
          };
          for (const name of names)
            (w.innerBlobs.delete(`${scope}/${name}`)
              ? out.deleted
              : out.missing
            ).push(name);
          return out;
        },
      },
    };
    const a = await device(w, "a", {
      erasure: () => erasure,
      deleteRetryMs: RETRY,
    });
    await a.run("run-1", [{ stream: sName(0), id: "x", v: 0 }], {
      observedAt: 1100,
    });
    await a.cycle();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    await a.sync.deleter.requestConnectionDelete(CONNECTOR);
    await until(() => gap.deleter!.erasureOwed());

    // The resume's pass starts the second erasure, which waits on storage.
    let answered = false;
    const resumed = a.sync.deleter
      .resumeDeletes()
      .then(() => (answered = true));
    await until(() => asked === 2);
    await settle();

    // Storage answers; the loop's next look at what is owed is held open.
    const originalQuery = a.db.query;
    const query = originalQuery.bind(a.db);
    let reading!: () => void;
    const looked = new Promise<void>((resolve) => (reading = resolve));
    let open!: () => void;
    const held = new Promise<void>((resolve) => (open = resolve));
    a.db.query = (async (sql: string, params?: readonly unknown[]) => {
      const rows = await query(sql, params);
      if (sql.includes("FROM delete_intents LIMIT 1")) {
        reading();
        await held;
      }
      return rows;
    }) as typeof a.db.query;
    try {
      release();
      await looked;
      await settle();
      expect(answered).toBe(false);
      open();
      await resumed;
      // Answered after the decision: nothing is owed, so no timer is armed.
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      release();
      open();
      a.db.query = originalQuery;
    }
  });

  it("waits for sibling runs and the timer decision before surfacing an erasure failure", async () => {
    const { a } = await collected();
    const originalQuery = a.db.query;
    const error = new Error("synthetic erasure failed");
    let fail!: (error: Error) => void;
    const failed = new Promise<void>((_, reject) => (fail = reject));
    void failed.catch(() => undefined);
    let finishSibling!: () => void;
    const sibling = new Promise<void>((resolve) => (finishSibling = resolve));
    let sawRead!: () => void;
    const reading = new Promise<void>((resolve) => (sawRead = resolve));
    let releaseRead!: () => void;
    const holdRead = new Promise<void>((resolve) => (releaseRead = resolve));
    let installed = false;
    let answered = false;
    const original = originalQuery.bind(a.db);
    gap.extraRuns = () => {
      installed = true;
      return [failed, sibling];
    };
    a.db.query = (async (sql: string, params?: readonly unknown[]) => {
      if (installed && sql.includes("FROM delete_intents LIMIT 1")) {
        sawRead();
        await holdRead;
      }
      return original(sql, params);
    }) as typeof a.db.query;
    const resumed = a.sync.deleter.resumeDeletes().then(
      () => {
        answered = true;
        return undefined;
      },
      (reason: unknown) => {
        answered = true;
        return reason;
      },
    );
    try {
      await reading;
      fail(error);
      releaseRead();
      await settle();
      expect(answered).toBe(false);
      finishSibling();
      expect(await resumed).toBe(error);
    } finally {
      releaseRead();
      finishSibling();
      fail(error);
      a.db.query = originalQuery;
      gap.extraRuns = undefined;
      await resumed;
    }
  });

  it("leaves no rejection unhandled when a run fails while the loop's read of what is owed fails", async () => {
    const { a } = await collected();
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    process.on("unhandledRejection", onUnhandled);
    try {
      // The tick is handed a run that fails; then its read of what is owed
      // fails, after the run has already failed.
      gap.extraRuns = () => [Promise.reject(new Error("erasure run failed"))];
      const query = a.db.query.bind(a.db);
      let failRead = true;
      a.db.query = (async (sql: string, params?: readonly unknown[]) => {
        if (failRead && sql.includes("FROM delete_intents LIMIT 1")) {
          failRead = false;
          await nextTask();
          await nextTask();
          throw new Error("database busy");
        }
        return query(sql, params);
      }) as typeof a.db.query;
      await a.sync.deleter.resumeDeletes().catch(() => undefined);
      gap.extraRuns = undefined;
      await settle();
      expect(unhandled).toEqual([]);
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
  });
});
