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
      const resumeErasures = deleter.resumeErasures.bind(deleter);
      gap.deleter = deleter;
      deleter.resumeErasures = async () => {
        const answer = await resumeErasures();
        await gap.afterErasures?.();
        return answer;
      };
      return deleter;
    },
  };
});

afterEach(async () => {
  gap.afterErasures = undefined;
  vi.useRealTimers();
  await closeWorldDrivers();
});

const LOG = logScope(CONNECTOR, "");
const RETRY = { first: 5, max: 20 };
const nextTask = () => new Promise<void>((resolve) => setImmediate(resolve));
/** Wait on state with real macrotasks only: the timers under test are faked. */
async function until(done: () => boolean | Promise<boolean>) {
  for (let spins = 0; spins < 2000; spins += 1) {
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
          return out;
        },
      },
    };
    const a = await w.device("a", {
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
      await until(() => vi.getTimerCount() > 0);
    };
    await a.sync.deleter.resumeDeletes();

    // The erasure is owed: the timer the run armed is still there.
    expect(vi.getTimerCount()).toBe(1);
    expect(logKeys().length).toBeGreaterThan(0);

    // And the retry it fires finishes the erasure.
    for (let rounds = 0; rounds < 200 && logKeys().length > 0; rounds += 1) {
      await vi.advanceTimersByTimeAsync(RETRY.max);
      await nextTask();
    }
    expect(logKeys().filter((key) => !key.includes("/v-"))).toEqual([]);
  });
});

describe("an in-memory retry marker is cleared when the durable fact it mirrors goes away", () => {
  /** A device that collected the connector, with the retry timer faked. */
  async function collected() {
    const w = await world({ streams: 1, partTargetBytes: 65536 });
    const a = await w.device("a", { deleteRetryMs: RETRY });
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
    expect(gap.deleter!.retryOwed()).toBe(false);
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
    expect(gap.deleter!.retryOwed()).toBe(true);

    // The intent goes (another process finished or replaced the delete). The
    // next tick finds nothing to land and nothing owed.
    await a.db.batch([{ sql: "DELETE FROM delete_intents" }]);
    await a.sync.deleter.resumeDeletes();
    expect(gap.deleter!.retryOwed()).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  });
});
