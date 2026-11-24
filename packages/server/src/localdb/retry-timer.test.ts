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
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

// What the tick does between learning its answer and returning it.
const gap: { afterErasures?: () => Promise<void> } = {};
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
    for (let rounds = 0; rounds < 10 && logKeys().length > 0; rounds += 1) {
      await vi.advanceTimersByTimeAsync(RETRY.max);
      await nextTask();
    }
    expect(logKeys().filter((key) => !key.includes("/v-"))).toEqual([]);
  });
});
