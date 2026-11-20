// Changes that follow one another reach the device as deltas.
//
// The real change push runs over a fake gateway feed, so what each held
// request carries is read where the gateway would read it. The feed models the
// one rule of the gateway that matters here: an answer carries a delta only
// when its request carried `since`. A change that comes back without a delta
// costs a full cycle (listing, control reads, log read, segment GET), so each
// test counts `cycle()` calls against `applyDelta()` calls.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Logger } from "../../logger/index.js";
import type {
  DeltaApplyResult,
  RegistryChangeAnswer,
  RegistryChangeDelta,
  StreamSyncRegistry,
} from "../../stream-sync/ports.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { UploadWorkerDeps } from "../workers/upload.js";
import {
  createRegistryChangePush,
  CHANGE_PUSH_WAIT_MS,
} from "./change-push.js";
import { createSyncManager, type SyncManagerOptions } from "./sync-manager.js";

const logger = {
  info: vi.fn(),
  error: vi.fn(),
  warn: vi.fn(),
  debug: vi.fn(),
  trace: vi.fn(),
  fatal: vi.fn(),
} as unknown as Logger;

const APPLIED: DeltaApplyResult = {
  outcome: "applied",
  connections: 1,
  deleted: 0,
  blobGets: 1,
  blobMs: 0,
  applyMs: 0,
};

const TOMBSTONE = {
  scope: "control",
  read: {
    found: true,
    version: 2,
    dataHash: "0x00",
    metadataHash: "0x00",
    deleted: true,
  },
} as const;

/**
 * The gateway's change feed: one sequence, held requests answered when it
 * moves or when their wait runs out. `requests` is what each request carried.
 */
function gateway() {
  let seq = 7;
  const deletes = new Set<number>();
  const requests: { after: string | undefined; since: string | undefined }[] =
    [];
  const parked: Array<() => void> = [];
  const answerFor = (
    after: string | undefined,
    since: string | undefined,
  ): RegistryChangeAnswer => {
    const changed = after === undefined || String(seq) !== after;
    const delta: RegistryChangeDelta | undefined =
      changed && since !== undefined
        ? {
            since,
            seq: String(seq),
            reset: false,
            rows: [...deletes].some((d) => d > Number(since) && d <= seq)
              ? [TOMBSTONE]
              : [],
            gone: [],
            serversChanged: false,
          }
        : undefined;
    return { seq: String(seq), changed, ...(delta ? { delta } : {}) };
  };
  const registry = {
    waitForChange: (
      after: string | undefined,
      waitMs: number,
      signal: AbortSignal,
      since: string | undefined,
    ) =>
      new Promise<RegistryChangeAnswer>((resolve, reject) => {
        requests.push({ after, since });
        const answer = () => resolve(answerFor(after, since));
        if (after === undefined || String(seq) !== after) return answer();
        const timer = setTimeout(answer, waitMs);
        parked.push(() => {
          clearTimeout(timer);
          answer();
        });
        signal.addEventListener("abort", () => reject(signal.reason), {
          once: true,
        });
      }),
  } as unknown as StreamSyncRegistry;
  return {
    registry,
    requests,
    /** A write lands in the registry: every held request answers. */
    commit: (opts: { delete?: boolean } = {}) => {
      seq += 1;
      if (opts.delete) deletes.add(seq);
      for (const wake of parked.splice(0)) wake();
      return String(seq);
    },
  };
}

function setup(
  opts: {
    applyDelta?: (d: RegistryChangeDelta) => Promise<DeltaApplyResult>;
  } = {},
) {
  const feed = gateway();
  const push = createRegistryChangePush(feed.registry, {
    waitMs: CHANGE_PUSH_WAIT_MS,
  })!;
  const cycle = vi.fn<() => Promise<unknown>>(async () => {});
  const applyDelta = vi.fn(opts.applyDelta ?? (async () => APPLIED));
  const manager = createSyncManager(
    {
      logger,
      serverOwner: "0x1111111111111111111111111111111111111111",
      storage: { findUnsynced: () => [] },
    } as unknown as UploadWorkerDeps,
    { logger } as unknown as DownloadWorkerDeps,
    {
      accountStorageMode: { read: () => "switched" as const },
      pollInterval: 60_000,
      localSync: { cycle, applyDelta },
      changeProbe: { read: async () => "m1", intervalMs: 5_000, push },
      canSync: async () => ({ ok: true as const }),
    } as SyncManagerOptions,
  );
  return { manager, feed, cycle, applyDelta };
}

type T = ReturnType<typeof setup>;

const flush = () => vi.advanceTimersByTimeAsync(0);

/**
 * Start, and let the first answer (it has no cursor, so no delta) run the
 * pass that settles the device at the feed's position.
 */
async function started(t: T) {
  t.manager.start();
  await flush();
  t.cycle.mockClear();
}

/** One write, and the answer it causes, applied. */
async function write(t: T, opts: { delete?: boolean } = {}) {
  const seq = t.feed.commit(opts);
  await flush();
  return seq;
}

/** A pass the test holds open until `release()`. */
function held<T>(result: T) {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => (release = resolve));
  return {
    gate,
    release: () => release(),
    then: async () => (await gate, result),
  };
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.spyOn(Math, "random").mockReturnValue(0.5);
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("changes that follow one another", () => {
  it("the held request after an answer that started a pass asks from that answer's position", async () => {
    const t = setup();
    await started(t);
    const seq = await write(t);
    // Request 0 has no cursor; request 1 follows it; request 2 follows the
    // answer to the write.
    expect(t.feed.requests.at(-1)).toEqual({ after: seq, since: seq });
    await t.manager.stop();
  });

  it("a second write after the first pass ended is applied as a delta: no cycle", async () => {
    const t = setup();
    await started(t);
    await write(t);
    await write(t);
    // What each held request carried: a position to follow, every time.
    expect(t.feed.requests.map((r) => r.since)).toEqual([
      undefined,
      "7",
      "8",
      "9",
    ]);
    expect(t.cycle).not.toHaveBeenCalled();
    expect(t.applyDelta).toHaveBeenCalledTimes(2);
    await t.manager.stop();
  });

  it("a write that lands while the first one's pass runs is applied as a delta right after it", async () => {
    const first = held(APPLIED);
    const t = setup();
    t.applyDelta.mockImplementationOnce(first.then);
    await started(t);
    await write(t);
    expect(t.applyDelta).toHaveBeenCalledTimes(1); // the pass is open
    const second = await write(t);
    expect(t.applyDelta).toHaveBeenCalledTimes(1); // queued behind it
    first.release();
    await flush();
    expect(t.applyDelta).toHaveBeenCalledTimes(2);
    expect(t.applyDelta.mock.calls[1]![0]).toMatchObject({ seq: second });
    expect(t.cycle).not.toHaveBeenCalled();
    expect(t.feed.requests.at(-1)).toEqual({ after: second, since: second });
    await t.manager.stop();
  });

  it.each([3, 5, 10])(
    "a burst of %i changes applies every delta without a full cycle",
    async (count) => {
      const first = held(APPLIED);
      const t = setup();
      t.applyDelta.mockImplementationOnce(first.then);
      await started(t);
      await write(t);
      let last = "";
      for (let i = 0; i < count; i++) last = await write(t);
      first.release();
      await flush();
      expect(t.applyDelta).toHaveBeenCalledTimes(count + 1);
      expect(t.cycle).not.toHaveBeenCalled();
      expect(t.feed.requests.at(-1)).toEqual({ after: last, since: last });
      await t.manager.stop();
    },
  );

  it("a delete that lands while a pass runs is applied after it: the tombstone reaches the purge", async () => {
    const first = held(APPLIED);
    const purged: string[] = [];
    const t = setup({
      applyDelta: async (d) => {
        if (!d.reset && d.rows.some((r) => r.read.found && r.read.deleted))
          purged.push(d.seq);
        return APPLIED;
      },
    });
    t.applyDelta.mockImplementationOnce(first.then);
    await started(t);
    await write(t); // pass 1 opens
    const deleted = await write(t, { delete: true });
    expect(purged).toEqual([]); // queued behind pass 1
    first.release();
    await flush();
    expect(purged).toEqual([deleted]);
    expect(t.cycle).not.toHaveBeenCalled();
    await t.manager.stop();
  });

  it("a pass that fails leaves no position: the next request carries none, and the position never passes what was applied", async () => {
    const t = setup({
      applyDelta: async () => ({ outcome: "cycle", reason: "a control row" }),
    });
    await started(t);
    t.cycle.mockRejectedValue(new Error("storage down"));
    const seq = await write(t); // hands back to a cycle that fails
    // The request sent during that pass asked from the position the pass
    // would settle at; the pass did not settle.
    expect(t.feed.requests.at(-1)).toEqual({ after: seq, since: seq });
    // Its answer (the wait runs out) is delta-less; the request after it
    // falls back to what is settled: nothing.
    await vi.advanceTimersByTimeAsync(CHANGE_PUSH_WAIT_MS);
    expect(t.feed.requests.at(-1)?.since).toBeUndefined();
    // A write now carries no delta, so it is not applied as one.
    t.applyDelta.mockClear();
    await write(t);
    expect(t.applyDelta).not.toHaveBeenCalled();
    await t.manager.stop();
  });

  it("a delta that arrives while the pass in flight fails is not applied after it", async () => {
    const hold = held(undefined);
    const t = setup({
      applyDelta: async () => ({ outcome: "cycle", reason: "a control row" }),
    });
    await started(t);
    t.cycle.mockImplementationOnce(async () => {
      await hold.gate;
      throw new Error("storage down");
    });
    await write(t); // a cycle, held open
    await write(t); // its delta arrives mid-pass and is queued
    t.applyDelta.mockClear();
    t.cycle.mockResolvedValue(undefined);
    hold.release();
    await vi.advanceTimersByTimeAsync(5_000); // past the retry cooldown
    expect(t.applyDelta).not.toHaveBeenCalled();
    await t.manager.stop();
  });
});
