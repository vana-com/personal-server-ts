// How many parts of one stream are on the wire at once.
//
// The send gate (window, quota, Retry-After) and the byte budget are the only
// limits on a stream's part uploads: no width is fixed per stream. The real
// storage client and the real encoder run over a fake storage adapter whose
// every PUT takes a fixed virtual time. The gate's and the retry layer's clock
// is a fake clock; the SQLite reads that feed the encoder are real, so the test
// steps the clock only when the encoder and the uploads have stopped moving.
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { openLocalDb } from "@opendatalabs/personal-server-ts-core/localdb";
import type { SqlDriver } from "@opendatalabs/personal-server-ts-core/localdb";
import { encodePrefixes } from "../../../core/src/localdb/encode.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import { createStorageStreamSyncBlobs } from "../../../core/src/stream-sync/blobs.js";
import { createMemoryStreamSyncBlobs } from "../../../core/src/stream-sync/memory-registry.js";
import {
  fakeClock,
  type FakeClock,
} from "../../../core/src/stream-sync/fake-clock.test-helper.js";
import {
  DEFAULT_STORAGE_ACCESS_POLICY,
  type StorageAccessPolicy,
} from "../../../core/src/stream-sync/storage-retry.js";
import type { StreamSyncBlobs } from "../../../core/src/stream-sync/ports.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

/** One PUT takes this long in storage, as measured: about 1 s each. */
const PUT_MS = 1_000;
const PART = 2_048;
/** A row of this many bytes fills a part of its own. */
const ROW_VALUE_BYTES = 1_500;
const INPUT = {
  connectionId: "connection",
  stream: "items",
  scope: "pdpp.source.items",
  generation: 3,
  changedPrefixes: [""],
  upToSeq: 0,
} as const;

const drivers: SqlDriver[] = [];
const dirs: string[] = [];
afterEach(async () => {
  for (const driver of drivers.splice(0)) await driver.close();
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

const realSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const throttle = (status: 429 | 503, retryAfterMs?: number) =>
  Object.assign(new Error(`storage request failed (${status})`), {
    status,
    ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
  });

interface PutContext {
  /** Which PUT this is, counted from 1 in the order they leave the gate. */
  readonly n: number;
  /** The gate's in-flight window right now. */
  readonly window: number;
  readonly now: number;
}

interface Rig {
  readonly clock: FakeClock;
  readonly publish: () => Promise<unknown>;
  readonly stats: {
    started: number;
    stored: number;
    onWire: number;
    peakOnWire: number;
    /**
     * Bytes in memory for parts encrypted and not yet stored: the plain
     * encoded part and its ciphertext, both held while the PUT runs.
     */
    heldBytes: number;
    peakHeldBytes: number;
    readonly startTimes: number[];
  };
  readonly governor: ReturnType<
    typeof createStorageStreamSyncBlobs
  >["governor"];
  /** Lets every parked PUT finish. */
  readonly release: () => void;
  /** Runs `work` while stepping the fake clock whenever everything has gone quiet. */
  readonly drive: <T>(work: Promise<T>) => Promise<T>;
}

async function rig(options: {
  readonly parts: number;
  readonly policy: Partial<StorageAccessPolicy>;
  /** Throw this for a PUT instead of storing it. */
  readonly failPut?: (put: PutContext) => Error | undefined;
  /** Called when a failing PUT answers, with the window at that moment. */
  readonly onFailureAnswer?: (put: PutContext) => void;
  /** Called for every PUT as it starts. */
  readonly onPutStart?: (put: PutContext) => void;
  /**
   * Use the in-memory store, with this policy, in place of the storage client,
   * and park every PUT until `release` is called.
   */
  readonly parked?: { readonly policy: Partial<StorageAccessPolicy> };
}): Promise<Rig> {
  const dir = mkdtempSync(join(process.cwd(), ".upload-width-"));
  dirs.push(dir);
  const driver = openBetterSqlite3(join(dir, "db.sqlite"));
  drivers.push(driver);
  const db = await openLocalDb(driver, {
    owner: "0xabc",
    network: "test",
    deviceId: "upload-width-test",
  });
  await db.batch(
    Array.from({ length: options.parts }, (_, i) => {
      const key = String(i).padStart(4, "0").padEnd(64, "0");
      const body = JSON.stringify({
        id: key,
        value: String(i).padEnd(ROW_VALUE_BYTES, "x"),
      });
      const h = String(i).padStart(64, "a");
      return {
        sql: "INSERT INTO records (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params: [
          INPUT.connectionId,
          INPUT.stream,
          key,
          key,
          10,
          "run",
          body,
          h,
          null,
        ],
      };
    }),
  );
  const clock = fakeClock();
  const stats: Rig["stats"] = {
    started: 0,
    stored: 0,
    onWire: 0,
    peakOnWire: 0,
    heldBytes: 0,
    peakHeldBytes: 0,
    startTimes: [],
  };
  const gate: { governor?: Rig["governor"] } = {};
  const adapter = {
    urlForKey: (key: string) => key,
    exists: async () => false,
    download: async () => new Uint8Array(),
    delete: async () => true,
    upload: async (_key: string, bytes: Uint8Array) => {
      stats.started += 1;
      stats.startTimes.push(clock.now());
      stats.onWire += 1;
      stats.peakOnWire = Math.max(stats.peakOnWire, stats.onWire);
      const context = (): PutContext => ({
        n: stats.started,
        window: gate.governor!.window().end().window,
        now: clock.now(),
      });
      const started = context();
      options.onPutStart?.(started);
      const failure = options.failPut?.(started);
      await new Promise<void>((resolve) =>
        clock.after(failure ? PUT_MS + 1 : PUT_MS, resolve),
      );
      stats.onWire -= 1;
      if (failure) options.onFailureAnswer?.({ ...context(), n: started.n });
      if (failure) throw failure;
      stats.stored += 1;
      stats.heldBytes -= 2 * bytes.length;
      return "";
    },
  };
  let release!: () => void;
  const parkedUntil = new Promise<void>((resolve) => (release = resolve));
  const blobs: StreamSyncBlobs = options.parked
    ? {
        ...createMemoryStreamSyncBlobs(options.parked.policy),
        put: async (_key, bytes) => {
          stats.started += 1;
          stats.onWire += 1;
          stats.peakOnWire = Math.max(stats.peakOnWire, stats.onWire);
          await parkedUntil;
          stats.onWire -= 1;
          stats.stored += 1;
          stats.heldBytes -= 2 * bytes.length;
        },
      }
    : createStorageStreamSyncBlobs(adapter as never, {
        ...DEFAULT_STORAGE_ACCESS_POLICY,
        now: clock.now,
        after: clock.after,
        random: () => 0,
        ...options.policy,
      });
  gate.governor = blobs.governor;
  const deps = {
    db,
    blobs,
    keys: {
      encryptPart: async (_scope: string, clear: Uint8Array) => {
        // The encoder still holds `clear` while the ciphertext is uploaded.
        stats.heldBytes += 2 * clear.length;
        stats.peakHeldBytes = Math.max(stats.peakHeldBytes, stats.heldBytes);
        return clear.slice();
      },
    },
    partTargetBytes: PART,
  } as unknown as LocalSyncDeps;
  const drive = async <T>(work: Promise<T>): Promise<T> => {
    let settled: { ok: T } | { error: unknown } | undefined;
    work.then(
      (ok) => (settled = { ok }),
      (error: unknown) => (settled = { error }),
    );
    let last = "";
    let quiet = 0;
    for (let spins = 0; !settled; spins++) {
      if (spins > 20_000) throw new Error("upload width rig: work is stuck");
      await realSleep(8);
      const now = `${stats.started}/${stats.stored}/${stats.heldBytes}`;
      quiet = now === last ? quiet + 1 : 0;
      last = now;
      // The encoder reads SQLite for real: step time only when it has stopped.
      if (quiet >= 3) {
        await clock.advance(PUT_MS);
        quiet = 0;
      }
    }
    if ("error" in settled) throw settled.error;
    return settled.ok;
  };
  return {
    clock,
    stats,
    governor: gate.governor,
    release,
    drive,
    publish: () => encodePrefixes(deps, INPUT),
  };
}

/**
 * The window may grow to `cap` parts; the budget holds `budgetParts` of them.
 * A part counts twice (plain and ciphertext), so the budget is two parts' bytes
 * for each.
 */
const policyFor = (cap: number, budgetParts: number) => ({
  // The gate's cap is maxBytesInFlight / partBytes.
  maxBytesInFlight: budgetParts * 2 * PART,
  partBytes: Math.floor((budgetParts * 2 * PART) / cap),
});

describe("a stream's part uploads are limited by the send gate and the byte budget, not by a width of their own", () => {
  it("puts more than two parts on the wire at once, up to the gate's window", async () => {
    const r = await rig({ parts: 48, policy: policyFor(8, 48) });
    await r.drive(r.publish());
    expect(r.stats.stored).toBe(48);
    expect(r.stats.peakOnWire).toBeGreaterThan(2);
    expect(r.stats.peakOnWire).toBeLessThanOrEqual(8);
  });

  it("never holds more bytes in memory (plain and ciphertext) than the byte budget, however wide the gate allows", async () => {
    const budgetParts = 5;
    const r = await rig({
      parts: 48,
      // A window of 20 would allow far more than the budget holds.
      policy: policyFor(20, budgetParts),
    });
    const window = r.governor.window();
    await r.drive(r.publish());
    expect(r.stats.stored).toBe(48);
    expect(r.stats.peakOnWire).toBeGreaterThan(2);
    expect(r.stats.peakHeldBytes).toBeLessThanOrEqual(budgetParts * 2 * PART);
    expect(r.stats.peakOnWire).toBeLessThanOrEqual(budgetParts);
    // The governor's own count of reserved bytes agrees.
    expect(window.end().peakBytesInFlight).toBeLessThanOrEqual(
      budgetParts * 2 * PART,
    );
  });

  it("starts a bounded number of PUTs of a store whose PUTs stay parked, however many parts the stream has", async () => {
    const budgetParts = 4;
    const r = await rig({
      parts: 48,
      policy: {},
      parked: { policy: { maxBytesInFlight: budgetParts * 2 * PART } },
    });
    const publishing = r.publish();
    // Let the encoder run until it stops: every part it can encode has started.
    let last = -1;
    for (let quiet = 0; quiet < 6;) {
      await realSleep(25);
      quiet = r.stats.started === last ? quiet + 1 : 0;
      last = r.stats.started;
    }
    expect(r.stats.started).toBeGreaterThan(0);
    expect(r.stats.started).toBeLessThanOrEqual(budgetParts);
    expect(r.stats.peakHeldBytes).toBeLessThanOrEqual(budgetParts * 2 * PART);
    r.release();
    await publishing;
    expect(r.stats.stored).toBe(48);
    expect(r.stats.peakHeldBytes).toBeLessThanOrEqual(budgetParts * 2 * PART);
  });

  it("starts no request while a 429's Retry-After lasts, then goes on at the same window", async () => {
    const retryAfterMs = 5_000;
    let throttledAt: number | undefined;
    const r = await rig({
      parts: 48,
      policy: policyFor(8, 48),
      failPut: ({ n, now }) => {
        if (n !== 12) return undefined;
        throttledAt = now;
        return throttle(429, retryAfterMs);
      },
    });
    await r.drive(r.publish());
    expect(r.stats.stored).toBe(48);
    expect(throttledAt).toBeDefined();
    // It had gone wide before the throttle, so the pause is a real drop in width.
    expect(r.stats.peakOnWire).toBeGreaterThan(2);
    // The throttled PUT answered at throttledAt + PUT_MS + 1; nothing leaves the
    // gate between that answer and the end of the wait it asked for.
    const answered = throttledAt! + PUT_MS + 1;
    const during = r.stats.startTimes.filter(
      (t) => t > answered && t < answered + retryAfterMs,
    );
    expect(during).toEqual([]);
  });

  it("halves the window on a 503, so the next request leaves under the smaller window", async () => {
    let answer: PutContext | undefined;
    const starts: PutContext[] = [];
    const r = await rig({
      parts: 48,
      policy: policyFor(8, 48),
      failPut: ({ n }) => (n === 20 ? throttle(503) : undefined),
      onFailureAnswer: (put) => (answer = put),
      onPutStart: (put) => starts.push(put),
    });
    await r.drive(r.publish());
    expect(r.stats.stored).toBe(48);
    expect(answer).toBeDefined();
    expect(answer!.window).toBeGreaterThan(2);
    // The window was in use: parts were on the wire wider than two.
    expect(r.stats.peakOnWire).toBeGreaterThan(2);
    // The first request to leave after the answer sees the halved window.
    const next = starts.find((s) => s.now > answer!.now);
    expect(next?.window).toBe(Math.floor(answer!.window / 2));
  });

  it("sends 129 PUTs, as a ChatGPT first sync does, in a fraction of two-at-a-time, under the 10 PUT/s guard", async () => {
    // The gate and the quota alone, with no encoder in front, so the host's
    // load cannot move the virtual time. Every part is ready at once.
    const clock = fakeClock();
    let onWire = 0;
    let peak = 0;
    const adapter = {
      urlForKey: (key: string) => key,
      exists: async () => false,
      download: async () => new Uint8Array(),
      delete: async () => true,
      upload: async () => {
        onWire += 1;
        peak = Math.max(peak, onWire);
        await new Promise<void>((resolve) => clock.after(PUT_MS, resolve));
        onWire -= 1;
        return "";
      },
    };
    const blobs = createStorageStreamSyncBlobs(adapter as never, {
      ...DEFAULT_STORAGE_ACCESS_POLICY,
      now: clock.now,
      after: clock.after,
      random: () => 0,
      // The production default: a window of up to 64 MiB / 4 MiB = 16.
      // vana-storage's guard: 600 PUTs per 60 s.
      quota: { limit: 600, windowMs: 60_000 },
    });
    const parts = 129;
    await clock.drive(
      Promise.all(
        Array.from({ length: parts }, (_, i) =>
          blobs.put(`part-${i}`, new Uint8Array(1)),
        ),
      ),
      PUT_MS,
    );
    const spentMs = clock.now();
    // Two at a time, at one PUT_MS each: 64.5 s.
    expect(peak).toBeGreaterThan(2);
    expect(peak).toBeLessThanOrEqual(16);
    expect(spentMs).toBeLessThan(((parts / 2) * PUT_MS) / 2);
    // Slow start reaches the guard's rate in 1+2+4+8 PUTs over four round
    // trips. Growing by one per window of successes took 19 s on this model.
    expect(spentMs).toBeLessThan(19_000);
    // The guard's 10 PUT/s is the floor.
    expect(spentMs).toBeGreaterThanOrEqual((parts / 10) * 1_000);
  });
});
