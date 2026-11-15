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
import v8 from "node:v8";
import vm from "node:vm";
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
const ROW_VALUE_BYTES = 1_700;
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

/**
 * Waits until the encoder has stopped: at least `atLeast` uploads have started
 * and no more has started for 150 ms. Waiting for the count first keeps a slow
 * host, where the first upload starts late, from reading a quiet start as a stop.
 */
async function parked(
  r: { stats: { started: number } },
  atLeast: number,
): Promise<void> {
  const deadline = Date.now() + 60_000;
  while (r.stats.started < atLeast && Date.now() < deadline)
    await realSleep(25);
  let last = -1;
  for (let quiet = 0; quiet < 6;) {
    await realSleep(25);
    quiet = r.stats.started === last ? quiet + 1 : 0;
    last = r.stats.started;
  }
}
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
    /** In order: each part encrypted, each PUT started. */
    readonly events: string[];
    /** Every object stored, by key. */
    readonly objects: Map<string, Uint8Array>;
    /** A weak reference to the plain bytes of each part, taken as it is encrypted. */
    readonly plain: WeakRef<Uint8Array>[];
    encrypted: number;
  };
  readonly governor: ReturnType<
    typeof createStorageStreamSyncBlobs
  >["governor"];
  /** Lets every parked PUT finish. */
  readonly release: () => void;
  readonly budgetIsFree: () => Promise<boolean>;
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
  const maxBytes = Math.max(
    1,
    (options.parked?.policy.maxBytesInFlight ??
      options.policy.maxBytesInFlight ??
      DEFAULT_STORAGE_ACCESS_POLICY.maxBytesInFlight) as number,
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
    events: [],
    objects: new Map(),
    plain: [],
    encrypted: 0,
  };
  const gate: { governor?: Rig["governor"] } = {};
  const adapter = {
    urlForKey: (key: string) => key,
    exists: async () => false,
    download: async () => new Uint8Array(),
    delete: async () => true,
    upload: async (key: string, bytes: Uint8Array) => {
      stats.started += 1;
      stats.events.push("put");
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
      stats.heldBytes -= bytes.length;
      stats.objects.set(key, bytes.slice());
      return "";
    },
  };
  let release!: () => void;
  const parkedUntil = new Promise<void>((resolve) => (release = resolve));
  const blobs: StreamSyncBlobs = options.parked
    ? {
        ...createMemoryStreamSyncBlobs(options.parked.policy),
        put: async (key, bytes) => {
          stats.started += 1;
          stats.events.push("put");
          stats.onWire += 1;
          stats.peakOnWire = Math.max(stats.peakOnWire, stats.onWire);
          await parkedUntil;
          stats.onWire -= 1;
          stats.stored += 1;
          stats.heldBytes -= bytes.length;
          stats.objects.set(key, bytes.slice());
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
        const cipher = clear.slice();
        stats.events.push("encrypt");
        stats.encrypted += 1;
        stats.plain.push(new WeakRef(clear));
        // The plain bytes and the ciphertext exist together while it runs;
        // when it returns only the ciphertext is kept for the PUT.
        stats.peakHeldBytes = Math.max(
          stats.peakHeldBytes,
          stats.heldBytes + clear.length + cipher.length,
        );
        stats.heldBytes += cipher.length;
        return cipher;
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
    /** Whether every reserved byte was given back: a reservation of the whole budget is granted at once. */
    budgetIsFree: async () => {
      const all = await Promise.race([
        gate.governor!.reserve(maxBytes),
        realSleep(50).then(() => "held" as const),
      ]);
      if (all === "held") return false;
      all();
      return true;
    },
  };
}

/**
 * The window may grow to `cap` parts, and the budget holds `budgetParts` parts
 * in flight and the part being built. An uploading part keeps its ciphertext
 * (one part's bytes); the builder's reservation is the plain bytes and room for
 * their ciphertext (two).
 */
const policyFor = (cap: number, budgetParts: number) => ({
  maxPartsInFlight: cap,
  partBytes: PART,
  maxBytesInFlight: (budgetParts + 2) * PART,
});

/** The production policy, scaled from 4 MiB parts to this test's part size. */
const productionPolicy = (): Partial<StorageAccessPolicy> => {
  const scale = PART / DEFAULT_STORAGE_ACCESS_POLICY.partBytes;
  return {
    partBytes: PART,
    maxBytesInFlight: Math.round(
      DEFAULT_STORAGE_ACCESS_POLICY.maxBytesInFlight * scale,
    ),
  };
};

/** One part at a time: the serial path every wider policy must equal in bytes. */
const serialPolicy = (): Partial<StorageAccessPolicy> => ({
  maxPartsInFlight: 1,
  partBytes: 2 * PART,
  maxBytesInFlight: 2 * PART,
});

/** Run the gc the test runner does not expose. */
const collect = (() => {
  v8.setFlagsFromString("--expose-gc");
  const gc = vm.runInNewContext("gc") as () => void;
  return async () => {
    for (let i = 0; i < 3; i++) {
      await realSleep(5);
      gc();
    }
  };
})();

describe("a stream's part uploads are limited by the send gate and the byte budget, not by a width of their own", () => {
  it("puts more than two parts on the wire at once, up to the gate's window", async () => {
    const r = await rig({ parts: 48, policy: policyFor(8, 48) });
    await r.drive(r.publish());
    expect(r.stats.stored).toBe(48);
    expect(r.stats.peakOnWire).toBeGreaterThan(2);
    expect(r.stats.peakOnWire).toBeLessThanOrEqual(8);
  });

  it("never holds more bytes in memory than the byte budget, however wide the gate allows", async () => {
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
    const budget = (budgetParts + 2) * PART;
    expect(r.stats.peakHeldBytes).toBeLessThanOrEqual(budget);
    // The budget's parts in flight, and the part that was being built and has
    // just become one of them.
    expect(r.stats.peakOnWire).toBeLessThanOrEqual(budgetParts + 1);
    // The governor's own count of reserved bytes agrees.
    expect(window.end().peakBytesInFlight).toBeLessThanOrEqual(budget);
  });

  it("starts a bounded number of PUTs of a store whose PUTs stay parked, however many parts the stream has", async () => {
    const budgetParts = 4;
    const r = await rig({
      parts: 48,
      policy: {},
      parked: { policy: policyFor(budgetParts, budgetParts) },
    });
    const publishing = r.publish();
    // Let the encoder run until it stops: every part it can encode has started.
    await parked(r, budgetParts);
    const budget = (budgetParts + 2) * PART;
    expect(r.stats.started).toBeGreaterThan(0);
    // The parts of one budget are the parts it holds: at most its parts in
    // flight and the one being built.
    expect(r.stats.started).toBeLessThanOrEqual(budgetParts + 1);
    expect(r.stats.peakHeldBytes).toBeLessThanOrEqual(budget);
    r.release();
    await publishing;
    expect(r.stats.stored).toBe(48);
    expect(r.stats.peakHeldBytes).toBeLessThanOrEqual(budget);
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

/**
 * The upload pipeline at the production geometry: how wide it runs, how much
 * it holds, and what it must not change. The geometry is the production
 * policy (`DEFAULT_STORAGE_ACCESS_POLICY`) scaled to this test's part size, so
 * a change to the width or the budget there is what these tests read.
 */
describe("the part upload pipeline at the production policy", () => {
  const WIDTH = 16;
  const PARTS = 64;

  it("keeps the production width of parts on the wire once the window has ramped up", async () => {
    const r = await rig({ parts: PARTS, policy: productionPolicy() });
    await r.drive(r.publish());
    expect(r.stats.stored).toBe(PARTS);
    expect(r.stats.peakOnWire).toBe(WIDTH);
  });

  it("never has more than the width on the wire, with a wider window offered", async () => {
    const r = await rig({
      parts: PARTS,
      policy: { ...productionPolicy(), maxBytesInFlight: 64 * PART },
    });
    await r.drive(r.publish());
    expect(r.stats.stored).toBe(PARTS);
    expect(r.stats.peakOnWire).toBeLessThanOrEqual(WIDTH);
  });

  it("starts the first upload before the later parts are read and encoded", async () => {
    const r = await rig({ parts: PARTS, policy: productionPolicy() });
    await r.drive(r.publish());
    const first = r.stats.events.indexOf("put");
    const lastEncoded = r.stats.events.lastIndexOf("encrypt");
    expect(first).toBeGreaterThanOrEqual(0);
    expect(first).toBeLessThan(lastEncoded);
    // Not just the first: parts are on the wire while others are still encoded.
    const putsBeforeLastEncode = r.stats.events
      .slice(0, lastEncoded)
      .filter((event) => event === "put").length;
    expect(putsBeforeLastEncode).toBeGreaterThanOrEqual(WIDTH / 2);
  });

  it("holds no more than the width of parts, plus the part being built, while every PUT is parked", async () => {
    const r = await rig({
      parts: PARTS,
      policy: {},
      parked: { policy: productionPolicy() },
    });
    const publishing = r.publish();
    await parked(r, WIDTH);
    // Every started upload is parked holding its ciphertext; the encoder has
    // stopped on the byte budget.
    expect(r.stats.started).toBeGreaterThanOrEqual(WIDTH);
    expect(r.stats.started).toBeLessThanOrEqual(WIDTH + 1);
    expect(r.stats.peakHeldBytes).toBeLessThanOrEqual((WIDTH + 2) * PART);
    r.release();
    await publishing;
    expect(r.stats.stored).toBe(PARTS);
    expect(await r.budgetIsFree()).toBe(true);
  });

  it("does not keep a part's plain bytes while its PUT is pending", async () => {
    const r = await rig({
      parts: PARTS,
      policy: {},
      parked: { policy: productionPolicy() },
    });
    const publishing = r.publish();
    await parked(r, WIDTH);
    expect(r.stats.encrypted).toBeGreaterThanOrEqual(WIDTH);
    await collect();
    const alive = r.stats.plain.filter((ref) => ref.deref() !== undefined);
    // Parked PUTs hold the ciphertext only. The encoder may still hold the
    // plain bytes of the part it has just encoded and not yet handed over.
    expect(alive.length).toBeLessThanOrEqual(1);
    r.release();
    await publishing;
  });

  it("starts no more PUTs per second than the storage guard allows", async () => {
    const r = await rig({
      parts: PARTS,
      // vana-storage: 600 PUTs per 60 s, which is 10 a second.
      policy: {
        ...productionPolicy(),
        quota: { limit: 600, windowMs: 60_000 },
      },
    });
    await r.drive(r.publish());
    expect(r.stats.stored).toBe(PARTS);
    const starts = r.stats.startTimes;
    for (let i = 0; i + 10 < starts.length; i++) {
      // Any eleven PUTs span at least a second.
      expect(starts[i + 10]! - starts[i]!).toBeGreaterThanOrEqual(1_000 - 1);
    }
    // The guard, not the window, set the pace: the window had room for more.
    expect(r.stats.peakOnWire).toBeGreaterThan(2);
  });

  it("stores the same parts, byte for byte, as one part at a time", async () => {
    const serial = await rig({ parts: PARTS, policy: serialPolicy() });
    await serial.drive(serial.publish());
    const wide = await rig({ parts: PARTS, policy: productionPolicy() });
    await wide.drive(wide.publish());
    expect(serial.stats.objects.size).toBe(PARTS);
    expect([...wide.stats.objects.keys()].sort()).toEqual(
      [...serial.stats.objects.keys()].sort(),
    );
    for (const [key, bytes] of serial.stats.objects) {
      expect(
        Buffer.from(wide.stats.objects.get(key)!).equals(Buffer.from(bytes)),
      ).toBe(true);
    }
    // And the two runs differ in how they got there: one wide, one narrow.
    expect(serial.stats.peakOnWire).toBe(1);
    expect(wide.stats.peakOnWire).toBeGreaterThan(8);
  });

  it("stops at the first final failure: no PUT starts after it, nothing stays reserved", async () => {
    let failedAt: number | undefined;
    const r = await rig({
      parts: PARTS,
      policy: productionPolicy(),
      failPut: ({ n, now }) => {
        if (n !== 20) return undefined;
        failedAt = now;
        return Object.assign(new Error("storage request failed (400)"), {
          status: 400,
        });
      },
    });
    await expect(r.drive(r.publish())).rejects.toThrow(/400/);
    expect(failedAt).toBeDefined();
    const startedAtFailure = r.stats.started;
    const encryptedAtFailure = r.stats.encrypted;
    // Later time does nothing: nothing of the stream runs on after the throw.
    await r.clock.advance(10 * PUT_MS);
    await realSleep(50);
    expect(r.stats.started).toBe(startedAtFailure);
    expect(r.stats.encrypted).toBe(encryptedAtFailure);
    expect(r.stats.stored).toBeLessThan(PARTS);
    expect(r.stats.onWire).toBe(0);
    expect(await r.budgetIsFree()).toBe(true);
  });
});
