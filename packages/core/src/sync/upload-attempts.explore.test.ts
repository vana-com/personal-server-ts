/**
 * Schedule exploration for the upload-attempt ledger.
 *
 * A fake store separates a write's invocation, its commit and its resolution:
 * a write can succeed, fail cleanly, fail uncertainly (stored or lost), be
 * held before it commits, or commit and be held before it resolves. A seeded
 * scheduler interleaves begin, settle (also stale), close (0, finite and
 * unbounded), recover, reconcile, owner retry, release of held writes, a
 * manager rebuilt over the same store, and a crash of the whole realm, across
 * microtask boundaries. Seeds may start from a foreign owner's records, a
 * leftover marker or a malformed value. A failure prints its seed and a trace
 * shortened to the fewest steps that still fail.
 *
 * Safety (checked at stable boundaries, after held writes are released):
 * 1. Before a body enters, its own begin succeeded and its marker is durable.
 *    A durable marker with no body that entered and is not yet acknowledged
 *    may exist only while the writer's last write failed (a repair is owed).
 * 2. A lease is released only after the committed state reached storage: a
 *    clean hand-over leaves no marker without a body, and the store is never
 *    written while its lock is free or before a malformed value is kept.
 * 3. No two bodies for one entry run at once.
 * 4. After a restart, an entry's interrupted count is within the range the
 *    bodies that entered and never settled allow. A crash between a durable
 *    marker and the body (or between a body and its settle) cannot be told
 *    apart in storage; those entries are exempt, as the contract says.
 * 5. Quarantine comes only from interruptions: a key is quarantined exactly
 *    when its stored count reached the threshold, and never without enough
 *    events that could leave a marker (a body that entered and never settled,
 *    an abrupt crash that held an admission, or a stop that gave up).
 * 6. A stop rejects only when its next retry would pass the deadline; a clean stop
 *    leaves no marker behind, however many admissions it refused.
 * Liveness: once faults stop and held writes are released, every operation
 * finishes, a stop that failed hands the store over by itself, and a clean
 * close always succeeds.
 *
 * Intentional shutdown (`stop`, then the realm ends) is explored with no
 * abrupt-crash exemptions: its bodies and refused admissions are counted only
 * by what storage could still hold.
 */
import { describe, expect, it, vi } from "vitest";

import {
  acquireProcessLock,
  createUploadAttemptLedger,
  UploadAttemptWriteUncertainError,
  uploadAttemptKey,
  type UploadAttemptLedger,
  type UploadAttemptStore,
  type UploadAttemptToken,
} from "./upload-attempts.js";
import type { IndexEntry } from "../storage/index/types.js";

const OWNER = "0x2222222222222222222222222222222222222222";
const FOREIGN = "0x3333333333333333333333333333333333333333";
const KEYS = [1, 2, 3];
const SEEDS = Number(process.env.UPLOAD_ATTEMPT_SEEDS ?? 2000);
const FIRST = Number(process.env.UPLOAD_ATTEMPT_FIRST_SEED ?? 1);
/** Retry base and stop window the explored ledgers use (real time). */
const RETRY_MS = 1;
const STOP_WINDOW = 40;

/** Earliest final retry across nonnegative storage and scheduler latency. */
function earliestStopFailure(grace: number): number {
  const giveUpAt = (start: number) => {
    let earliest = Infinity;
    let elapsed = start;
    let delay = RETRY_MS;
    while (elapsed <= STOP_WINDOW) {
      // A failed write may finish later than it started. The next sleep is
      // refused once its end would exceed the deadline (integer milliseconds).
      earliest = Math.min(earliest, Math.max(elapsed, STOP_WINDOW - delay + 1));
      elapsed += delay;
      delay *= 2;
    }
    return earliest;
  };
  return Math.min(giveUpAt(0), giveUpAt(grace));
}

function entry(n: number): IndexEntry {
  const collectedAt = `2026-11-07T10:0${n}:00Z`;
  return {
    id: n,
    fileId: null,
    schemaId: null,
    path: `scope.${n}/${collectedAt}.json`,
    scope: `scope.${n}`,
    collectedAt,
    createdAt: collectedAt,
    sizeBytes: 1024,
    version: 1,
    dataPointId: null,
  };
}

function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

type Stored = { records: Array<Record<string, unknown>> } | unknown;
interface Rec {
  owner: string;
  rowId: number;
  inFlight: boolean;
  interrupted: number;
}
const recordsOf = (value: Stored): Rec[] =>
  value && Array.isArray((value as { records?: unknown }).records)
    ? (value as { records: Rec[] }).records
    : [];
const FOREIGN_RECORD = {
  key: "foreign",
  owner: FOREIGN,
  scope: "scope.9",
  path: "scope.9/p.json",
  rowId: 9,
  interrupted: 1,
  inFlight: true,
  quarantined: false,
};

interface Body {
  entry: number;
  manager: Manager;
  token: UploadAttemptToken;
  /** settle not called / called with no durable answer yet / answered. */
  settle: "none" | "called" | "ok" | "rejected";
  counted: boolean;
  cleared: boolean;
}

interface Manager {
  id: number;
  ns: string;
  ledger: UploadAttemptLedger;
  dead: boolean;
  /** A close resolved and no recover since: the lease is gone. */
  closed: boolean;
  /** A stop failed: the ledger owes the store a repair by itself. */
  stopFailed: boolean;
  closeCalls: number;
  /** Another manager over this store took it after this one let go. */
  owned: boolean;
  recoverCalls: number;
  pending: number;
  held: Array<() => void>;
  /** Entries with a begin in flight, or rejected while storage was failing. */
  suspect: Map<number, number>;
  /** A stop was started; the realm ends once it has resolved. */
  shutting: boolean;
}

class Failure extends Error {}

/** Which transitions and outcomes the explored schedules reached. */
const coverage = new Map<string, number>();
const covered = (name: string) =>
  coverage.set(name, (coverage.get(name) ?? 0) + 1);

let runs = 0;
async function runSeed(seed: number, maxSteps = Infinity) {
  const run = ++runs;
  const rng = mulberry32(seed);
  const events: string[] = [];
  const violations: string[] = [];
  const flag = (invariant: string, detail: string) => {
    violations.push(`invariant ${invariant}: ${detail}`);
  };
  const fail = (invariant: string, detail: string): never => {
    throw new Failure(
      `invariant ${invariant}: ${detail}` +
        (process.env.UPLOAD_ATTEMPT_TRACE
          ? `\n  ${events.slice(-120).join("\n  ")}`
          : ""),
    );
  };
  const pick = <T>(items: readonly T[]) =>
    items[Math.floor(rng() * items.length)]!;

  // Some seeds use a threshold a schedule can reach; the rest never quarantine.
  const threshold = rng() < 0.35 ? 2 : 1_000;
  // Some seeds refuse nearly every write while faults last, so a stop gives up.
  const stormy = rng() < 0.4;
  // Initial storage.
  const start = rng();
  const malformed = { version: 99, records: "?" };
  let durable: Stored = null;
  let preserved = false;
  const expectedStart = new Map<number, number>();
  if (start < 0.12) durable = malformed;
  else if (start < 0.27)
    durable = { version: 1, records: [{ ...FOREIGN_RECORD }] };
  else if (start < 0.37) {
    expectedStart.set(2, 1);
    durable = {
      version: 1,
      records: [
        {
          key: uploadAttemptKey(OWNER, entry(2)),
          owner: OWNER,
          scope: entry(2).scope,
          path: entry(2).path,
          rowId: 2,
          interrupted: 0,
          inFlight: true,
          quarantined: false,
        },
      ],
    };
  }
  /** A marker left by an earlier process stays until a recovery counts it. */
  const leftover = new Set(expectedStart.keys());
  const startedMalformed = durable === malformed;
  const lastWriteOk = new Map<string, boolean>();
  let faults = true;
  let managers = 0;
  const alive: Manager[] = [];
  const everyManager: Manager[] = [];
  const bodies: Body[] = [];
  const exempt = new Set<number>();
  const lo = new Map<number, number>(expectedStart);
  const hi = new Map<number, number>(expectedStart);
  /**
   * Quarantine evidence. `real`: crashes or shutdowns that left a body which
   * entered and never settled (plus leftovers). `admitted`: abrupt crashes that
   * held an admission, and shutdowns whose stop gave up (only after the
   * window). A clean stop adds nothing. Never reset: each is an upper bound on
   * what can have counted.
   */
  const real = new Map<number, number>(expectedStart);
  const admitted = new Map<number, number>();
  /** Namespaces whose intentional stop resolved clean. */
  const cleanStops = new Set<string>();
  const bump = (m: Map<number, number>, k: number, by: number) =>
    m.set(k, (m.get(k) ?? 0) + by);
  const tick = async () => {
    for (let i = Math.floor(rng() * 4); i > 0; i--) await Promise.resolve();
  };
  const lockFree = (ns: string) => {
    const probe = acquireProcessLock(`upload-attempts:${ns}`);
    probe?.release();
    return probe !== null;
  };

  function makeManager(ns?: string): Manager {
    const id = ++managers;
    const manager: Manager = {
      id,
      ns: ns ?? `explore:${run}:${id}`,
      ledger: undefined as never,
      dead: false,
      closed: false,
      stopFailed: false,
      closeCalls: 0,
      owned: false,
      recoverCalls: 0,
      pending: 0,
      held: [],
      suspect: new Map(),
      shutting: false,
    };
    const never = () => new Promise<never>(() => undefined);
    const store: UploadAttemptStore = {
      namespace: manager.ns,
      read: async () => (manager.dead ? never() : structuredClone(durable)),
      async preserveCorrupt() {
        if (manager.dead) return never();
        await tick();
        if (faults && rng() < 0.2) throw new Error("preserve failed");
        preserved = true;
        covered("preserve kept");
      },
      async write(envelope) {
        if (manager.dead) return never();
        const snapshot = structuredClone(envelope);
        if (lockFree(manager.ns))
          flag("2", `m${id} wrote while its store lock was free`);
        await tick();
        if (manager.dead) return never();
        const commit = () => {
          if (durable === malformed && !preserved)
            flag("2", "a malformed value was replaced before it was kept");
          durable = snapshot;
        };
        const roll = faults ? rng() : 0;
        const kind =
          faults && stormy && rng() < 0.9
            ? rng() < 0.5
              ? "fail"
              : "uncertain-stored"
            : roll < 0.5
              ? "ok"
              : roll < 0.6
                ? "fail"
                : roll < 0.68
                  ? "uncertain-stored"
                  : roll < 0.75
                    ? "uncertain-lost"
                    : roll < 0.88
                      ? "hold-before"
                      : "hold-after";
        covered(`write ${kind}`);
        events.push(
          `m${id} write ${kind} ${JSON.stringify(recordsOf(snapshot).map((r) => `${r.rowId}${r.inFlight ? "F" : "-"}${r.interrupted}`))}`,
        );
        const ok = (value: boolean) => lastWriteOk.set(manager.ns, value);
        if (kind === "ok") {
          commit();
          ok(true);
        } else if (kind === "fail") {
          ok(false);
          throw new Error("write failed");
        } else if (kind === "uncertain-stored") {
          commit();
          ok(false);
          throw new UploadAttemptWriteUncertainError("stored");
        } else if (kind === "uncertain-lost") {
          ok(false);
          throw new UploadAttemptWriteUncertainError("lost");
        } else if (kind === "hold-before") {
          await new Promise<void>((resolve) =>
            manager.held.push(() => {
              if (!manager.dead) {
                commit();
                ok(true);
              }
              resolve();
            }),
          );
          if (manager.dead) return never();
        } else {
          commit();
          ok(true);
          await new Promise<void>((resolve) => manager.held.push(resolve));
          if (manager.dead) return never();
        }
      },
    };
    manager.ledger = createUploadAttemptLedger(store, OWNER, {
      maxInterrupted: threshold,
      repairRetryMs: RETRY_MS,
      stopRepairWindowMs: STOP_WINDOW,
    });
    alive.push(manager);
    everyManager.push(manager);
    return manager;
  }

  const track = <T>(
    manager: Manager,
    promise: Promise<T>,
    infinite = false,
  ) => {
    if (!infinite) manager.pending += 1;
    return promise.then(
      (value) => {
        if (!infinite) manager.pending -= 1;
        return { ok: true as const, value };
      },
      (error: unknown) => {
        if (!infinite) manager.pending -= 1;
        return { ok: false as const, error };
      },
    );
  };
  const errorName = (error: unknown) =>
    error instanceof Error ? error.name : "other";

  const running = (n: number) =>
    bodies.filter(
      (b) =>
        b.entry === n && b.settle === "none" && !b.manager.dead && !b.counted,
    );
  /**
   * A live body whose marker storage may still hold. Bodies of ended realms
   * are not live: their markers are leftovers, tracked by `leftover`.
   */
  const keyFor = (n: number) => uploadAttemptKey(OWNER, entry(n));
  const owns = (n: number) =>
    bodies.some(
      (b) => b.entry === n && !b.counted && b.settle !== "ok" && !b.cleared,
    );
  /**
   * Storage and timer latency can move the final retry earlier than the
   * zero-latency schedule: its next doubled sleep no longer fits. Retain a
   * lower bound across those schedules and an allowance for host stalls.
   */
  const stopGaveUp = (started: number, rejected: boolean, grace: number) => {
    if (!rejected) return;
    const elapsed = Date.now() - started;
    const earliest = earliestStopFailure(grace);
    if (elapsed + 2 < earliest)
      flag(
        "6",
        `a stop gave up at ${elapsed} ms, before its earliest valid final retry`,
      );
    if (elapsed > STOP_WINDOW + 500)
      flag(
        "6",
        `a stop gave up at ${elapsed} ms, after its ${STOP_WINDOW} ms window`,
      );
    covered("stop gave up");
  };

  function checkStable(label: string) {
    const groups = new Set(alive.map((m) => m.ns));
    for (const ns of groups) {
      const free = lockFree(ns);
      const cleanHandOver = alive.some((m) => m.ns === ns && m.closed);
      for (const record of recordsOf(durable)) {
        if (record.owner !== OWNER || !record.inFlight) continue;
        if (
          exempt.has(record.rowId) ||
          leftover.has(record.rowId) ||
          owns(record.rowId)
        )
          continue;
        if (free && cleanHandOver)
          fail(
            "2",
            `${label}: lease released with a marker for entry ${record.rowId} that no body owns`,
          );
        if (free || lastWriteOk.get(ns) !== false)
          fail(
            "1",
            `${label}: durable marker for entry ${record.rowId} that no body owns, with no repair owed`,
          );
      }
    }
  }

  /**
   * A stop that resolved clean left the store handed over: its lock is free
   * and no durable marker lacks a body that will settle it.
   */
  function checkCleanStops() {
    for (const ns of cleanStops) {
      if (!lockFree(ns)) continue;
      for (const record of recordsOf(durable)) {
        if (record.owner !== OWNER || !record.inFlight) continue;
        if (
          exempt.has(record.rowId) ||
          leftover.has(record.rowId) ||
          owns(record.rowId)
        )
          continue;
        fail(
          "2",
          `clean stop left a marker for entry ${record.rowId} that no body owns`,
        );
      }
    }
    cleanStops.clear();
  }

  async function stable(label: string) {
    for (let round = 0; round < 600; round++) {
      await new Promise<void>((r) => setImmediate(r));
      let released = 0;
      for (const m of alive)
        for (const release of m.held.splice(0)) {
          release();
          released += 1;
        }
      if (violations.length)
        fail("?", violations[0]!.replace(/^invariant /, ""));
      if (!released && alive.every((m) => m.pending === 0 && !m.held.length)) {
        checkCleanStops();
        return;
      }
      if (round > 5 && !released)
        await new Promise<void>((r) => setTimeout(r, 1));
    }
    fail(
      "liveness",
      `${label}: operations still pending (${alive.map((m) => m.pending)})`,
    );
  }

  function startBody(manager: Manager, n: number, token: UploadAttemptToken) {
    if (manager.dead) return;
    if (running(n).length > 0)
      flag("3", `two bodies for entry ${n} run at once`);
    if (
      !recordsOf(durable).some(
        (r) => r.owner === OWNER && r.rowId === n && r.inFlight,
      )
    )
      flag("1", `body for entry ${n} entered without a durable marker`);
    covered("body entered");
    bodies.push({
      entry: n,
      manager,
      token,
      settle: "none",
      counted: false,
      cleared: false,
    });
  }

  /**
   * A realm ends. Each body that never settled is counted once; each body
   * whose settle was in flight or refused may leave a marker. Refused
   * admissions may leave one too, but only where `admissions` says so.
   */
  function endRealm(old: Manager, admissions: boolean) {
    old.dead = true;
    old.held.length = 0;
    for (const body of bodies) {
      if (body.counted || body.manager !== old || body.settle === "ok")
        continue;
      body.counted = true;
      bump(hi, body.entry, 1);
      leftover.add(body.entry);
      if (body.settle === "none") {
        bump(lo, body.entry, 1);
        bump(real, body.entry, 1);
      } else bump(admitted, body.entry, 1);
    }
    for (const [n, count] of old.suspect) {
      if (count <= 0 || !admissions) continue;
      bump(hi, n, 1);
      leftover.add(n);
      bump(admitted, n, 1);
    }
    alive.splice(alive.indexOf(old), 1);
  }

  function crash() {
    covered("crash");
    for (const old of [...alive]) {
      for (const [n, count] of old.suspect) if (count > 0) exempt.add(n);
      if (old.stopFailed) for (const n of KEYS) exempt.add(n);
      endRealm(old, true);
    }
    alive.length = 0;
  }

  const doRecover = (manager: Manager) => {
    manager.closed = false;
    manager.stopFailed = false;
    const closes = manager.closeCalls;
    manager.recoverCalls += 1;
    void track(manager, manager.ledger.recover()).then((result) => {
      events.push(
        `m${manager.id} recover -> ${result.ok ? result.value : String(result.error)}`,
      );
      if (manager.dead) return;
      covered(
        result.ok
          ? `recover ${result.value ? "owned" : "refused"}`
          : `recover failed`,
      );
      if (result.ok && result.value) {
        if (manager.closeCalls === closes && lockFree(manager.ns))
          flag("2", `m${manager.id} owns the store but its lock is free`);
        manager.owned = true;
        // The lock was free, so every earlier holder of this store has let go.
        for (const other of alive)
          if (other !== manager && other.ns === manager.ns) other.owned = false;
        leftover.clear();
        for (const body of bodies) if (body.counted) body.cleared = true;
      }
    });
  };

  const first = makeManager();
  const steps = Math.min(
    20 + Math.floor(rng() * 30) + (threshold < 1_000 ? 60 : 0),
    maxSteps,
  );
  doRecover(first);
  for (let step = 0; step < steps; step++) {
    if (violations.length) break;
    const manager = pick(alive.length ? alive : [makeManager()]);
    const roll = rng();
    if (roll < 0.24) {
      const n = pick(KEYS);
      events.push(`m${manager.id} begin${n}`);
      const suspect = (by: number) =>
        manager.suspect.set(n, (manager.suspect.get(n) ?? 0) + by);
      suspect(1);
      void track(manager, manager.ledger.begin(entry(n))).then((result) => {
        suspect(result.ok || lastWriteOk.get(manager.ns) !== false ? -1 : 0);
        covered(`begin ${result.ok ? "ok" : errorName(result.error)}`);
        events.push(
          `m${manager.id} begin${n} -> ${result.ok ? "ok" : errorName(result.error)}`,
        );
        if (result.ok && manager.dead) {
          // The marker is durable, but the realm ended before its body
          // could start: an interruption, counted at the next boot.
          covered("begin after realm end");
          bodies.push({
            entry: n,
            manager,
            token: result.value,
            settle: "none",
            counted: true,
            cleared: false,
          });
          bump(hi, n, 1);
          bump(lo, n, 1);
          bump(real, n, 1);
          leftover.add(n);
        } else if (result.ok) startBody(manager, n, result.value);
      });
    } else if (roll < 0.42) {
      const mine = bodies.filter(
        (b) => b.manager === manager && b.settle === "none",
      );
      if (mine.length) {
        const body = pick(mine);
        const outcome = rng() < 0.5 ? "success" : "failure";
        events.push(`m${manager.id} settle${body.entry}:${outcome}`);
        body.settle = "called";
        if (outcome === "success") lo.set(body.entry, 0);
        void track(manager, manager.ledger.settle(body.token, outcome)).then(
          (result) => {
            covered(`settle ${result.ok ? "ok" : errorName(result.error)}`);
            events.push(
              `m${manager.id} settle${body.entry} -> ${result.ok ? "ok" : errorName(result.error)}`,
            );
            if (result.ok) {
              body.settle = "ok";
              if (outcome === "success") {
                lo.set(body.entry, 0);
                hi.set(body.entry, 0);
              }
            } else body.settle = "rejected";
          },
        );
      }
    } else if (roll < 0.47) {
      const old = bodies.filter(
        (b) => b.settle === "ok" && b.manager === manager,
      );
      if (old.length) {
        const body = pick(old);
        events.push(`m${manager.id} stale-settle${body.entry}`);
        covered("stale settle");
        void track(manager, manager.ledger.settle(body.token, "failure"));
      }
    } else if (roll < 0.56) {
      const grace = pick([0, 0, 12, Infinity]);
      events.push(`m${manager.id} close(${grace})`);
      manager.closeCalls += 1;
      const reactivated = manager.recoverCalls;
      const started = Date.now();
      void track(manager, manager.ledger.close(grace), grace === Infinity).then(
        (result) => {
          covered(`close ${result.ok ? "ok" : errorName(result.error)}`);
          stopGaveUp(started, !result.ok, grace);
          if (manager.recoverCalls !== reactivated) return;
          if (result.ok) manager.closed = true;
          else manager.stopFailed = true;
        },
      );
    } else if (roll < 0.63) {
      events.push(`m${manager.id} recover`);
      doRecover(manager);
    } else if (roll < 0.68) {
      const old = pick(alive);
      events.push(`m${old.id} rebuild-same-store`);
      const next = makeManager(old.ns);
      doRecover(next);
    } else if (roll < 0.72) {
      events.push("crash");
      crash();
      const next = makeManager();
      if (rng() < 0.7) doRecover(next);
    } else if (roll < 0.78) {
      const kept = KEYS.filter(() => rng() < 0.5);
      events.push(`m${manager.id} reconcile keep=${kept}`);
      for (const n of KEYS) lo.set(n, 0);
      void track(
        manager,
        manager.ledger.reconcile(kept.map(entry), {
          afterId: 0,
          throughId: pick(KEYS),
        }),
      ).then((result) =>
        covered(`reconcile ${result.ok ? "ok" : errorName(result.error)}`),
      );
    } else if (roll < 0.82) {
      const scope = rng() < 0.5 ? undefined : entry(pick(KEYS)).scope;
      events.push(`m${manager.id} retry(${scope})`);
      for (const n of KEYS) lo.set(n, 0);
      void track(manager, manager.ledger.release(scope)).then((result) =>
        covered(`retry ${result.ok ? "ok" : errorName(result.error)}`),
      );
    } else if (roll < 0.92) {
      events.push(`m${manager.id} release-held`);
      const held = manager.held;
      if (held.length) held.splice(Math.floor(rng() * held.length), 1)[0]!();
    } else if (roll < 0.95) {
      // Intentional shutdown: stop, then the realm ends. No crash exemptions;
      // a realm is one process, so every manager in it ends with the stop.
      if (manager.shutting) continue;
      manager.shutting = true;
      events.push(`m${manager.id} shutdown`);
      manager.closeCalls += 1;
      const reactivated = manager.recoverCalls;
      const started = Date.now();
      // Some stops run on healed storage: every write they make succeeds.
      const healed = rng() < 0.4;
      if (healed) faults = false;
      let refused: number[] = [];
      void track(manager, manager.ledger.close(0)).then((result) => {
        if (healed) faults = true;
        // Admissions this stop refused and no live body of its own holds. Only
        // when no operation is pending anywhere: an admission in flight may
        // still land as a marker for its own (ended) realm.
        if (
          healed &&
          result.ok &&
          manager.owned &&
          alive.every((m) => m.pending === 0)
        )
          refused = KEYS.filter(
            (n) =>
              (manager.suspect.get(n) ?? 0) > 0 &&
              !bodies.some(
                (b) =>
                  b.entry === n &&
                  b.manager === manager &&
                  b.settle !== "ok" &&
                  !b.counted,
              ),
          );
        covered(`shutdown ${result.ok ? "clean" : "stop refused"}`);
        events.push(
          `m${manager.id} shutdown -> ${result.ok ? "ok" : errorName(result.error)}`,
        );
        if (manager.dead || manager.recoverCalls !== reactivated) return;
        stopGaveUp(started, !result.ok, 0);
        // Handed over: the stop resolved and no attempt is still live. Only
        // then does a refused admission's marker count as gone.
        const handedOver =
          result.ok && KEYS.every((n) => !manager.ledger.isLive(keyFor(n)));
        // Checked at the next stable boundary, once no operation can still
        // commit a marker.
        if (handedOver) cleanStops.add(manager.ns);
        else if (!result.ok) manager.stopFailed = true;
        // The realm is the process: once this stop has resolved, every
        // manager in it ends. A manager that never stopped ended abruptly, so
        // its admissions may count. The stopping manager's refused admissions
        // count only where its stop exhausted the repair window (it rejected).
        for (const old of [...alive])
          endRealm(old, old !== manager || !result.ok);
      });
      events.push("stable");
      await stable("mid-run");
      checkStable(`after step ${step}`);
      // A clean stop on healthy storage leaves no marker for a refused admission.
      for (const n of refused)
        if (
          !bodies.some(
            (b) => b.entry === n && b.settle !== "ok" && !b.cleared,
          ) &&
          recordsOf(durable).some(
            (r) => r.owner === OWNER && r.rowId === n && r.inFlight,
          )
        )
          fail("2", `healthy clean stop left a marker for refused entry ${n}`);
    }
    if (rng() < 0.75) await tick();
  }
  if (violations.length) fail("?", violations[0]!.replace(/^invariant /, ""));

  // Storage heals. Everything settles; failed stops must hand over unaided.
  events.push("heal");
  faults = false;
  await stable("heal");
  checkStable("before settle");
  for (const body of bodies) {
    if (body.manager.dead || body.settle !== "none") continue;
    body.settle = "called";
    const outcome = rng() < 0.5 ? "success" : "failure";
    const result = await track(
      body.manager,
      body.manager.ledger.settle(body.token, outcome),
    );
    if (!result.ok)
      fail(
        "liveness",
        `a healed store rejected a settle: ${String(result.error)}`,
      );
    body.settle = "ok";
    if (outcome === "success") {
      lo.set(body.entry, 0);
      hi.set(body.entry, 0);
    }
  }
  await stable("settled");
  for (const manager of alive) {
    if (!manager.stopFailed) continue;
    if (alive.some((o) => o !== manager && o.ns === manager.ns && o.owned)) {
      covered("handed over to a rebuilt manager");
      continue;
    }
    for (let i = 0; i < 1500 && !lockFree(manager.ns); i++)
      await new Promise<void>((r) => setTimeout(r, 2));
    if (!lockFree(manager.ns))
      fail(
        "liveness",
        `m${manager.id} failed to stop and never handed the store over after storage healed`,
      );
    covered("unaided hand-over");
  }
  for (const manager of alive) {
    const result = await track(manager, manager.ledger.close(Infinity));
    if (!result.ok)
      fail(
        "liveness",
        `a healed store could not close: ${String(result.error)}`,
      );
    manager.closed = true;
  }
  await stable("closed");
  for (const manager of alive)
    if (!lockFree(manager.ns))
      fail("2", `m${manager.id} closed clean but kept its lease`);
  checkStable("after clean close");

  // A fresh process over the same bytes counts what never settled.
  const next = makeManager();
  const owned = await track(next, next.ledger.recover());
  await stable("final recover");
  if (!owned.ok || !owned.value)
    fail(
      "liveness",
      `the next manager could not take the released store: ${owned.ok ? "refused" : String(owned.error)}`,
    );
  for (const n of KEYS) {
    if (exempt.has(n)) continue;
    const stored = recordsOf(durable).find(
      (r) => r.owner === OWNER && r.rowId === n,
    );
    const interrupted = stored?.interrupted ?? 0;
    if (interrupted < (lo.get(n) ?? 0) || interrupted > (hi.get(n) ?? 0))
      fail(
        "4",
        `entry ${n} counted ${interrupted} interrupted, expected ${lo.get(n) ?? 0}..${hi.get(n) ?? 0}`,
      );
  }
  for (const record of recordsOf(durable))
    if (record.owner === OWNER && record.inFlight)
      fail("1", `marker left after recovery for entry ${record.rowId}`);
  for (const n of KEYS) {
    const stored = recordsOf(durable).find(
      (r) => r.owner === OWNER && r.rowId === n,
    ) as (Rec & { quarantined?: boolean }) | undefined;
    const interrupted = stored?.interrupted ?? 0;
    const quarantined = stored?.quarantined === true;
    if (quarantined) covered("quarantine set");
    if (quarantined !== interrupted >= threshold)
      fail(
        "5",
        `entry ${n}: quarantined=${quarantined} with ${interrupted} interrupted at threshold ${threshold}`,
      );
    if (quarantined && (real.get(n) ?? 0) + (admitted.get(n) ?? 0) < threshold)
      fail(
        "5",
        `entry ${n} quarantined on ${real.get(n) ?? 0} real and ${admitted.get(n) ?? 0} admitted interruptions, below ${threshold}`,
      );
  }
  if (start >= 0.12 && start < 0.27) {
    const kept = recordsOf(durable).find((r) => r.owner === FOREIGN);
    if (JSON.stringify(kept) !== JSON.stringify(FOREIGN_RECORD))
      fail("isolation", "a foreign owner's record changed");
  }
  if (startedMalformed && !preserved)
    fail("2", "a malformed value was reset without being kept");
  return events;
}

describe("upload attempt ledger: seeded schedule exploration", () => {
  it("accepts the final retry when a failed storage write consumes time", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
    let fault = false;
    let writes = 0;
    const store: UploadAttemptStore = {
      namespace: "explorer-storage-latency",
      read: async () => null,
      preserveCorrupt: async () => undefined,
      write: async () => {
        if (!fault) return;
        writes++;
        if (writes === 4)
          await new Promise<void>((resolve) => setTimeout(resolve, 11));
        throw new UploadAttemptWriteUncertainError("injected write failure");
      },
    };
    const ledger = createUploadAttemptLedger(store, OWNER, {
      repairRetryMs: RETRY_MS,
      stopRepairWindowMs: STOP_WINDOW,
    });
    try {
      await ledger.recover();
      fault = true;
      await expect(ledger.begin(entry(1))).rejects.toThrow();
      writes = 0;
      let rejectedAt: number | undefined;
      const stopped = ledger.close(0).catch(() => {
        rejectedAt = Date.now();
      });
      await vi.advanceTimersByTimeAsync(26);
      await stopped;
      expect(rejectedAt).toBe(26);
      expect(rejectedAt! + 2).toBeGreaterThanOrEqual(earliestStopFailure(0));
    } finally {
      fault = false;
      await vi.runAllTimersAsync();
      await ledger.close(0);
      vi.useRealTimers();
    }
  });

  it(`keeps its invariants across ${SEEDS} seeded schedules`, async () => {
    const started = Date.now();
    for (let seed = FIRST; seed <= SEEDS; seed++) {
      try {
        await runSeed(seed);
      } catch (error) {
        if (!(error instanceof Failure))
          throw new Error(`seed ${seed}: ${String(error)}`, { cause: error });
        // Report the fewest steps that still fail.
        let report = error.message;
        let trace = "";
        for (let steps = 1; steps <= 60; steps++) {
          try {
            await runSeed(seed, steps);
          } catch (shorter) {
            if (shorter instanceof Failure) {
              report = shorter.message;
              trace = `after ${steps} steps`;
              break;
            }
          }
        }
        const message = `seed ${seed}: ${report} (${trace || "full run"})`;
        console.error(message);
        expect.fail(message);
      }
    }
    const table = [...coverage].map(([k, v]) => `${k}=${v}`).join(", ");
    console.info(
      `explored ${SEEDS} seeds in ${Date.now() - started} ms; ${table}`,
    );
    if (SEEDS >= 1000)
      for (const name of [
        "write fail",
        "write uncertain-stored",
        "write uncertain-lost",
        "write hold-before",
        "write hold-after",
        "begin ok",
        "begin UploadAttemptStorageFailedError",
        "settle Error",
        "stale settle",
        "shutdown clean",
        "quarantine set",
        "recover refused",
        "recover failed",
        "crash",
        "stop gave up",
        "preserve kept",
      ])
        expect(
          coverage.get(name) ?? 0,
          `never reached: ${name}`,
        ).toBeGreaterThan(0);
  }, 120_000);
});
