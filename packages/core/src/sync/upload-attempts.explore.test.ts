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
 * Liveness: once faults stop and held writes are released, every operation
 * finishes, a stop that failed hands the store over by itself, and a clean
 * close always succeeds.
 */
import { describe, expect, it } from "vitest";

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
          roll < 0.5
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
      maxInterrupted: 1_000,
      repairRetryMs: 1,
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
  /** A body whose marker storage may still hold. */
  const owns = (n: number) =>
    bodies.some((b) => b.entry === n && b.settle !== "ok" && !b.cleared);

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
      if (!released && alive.every((m) => m.pending === 0 && !m.held.length))
        return;
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

  function crash() {
    covered("crash");
    for (const old of alive) {
      old.dead = true;
      old.held.length = 0;
      for (const [n, count] of old.suspect) if (count > 0) exempt.add(n);
      if (old.stopFailed) for (const n of KEYS) exempt.add(n);
    }
    for (const body of bodies) {
      if (body.counted || !body.manager.dead || body.settle === "ok") continue;
      body.counted = true;
      bump(hi, body.entry, 1);
      if (body.settle === "none") bump(lo, body.entry, 1);
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
        leftover.clear();
        for (const body of bodies) if (body.counted) body.cleared = true;
      }
    });
  };

  const first = makeManager();
  const steps = Math.min(20 + Math.floor(rng() * 30), maxSteps);
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
        if (result.ok) startBody(manager, n, result.value);
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
      void track(manager, manager.ledger.close(grace), grace === Infinity).then(
        (result) => {
          covered(`close ${result.ok ? "ok" : errorName(result.error)}`);
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
    } else if (roll < 0.94) {
      events.push(`m${manager.id} release-held`);
      const held = manager.held;
      if (held.length) held.splice(Math.floor(rng() * held.length), 1)[0]!();
    } else {
      events.push("stable");
      await stable("mid-run");
      checkStable(`after step ${step}`);
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
        "close UploadAttemptStorageFailedError",
        "unaided hand-over",
        "recover refused",
        "recover failed",
        "crash",
        "preserve kept",
      ])
        expect(
          coverage.get(name) ?? 0,
          `never reached: ${name}`,
        ).toBeGreaterThan(0);
  }, 120_000);
});
