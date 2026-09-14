import { performance } from "node:perf_hooks";
import {
  fleetOwnerKey,
  sameAssignment,
  FLEET_LEASE_MS,
  type FleetAssignment,
  type FleetExecuteRequest,
  type FleetExecuteResponse,
  type FleetPrepareRequest,
  type FleetReadiness,
  type FleetWorkerPort,
} from "./contracts.js";

export class StalePlacementError extends Error {
  constructor() {
    super("stale placement");
    this.name = "StalePlacementError";
  }
}
export interface FleetWorkerBackend {
  activity(a: FleetAssignment): { present: boolean; busy: boolean };
  prepare(
    request: FleetPrepareRequest,
    signal: AbortSignal,
  ): Promise<FleetReadiness[]>;
  readiness(
    request: FleetPrepareRequest,
    signal: AbortSignal,
  ): Promise<FleetReadiness[]>;
  execute(
    request: FleetExecuteRequest,
    signal: AbortSignal,
  ): Promise<Omit<FleetExecuteResponse, "assignment">>;
  release(assignment: FleetAssignment): Promise<void>;
}
export interface LocalFleetWorker extends FleetWorkerPort {
  assignments(): FleetAssignment[];
  assertCurrent(assignment: FleetAssignment): void;
  trackAssignment<T>(a: FleetAssignment, work: () => Promise<T>): Promise<T>;
  signal(assignment: FleetAssignment): AbortSignal;
}
interface Lease {
  assignment: FleetAssignment;
  deadline: number;
  cleanup?: Promise<void>;
  active: number;
  abort: AbortController;
  timer?: ReturnType<typeof setTimeout>;
}
/** Called only behind the attested controller channel. Keeps retired generations
 * until process exit; a restart is fenced by its new node incarnation. */
export function createFleetWorker(options: {
  nodeId: string;
  nodeIncarnation: string;
  capacity: number;
  backend: FleetWorkerBackend;
  safetyMs?: number;
  wallNow?: () => number;
  monotonicNow?: () => number;
}): LocalFleetWorker {
  const wall = options.wallNow ?? Date.now;
  const mono = options.monotonicNow ?? (() => performance.now());
  const safety = options.safetyMs ?? 1_000;
  const leases = new Map<string, Lease>();
  const generations = new Map<string, number>();
  function validate(a: FleetAssignment): number {
    const remaining = Date.parse(a.leaseExpiresAt) - wall();
    if (
      a.nodeId !== options.nodeId ||
      a.nodeIncarnation !== options.nodeIncarnation ||
      a.controllerTerm !== 1 ||
      !Number.isSafeInteger(a.generation) ||
      a.generation < 1 ||
      !Number.isSafeInteger(a.chainId) ||
      a.chainId < 1 ||
      !Number.isSafeInteger(a.identityEpoch) ||
      a.identityEpoch < 1 ||
      !/^0x[0-9a-fA-F]{64}$/.test(a.userPsId) ||
      !["starting", "ready", "draining"].includes(a.state) ||
      !Number.isFinite(remaining) ||
      remaining <= safety ||
      remaining > FLEET_LEASE_MS + safety
    ) {
      throw new StalePlacementError();
    }
    return remaining - safety;
  }
  function retire(lease: Lease): Promise<void> {
    lease.abort.abort(new StalePlacementError());
    clearTimeout(lease.timer);
    lease.cleanup ??= Promise.resolve().then(() =>
      options.backend.release(lease.assignment),
    );
    // Timer-triggered cleanup is retained and rethrown on any replacement.
    void lease.cleanup.catch(() => {});
    return lease.cleanup;
  }
  function current(a: FleetAssignment): Lease {
    const lease = leases.get(fleetOwnerKey(a));
    if (
      !lease ||
      !sameAssignment(lease.assignment, a) ||
      lease.abort.signal.aborted ||
      mono() >= lease.deadline
    ) {
      if (lease && mono() >= lease.deadline) retire(lease);
      throw new StalePlacementError();
    }
    return lease;
  }
  function arm(lease: Lease): void {
    clearTimeout(lease.timer);
    lease.timer = setTimeout(
      () => {
        if (mono() >= lease.deadline) retire(lease);
        else arm(lease);
      },
      Math.max(1, lease.deadline - mono()),
    );
    lease.timer.unref();
  }
  async function install(a: FleetAssignment): Promise<Lease> {
    validate(a);
    const key = fleetOwnerKey(a);
    const existing = leases.get(key);
    if (existing && sameAssignment(existing.assignment, a)) return current(a);
    if (a.generation <= (generations.get(key) ?? 0))
      throw new StalePlacementError();
    // A newer generation cannot overlap a still-valid local executor.
    if (
      existing &&
      !existing.abort.signal.aborted &&
      mono() < existing.deadline
    )
      throw new StalePlacementError();
    if (
      [...leases.values()].filter(
        (l) => !l.abort.signal.aborted && mono() < l.deadline,
      ).length >= options.capacity
    )
      throw new Error("worker capacity exhausted");
    if (existing) {
      await retire(existing);
      if (leases.get(key) !== existing) return install(a);
    }
    const ttl = validate(a);
    const lease: Lease = {
      active: 0,
      assignment: { ...a },
      deadline: mono() + ttl,
      abort: new AbortController(),
    };
    generations.set(key, a.generation);
    leases.set(key, lease);
    arm(lease);
    return lease;
  }
  async function trackAssignment<T>(
    a: FleetAssignment,
    work: () => Promise<T>,
  ): Promise<T> {
    const lease = current(a);
    if (lease.assignment.state === "draining") throw new StalePlacementError();
    lease.active += 1;
    try {
      const result = await work();
      current(a);
      return result;
    } finally {
      lease.active -= 1;
    }
  }
  return {
    trackAssignment,
    async activity(a) {
      const lease = current(a);
      const observed = options.backend.activity(a);
      return {
        assignment: { ...lease.assignment },
        present: observed.present,
        busy: observed.busy || lease.active > 0,
      };
    },
    assignments() {
      return [...leases.values()]
        .filter(
          (l) =>
            !l.abort.signal.aborted &&
            mono() < l.deadline &&
            l.assignment.state !== "draining",
        )
        .map((l) => ({ ...l.assignment }));
    },
    assertCurrent(a) {
      current(a);
    },
    signal(a) {
      return current(a).abort.signal;
    },
    async prepare(request) {
      const lease = await install(request.assignment);
      if (lease.assignment.state === "draining")
        throw new StalePlacementError();
      const result = await trackAssignment(request.assignment, () =>
        options.backend.prepare(request, lease.abort.signal),
      );
      current(request.assignment);
      return result;
    },
    async renew(a) {
      const lease = current(a);
      const ttl = validate(a);
      if (
        Date.parse(a.leaseExpiresAt) <
        Date.parse(lease.assignment.leaseExpiresAt)
      )
        throw new StalePlacementError();
      const extension =
        Date.parse(a.leaseExpiresAt) -
        Date.parse(lease.assignment.leaseExpiresAt);
      lease.deadline = Math.min(mono() + ttl, lease.deadline + extension);
      lease.assignment = { ...a };
      arm(lease);
    },
    async readiness(request) {
      const lease = current(request.assignment);
      const result = await trackAssignment(request.assignment, () =>
        options.backend.readiness(request, lease.abort.signal),
      );
      current(request.assignment);
      return result;
    },
    async execute(request) {
      const lease = current(request.assignment);
      if (lease.assignment.state === "draining")
        throw new StalePlacementError();
      const budget = Date.parse(request.deadline) - wall();
      if (!Number.isFinite(budget) || budget <= 0 || budget > 120_000)
        throw new StalePlacementError();
      const result = await trackAssignment(request.assignment, () =>
        options.backend.execute(
          request,
          AbortSignal.any([lease.abort.signal, AbortSignal.timeout(budget)]),
        ),
      );
      current(request.assignment);
      if (Date.parse(request.deadline) <= wall())
        throw new StalePlacementError();
      return { ...result, assignment: { ...lease.assignment } };
    },
    async release(a) {
      const lease = current(a);
      if (lease.active > 0 || options.backend.activity(a).busy)
        throw new Error("placement busy");
      await retire(lease);
      if (leases.get(fleetOwnerKey(a)) === lease)
        leases.delete(fleetOwnerKey(a));
    },
  };
}
