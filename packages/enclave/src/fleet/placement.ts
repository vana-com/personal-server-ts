import { mkdir, open, readFile, rename, rm } from "node:fs/promises";
import { dirname } from "node:path";
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import {
  FLEET_LEASE_MS,
  FLEET_READINESS_MAX_AGE_MS,
  fleetOwnerKey,
  sameAssignment,
  type FleetAssignment,
  type FleetOwner,
  type FleetReadiness,
  type FleetScope,
  type FleetWorkerPort,
} from "./contracts.js";

export interface FleetPlacementRow {
  owner: FleetOwner;
  generation: number;
  lastActivityAt: string;
  renewalBlocked?: boolean;
  /** Successful metadata-only membership is retained for paused recovery. */
  enrolled?: boolean;
  assignment: FleetAssignment | null;
}
export interface FleetAdmittedNode {
  nodeId: string;
  nodeIncarnation: string;
  capacity: number;
  worker: FleetWorkerPort;
  /** Omit on restart to retain an operator's durable drain decision. */
  draining?: boolean;
}
interface NodeRecord {
  nodeId: string;
  nodeIncarnation: string;
  capacity: number;
  draining: boolean;
  unavailable: boolean;
}
interface Directory {
  v: 1;
  paused: boolean;
  rows: Record<string, FleetPlacementRow>;
  nodes: Record<string, NodeRecord>;
}
export interface FleetControllerOptions {
  path: string;
  enroll(owner: FleetOwner): Promise<void>;
  publish(assignment: FleetAssignment): Promise<void>;
  release(assignment: FleetAssignment): Promise<void>;
  now?: () => number;
  drainGraceMs?: number;
  startPaused?: boolean;
  event?(event: string, fields: Record<string, unknown>): void;
}

function serialByKey() {
  const pending = new Map<string, Promise<unknown>>();
  const run = <T>(key: string, operation: () => Promise<T>): Promise<T> => {
    const result = (pending.get(key) ?? Promise.resolve()).then(operation);
    const tail = result.catch(() => undefined);
    pending.set(key, tail);
    void tail.then(() => {
      if (pending.get(key) === tail) pending.delete(key);
    });
    return result;
  };
  return Object.assign(run, {
    idle: async (): Promise<void> => {
      await Promise.all([...pending.values()]);
    },
  });
}

/** One active controller, term 1. The launcher holds a kernel flock for this
 * directory. Atomic fsync snapshots retain generations and operator drains;
 * Gateway is a transactionally fenced projection, never another allocator. */
export async function openFleetController(options: FleetControllerOptions) {
  const now = options.now ?? Date.now;
  let directory: Directory = {
    v: 1,
    paused: options.startPaused ?? false,
    rows: {},
    nodes: {},
  };
  try {
    directory = JSON.parse(await readFile(options.path, "utf8")) as Directory;
    if (directory.v !== 1 || !directory.rows || !directory.nodes)
      throw new Error("Invalid fleet directory");
    for (const [key, row] of Object.entries(directory.rows)) {
      if (
        fleetOwnerKey(row.owner) !== key ||
        !Number.isSafeInteger(row.generation) ||
        row.generation < 0 ||
        (row.assignment &&
          (row.assignment.generation !== row.generation ||
            row.assignment.controllerTerm !== 1 ||
            !Number.isFinite(Date.parse(row.assignment.leaseExpiresAt))))
      )
        throw new Error("Invalid fleet generation history");
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const rows = directory.rows;
  const nodes = new Map<string, FleetAdmittedNode>();
  const observations = new Map<string, FleetReadiness[]>();
  const ownerOperation = serialByKey();
  const leaseOperation = serialByKey();
  let writes: Promise<unknown> = Promise.resolve();
  const persist = (): Promise<void> => {
    const snapshot = JSON.stringify(directory);
    const result = writes.then(async () => {
      await mkdir(dirname(options.path), { recursive: true, mode: 0o700 });
      const temporary = `${options.path}.${randomUUID()}.tmp`;
      try {
        const file = await open(temporary, "wx", 0o600);
        try {
          await file.writeFile(snapshot);
          await file.sync();
        } finally {
          await file.close();
        }
        await rename(temporary, options.path);
        const parent = await open(dirname(options.path), "r");
        try {
          await parent.sync();
        } finally {
          await parent.close();
        }
      } finally {
        await rm(temporary, { force: true });
      }
    });
    writes = result.catch(() => undefined);
    return result;
  };
  const current = (assignment: FleetAssignment): boolean => {
    const row = rows[fleetOwnerKey(assignment)];
    return (
      !!row?.assignment &&
      sameAssignment(row.assignment, assignment) &&
      Date.parse(row.assignment.leaseExpiresAt) > now() &&
      nodes.get(assignment.nodeId)?.nodeIncarnation ===
        assignment.nodeIncarnation
    );
  };
  const healthy = (nodeId: string): boolean =>
    !directory.nodes[nodeId]?.unavailable;
  const emit = (event: string, assignment: FleetAssignment): void =>
    options.event?.(event, {
      userPsId: assignment.userPsId,
      identityEpoch: assignment.identityEpoch,
      nodeId: assignment.nodeId,
      nodeIncarnation: assignment.nodeIncarnation,
      generation: assignment.generation,
      leaseExpiresAt: assignment.leaseExpiresAt,
    });
  const publish = async (assignment: FleetAssignment): Promise<void> =>
    options.publish(structuredClone(assignment));
  const forget = async (assignment: FleetAssignment): Promise<void> => {
    const row = rows[fleetOwnerKey(assignment)];
    if (!row?.assignment || !sameAssignment(row.assignment, assignment)) return;
    await options.release(structuredClone(assignment));
    // Idle reconciliation can overlap a new generation after expiry. The
    // Gateway CAS and this second local comparison fence the delayed response.
    if (!row.assignment || !sameAssignment(row.assignment, assignment)) return;
    row.assignment = null;
    observations.delete(fleetOwnerKey(assignment));
    await persist();
    emit("placement_released", assignment);
  };
  const teardown = async (
    assignment: FleetAssignment,
    worker: FleetWorkerPort,
    graceMs = 0,
  ): Promise<void> => {
    await leaseOperation(fleetOwnerKey(assignment), async () => {
      const row = rows[fleetOwnerKey(assignment)];
      if (!row?.assignment || !sameAssignment(row.assignment, assignment))
        return;
      row.assignment.state = "draining";
      await persist();
      const stopAt = Date.now() + graceMs;
      let lastRenewal = -Infinity;
      for (;;) {
        if (Date.parse(row.assignment.leaseExpiresAt) <= now()) {
          await forget(row.assignment);
          return;
        }
        if (
          healthy(assignment.nodeId) &&
          !row.renewalBlocked &&
          now() - lastRenewal >= 10_000
        ) {
          if (graceMs > 0)
            row.assignment.leaseExpiresAt = new Date(
              now() + FLEET_LEASE_MS,
            ).toISOString();
          await persist();
          let projected = false;
          try {
            await publish(row.assignment);
            projected = true;
          } catch {
            row.renewalBlocked = true;
            await persist();
          }
          if (projected) {
            try {
              await worker.renew(structuredClone(row.assignment));
            } catch {
              directory.nodes[assignment.nodeId]!.unavailable = true;
              row.renewalBlocked = true;
              await persist();
            }
          }
          lastRenewal = now();
        }
        try {
          // Worker atomically refuses busy references, then fences new work
          // before awaiting teardown. Idle observations alone never authorize it.
          await worker.release(structuredClone(row.assignment));
          await forget(row.assignment);
          return;
        } catch (error) {
          if (Date.now() >= stopAt) throw error;
          await delay(Math.min(1_000, stopAt - Date.now()));
        }
      }
    });
  };
  const api = {
    paused(): boolean {
      return directory.paused;
    },
    async pause(): Promise<void> {
      directory.paused = true;
      await persist();
      await ownerOperation.idle();
      await leaseOperation.idle();
    },
    async resume(): Promise<void> {
      directory.paused = false;
      await persist();
    },
    enroll(owner: FleetOwner): Promise<void> {
      return ownerOperation(fleetOwnerKey(owner), async () => {
        if (
          !Number.isSafeInteger(owner.chainId) ||
          !Number.isSafeInteger(owner.identityEpoch) ||
          owner.identityEpoch < 1 ||
          !owner.userPsId
        )
          throw new Error("Invalid owner");
        const key = fleetOwnerKey(owner);
        const row = (rows[key] ??= {
          owner: structuredClone(owner),
          generation: 0,
          lastActivityAt: new Date(now()).toISOString(),
          assignment: null,
        });
        if (row.enrolled) return;
        // Record attempted membership before the remote transaction, including
        // ambiguous acknowledgments that an operator must reconcile on rollback.
        await persist();
        await options.enroll(owner);
        row.enrolled = true;
        await persist();
      });
    },
    async admit(node: FleetAdmittedNode): Promise<void> {
      if (
        !node.nodeId ||
        !node.nodeIncarnation ||
        !Number.isSafeInteger(node.capacity) ||
        node.capacity < 1
      )
        throw new Error("Invalid worker admission");
      const prior = directory.nodes[node.nodeId];
      directory.nodes[node.nodeId] = {
        nodeId: node.nodeId,
        nodeIncarnation: node.nodeIncarnation,
        capacity: node.capacity,
        draining: node.draining ?? prior?.draining ?? false,
        unavailable: false,
      };
      nodes.set(node.nodeId, node);
      await persist();
    },
    assignment(owner: FleetOwner): FleetAssignment | null {
      const assignment = rows[fleetOwnerKey(owner)]?.assignment;
      return assignment && current(assignment)
        ? structuredClone(assignment)
        : null;
    },
    worker(assignment: FleetAssignment): FleetWorkerPort {
      if (
        directory.paused ||
        !current(assignment) ||
        !healthy(assignment.nodeId)
      )
        throw new Error("Stale or unavailable placement");
      return nodes.get(assignment.nodeId)!.worker;
    },
    ensure(owner: FleetOwner, scopes: FleetScope[]): Promise<FleetAssignment> {
      return ownerOperation(fleetOwnerKey(owner), async () => {
        if (directory.paused) throw new Error("Fleet controller paused");
        if (
          !Number.isSafeInteger(owner.chainId) ||
          !Number.isSafeInteger(owner.identityEpoch) ||
          owner.identityEpoch < 1 ||
          !owner.userPsId
        )
          throw new Error("Invalid owner");
        const key = fleetOwnerKey(owner);
        let row = rows[key];
        const existing = row?.assignment;
        if (existing && current(existing)) {
          if (
            existing.state === "draining" ||
            row.renewalBlocked ||
            !healthy(existing.nodeId)
          )
            throw new Error("Placement draining or unavailable");
          row.lastActivityAt = new Date(now()).toISOString();
          await persist();
          if (scopes.length)
            observations.set(
              key,
              await nodes.get(existing.nodeId)!.worker.prepare({
                assignment: structuredClone(existing),
                scopes,
              }),
            );
          if (!current(existing) || !healthy(existing.nodeId))
            throw new Error("Placement changed during preparation");
          return structuredClone(existing);
        }
        // A restarted agent cannot bypass its old incarnation's live lease.
        if (existing && Date.parse(existing.leaseExpiresAt) > now())
          throw new Error("Prior placement lease still live");
        if (!row) {
          row = rows[key] = {
            owner: structuredClone(owner),
            generation: 0,
            lastActivityAt: new Date(now()).toISOString(),
            assignment: null,
          };
          await persist();
        }
        await options.enroll(owner);
        row.enrolled = true;
        await persist();
        if (directory.paused) throw new Error("Fleet controller paused");
        const load = (node: FleetAdmittedNode): number =>
          Object.values(rows).filter(
            (r) =>
              r.assignment?.nodeId === node.nodeId &&
              Date.parse(r.assignment.leaseExpiresAt) > now(),
          ).length;
        const node = [...nodes.values()]
          .filter(
            (n) =>
              healthy(n.nodeId) &&
              !directory.nodes[n.nodeId]!.draining &&
              load(n) < n.capacity,
          )
          .sort(
            (a, b) => load(a) - load(b) || a.nodeId.localeCompare(b.nodeId),
          )[0];
        if (!node) throw new Error("Fleet capacity unavailable");
        if (!Number.isSafeInteger(row.generation + 1))
          throw new Error("Fleet generation exhausted");
        const assignment: FleetAssignment = {
          ...owner,
          nodeId: node.nodeId,
          nodeIncarnation: node.nodeIncarnation,
          generation: ++row.generation,
          controllerTerm: 1,
          state: "starting",
          leaseExpiresAt: new Date(now() + FLEET_LEASE_MS).toISOString(),
        };
        row.lastActivityAt = new Date(now()).toISOString();
        row.renewalBlocked = false;
        row.assignment = assignment;
        await persist();
        emit("placement_starting", assignment);
        try {
          await leaseOperation(key, () => publish(assignment));
          const reports = await node.worker.prepare({
            assignment: structuredClone(assignment),
            scopes,
          });
          return await leaseOperation(key, async () => {
            if (
              !current(assignment) ||
              assignment.state === "draining" ||
              !healthy(node.nodeId)
            )
              throw new Error("Placement startup lease expired");
            observations.set(key, reports);
            assignment.state = "ready";
            await persist();
            await publish(assignment);
            emit("placement_ready", assignment);
            return structuredClone(assignment);
          });
        } catch (error) {
          // A lost startup ACK is not teardown proof. Keep the last potentially
          // live reservation if release cannot be acknowledged.
          try {
            await teardown(assignment, node.worker);
          } catch {
            emit("placement_release_pending", assignment);
          }
          throw error;
        }
      });
    },
    async readiness(
      owner: FleetOwner,
      scopes: FleetScope[],
    ): Promise<FleetReadiness[]> {
      const assignment = api.assignment(owner);
      if (!assignment) return [];
      const valid = (report: FleetReadiness, scope: FleetScope): boolean =>
        sameAssignment(report.assignment, assignment) &&
        report.scope === scope.scope &&
        report.state === "ready" &&
        Date.parse(report.observedAt) <= now() &&
        now() - Date.parse(report.observedAt) <= FLEET_READINESS_MAX_AGE_MS &&
        (scope.minimumVersion === undefined ||
          (report.dataVersion !== null &&
            report.dataVersion >= scope.minimumVersion));
      let reports = observations.get(fleetOwnerKey(owner)) ?? [];
      if (
        !scopes.every((scope) => reports.some((report) => valid(report, scope)))
      ) {
        reports = await api
          .worker(assignment)
          .readiness({ assignment, scopes });
        if (!current(assignment)) return [];
        observations.set(fleetOwnerKey(owner), reports);
      }
      return reports.filter((report) =>
        scopes.some((scope) => valid(report, scope)),
      );
    },
    async renew(): Promise<void> {
      if (directory.paused) return;
      // Per-owner lease transitions run concurrently. Slow startup, one dead
      // peer, or another owner's hydration cannot block all fleet renewals.
      await Promise.all(
        Object.keys(rows).map((key) =>
          leaseOperation(key, async () => {
            const assignment = rows[key]?.assignment;
            if (directory.paused) return;
            if (
              !assignment ||
              !current(assignment) ||
              assignment.state === "draining" ||
              rows[key]?.renewalBlocked ||
              !healthy(assignment.nodeId)
            )
              return;
            const node = nodes.get(assignment.nodeId)!;
            assignment.leaseExpiresAt = new Date(
              now() + FLEET_LEASE_MS,
            ).toISOString();
            await persist();
            try {
              await publish(assignment);
            } catch {
              if (
                rows[key]?.assignment &&
                sameAssignment(rows[key]!.assignment!, assignment)
              ) {
                rows[key]!.renewalBlocked = true;
                observations.delete(key);
                await persist();
              }
              emit("placement_projection_failed", assignment);
              return;
            }
            try {
              await node.worker.renew(structuredClone(assignment));
              if (assignment.state === "ready") {
                const activity = await node.worker.activity(
                  structuredClone(assignment),
                );
                if (!sameAssignment(activity.assignment, assignment))
                  throw new Error("Stale worker activity");
                if (!activity.present && !activity.busy) {
                  try {
                    await node.worker.release(structuredClone(assignment));
                    await forget(assignment);
                  } catch {
                    /* A concurrent begin may now own a reference. */
                  }
                }
              }
            } catch {
              // The worker might have received this extension. Retain precisely
              // that possible expiry, but never keep extending an unreachable node.
              if (
                directory.nodes[node.nodeId]?.nodeIncarnation ===
                node.nodeIncarnation
              )
                directory.nodes[node.nodeId]!.unavailable = true;
              if (
                rows[key]?.assignment &&
                sameAssignment(rows[key]!.assignment!, assignment)
              )
                rows[key]!.renewalBlocked = true;
              observations.delete(key);
              await persist();
              emit("placement_renewal_failed", assignment);
            }
          }),
        ),
      );
    },
    async drain(nodeId: string): Promise<void> {
      const node = nodes.get(nodeId);
      if (!directory.nodes[nodeId]) throw new Error("Unknown worker");
      directory.nodes[nodeId]!.draining = true;
      await persist();
      await Promise.all(
        Object.keys(rows).map((key) =>
          ownerOperation(key, async () => {
            const assignment = rows[key]?.assignment;
            if (assignment?.nodeId !== nodeId) return;
            if (!node || node.nodeIncarnation !== assignment.nodeIncarnation) {
              if (Date.parse(assignment.leaseExpiresAt) > now())
                throw new Error("Prior worker lease still live");
              await leaseOperation(key, () => forget(assignment));
            } else {
              await teardown(
                assignment,
                node.worker,
                options.drainGraceMs ?? 120_000,
              );
            }
          }),
        ),
      );
    },
    nodeStatus(): NodeRecord[] {
      return structuredClone(Object.values(directory.nodes));
    },
    snapshot(): FleetPlacementRow[] {
      return structuredClone(Object.values(rows));
    },
  };
  return api;
}
export type FleetController = Awaited<ReturnType<typeof openFleetController>>;
