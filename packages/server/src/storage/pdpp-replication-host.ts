/**
 * Node host wiring for record replication (plan item A9).
 *
 * Bootstrap calls this only when the boot's replication door is on. It
 * builds the receiver, the transport worker and the shared host driver over
 * the boot's database, and returns the driver for start and shutdown. Phase
 * order, retries and backoff stay in the core coordinator; this file only
 * constructs ports and passes finite budgets.
 */
import type { Database } from "better-sqlite3";
import type { Logger } from "pino";
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import type { ServerAccount } from "@opendatalabs/personal-server-ts-core/keys";
import type {
  ProgressReport,
  ReplicaBudget,
} from "@opendatalabs/personal-server-ts-core/replication/coordinator";
import { REPLICA_WAIT_FALLBACK_MS } from "@opendatalabs/personal-server-ts-core/replication/schedule";
import {
  planReplicationHost,
  type ReplicationNetworkPorts,
} from "@opendatalabs/personal-server-ts-core/replication/host-ports";
import {
  createReplicationDriver,
  type ReplicationDriver,
  type ReplicationStepper,
  type ReplicationTimers,
} from "@opendatalabs/personal-server-ts-core/replication/host-driver";
import type { PdppReplicaReads } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import {
  createReplicaRecordStore,
  type ReplicaRecordStore,
} from "./pdpp-replica-canonical-port.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";
import { createReplicaTransportWorker } from "./pdpp-replication-transport.js";
import { enableReplicaWriterIdentity } from "./pdpp-replica-writer-identity.js";

/**
 * Desktop step bound (host contract §6): 50 units, 64 MiB. Bytes stay
 * omitted so the coordinator's 64 MiB default applies, under which a batch
 * larger than the whole step still runs alone; an explicit 64 MiB would
 * defer it forever.
 */
export const NODE_REPLICATION_BUDGET: ReplicaBudget = { units: 50 };
/** How long shutdown waits for an aborted step before closing storage. */
export const NODE_REPLICATION_STOP_GRACE_MS = 5_000;

export type NodeReplication =
  | {
      state: "started";
      /** The boot's record store. The resource server must use this one. */
      store: ReplicaRecordStore;
      /** The resource server's reader port (pending preview for owners). */
      reads: PdppReplicaReads;
      driver: ReplicationDriver;
      worker: ReturnType<typeof createReplicaTransportWorker>;
    }
  /** Replication is on for this database but cannot run this boot. */
  | { state: "blocked"; reason: string };

/**
 * Build the replication runtime for one owner's database. Does not step:
 * the caller starts the returned driver once the server is serving.
 *
 * The returned store and reads replace the resource server's own: the
 * receiver's local-write and visibility observers live on one store instance,
 * and a host with a receiver reads through `receiver.readStore`.
 */
export function createNodeReplication(input: {
  db: Database;
  owner: `0x${string}`;
  chainId: number;
  /** The retained declarations the resource server serves. */
  declarations: readonly DeclarationSnapshot[];
  /** The registered server key (`key.json`). Never the owner wallet. */
  serverAccount: Pick<ServerAccount, "address" | "signTypedData">;
  /** Built only once the chain, owner and declarations are known good. */
  ports: (owner: `0x${string}`) => ReplicationNetworkPorts;
  logger: Pick<Logger, "info" | "warn">;
  budget?: ReplicaBudget;
  timers?: ReplicationTimers;
  /** Worker options for tests (e.g. `now`, chunk sizes). */
  worker?: Partial<Parameters<typeof createReplicaTransportWorker>[0]>;
}): NodeReplication {
  const plan = planReplicationHost(input);
  if (plan.state === "blocked") return plan;
  const { owner, environment, context } = plan;
  let ports: ReplicationNetworkPorts;
  const store = createReplicaRecordStore(input.db);
  const baseline = () =>
    store.replication.beginBaseline({
      owner,
      declarations: [...context.expected.declarations],
    });
  const baselined = () =>
    input.db
      .prepare("SELECT 1 FROM pdpp_replica_settings WHERE id = 1")
      .get() !== undefined;
  try {
    ports = input.ports(owner);
    // An existing baseline must match now: idempotent for the same bindings,
    // refused for different ones. A first baseline waits for the writer
    // identity (see `stepper`).
    if (baselined()) baseline();
  } catch (error) {
    return {
      state: "blocked",
      reason: error instanceof Error ? error.message : String(error),
    };
  }
  // A private capability: only this worker can hand batches to this receiver.
  const credential = Symbol("node-replication-worker");
  const receiver = createReplicaReceiver({
    db: input.db,
    store,
    owner,
    authenticate: (presented) => (presented === credential ? owner : undefined),
    declarations: () => context.declarations,
  });
  const worker = createReplicaTransportWorker({
    db: input.db,
    enabled: true,
    expected: () => context.expected,
    exporter: store.replication,
    receiver,
    credential,
    transport: ports.transport,
    authority: {
      signer: {
        address: input.serverAccount.address,
        signTypedData: (params) => input.serverAccount.signTypedData(params),
      },
      roster: ports.roster,
      chainId: input.chainId,
      environment,
    },
    ...input.worker,
  });
  // The first enable: the writer identity must exist before the baseline
  // journals anything, and establishing it needs the roster (network). So the
  // first steps establish it, then baseline, then hand over to the worker.
  let ready = baselined();
  const now = input.worker?.now ?? (() => Date.now());
  const idle = (): ProgressReport => ({
    receipts: [],
    waits: [],
    problems: [],
    quarantines: [],
    unsupported: [],
    nextWake: undefined,
  });
  const stepper: ReplicationStepper = {
    async step(step) {
      if (!ready) {
        const own = await enableReplicaWriterIdentity({
          db: input.db,
          owner,
          server: input.serverAccount.address,
          roster: ports.roster,
          signal: step.signal,
          timers: input.timers,
        });
        if (step.signal.aborted || own.tag === "refused") return idle();
        if (own.tag === "waiting")
          return {
            ...idle(),
            waits: [
              {
                id: "writer-identity",
                phase: "retain",
                dependency: {
                  kind: "roster",
                  key: input.serverAccount.address.toLowerCase(),
                },
              },
            ],
            nextWake: now() + REPLICA_WAIT_FALLBACK_MS,
          };
        baseline();
        ready = true;
      }
      return worker.step(step);
    },
    onDependencyChanged: (key) => worker.onDependencyChanged(key),
  };
  const driver = createReplicationDriver({
    stepper,
    budget: input.budget ?? NODE_REPLICATION_BUDGET,
    timers: input.timers,
    onReport: (report) => {
      if (report.problems.length || report.quarantines.length)
        input.logger.warn(
          {
            problems: report.problems.length,
            quarantines: report.quarantines.length,
            unsupported: report.unsupported.length,
          },
          "Replication step reported problems",
        );
    },
    onError: (error) =>
      input.logger.warn({ err: error }, "Replication step failed"),
  });
  // A committed own write schedules a step soon, not at the next wake.
  store.setReplicaJournalObserver(() => driver.localWrite());
  return {
    state: "started",
    store,
    reads: (reader) => receiver.readStore({ reader }),
    driver,
    worker,
  };
}
