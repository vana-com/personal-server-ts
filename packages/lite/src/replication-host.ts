/**
 * PS-Lite host wiring for record replication: the counterpart of Node's
 * `createNodeReplication` (packages/server/src/storage/pdpp-replication-host.ts).
 *
 * The phone supplies native persistence and native object transfers. The
 * partition, the declaration bindings and the DPv2 network ports come from
 * core (`replication/host-ports.ts`), as on Node, so both hosts derive them
 * the same way. With the door anything but `on`, or the boot config off,
 * nothing here is built: the runtime is inert and says why.
 */
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import type { ReplicationDoorStatus } from "@opendatalabs/personal-server-ts-core/replication/door";
import type { ReplicaEngineConfig } from "@opendatalabs/personal-server-ts-core/replication/engine";
import type { ProgressReport } from "@opendatalabs/personal-server-ts-core/replication/coordinator";
import type { ReplicationTimers } from "@opendatalabs/personal-server-ts-core/replication/host-driver";
import {
  planReplicationHost,
  type ReplicationNetworkPorts,
} from "@opendatalabs/personal-server-ts-core/replication/host-ports";
import type {
  ReplicaBatchSigner,
  ReplicaWriterRotation,
} from "@opendatalabs/personal-server-ts-core/replication/writer-identity";
import { replicaWriterRotationOutcome } from "@opendatalabs/personal-server-ts-core/replication/writer-identity-store";
import type { ServerAccount } from "@opendatalabs/personal-server-ts-core/keys";
import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  resolveVanaStorageEndpoint,
  vanaBlobRequests,
  type BoundedStorageAdapter,
} from "@opendatalabs/personal-server-ts-core/storage/adapters";
import { createLiteCanonicalStore } from "./canonical-store.js";
import {
  createLiteReplicaEngine,
  type LiteReplicaEngine,
} from "./replication-engine.js";
import {
  replicationBootConfigProblem,
  type LiteReplicaObjectTransfers,
  type LiteReplicaPersistence,
  type ReplicationBootConfig,
} from "./replication-ports.js";
import {
  createLiteReplicationRuntime,
  type LiteReplicationRuntime,
} from "./replication-runtime.js";
import {
  createLiteReplicaStorage,
  type LiteReplicaUploadHeaders,
} from "./replication-storage.js";

/**
 * The fixed bytes an encrypted fragment adds to its plaintext, beyond the
 * base64 growth of 4/3: envelope framing plus encryption overhead.
 */
const FRAGMENT_FRAMING_BYTES = 4100;

/**
 * The plaintext chunk that encrypts to at most `fragmentBytes`. The native
 * store keeps a fragment as one value, so the encrypted size is the bound.
 */
export function liteTargetChunkBytes(fragmentBytes: number) {
  return Math.floor(((fragmentBytes - FRAGMENT_FRAMING_BYTES) * 3) / 4);
}

/**
 * Vana storage addressing and upload authorization for one owner's replica
 * objects: the URL layout and Web3Signed claim Node's storage adapter uses,
 * signed by the registered server key.
 */
export function liteVanaReplicaObjects(input: {
  config: ServerConfig;
  owner: string;
  signer: Pick<ServerAccount, "signMessage">;
}): LiteReplicationInput["objects"] {
  const endpoint = resolveVanaStorageEndpoint(input.config);
  const requests = vanaBlobRequests({
    endpoint,
    audience: endpoint,
    chainId: input.config.gateway.chainId,
    owner: input.owner.toLowerCase(),
    signer: input.signer,
  });
  return {
    urlForKey: requests.urlForKey,
    headers: async ({ method, url, body }) => ({
      authorization: await requests.authorization(method, url, body),
      "content-type": "application/octet-stream",
    }),
  };
}

export interface LiteReplicationInput {
  /** This boot's door (`resolveLiteReplication`). */
  door: ReplicationDoorStatus;
  /** The host's boot config (§4.1). Absent means off. */
  config?: ReplicationBootConfig;
  /** Native persistence opened with replica support. */
  persistence: LiteReplicaPersistence;
  /** Storage object I/O over the native `replica.*` bridge. */
  transfers: LiteReplicaObjectTransfers;
  /** The retained declarations the canonical store serves. */
  declarations: readonly DeclarationSnapshot[];
  /** The registered PS server key. Never the owner wallet. */
  serverAccount: ReplicaBatchSigner;
  /** Storage object addressing and upload authorization. */
  objects: {
    urlForKey(key: string): string;
    headers?: LiteReplicaUploadHeaders;
  };
  /**
   * The network ports over the given storage. Called only when replication
   * runs this boot (core `createReplicationNetworkPorts` in production).
   */
  network: (
    owner: `0x${string}`,
    storage: BoundedStorageAdapter,
  ) => ReplicationNetworkPorts;
  /**
   * Rotate the writer identity before this boot steps (host contract
   * §3.2): the host cannot rule out that this database is a copy.
   */
  rotateWriterIdentity?: boolean;
  timers?: ReplicationTimers;
  onReport?: (report: ProgressReport) => void;
  onError?: (error: unknown) => void;
  /** Engine options for tests (e.g. `now`). */
  engine?: Partial<ReplicaEngineConfig>;
}

export type LiteReplication =
  | {
      state: "started";
      runtime: LiteReplicationRuntime;
      engine: LiteReplicaEngine;
      /**
       * The canonical store over the same persistence and bindings: local
       * writes and reads go through it, never through a second context.
       */
      canonical: ReturnType<typeof createLiteCanonicalStore>;
      /** What this boot did with `rotateWriterIdentity`. */
      rotation: ReplicaWriterRotation;
    }
  | {
      state: "off" | "blocked";
      runtime: LiteReplicationRuntime;
      reason?: string;
    };

/**
 * Build replication for one boot. Does not step: the host resumes the
 * returned runtime when the app is active.
 */
export async function createLiteReplication(
  input: LiteReplicationInput,
): Promise<LiteReplication> {
  const { door, config } = input;
  const inert = (state: "off" | "blocked", reason?: string) => ({
    state,
    reason,
    runtime: createLiteReplicationRuntime({ door, config }),
  });
  if (door.state !== "on" || !config?.enabled) return inert("off");
  const problem = replicationBootConfigProblem(config);
  if (problem) return inert("blocked", problem);
  const plan = planReplicationHost({
    owner: config.owner,
    chainId: config.chainId,
    declarations: input.declarations,
  });
  if (plan.state === "blocked") return inert("blocked", plan.reason);
  if (plan.environment !== config.environment)
    return inert("blocked", "environment_mismatch");
  const { owner, context } = plan;
  let network: ReplicationNetworkPorts;
  try {
    network = input.network(
      owner,
      createLiteReplicaStorage({
        persistence: input.persistence,
        transfers: input.transfers,
        urlForKey: input.objects.urlForKey,
        headers: input.objects.headers,
      }),
    );
  } catch (error) {
    return inert(
      "blocked",
      error instanceof Error ? error.message : String(error),
    );
  }
  // A private capability: only this engine can hand batches to its store.
  const credential = Symbol("lite-replication-engine");
  const trusted = {
    context: () => ({ owner, declarations: context.declarations }),
    authenticateReplica: (presented: unknown) =>
      presented === credential ? owner : undefined,
  };
  const engine = createLiteReplicaEngine({
    persistence: input.persistence,
    canonical: trusted,
    engine: {
      enabled: true,
      expected: () => context.expected,
      credential,
      transport: network.transport,
      authority: {
        signer: input.serverAccount,
        roster: network.roster,
        chainId: config.chainId,
        environment: plan.environment,
      },
      targetChunkBytes: liteTargetChunkBytes(config.limits.fragmentBytes),
      ...input.engine,
    },
  });
  const rotation = input.rotateWriterIdentity
    ? await rotateAtBoot(engine)
    : "not_requested";
  const runtime = createLiteReplicationRuntime({
    door,
    config,
    engine,
    timers: input.timers,
    onReport: input.onReport,
    onError: input.onError,
  });
  return {
    state: "started",
    engine,
    canonical: createLiteCanonicalStore({
      persistence: input.persistence,
      enabled: true,
      ...trusted,
      // A committed own write steps soon, not at the next wake (Node: #517).
      localCommitted: () => runtime.localWrite(),
    }),
    rotation,
    runtime,
  };
}

/** Node's `rotateReplicaWriterIdentityAtBoot`, on the Lite engine. */
async function rotateAtBoot(
  engine: LiteReplicaEngine,
): Promise<ReplicaWriterRotation> {
  try {
    await engine.rotateWriter();
    return "rotated";
  } catch (error) {
    const outcome = replicaWriterRotationOutcome(error);
    if (outcome) return outcome;
    throw error;
  }
}
