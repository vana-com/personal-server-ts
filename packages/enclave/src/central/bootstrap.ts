import { randomUUID } from "node:crypto";
import {
  fleetConfigValidity,
  verifiedFleetEnvironment,
} from "../fleet/security-config.js";
import { isAbsolute } from "node:path";
import { serve } from "@hono/node-server";
import { DEFAULTS } from "@opendatalabs/personal-server-ts-core/schemas";
import type { DstackClient } from "../dstack/client.js";
import type { SupportedChainId } from "../agent/bootstrap.js";
import { startMcpRouter, type McpMigrationSnapshot } from "../mcp/service.js";
import { createFleetControlHttp } from "../fleet/controller-http.js";
import { createFleetMcpRouting, resolveFleetOwner } from "../fleet/router.js";
import {
  createFleetPeerClient,
  createFleetPeerServer,
  fleetWorkerPort,
} from "../fleet/peer.js";
import {
  createDcapPeerVerifier,
  type FleetPeerPolicy,
} from "../fleet/peer-verifier.js";
import {
  openFleetController,
  type FleetController,
} from "../fleet/placement.js";
import {
  FLEET_RENEW_MS,
  type FleetOwner,
  type FleetPeerIdentity,
  type FleetScope,
} from "../fleet/contracts.js";

interface WorkerConfig {
  url: string;
  capacity: number;
  policy: FleetPeerPolicy;
}
/** Warm-pool size. Every member is pre-listed in the signed FLEET_WORKERS_JSON;
 * the external pool loop only starts and stops those declared machines. */
const MAX_FLEET_WORKERS = 4;
const logger = {
  info: (context: object, message: string) =>
    console.error({ level: "info", ...context, message }),
  warn: (context: object, message: string) =>
    console.error({ level: "warn", ...context, message }),
  error: (context: object, message: string) =>
    console.error({ level: "error", ...context, message }),
};
function required(env: NodeJS.ProcessEnv, key: string): string {
  const value = env[key];
  if (!value) throw new Error(`${key} is required`);
  return value;
}
function port(env: NodeJS.ProcessEnv, key: string, fallback: number): number {
  const value = Number(env[key] ?? fallback);
  if (!Number.isSafeInteger(value) || value < 1 || value > 65535)
    throw new Error(`${key} is invalid`);
  return value;
}
/** Separate central entrypoint: no Docker/owner-root/worker-key initialization. */
export async function startFleetCentral(
  env: NodeJS.ProcessEnv,
  client: DstackClient,
  requestFetch: typeof fetch = fetch,
): Promise<{
  controller: FleetController;
  identity: FleetPeerIdentity;
  close(): Promise<void>;
}> {
  env = await verifiedFleetEnvironment(env, {
    role: "controller",
    identity: () => client.info(),
  });
  if (env.CONTROLLER_TERM !== undefined && env.CONTROLLER_TERM !== "1")
    throw new Error("Only singleton controller term 1 is supported");
  const chainId = Number(env.CHAIN_ID ?? 14800);
  if (chainId !== 14800) throw new Error("Fleet pilot is restricted to Moksha");
  const gatewayUrl = required(env, "GATEWAY_URL");
  if (new URL(gatewayUrl).protocol !== "https:")
    throw new Error("Gateway requires HTTPS");
  const path = required(env, "FLEET_STATE_PATH");
  if (!isAbsolute(path)) throw new Error("FLEET_STATE_PATH must be absolute");
  const gatewayToken = required(env, "FLEET_GATEWAY_TOKEN"),
    adminToken = required(env, "FLEET_CONTROLLER_ADMIN_TOKEN"),
    reverseToken = required(env, "FLEET_CONTROLLER_GATEWAY_TOKEN");
  if (
    new Set([gatewayToken, adminToken, reverseToken]).size !== 3 ||
    [gatewayToken, adminToken, reverseToken].some((t) => t.length < 32)
  )
    throw new Error(
      "Distinct fleet service credentials of at least 32 characters are required",
    );
  const workers = JSON.parse(
    required(env, "FLEET_WORKERS_JSON"),
  ) as WorkerConfig[];
  if (
    !Array.isArray(workers) ||
    workers.length > MAX_FLEET_WORKERS ||
    workers.some(
      (w) =>
        !w.policy ||
        w.policy.identity.role !== "worker" ||
        new URL(w.url).protocol !== "https:" ||
        !Number.isSafeInteger(w.capacity) ||
        w.capacity < 1,
    )
  )
    throw new Error(
      `Configure zero to ${MAX_FLEET_WORKERS} admitted Moksha workers`,
    );
  const info = await client.info();
  if (workers.some((w) => w.policy.identity.appId === info.appId))
    throw new Error("Central and worker KMS app identities must differ");
  const validity = fleetConfigValidity(env);
  const identity: FleetPeerIdentity = {
    role: "controller",
    nodeId: env.NODE_ID ?? "moksha-personal-server-controller",
    nodeIncarnation: randomUUID(),
    appId: info.appId,
    instanceId: info.instanceId,
    composeHash: info.composeHash,
  };
  const gatewayFetch: typeof fetch = (input, init) => {
    const headers = new Headers(init?.headers);
    if (env.VERCEL_PROTECTION_BYPASS)
      headers.set("x-vercel-protection-bypass", env.VERCEL_PROTECTION_BYPASS);
    return requestFetch(input, { ...init, headers });
  };
  const gateway = async <T>(action: string, body: unknown): Promise<T> => {
    const response = await gatewayFetch(
      new URL(`/v1/fleet?action=${action}`, gatewayUrl),
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${reverseToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(15_000),
      },
    );
    if (!response.ok) throw new Error("Gateway fleet transaction failed");
    return response.json() as Promise<T>;
  };
  const controller = await openFleetController({
    path,
    startPaused: true,
    event: (event, fields) => logger.info(fields, event),
    enroll: async (owner) => {
      await gateway("enroll", owner);
    },
    publish: async (assignment) => {
      await gateway("assignment", assignment);
    },
    release: async (assignment) => {
      await gateway("release", assignment);
    },
  });
  const peers = new Map<string, ReturnType<typeof createFleetPeerClient>>();
  const admit = async (body: unknown) => {
    const { nodeId, resume } = body as { nodeId: string; resume?: boolean };
    const config = workers.find((w) => w.policy.identity.nodeId === nodeId);
    if (!config)
      throw new Error("Worker is not in configured admission policy");
    const peer = createFleetPeerClient({
      identity,
      client,
      verifyPeer: createDcapPeerVerifier([config.policy]),
      baseUrl: config.url,
      fetch: requestFetch,
    });
    const remote = await peer.call<{ identity: FleetPeerIdentity }>(
      "describe",
      {},
    );
    if (remote.identity.nodeId !== nodeId || remote.identity.role !== "worker")
      throw new Error("Worker identity mismatch");
    const pinnedPeer = createFleetPeerClient({
      identity,
      client,
      verifyPeer: createDcapPeerVerifier([config.policy]),
      baseUrl: config.url,
      fetch: requestFetch,
      expectedPeer: remote.identity,
    });
    await controller.admit({
      nodeId,
      nodeIncarnation: remote.identity.nodeIncarnation,
      capacity: config.capacity,
      worker: fleetWorkerPort(pinnedPeer),
      ...(resume === true ? { draining: false } : {}),
    });
    peers.set(nodeId, pinnedPeer);
    logger.info(
      { nodeId, nodeIncarnation: remote.identity.nodeIncarnation },
      "Worker peer admitted",
    );
    return { success: true, identity: remote.identity };
  };
  const firstPeer = () => {
    const peer = peers.values().next().value;
    if (!peer) throw new Error("No admitted worker");
    return peer;
  };
  const mcp = await startMcpRouter(
    {
      client,
      gatewayUrl,
      chainId: chainId as SupportedChainId,
      contracts: { ...DEFAULTS.gateway.contracts },
      logger,
    },
    env,
    gatewayFetch,
    () =>
      createFleetMcpRouting({
        controller,
        chainId,
        gatewayUrl,
        fetch: gatewayFetch,
      }),
  );
  if (!mcp) throw new Error("Central MCP public origin is required");
  const reconcileApprovedOwners = () =>
    mcp.reconcileApprovedOwners(async (binding) => {
      const owner = await resolveFleetOwner(binding, {
        chainId,
        gatewayUrl,
        fetch: gatewayFetch,
      });
      await controller.enroll(owner);
    });
  const drained = () =>
    !controller
      .snapshot()
      .some(
        (row) =>
          row.assignment &&
          Date.parse(row.assignment.leaseExpiresAt) > Date.now(),
      );
  const prepareRollback = async (body: unknown) => {
    const { sourceNodeId, migrationId } = body as {
      sourceNodeId: string;
      migrationId: string;
    };
    if (!controller.paused() || (await mcp.active()) || !drained())
      throw new Error("Fence and drain central before preparing rollback");
    if (typeof migrationId !== "string" || migrationId.length < 8)
      throw new Error("Migration ID required");
    const peer = peers.get(sourceNodeId);
    if (!peer) throw new Error("Migration peer is not admitted");
    return peer.call("migration.prepare-rollback", { migrationId });
  };
  const migrate = async (body: unknown) => {
    const { sourceNodeId, migrationId, direction } = body as {
      sourceNodeId: string;
      migrationId: string;
      direction?: string;
    };
    if (typeof migrationId !== "string" || migrationId.length < 8)
      throw new Error("Migration ID required");
    const peer = peers.get(sourceNodeId);
    if (!peer) throw new Error("Migration peer is not admitted");
    if (direction === "rollback") {
      if (
        !controller.paused() ||
        controller
          .snapshot()
          .some(
            (row) =>
              row.assignment &&
              Date.parse(row.assignment.leaseExpiresAt) > Date.now(),
          )
      )
        throw new Error("Quiesce and drain fleet before rollback export");
      await reconcileApprovedOwners();
      const target = workers.find(
        (w) => w.policy.identity.nodeId === sourceNodeId,
      )!.policy.identity;
      const exported = await mcp.exportForMigration({
        migrationId,
        targetPeer: target,
      });
      return peer.call<{ connections: number; digest: string }>(
        "migration.import",
        exported,
      );
    }
    const exported = await peer.call<McpMigrationSnapshot>("migration.export", {
      migrationId,
      targetPeer: identity,
    });
    return mcp.importFromMigration(exported);
  };
  const common = {
    controller,
    config: {
      issuedAt: validity?.issuedAt ?? null,
      expiresAt: validity?.expiresAt ?? null,
      composeHash: identity.composeHash,
      appId: identity.appId,
      instanceId: identity.instanceId,
    },
    active: async () => !controller.paused() && (await mcp.active()),
    activate: async () => {
      if (!(await mcp.active()))
        throw new Error("Protected state import required");
      await controller.pause();
      await reconcileApprovedOwners();
      await controller.resume();
      return { success: true, paused: false };
    },
    quiesce: async () => {
      await controller.pause();
      const outcomes = await Promise.allSettled([
        ...controller.nodeStatus().map((node) => controller.drain(node.nodeId)),
        reconcileApprovedOwners(),
      ]);
      const failure = outcomes.find((result) => result.status === "rejected");
      if (failure?.status === "rejected") throw failure.reason;
      return { success: true, paused: true, placements: controller.snapshot() };
    },
    identity: (body: unknown) => firstPeer().call("worker.identity", body),
    seal: (body: unknown) => firstPeer().call("worker.seal", body),
    admit,
    migrate,
    prepareRollback,
  };
  const servers = [
    serve({
      hostname: env.FLEET_CONTROL_HOST ?? "0.0.0.0",
      port: port(env, "FLEET_CONTROL_PORT", 8790),
      fetch: createFleetControlHttp({
        ...common,
        credential: gatewayToken,
        role: "gateway",
      }),
    }),
    serve({
      hostname: env.FLEET_ADMIN_HOST ?? "0.0.0.0",
      port: port(env, "FLEET_ADMIN_PORT", 8791),
      fetch: createFleetControlHttp({
        ...common,
        credential: adminToken,
        role: "admin",
      }),
    }),
    serve({
      hostname: env.FLEET_PEER_HOST ?? "0.0.0.0",
      port: port(env, "FLEET_PEER_PORT", 8792),
      fetch: createFleetPeerServer({
        identity,
        client,
        verifyPeer: createDcapPeerVerifier(workers.map((w) => w.policy)),
        dispatch: async () => {
          throw new Error("Controller peer method unavailable");
        },
      }),
    }),
  ];
  await Promise.all(
    servers.map(
      (server) =>
        new Promise<void>((resolve, reject) => {
          server.once("listening", resolve);
          server.once("error", reject);
        }),
    ),
  );
  let stopped = false;
  const timers = new Set<ReturnType<typeof setTimeout>>();
  const schedule = (interval: number, operation: () => Promise<void>): void => {
    const timer = setTimeout(() => {
      timers.delete(timer);
      void operation()
        .catch(() => logger.warn({}, "Fleet reconcile unavailable"))
        .finally(() => {
          if (!stopped) schedule(interval, operation);
        });
    }, interval);
    timer.unref();
    timers.add(timer);
  };
  // Renewal is independent of potentially slow queued-owner hydration.
  schedule(FLEET_RENEW_MS, async () => {
    if (!controller.paused() && (await mcp.active())) await controller.renew();
  });
  schedule(5_000, async () => {
    if (controller.paused() || !(await mcp.active())) return;
    const pending = await gateway<{
      owners: (FleetOwner & { scopes: FleetScope[] })[];
    }>("pending", {});
    await Promise.all(
      pending.owners.map(async ({ scopes, ...owner }) => {
        try {
          await controller.ensure(owner, scopes);
        } catch {
          logger.warn(
            { userPsId: owner.userPsId },
            "Pending owner placement unavailable",
          );
        }
      }),
    );
  });
  schedule(30_000, async () => {
    await Promise.all(
      workers.map(async (worker) => {
        try {
          await admit({ nodeId: worker.policy.identity.nodeId });
        } catch {
          logger.warn(
            { nodeId: worker.policy.identity.nodeId },
            "Worker health attestation unavailable",
          );
        }
      }),
    );
  });
  // Staging may precede worker activation. No admission failure silently relaxes policy.
  void Promise.all(
    workers.map(async (worker) => {
      try {
        await admit({ nodeId: worker.policy.identity.nodeId });
      } catch {
        logger.warn(
          { nodeId: worker.policy.identity.nodeId },
          "Worker admission pending",
        );
      }
    }),
  );
  logger.info(
    {
      nodeId: identity.nodeId,
      nodeIncarnation: identity.nodeIncarnation,
      controllerTerm: 1,
    },
    "Central fleet listeners started",
  );
  return {
    controller,
    identity,
    async close() {
      stopped = true;
      for (const timer of timers) clearTimeout(timer);
      await mcp.close();
      await Promise.all(
        servers.map(
          (server) =>
            new Promise<void>((resolve, reject) =>
              server.close((error) => (error ? reject(error) : resolve())),
            ),
        ),
      );
    },
  };
}
