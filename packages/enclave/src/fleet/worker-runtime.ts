import { randomUUID } from "node:crypto";
import { serve } from "@hono/node-server";
import type { GatewayClient as ProtocolGatewayClient } from "@opendatalabs/vana-sdk/node";
import { DEFAULTS } from "@opendatalabs/personal-server-ts-core/schemas";
import { verifyTeeMcpGrants } from "@opendatalabs/personal-server-ts-server/mcp/tee";
import type { PrewarmDeps } from "../jobs/run.js";
import { dstackInfo } from "../dstack/info-cache.js";
import { buildEvidence } from "../agent/evidence.js";
import { sealDelivery } from "../agent/seal.js";
import { identityBody, sealBody } from "../agent/http.js";
import type {
  FleetAssignment,
  FleetEnvelopeResponse,
  FleetPeerIdentity,
  FleetPrepareRequest,
  FleetExecuteRequest,
} from "./contracts.js";
import { createFleetPeerServer } from "./peer.js";
import {
  createDcapPeerVerifier,
  type FleetPeerPolicy,
} from "./peer-verifier.js";
import { createFleetWorker, type LocalFleetWorker } from "./worker.js";
import { createFleetWorkerBackend } from "./worker-backend.js";

export interface FleetMigrationPort {
  prepareRollback(migrationId: string): Promise<unknown>;
  exportForMigration(input: {
    migrationId: string;
    targetPeer: FleetPeerIdentity;
  }): Promise<unknown>;
  importFromMigration(input: {
    migrationId: string;
    snapshotBase64: string;
    digest: string;
  }): Promise<unknown>;
}
export interface FleetWorkerRuntime {
  worker: LocalFleetWorker;
  identity: FleetPeerIdentity;
  close(): Promise<void>;
}
export async function startFleetWorker(options: {
  env: NodeJS.ProcessEnv;
  sandbox: PrewarmDeps;
  nodeId: string;
  nodeSecret: string;
  capacity: number;
  migration?: FleetMigrationPort;
  fetch?: typeof fetch;
}): Promise<FleetWorkerRuntime | undefined> {
  if (options.env.FLEET_ENABLED !== "true") return undefined;
  if (options.sandbox.chainId !== 14800)
    throw new Error("Fleet pilot only supports Moksha");
  const policies = JSON.parse(
    options.env.FLEET_PEER_POLICIES ?? "[]",
  ) as FleetPeerPolicy[];
  if (
    !Array.isArray(policies) ||
    !policies.length ||
    policies.some((p) => p.identity.role !== "controller")
  )
    throw new Error("Admitted controller peer policy required");
  const port = Number(options.env.FLEET_PEER_PORT ?? "8789");
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535)
    throw new Error("FLEET_PEER_PORT invalid");
  const info = await dstackInfo(options.sandbox.client);
  const identity: FleetPeerIdentity = {
    ...info,
    role: "worker",
    nodeId: options.nodeId,
    nodeIncarnation: randomUUID(),
  };
  const requestFetch = options.fetch ?? fetch;
  const publicRead = async <T>(path: string): Promise<T | null> => {
    const response = await requestFetch(
      new URL(path, options.sandbox.gatewayUrl),
      { signal: AbortSignal.timeout(15_000) },
    );
    if (response.status === 404) return null;
    if (!response.ok)
      throw new Error("Worker protocol verification unavailable");
    const body = (await response.json()) as { data?: T };
    if (!body.data) throw new Error("Invalid worker protocol response");
    return body.data;
  };
  const gateway: Pick<ProtocolGatewayClient, "getGrant" | "getBuilder"> = {
    getGrant: (grant) => publicRead(`/v1/grants/${encodeURIComponent(grant)}`),
    getBuilder: (address) =>
      publicRead(`/v1/builders/${encodeURIComponent(address)}`),
  };
  const backend = createFleetWorkerBackend({
    sandbox: options.sandbox,
    fetch: requestFetch,
    async envelope(assignment, signal): Promise<FleetEnvelopeResponse> {
      const response = await requestFetch(
        new URL("/v1/fleet?action=envelope", options.sandbox.gatewayUrl),
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${options.nodeSecret}`,
            "X-Node-Id": options.nodeId,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ assignment }),
          signal: AbortSignal.any([signal, AbortSignal.timeout(15_000)]),
        },
      );
      if (!response.ok) throw new Error("Worker envelope unavailable");
      return (await response.json()) as FleetEnvelopeResponse;
    },
    verifyGrants: (request) =>
      verifyTeeMcpGrants({
        connection: request.connection,
        binding: request.binding,
        grants: request.connection.grants,
        gateway,
        gatewayConfig: {
          chainId: options.sandbox.chainId,
          contracts: {
            ...DEFAULTS.gateway.contracts,
            ...options.sandbox.contracts,
          },
        },
        chainId: options.sandbox.chainId,
      }),
  });
  const worker = createFleetWorker({
    ...identity,
    capacity: options.capacity,
    backend,
  });
  const handler = createFleetPeerServer({
    identity,
    client: options.sandbox.client,
    verifyPeer: createDcapPeerVerifier(policies),
    async dispatch(method, body, peer) {
      if (peer.role !== "controller")
        throw new Error("Controller peer required");
      switch (method) {
        case "activity":
          return worker.activity(body as FleetAssignment);
        case "prepare":
          return worker.prepare(body as FleetPrepareRequest);
        case "renew":
          return worker.renew(body as FleetAssignment);
        case "readiness":
          return worker.readiness(body as FleetPrepareRequest);
        case "execute":
          return worker.execute(body as FleetExecuteRequest);
        case "release":
          return worker.release(body as FleetAssignment);
        case "worker.identity":
          return buildEvidence(options.sandbox.client, identityBody(body));
        case "worker.seal":
          return sealDelivery(options.sandbox.client, sealBody(body));
        case "migration.export": {
          if (!options.migration) throw new Error("Migration unavailable");
          const input = body as { migrationId: string };
          // Target identity comes from the verified peer, never request input.
          return options.migration.exportForMigration({
            migrationId: input.migrationId,
            targetPeer: peer,
          });
        }
        case "migration.prepare-rollback": {
          if (!options.migration) throw new Error("Migration unavailable");
          return options.migration.prepareRollback(
            (body as { migrationId: string }).migrationId,
          );
        }
        case "migration.import": {
          if (!options.migration) throw new Error("Migration unavailable");
          return options.migration.importFromMigration(
            body as Parameters<FleetMigrationPort["importFromMigration"]>[0],
          );
        }
        default:
          throw new Error("Unknown worker method");
      }
    },
  });
  const server = serve({
    fetch: handler,
    hostname: options.env.FLEET_PEER_HOST ?? "0.0.0.0",
    port,
  });
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  options.sandbox.logger.info(
    {
      nodeId: identity.nodeId,
      nodeIncarnation: identity.nodeIncarnation,
      port,
    },
    "Fleet worker peer started",
  );
  return {
    worker,
    identity,
    async close() {
      await Promise.all(worker.assignments().map((a) => worker.release(a)));
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    },
  };
}
