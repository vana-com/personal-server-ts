import { startFleetWorker } from "../fleet/worker-runtime.js";
import {
  fleetConfigValidity,
  verifiedFleetEnvironment,
} from "../fleet/security-config.js";
import { createRealDstackClient } from "../dstack/real.js";
/**
 * Node agent entrypoint. ENCLAVE_AGENT_SECRET is required;
 * ENCLAVE_AGENT_HOST defaults to 127.0.0.1, ENCLAVE_AGENT_PORT to 8787;
 * DSTACK_FAKE=1 selects the fake and DSTACK_FAKE_APP_ID names its app.
 */

import { agentConfigFromEnv, resolveSandboxAgentUrl } from "./bootstrap.js";
import { drainWithTimeout } from "./lifecycle.js";
import { createAgentServer, type AgentJobsControl } from "./http.js";
import { startClaimLoop, type JobLogger } from "../jobs/claim-loop.js";
import { createGatewayClient } from "../jobs/gateway-client.js";
import { startNodeHeartbeat } from "../jobs/node-heartbeat.js";
import { prewarmSandbox, runJob, type PrewarmDeps } from "../jobs/run.js";
import { MAX_WAIT_SECONDS } from "../jobs/types.js";
import { createDockerRuntime } from "../sandbox/docker-runtime.js";
import { createFakeRuntime } from "../sandbox/fake-runtime.js";
import { createSandboxRegistry } from "../sandbox/registry.js";
import type { SandboxRuntime } from "../sandbox/runtime.js";
import { startMcpIngress } from "../mcp/service.js";

const EXIT_FAILURE = 1;
const SIGTERM = "SIGTERM";
const AGENT_DRAIN_TIMEOUT_MS = 110_000;
const CONSOLE_LOGGER: JobLogger = {
  error(context, message): void {
    console.error({ level: "error", ...context, message });
  },
  info(context, message): void {
    console.error({ level: "info", ...context, message });
  },
  warn(context, message): void {
    console.error({ level: "warn", ...context, message });
  },
};

void main();

async function main(): Promise<void> {
  try {
    // The fleet compose always embeds this trust key as a measured literal.
    // An unsigned FLEET_ENABLED=false cannot skip authentication on that image.
    const raw = process.env;
    const env =
      raw.FLEET_CONFIG_PUBLIC_KEY !== undefined ||
      raw.FLEET_SIGNED_CONFIG !== undefined ||
      raw.FLEET_ENABLED === "true"
        ? await verifiedFleetEnvironment(raw, {
            role: "worker",
            identity: () => createRealDstackClient().info(),
          })
        : raw;
    const { client, host, jobs, port, secret } = agentConfigFromEnv(env);
    const jobsControl = jobs
      ? await startJobs(client, jobs, port, env)
      : undefined;
    const config = fleetConfigValidity(env);
    const server = createAgentServer({
      client,
      secret,
      ...(jobsControl ? { jobs: jobsControl } : {}),
      ...(config ? { config } : {}),
    });

    server.listen(port, host);
    process.once(SIGTERM, () => {
      void shutdown(server, jobsControl).catch((error: unknown) => {
        CONSOLE_LOGGER.warn({ error: String(error) }, "Agent shutdown failed");
        process.exitCode = EXIT_FAILURE;
      });
    });
  } catch (error) {
    console.error(
      error instanceof Error ? error.message : "enclave agent failed to start",
    );
    process.exitCode = EXIT_FAILURE;
  }
}

async function startJobs(
  client: ReturnType<typeof agentConfigFromEnv>["client"],
  config: NonNullable<ReturnType<typeof agentConfigFromEnv>["jobs"]>,
  agentPort: number,
  env: NodeJS.ProcessEnv,
): Promise<AgentJobsControl> {
  const sandboxAgentUrl = await resolveSandboxAgentUrl({
    ...(config.sandboxAgentUrl ? { override: config.sandboxAgentUrl } : {}),
    dockerHost: config.dockerHost,
    agentPort,
  });
  CONSOLE_LOGGER.info({ sandboxAgentUrl }, "Sandbox agent URL resolved");
  const runtime = createRuntime(config);
  await runtime.reconcile();
  const registry = createSandboxRegistry({
    runtime,
    logger: CONSOLE_LOGGER,
    max: config.sandboxMax,
    idleTtlMs: config.idleTtlMs,
  });
  const gateway = createGatewayClient({
    baseUrl: config.gatewayUrl,
    nodeId: config.nodeId,
    nodeSecret: config.nodeSecret,
    ...(config.gatewayBypassSecret
      ? { fetch: gatewayFetch(config.gatewayBypassSecret) }
      : {}),
  });
  const logger = CONSOLE_LOGGER;
  const sandboxDeps = {
    client,
    registry,
    image: config.image,
    gatewayUrl: config.gatewayUrl,
    storageApiUrl: config.storageApiUrl,
    agentUrl: sandboxAgentUrl,
    chainId: config.chainId,
    contracts: config.contracts,
    ...(config.gatewayBypassSecret
      ? { gatewayBypassSecret: config.gatewayBypassSecret }
      : {}),
    sync: config.sync,
    logger,
    jobResultMaxBytes: config.jobResultMaxBytes,
  } satisfies PrewarmDeps;
  const mcp = await startMcpIngress(
    sandboxDeps,
    env,
    config.gatewayBypassSecret
      ? gatewayFetch(config.gatewayBypassSecret)
      : fetch,
  );
  const fleet = await startFleetWorker({
    env,
    sandbox: sandboxDeps,
    nodeId: config.nodeId,
    nodeSecret: config.nodeSecret,
    capacity: config.sandboxMax,
    ...(mcp ? { migration: mcp } : {}),
    ...(config.gatewayBypassSecret
      ? { fetch: gatewayFetch(config.gatewayBypassSecret) }
      : {}),
  });
  const claimLoop = startClaimLoop({
    gateway,
    run: async (job, identity, assignment) => {
      if (!fleet) await mcp?.rememberIdentity(identity);
      const work = () =>
        runJob(job, identity, {
          ...sandboxDeps,
          ...(assignment && fleet
            ? {
                assignment,
                assignmentSignal: fleet.worker.signal(assignment),
                assertAssignment: () => fleet.worker.assertCurrent(assignment),
              }
            : {}),
          gateway,
          leaseSeconds: config.leaseSeconds,
          workDelayMs: config.workDelayMs,
        });
      return assignment && fleet
        ? fleet.worker.trackAssignment(assignment, work)
        : work();
    },
    ...(fleet
      ? {
          assignments: () => fleet.worker.assignments(),
          assertAssignment: (a) => fleet.worker.assertCurrent(a),
        }
      : {}),
    registry,
    leaseSeconds: config.leaseSeconds,
    wait: MAX_WAIT_SECONDS,
    capacity: config.sandboxMax,
    logger,
  });
  const nodeHeartbeat = startNodeHeartbeat({
    gateway,
    nodeId: config.nodeId,
    client,
    registry,
    capacity: config.sandboxMax,
    logger,
  });
  let drainPromise: Promise<void> | undefined;

  return {
    nodeId: config.nodeId,
    ...(fleet
      ? { nodeIncarnation: fleet.identity.nodeIncarnation, fleetEnabled: true }
      : {}),
    storageApiUrl: config.storageApiUrl,
    activeCount: () => registry.activeCount(),
    draining: () => claimLoop.draining(),
    sandboxDebug: config.sandboxDebug,
    listSandboxes: () => registry.listSandboxes(),
    sandboxLogs: (containerId, tail) => registry.sandboxLogs(containerId, tail),
    lookupSandboxJob: (accessToken, jobId) => {
      const lookup = registry.lookupJob(accessToken, jobId);
      if (fleet && lookup.kind === "active") {
        if (!lookup.job.assignment) return { kind: "inactive" };
        try {
          fleet.worker.assertCurrent(lookup.job.assignment);
        } catch {
          return { kind: "inactive" };
        }
      }
      return lookup;
    },
    lookupSandbox: (accessToken) => registry.lookupSandbox(accessToken),
    postAccessRecords: (records) => gateway.postAccessRecords({ records }),
    prewarm(body): void {
      if (!mcp) {
        void prewarmSandbox(body, body.scope, sandboxDeps);
        return;
      }
      void (async () => {
        await mcp.rememberIdentity(body);
        await prewarmSandbox(body, body.scope, sandboxDeps);
      })().catch((error: unknown) =>
        logger.warn({ error: String(error) }, "MCP prewarm state unavailable"),
      );
    },
    drain(): Promise<void> {
      drainPromise ??= claimLoop
        .drain()
        .then(() => Promise.all([fleet?.close(), mcp?.close()]))
        .then(() => undefined)
        .finally(() => nodeHeartbeat.stop());

      return drainPromise;
    },
  };
}

function gatewayFetch(secret: string): typeof fetch {
  return (input, init) => {
    const headers = new Headers(
      input instanceof Request ? input.headers : undefined,
    );
    new Headers(init?.headers).forEach((value, key) => headers.set(key, value));
    headers.set("x-vercel-protection-bypass", secret);

    return fetch(input, { ...init, headers });
  };
}

function createRuntime(
  config: NonNullable<ReturnType<typeof agentConfigFromEnv>["jobs"]>,
): SandboxRuntime {
  if (config.runtime === "fake") {
    return createFakeRuntime({
      ...(config.psEntry ? { psEntry: config.psEntry } : {}),
      ...(config.fakeRoot ? { fakeRoot: config.fakeRoot } : {}),
    });
  }

  return createDockerRuntime({
    dockerHost: config.dockerHost,
    memory: config.sandboxMemory,
    dataSize: config.sandboxDataSize,
    cpus: config.sandboxCpus,
    pidsLimit: config.sandboxPidsLimit,
    logger: CONSOLE_LOGGER,
  });
}

async function shutdown(
  server: ReturnType<typeof createAgentServer>,
  jobs: AgentJobsControl | undefined,
): Promise<void> {
  if (jobs) {
    await drainWithTimeout(
      () => jobs.drain(),
      AGENT_DRAIN_TIMEOUT_MS,
      CONSOLE_LOGGER,
    );
  }
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }

      resolve();
    });
  });
}
