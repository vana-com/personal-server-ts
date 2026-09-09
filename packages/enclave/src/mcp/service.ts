import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";
import { serve } from "@hono/node-server";
import {
  createGatewayClient,
  type GatewayClient,
} from "@opendatalabs/vana-sdk/node";
import {
  appUrlFromOAuthRedirectUri,
  ensureMcpGranteeRegistered,
} from "@opendatalabs/personal-server-ts-core/mcp";
import { DEFAULTS } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  createTeeMcpIngress,
  openMcpDurableState,
  verifyTeeMcpGrants,
  type McpWakeupIdentity,
  type McpDurableState,
  type TeeMcpIngressDeps,
} from "@opendatalabs/personal-server-ts-server/mcp/tee";
import type { PrewarmDeps } from "../jobs/run.js";
import { currentMcpIdentity, dispatchOwnerMcp } from "./dispatch.js";

export interface McpMigrationSnapshot {
  migrationId: string;
  snapshotBase64: string;
  digest: string;
}

export interface McpIngressControl {
  exportForMigration(request: {
    migrationId: string;
    targetPeer: { appId: string; instanceId: string };
  }): Promise<McpMigrationSnapshot>;
  importFromMigration(
    request: McpMigrationSnapshot,
  ): Promise<{ connections: number; digest: string }>;
  rememberIdentity(identity: McpWakeupIdentity): Promise<void>;
  close(): Promise<void>;
}

/** Disabled unless explicitly configured on the demo CVM. */
export async function startMcpIngress(
  deps: PrewarmDeps,
  env: NodeJS.ProcessEnv,
  requestFetch: typeof fetch,
): Promise<McpIngressControl | undefined> {
  return startMcpRouter(deps, env, requestFetch, (state) => {
    const dispatchDeps = { ...deps, state, fetch: requestFetch };
    return {
      ownerReady: async (binding) => {
        try {
          await currentMcpIdentity(binding, dispatchDeps);
          return true;
        } catch {
          return false;
        }
      },
      dispatch: (request, connection, binding) =>
        dispatchOwnerMcp(request, connection, binding, dispatchDeps),
    };
  });
}

export async function startMcpRouter(
  deps: Pick<
    PrewarmDeps,
    "client" | "gatewayUrl" | "chainId" | "contracts" | "logger"
  >,
  env: NodeJS.ProcessEnv,
  requestFetch: typeof fetch,
  routing: (
    state: McpDurableState,
  ) => Pick<TeeMcpIngressDeps, "ownerReady" | "dispatch">,
): Promise<McpIngressControl | undefined> {
  if (!env.MCP_PUBLIC_ORIGIN) return undefined;
  const origin = new URL(env.MCP_PUBLIC_ORIGIN);
  if (origin.protocol !== "https:" || origin.origin !== env.MCP_PUBLIC_ORIGIN)
    throw new Error("MCP_PUBLIC_ORIGIN must be an HTTPS origin");
  if (
    !env.MCP_APPROVAL_URL ||
    new URL(env.MCP_APPROVAL_URL).protocol !== "https:"
  )
    throw new Error("MCP_APPROVAL_URL must be HTTPS");
  if (!env.MCP_STATE_PATH || !isAbsolute(env.MCP_STATE_PATH))
    throw new Error("MCP_STATE_PATH must be an absolute durable-volume path");
  const redirects: unknown = JSON.parse(env.MCP_REDIRECT_URIS ?? "[]");
  if (
    !Array.isArray(redirects) ||
    redirects.length === 0 ||
    redirects.some(
      (uri) => typeof uri !== "string" || new URL(uri).protocol !== "https:",
    )
  )
    throw new Error("MCP_REDIRECT_URIS must list the allowed HTTPS callbacks");
  const port = Number(env.MCP_INGRESS_PORT ?? "8788");
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535)
    throw new Error("MCP_INGRESS_PORT is invalid");
  const derived = await deps.client.deriveKey(
    "mcp/ingress/state/v1",
    "vana.mcp.ingress.state.v1",
  );
  let state;
  try {
    state = await openMcpDurableState({
      path: env.MCP_STATE_PATH,
      key: derived.key,
    });
  } finally {
    derived.key.fill(0);
  }
  const gateway = teeGatewayClient(deps.gatewayUrl, requestFetch);
  const gatewayConfig = {
    chainId: deps.chainId,
    contracts: { ...DEFAULTS.gateway.contracts, ...deps.contracts },
  };
  const app = createTeeMcpIngress({
    origin: origin.origin,
    approvalUrl: env.MCP_APPROVAL_URL,
    allowedRedirectUris: redirects as string[],
    gateway,
    state,
    registerGrantee: async (connection, redirectUri) => {
      await ensureMcpGranteeRegistered({
        connection,
        gateway,
        gatewayConfig,
        gatewayUrl: deps.gatewayUrl,
        appUrl: appUrlFromOAuthRedirectUri(redirectUri, "Claude"),
        fetch: requestFetch,
      });
    },
    verifyGrants: (connection, binding, grants) =>
      verifyTeeMcpGrants({
        connection,
        binding,
        grants,
        gateway,
        gatewayConfig,
        chainId: deps.chainId,
      }),
    ...routing(state),
  });
  // This listener is reachable only by the TLS sidecar on the CVM network;
  // compose must not publish it through a separately terminated public port.
  const server = serve({
    fetch: async (request) => {
      const status = await state.migrationStatus();
      if (
        status.fenced ||
        (env.MCP_MIGRATION_REQUIRED === "1" && !status.importedId)
      )
        return Response.json(
          { error: "MCP migration pending" },
          { status: 503 },
        );
      return app.fetch(request);
    },
    hostname: env.MCP_INGRESS_HOST ?? "0.0.0.0",
    port,
  });
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  deps.logger.info({ origin: origin.origin, port }, "TEE MCP ingress started");
  let closed: Promise<void> | undefined;
  const close = (): Promise<void> =>
    (closed ??= new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    ));
  return {
    rememberIdentity: (identity) => state.rememberIdentity(identity),
    close,
    exportForMigration: async ({ migrationId, targetPeer }) => {
      await close();
      const snapshot = await state.fenceAndExport(
        migrationId,
        `${targetPeer.appId}:${targetPeer.instanceId}`,
      );
      try {
        return {
          migrationId,
          snapshotBase64: Buffer.from(snapshot).toString("base64"),
          digest: createHash("sha256").update(snapshot).digest("hex"),
        };
      } finally {
        snapshot.fill(0);
      }
    },
    importFromMigration: async ({ migrationId, snapshotBase64, digest }) => {
      const snapshot = Buffer.from(snapshotBase64, "base64");
      try {
        if (createHash("sha256").update(snapshot).digest("hex") !== digest)
          throw new Error("Migration digest mismatch");
        return await state.importSnapshot(snapshot, migrationId);
      } finally {
        snapshot.fill(0);
      }
    },
  };
}

function teeGatewayClient(
  baseUrl: string,
  requestFetch: typeof fetch,
): GatewayClient {
  const sdk = createGatewayClient(baseUrl);
  const read = async <T>(path: string): Promise<T | null> => {
    const response = await requestFetch(new URL(path, baseUrl), {
      signal: AbortSignal.timeout(15_000),
    });
    if (response.status === 404) return null;
    if (!response.ok) throw new Error("MCP Gateway read unavailable");
    const body = (await response.json()) as { data?: T };
    if (!body.data) throw new Error("MCP Gateway response invalid");
    return body.data;
  };
  return {
    ...sdk,
    getBuilder: (address) =>
      read<NonNullable<Awaited<ReturnType<GatewayClient["getBuilder"]>>>>(
        `/v1/builders/${encodeURIComponent(address)}`,
      ),
    getGrant: (grantId) =>
      read<NonNullable<Awaited<ReturnType<GatewayClient["getGrant"]>>>>(
        `/v1/grants/${encodeURIComponent(grantId)}`,
      ),
  };
}
