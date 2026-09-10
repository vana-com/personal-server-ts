import { createServer } from "node:net";
import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import {
  canonicalFleetConfigPayload,
  type FleetSecurityConfigPayload,
} from "../fleet/security-config.js";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { createFakeDstackClient } from "../dstack/fake.js";
import { startFleetCentral } from "./bootstrap.js";
import { createMcpConnection } from "@opendatalabs/personal-server-ts-core/mcp";
import { openMcpDurableState } from "@opendatalabs/personal-server-ts-server/mcp/tee";
import { userPsId } from "@opendatalabs/vana-sdk/protocol/identity";
import type { FleetOwner } from "../fleet/contracts.js";
async function freePort() {
  const server = createServer();
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Expected port");
  await new Promise<void>((r, j) => server.close((e) => (e ? j(e) : r())));
  return String(address.port);
}
it("rejects unsigned runtime configuration before reading any protected central state", async () => {
  const path = await mkdtemp(join(tmpdir(), "central-config-"));
  const dstack = createFakeDstackClient({ appId: "1".repeat(40) });
  const derive = vi.spyOn(dstack, "deriveKey");
  const info = vi.spyOn(dstack, "info");
  let runtime: Awaited<ReturnType<typeof startFleetCentral>> | undefined;
  try {
    const starting = startFleetCentral(
      {
        CHAIN_ID: "14800",
        GATEWAY_URL: "https://gateway.invalid",
        NODE_ID: "controller",
        FLEET_STATE_PATH: join(path, "placements.json"),
        FLEET_WORKERS_JSON: "[]",
        FLEET_GATEWAY_TOKEN: "g".repeat(32),
        FLEET_CONTROLLER_ADMIN_TOKEN: "a".repeat(32),
        FLEET_CONTROLLER_GATEWAY_TOKEN: "r".repeat(32),
        FLEET_CONTROL_HOST: "127.0.0.1",
        FLEET_ADMIN_HOST: "127.0.0.1",
        FLEET_PEER_HOST: "127.0.0.1",
        FLEET_CONTROL_PORT: await freePort(),
        FLEET_ADMIN_PORT: await freePort(),
        FLEET_PEER_PORT: await freePort(),
        MCP_PUBLIC_ORIGIN: "https://mcp-dev.vana.org",
        MCP_APPROVAL_URL: "https://web.invalid/approve",
        MCP_STATE_PATH: join(path, "mcp.sealed"),
        MCP_INGRESS_HOST: "127.0.0.1",
        MCP_INGRESS_PORT: await freePort(),
        MCP_REDIRECT_URIS: '["https://claude.ai/api/mcp/auth_callback"]',
      },
      dstack,
    ).then((value) => {
      runtime = value;
      return value;
    });
    await expect(starting).rejects.toThrow();
    expect(info).not.toHaveBeenCalled();
    expect(derive).not.toHaveBeenCalled();
  } finally {
    await runtime?.close();
    await rm(path, { recursive: true, force: true });
  }
});

it("stages an authenticated empty directory paused and ignores unsigned runtime overrides", async () => {
  const path = await mkdtemp(join(tmpdir(), "central-signed-config-"));
  const dstack = createFakeDstackClient({ appId: "1".repeat(40) });
  const info = await dstack.info();
  const keys = generateKeyPairSync("ed25519");
  const env = {
    CHAIN_ID: "14800",
    CONTROLLER_TERM: "1",
    NODE_ID: "controller",
    GATEWAY_URL: "https://gateway.invalid",
    FLEET_STATE_PATH: join(path, "placements.json"),
    FLEET_WORKERS_JSON: "[]",
    FLEET_GATEWAY_TOKEN: "g".repeat(32),
    FLEET_CONTROLLER_ADMIN_TOKEN: "a".repeat(32),
    FLEET_CONTROLLER_GATEWAY_TOKEN: "r".repeat(32),
    FLEET_CONTROL_HOST: "127.0.0.1",
    FLEET_ADMIN_HOST: "127.0.0.1",
    FLEET_PEER_HOST: "127.0.0.1",
    FLEET_CONTROL_PORT: await freePort(),
    FLEET_ADMIN_PORT: await freePort(),
    FLEET_PEER_PORT: await freePort(),
    MCP_PUBLIC_ORIGIN: "https://mcp-dev.vana.org",
    MCP_APPROVAL_URL: "https://web.invalid/approve",
    MCP_STATE_PATH: join(path, "mcp.sealed"),
    MCP_INGRESS_HOST: "127.0.0.1",
    MCP_INGRESS_PORT: await freePort(),
    MCP_REDIRECT_URIS: '["https://claude.ai/api/mcp/auth_callback"]',
    MCP_MIGRATION_REQUIRED: "1",
  };
  const payload: FleetSecurityConfigPayload = {
    version: 1,
    purpose: "vana.fleet.security-config",
    role: "controller",
    appId: info.appId,
    instanceId: info.instanceId,
    nodeId: env.NODE_ID,
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    env,
  };
  const requestFetch = vi.fn<typeof fetch>(async () => {
    throw new Error("Must not call Gateway while staged");
  });
  let runtime: Awaited<ReturnType<typeof startFleetCentral>> | undefined;
  try {
    runtime = await startFleetCentral(
      {
        FLEET_CONFIG_PUBLIC_KEY: keys.publicKey
          .export({ type: "spki", format: "der" })
          .toString("base64"),
        FLEET_SIGNED_CONFIG:
          "base64:" +
          Buffer.from(
            JSON.stringify({
              payload,
              signature: sign(
                null,
                canonicalFleetConfigPayload(payload),
                keys.privateKey,
              ).toString("base64"),
            }),
          ).toString("base64"),
        NODE_ID: "unsigned-attacker",
        GATEWAY_URL: "https://attacker.invalid",
        FLEET_CONTROLLER_ADMIN_TOKEN: "attacker".repeat(10),
      },
      dstack,
      requestFetch,
    );
    expect(runtime.identity.nodeId).toBe("controller");
    expect(runtime.controller.paused()).toBe(true);
    expect(runtime.controller.nodeStatus()).toEqual([]);
    const request = (port: string, route: string, token: string) =>
      fetch(`http://127.0.0.1:${port}/fleet/v1/${route}`, {
        method: "POST",
        headers: { authorization: `Bearer ${token}` },
        body: "{}",
      });
    expect(
      (
        await request(
          env.FLEET_ADMIN_PORT,
          "status",
          env.FLEET_CONTROLLER_ADMIN_TOKEN,
        )
      ).status,
    ).toBe(200);
    expect(
      (await request(env.FLEET_ADMIN_PORT, "status", "attacker".repeat(10)))
        .status,
    ).toBe(401);
    expect(
      (
        await request(
          env.FLEET_ADMIN_PORT,
          "activate",
          env.FLEET_CONTROLLER_ADMIN_TOKEN,
        )
      ).status,
    ).toBe(503);
    expect(
      (await request(env.FLEET_CONTROL_PORT, "ensure", env.FLEET_GATEWAY_TOKEN))
        .status,
    ).toBe(503);
    expect(requestFetch).not.toHaveBeenCalled();
  } finally {
    await runtime?.close();
    await rm(path, { recursive: true, force: true });
  }
});

it("activates a signed net-new empty controller without an imported MCP snapshot", async () => {
  const path = await mkdtemp(join(tmpdir(), "central-net-new-"));
  const dstack = createFakeDstackClient({ appId: "1".repeat(40) });
  const info = await dstack.info();
  const keys = generateKeyPairSync("ed25519");
  const env = {
    CHAIN_ID: "14800",
    CONTROLLER_TERM: "1",
    NODE_ID: "controller",
    GATEWAY_URL: "https://gateway.invalid",
    FLEET_STATE_PATH: join(path, "placements.json"),
    FLEET_WORKERS_JSON: "[]",
    FLEET_GATEWAY_TOKEN: "g".repeat(32),
    FLEET_CONTROLLER_ADMIN_TOKEN: "a".repeat(32),
    FLEET_CONTROLLER_GATEWAY_TOKEN: "r".repeat(32),
    FLEET_CONTROL_HOST: "127.0.0.1",
    FLEET_ADMIN_HOST: "127.0.0.1",
    FLEET_PEER_HOST: "127.0.0.1",
    FLEET_CONTROL_PORT: await freePort(),
    FLEET_ADMIN_PORT: await freePort(),
    FLEET_PEER_PORT: await freePort(),
    MCP_PUBLIC_ORIGIN: "https://mcp-dev.vana.org",
    MCP_APPROVAL_URL: "https://web.invalid/approve",
    MCP_STATE_PATH: join(path, "mcp.sealed"),
    MCP_INGRESS_HOST: "127.0.0.1",
    MCP_INGRESS_PORT: await freePort(),
    MCP_REDIRECT_URIS: '["https://claude.ai/api/mcp/auth_callback"]',
    MCP_MIGRATION_REQUIRED: "0",
  };
  const payload: FleetSecurityConfigPayload = {
    version: 1,
    purpose: "vana.fleet.security-config",
    role: "controller",
    appId: info.appId,
    instanceId: info.instanceId,
    nodeId: env.NODE_ID,
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    env,
  };
  const requestFetch = vi.fn<typeof fetch>(async () => {
    throw new Error("Net-new empty controller must not call Gateway");
  });
  let runtime: Awaited<ReturnType<typeof startFleetCentral>> | undefined;
  try {
    runtime = await startFleetCentral(
      {
        FLEET_CONFIG_PUBLIC_KEY: keys.publicKey
          .export({ type: "spki", format: "der" })
          .toString("base64"),
        FLEET_SIGNED_CONFIG:
          "base64:" +
          Buffer.from(
            JSON.stringify({
              payload,
              signature: sign(
                null,
                canonicalFleetConfigPayload(payload),
                keys.privateKey,
              ).toString("base64"),
            }),
          ).toString("base64"),
      },
      dstack,
      requestFetch,
    );
    expect(runtime.controller.paused()).toBe(true);
    const response = await fetch(
      `http://127.0.0.1:${env.FLEET_ADMIN_PORT}/fleet/v1/activate`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${env.FLEET_CONTROLLER_ADMIN_TOKEN}`,
        },
        body: "{}",
      },
    );
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      success: true,
      paused: false,
    });
    expect(runtime.controller.paused()).toBe(false);
    expect(requestFetch).not.toHaveBeenCalled();
  } finally {
    await runtime?.close();
    await rm(path, { recursive: true, force: true });
  }
});

it("keeps imported approved owners paused on partial enrollment and reconciles a later epoch at quiesce without MCP activity", async () => {
  const path = await mkdtemp(join(tmpdir(), "central-imported-membership-"));
  const dstack = createFakeDstackClient({ appId: "1".repeat(40) });
  const info = await dstack.info();
  const keys = generateKeyPairSync("ed25519");
  const env = {
    CHAIN_ID: "14800",
    CONTROLLER_TERM: "1",
    NODE_ID: "controller",
    GATEWAY_URL: "https://gateway.invalid",
    FLEET_STATE_PATH: join(path, "placements.json"),
    FLEET_WORKERS_JSON: "[]",
    FLEET_GATEWAY_TOKEN: "g".repeat(32),
    FLEET_CONTROLLER_ADMIN_TOKEN: "a".repeat(32),
    FLEET_CONTROLLER_GATEWAY_TOKEN: "r".repeat(32),
    FLEET_CONTROL_HOST: "127.0.0.1",
    FLEET_ADMIN_HOST: "127.0.0.1",
    FLEET_PEER_HOST: "127.0.0.1",
    FLEET_CONTROL_PORT: await freePort(),
    FLEET_ADMIN_PORT: await freePort(),
    FLEET_PEER_PORT: await freePort(),
    MCP_PUBLIC_ORIGIN: "https://mcp-dev.vana.org",
    MCP_APPROVAL_URL: "https://web.invalid/approve",
    MCP_STATE_PATH: join(path, "mcp.sealed"),
    MCP_INGRESS_HOST: "127.0.0.1",
    MCP_INGRESS_PORT: await freePort(),
    MCP_REDIRECT_URIS: '["https://claude.ai/api/mcp/auth_callback"]',
    MCP_MIGRATION_REQUIRED: "1",
  };
  const payload: FleetSecurityConfigPayload = {
    version: 1,
    purpose: "vana.fleet.security-config",
    role: "controller",
    appId: info.appId,
    instanceId: info.instanceId,
    nodeId: env.NODE_ID,
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    env,
  };

  const owners = [
    "0x1111111111111111111111111111111111111111",
    "0x2222222222222222222222222222222222222222",
  ] as const;
  const ids = owners.map((owner) => userPsId(14800, owner));
  const source = await openMcpDurableState({
    path: join(path, "source.sealed"),
    key: randomBytes(32),
  });
  for (const owner of owners) {
    const connection = await createMcpConnection(
      { displayName: "imported approved owner" },
      { store: source.connections, publicOrigin: env.MCP_PUBLIC_ORIGIN },
    );
    await source.bindOwner(connection.connectionId, { owner, chainId: 14800 });
    await source.connections.update(connection.connectionId, {
      status: "approved",
    });
  }
  const derived = await dstack.deriveKey(
    "mcp/ingress/state/v1",
    "vana.mcp.ingress.state.v1",
  );
  const snapshot = await source.fenceAndExport(
    "membership-import-1",
    "central",
  );
  try {
    const target = await openMcpDurableState({
      path: env.MCP_STATE_PATH,
      key: derived.key,
    });
    await target.importSnapshot(snapshot, "membership-import-1");
  } finally {
    derived.key.fill(0);
    snapshot.fill(0);
  }
  let secondOwnerUnavailable = true;
  let firstOwnerEpoch = 1;
  let identityGate: Promise<void> | undefined;
  let identityLookupStarted: (() => void) | undefined;
  const enrollments: FleetOwner[] = [];
  const requestFetch = vi.fn<typeof fetch>(async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.pathname === "/v1/identity") {
      identityLookupStarted?.();
      await identityGate;
      const owner = url.searchParams.get("owner");
      if (owner !== owners[0] && owner !== owners[1])
        throw new Error("Unexpected owner");
      return Response.json({
        state: "sealed",
        sealed: true,
        identity: {
          userPsId: userPsId(14800, owner),
          ownerAddress: owner,
          chainId: 14800,
          epoch: owner === owners[0] ? firstOwnerEpoch : 1,
        },
      });
    }
    if (
      url.pathname === "/v1/fleet" &&
      url.searchParams.get("action") === "enroll"
    ) {
      expect(new Headers(init?.headers).get("authorization")).toBe(
        `Bearer ${env.FLEET_CONTROLLER_GATEWAY_TOKEN}`,
      );
      const owner = JSON.parse(String(init?.body)) as FleetOwner;
      enrollments.push(owner);
      if (secondOwnerUnavailable && enrollments.length === 2)
        return Response.json(
          { error: "temporarily_unavailable" },
          { status: 503 },
        );
      return Response.json({ success: true });
    }
    throw new Error("Unexpected Gateway allocation or data request");
  });
  let runtime: Awaited<ReturnType<typeof startFleetCentral>> | undefined;
  try {
    runtime = await startFleetCentral(
      {
        FLEET_CONFIG_PUBLIC_KEY: keys.publicKey
          .export({ type: "spki", format: "der" })
          .toString("base64"),
        FLEET_SIGNED_CONFIG:
          "base64:" +
          Buffer.from(
            JSON.stringify({
              payload,
              signature: sign(
                null,
                canonicalFleetConfigPayload(payload),
                keys.privateKey,
              ).toString("base64"),
            }),
          ).toString("base64"),
      },
      dstack,
      requestFetch,
    );
    const admin = (route: string) =>
      fetch(`http://127.0.0.1:${env.FLEET_ADMIN_PORT}/fleet/v1/${route}`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${env.FLEET_CONTROLLER_ADMIN_TOKEN}`,
        },
        body: "{}",
      });
    expect(requestFetch).not.toHaveBeenCalled();
    expect((await admin("activate")).status).toBe(503);
    expect(runtime.controller.paused()).toBe(true);
    expect(runtime.controller.snapshot()).toHaveLength(2);
    const firstEnrolledId = enrollments[0]!.userPsId;
    const retryOwnerId = enrollments[1]!.userPsId;
    expect(
      runtime.controller
        .snapshot()
        .every((row) => row.assignment === null && row.generation === 0),
    ).toBe(true);
    expect(
      runtime.controller
        .snapshot()
        .find((row) => row.owner.userPsId === firstEnrolledId)?.enrolled,
    ).toBe(true);
    expect(
      runtime.controller
        .snapshot()
        .find((row) => row.owner.userPsId === retryOwnerId)?.enrolled,
    ).not.toBe(true);
    expect(enrollments).toHaveLength(2);

    secondOwnerUnavailable = false;
    expect((await admin("activate")).status).toBe(200);
    expect(runtime.controller.paused()).toBe(false);
    expect(
      runtime.controller
        .snapshot()
        .every((row) => row.enrolled && row.assignment === null),
    ).toBe(true);
    expect(
      enrollments.filter((owner) => owner.userPsId === firstEnrolledId),
    ).toHaveLength(1);
    expect(
      enrollments.filter((owner) => owner.userPsId === retryOwnerId),
    ).toHaveLength(2);

    firstOwnerEpoch = 2;
    let releaseIdentity!: () => void;
    identityGate = new Promise<void>((resolve) => {
      releaseIdentity = resolve;
    });
    const lookupStarted = new Promise<void>((resolve) => {
      identityLookupStarted = resolve;
    });
    const nodes = vi.spyOn(runtime.controller, "nodeStatus").mockReturnValue([
      {
        nodeId: "worker-being-drained",
        nodeIncarnation: "incarnation",
        capacity: 1,
        draining: false,
        unavailable: false,
      },
    ]);
    const drain = vi.spyOn(runtime.controller, "drain").mockResolvedValue();
    const quiescing = admin("quiesce");
    let quiesceResponse: Response | undefined;
    try {
      await lookupStarted;
      expect(runtime.controller.paused()).toBe(true);
      expect(drain).toHaveBeenCalledWith("worker-being-drained");
    } finally {
      releaseIdentity();
      quiesceResponse = await quiescing;
      nodes.mockRestore();
      drain.mockRestore();
    }
    expect(quiesceResponse.status).toBe(200);
    expect(runtime.controller.paused()).toBe(true);
    expect(runtime.controller.snapshot()).toHaveLength(3);
    expect(
      runtime.controller
        .snapshot()
        .find(
          (row) =>
            row.owner.userPsId === ids[0] && row.owner.identityEpoch === 2,
        ),
    ).toMatchObject({ enrolled: true, generation: 0, assignment: null });
    expect(
      runtime.controller.snapshot().every((row) => row.assignment === null),
    ).toBe(true);
    expect(enrollments.at(-1)).toEqual({
      chainId: 14800,
      userPsId: ids[0],
      identityEpoch: 2,
    });
    expect(runtime.controller.nodeStatus()).toEqual([]);
  } finally {
    await runtime?.close();
    await rm(path, { recursive: true, force: true });
  }
});

const CONTROLLER_APP_ID = "1".repeat(40);
const CONTROLLER_NODE_ID = "controller";
const ADMIN_TOKEN = "a".repeat(32);
const GATEWAY_TOKEN = "g".repeat(32);
const REVERSE_TOKEN = "r".repeat(32);
const WARM_POOL_CAP = 4;

/** A directory entry whose HTTPS peer is deliberately unreachable in unit tests. */
function workerEntry(index: number, capacity = 1) {
  const hex = index.toString(16);
  return {
    url: `https://worker-${index}.invalid`,
    capacity,
    policy: {
      identity: {
        role: "worker" as const,
        nodeId: `worker-${index}`,
        appId: hex.repeat(40),
        instanceId: hex.repeat(40),
        composeHash: hex.repeat(64),
      },
      mrTd: "0".repeat(96),
      rtmrs: ["0", "1", "2", "3"].map((c) => c.repeat(96)) as [
        string,
        string,
        string,
        string,
      ],
    },
  };
}

async function controllerEnv(
  path: string,
  workers: ReturnType<typeof workerEntry>[],
): Promise<Record<string, string>> {
  return {
    CHAIN_ID: "14800",
    CONTROLLER_TERM: "1",
    NODE_ID: CONTROLLER_NODE_ID,
    GATEWAY_URL: "https://gateway.invalid",
    FLEET_STATE_PATH: join(path, "placements.json"),
    FLEET_WORKERS_JSON: JSON.stringify(workers),
    FLEET_GATEWAY_TOKEN: GATEWAY_TOKEN,
    FLEET_CONTROLLER_ADMIN_TOKEN: ADMIN_TOKEN,
    FLEET_CONTROLLER_GATEWAY_TOKEN: REVERSE_TOKEN,
    FLEET_CONTROL_HOST: "127.0.0.1",
    FLEET_ADMIN_HOST: "127.0.0.1",
    FLEET_PEER_HOST: "127.0.0.1",
    FLEET_CONTROL_PORT: await freePort(),
    FLEET_ADMIN_PORT: await freePort(),
    FLEET_PEER_PORT: await freePort(),
    MCP_PUBLIC_ORIGIN: "https://mcp-dev.vana.org",
    MCP_APPROVAL_URL: "https://web.invalid/approve",
    MCP_STATE_PATH: join(path, "mcp.sealed"),
    MCP_INGRESS_HOST: "127.0.0.1",
    MCP_INGRESS_PORT: await freePort(),
    MCP_REDIRECT_URIS: '["https://claude.ai/api/mcp/auth_callback"]',
    MCP_MIGRATION_REQUIRED: "0",
  };
}

function signedConfig(
  env: Record<string, string>,
  info: { appId: string; instanceId: string },
  keys: ReturnType<typeof generateKeyPairSync<"ed25519">>,
  expiresAt: string | null = new Date(Date.now() + 60_000).toISOString(),
): Record<string, string> {
  const payload: FleetSecurityConfigPayload = {
    version: 1,
    purpose: "vana.fleet.security-config",
    role: "controller",
    appId: info.appId,
    instanceId: info.instanceId,
    nodeId: env.NODE_ID!,
    issuedAt: new Date().toISOString(),
    expiresAt,
    env,
  };
  return {
    FLEET_CONFIG_PUBLIC_KEY: keys.publicKey
      .export({ type: "spki", format: "der" })
      .toString("base64"),
    FLEET_SIGNED_CONFIG:
      "base64:" +
      Buffer.from(
        JSON.stringify({
          payload,
          signature: sign(
            null,
            canonicalFleetConfigPayload(payload),
            keys.privateKey,
          ).toString("base64"),
        }),
      ).toString("base64"),
  };
}

it("accepts a full warm pool and refuses one member beyond the cap", async () => {
  const path = await mkdtemp(join(tmpdir(), "central-pool-cap-"));
  const dstack = createFakeDstackClient({ appId: CONTROLLER_APP_ID });
  const info = await dstack.info();
  const keys = generateKeyPairSync("ed25519");
  const members = Array.from({ length: WARM_POOL_CAP + 1 }, (_, index) =>
    workerEntry(index + 2),
  );
  const unreachable = vi.fn<typeof fetch>(async () => {
    throw new Error("Worker is stopped");
  });
  let runtime: Awaited<ReturnType<typeof startFleetCentral>> | undefined;
  try {
    const full = await controllerEnv(path, members.slice(0, WARM_POOL_CAP));
    runtime = await startFleetCentral(
      signedConfig(full, info, keys),
      dstack,
      unreachable,
    );
    expect(runtime.controller.paused()).toBe(true);

    const oversized = await controllerEnv(path, members);
    await expect(
      startFleetCentral(signedConfig(oversized, info, keys), dstack, () => {
        throw new Error("Must not reach a worker");
      }),
    ).rejects.toThrow(`Configure zero to ${WARM_POOL_CAP}`);
  } finally {
    await runtime?.close();
    await rm(path, { recursive: true, force: true });
  }
});

const ADMISSION_TICK_MS = 30_000;

interface LogEntry {
  level: string;
  message: string;
  nodeId?: string;
  code?: string;
  attempts?: number;
}

function logEntries(
  spy: { mock: { calls: unknown[][] } },
  level: string,
): LogEntry[] {
  return spy.mock.calls
    .map(([entry]) => entry as LogEntry)
    .filter((entry) => entry.level === level);
}

it("keeps stopped members visible and warns once per admission failure code", async () => {
  const path = await mkdtemp(join(tmpdir(), "central-declare-"));
  const dstack = createFakeDstackClient({ appId: CONTROLLER_APP_ID });
  const info = await dstack.info();
  const keys = generateKeyPairSync("ed25519");
  const env = await controllerEnv(path, [workerEntry(2), workerEntry(3)]);
  const logs = vi.spyOn(console, "error").mockImplementation(() => undefined);
  let refusal = new Error("Worker is stopped");
  vi.useFakeTimers({ shouldAdvanceTime: true });
  let runtime: Awaited<ReturnType<typeof startFleetCentral>> | undefined;
  try {
    runtime = await startFleetCentral(
      signedConfig(env, info, keys),
      dstack,
      () => Promise.reject(refusal),
    );
    await vi.advanceTimersByTimeAsync(3 * ADMISSION_TICK_MS);

    expect(runtime.controller.nodeStatus()).toEqual(
      ["worker-2", "worker-3"].map((nodeId) => ({
        nodeId,
        nodeIncarnation: "",
        capacity: 1,
        draining: false,
        unavailable: true,
      })),
    );
    // One warn per member for the first code; every repeat drops to debug.
    expect(
      logEntries(logs, "warn").map(({ nodeId, code, attempts }) => ({
        nodeId,
        code,
        attempts,
      })),
    ).toEqual([
      { nodeId: "worker-2", code: "UNAVAILABLE", attempts: 1 },
      { nodeId: "worker-3", code: "UNAVAILABLE", attempts: 1 },
    ]);
    expect(logEntries(logs, "debug").length).toBeGreaterThanOrEqual(6);

    refusal = new Error("Peer runtime events rejected");
    await vi.advanceTimersByTimeAsync(ADMISSION_TICK_MS);
    expect(logEntries(logs, "warn").map((entry) => entry.code)).toEqual([
      "UNAVAILABLE",
      "UNAVAILABLE",
      "PEER_EVENTS_REJECTED",
      "PEER_EVENTS_REJECTED",
    ]);
  } finally {
    vi.useRealTimers();
    logs.mockRestore();
    await runtime?.close();
    await rm(path, { recursive: true, force: true });
  }
});

it("publishes the controller bundle window and identity on admin status", async () => {
  const path = await mkdtemp(join(tmpdir(), "central-status-config-"));
  const dstack = createFakeDstackClient({ appId: CONTROLLER_APP_ID });
  const info = await dstack.info();
  const keys = generateKeyPairSync("ed25519");
  const env = await controllerEnv(path, []);
  let runtime: Awaited<ReturnType<typeof startFleetCentral>> | undefined;
  try {
    runtime = await startFleetCentral(
      signedConfig(env, info, keys, null),
      dstack,
      () => {
        throw new Error("Must not call Gateway while staged");
      },
    );
    const response = await fetch(
      `http://127.0.0.1:${env.FLEET_ADMIN_PORT}/fleet/v1/status`,
      {
        method: "POST",
        headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
        body: "{}",
      },
    );
    const text = await response.text();

    expect((JSON.parse(text) as { config: unknown }).config).toEqual({
      issuedAt: expect.any(String),
      expiresAt: null,
      composeHash: info.composeHash,
      appId: info.appId,
      instanceId: info.instanceId,
    });
    expect(text).toContain('"expiresAt":null');
    expect(text).not.toContain(ADMIN_TOKEN);
  } finally {
    await runtime?.close();
    await rm(path, { recursive: true, force: true });
  }
});
