import {
  generateKeyPairSync,
  randomBytes,
  sign,
  type KeyObject,
} from "node:crypto";
import {
  canonicalFleetConfigPayload,
  type FleetSecurityConfigPayload,
} from "../fleet/security-config.js";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import * as fs from "node:fs/promises";
import * as mcpService from "../mcp/service.js";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { createFakeDstackClient } from "../dstack/fake.js";
import { closeFleetListeners, startFleetCentral } from "./bootstrap.js";
import { MAINNET_CHAIN_ID, MAINNET_GATEWAY_ORIGIN } from "../chain-id.js";
import { createMcpConnection } from "@opendatalabs/personal-server-ts-core/mcp";
import { openMcpDurableState } from "@opendatalabs/personal-server-ts-server/mcp/tee";
import { userPsId } from "@opendatalabs/vana-sdk/protocol/identity";
import type { FleetOwner, FleetWorkerPort } from "../fleet/contracts.js";

vi.mock("node:fs/promises", { spy: true });

it("still closes fleet listeners when MCP cleanup fails, preserving the MCP error", async () => {
  const calls: string[] = [];
  const primary = new Error("synthetic MCP close error");
  const secondary = new Error("synthetic listener close error");
  await expect(
    closeFleetListeners(
      async () => {
        calls.push("mcp");
        throw primary;
      },
      async () => {
        calls.push("listeners");
        throw secondary;
      },
    ),
  ).rejects.toBe(primary);
  expect(calls).toEqual(["mcp", "listeners"]);
});

it("surfaces a listener close error when MCP cleanup succeeds", async () => {
  const secondary = new Error("synthetic listener close error");
  await expect(
    closeFleetListeners(
      async () => {},
      async () => {
        throw secondary;
      },
    ),
  ).rejects.toBe(secondary);
});

it("waits for MCP shutdown to settle before closing the fleet listeners", async () => {
  const calls: string[] = [];
  let release!: () => void;
  const pending = new Promise<void>((resolve) => {
    release = resolve;
  });
  const closed = closeFleetListeners(
    async () => {
      calls.push("mcp started");
      await pending;
      calls.push("mcp closed");
    },
    async () => {
      calls.push("listeners closed");
    },
  );
  try {
    await Promise.resolve();
    expect(calls).toEqual(["mcp started"]);
  } finally {
    release();
    await closed;
  }
  expect(calls).toEqual(["mcp started", "mcp closed", "listeners closed"]);
});

it("still closes the fleet listeners after a synchronous MCP cleanup throw", async () => {
  const calls: string[] = [];
  const failure = new Error("synchronous MCP close failure");
  await expect(
    closeFleetListeners(
      () => {
        calls.push("mcp");
        throw failure;
      },
      async () => {
        calls.push("listeners");
      },
    ),
  ).rejects.toBe(failure);
  expect(calls).toEqual(["mcp", "listeners"]);
});

it("does not report a failed MCP shutdown before the listener cleanup settles", async () => {
  const primary = new Error("synthetic MCP shutdown failure");
  let enter!: () => void;
  let release!: () => void;
  const entered = new Promise<void>((resolve) => { enter = resolve; });
  const hold = new Promise<void>((resolve) => { release = resolve; });
  let reported = false;
  const closing = closeFleetListeners(
    async () => { throw primary; },
    async () => { enter(); await hold; },
  ).catch((error: unknown) => { reported = true; throw error; });
  const outcome = expect(closing).rejects.toBe(primary);
  try {
    await entered;
    expect(reported).toBe(false);
  } finally {
    release();
    await outcome;
  }
});

it("surfaces a synchronous listener close error after MCP shutdown succeeds", async () => {
  const failure = new Error("synthetic listener close throw");
  const states: string[] = [];
  await expect(closeFleetListeners(
    async () => { states.push("mcp closed"); },
    () => { states.push("listener close attempted"); throw failure; },
  )).rejects.toBe(failure);
  expect(states).toEqual(["mcp closed", "listener close attempted"]);
});

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
        FLEET_CONTROL_PORT: "0",
        FLEET_ADMIN_PORT: "0",
        FLEET_PEER_PORT: "0",
        MCP_PUBLIC_ORIGIN: "https://mcp-dev.vana.org",
        MCP_APPROVAL_URL: "https://web.invalid/approve",
        MCP_STATE_PATH: join(path, "mcp.sealed"),
        MCP_INGRESS_HOST: "127.0.0.1",
        MCP_INGRESS_PORT: "0",
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
    FLEET_CONTROL_PORT: "0",
    FLEET_ADMIN_PORT: "0",
    FLEET_PEER_PORT: "0",
    MCP_PUBLIC_ORIGIN: "https://mcp-dev.vana.org",
    MCP_APPROVAL_URL: "https://web.invalid/approve",
    MCP_STATE_PATH: join(path, "mcp.sealed"),
    MCP_INGRESS_HOST: "127.0.0.1",
    MCP_INGRESS_PORT: "0",
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
    expect(Object.keys(runtime.ports).sort()).toEqual([
      "admin",
      "control",
      "mcp",
      "peer",
    ]);
    expect(new Set(Object.values(runtime.ports)).size).toBe(4);
    for (const port of Object.values(runtime.ports)) {
      expect(Number.isInteger(port)).toBe(true);
      expect(port).toBeGreaterThan(0);
      expect(port).toBeLessThanOrEqual(65535);
    }
    // An unestablished session must reach the peer listener, not merely a
    // plausible reported port or another central HTTP service.
    const peerResponse = await fetch(
      `http://127.0.0.1:${runtime.ports.peer}/fleet-peer/v1/call`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sessionId: "unestablished-test-session" }),
      },
    );
    expect(peerResponse.status).toBe(403);
    await expect(peerResponse.json()).resolves.toEqual({
      error: "peer_request_rejected",
    });
    const mcpResponse = await fetch(`http://127.0.0.1:${runtime.ports.mcp}/`);
    expect(mcpResponse.status).toBe(503);
    await expect(mcpResponse.json()).resolves.toEqual({
      error: "MCP migration pending",
    });
    expect(runtime.identity.nodeId).toBe("controller");
    expect(runtime.controller.paused()).toBe(true);
    expect(runtime.controller.nodeStatus()).toEqual([]);
    const request = (port: number, route: string, token: string) =>
      fetch(`http://127.0.0.1:${port}/fleet/v1/${route}`, {
        method: "POST",
        headers: { authorization: `Bearer ${token}` },
        body: "{}",
      });
    expect(
      (
        await request(
          runtime!.ports.admin,
          "status",
          env.FLEET_CONTROLLER_ADMIN_TOKEN,
        )
      ).status,
    ).toBe(200);
    expect(
      (await request(runtime!.ports.admin, "status", "attacker".repeat(10)))
        .status,
    ).toBe(401);
    expect(
      (
        await request(
          runtime!.ports.admin,
          "activate",
          env.FLEET_CONTROLLER_ADMIN_TOKEN,
        )
      ).status,
    ).toBe(503);
    expect(
      (await request(runtime!.ports.control, "ensure", env.FLEET_GATEWAY_TOKEN))
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
    FLEET_CONTROL_PORT: "0",
    FLEET_ADMIN_PORT: "0",
    FLEET_PEER_PORT: "0",
    MCP_PUBLIC_ORIGIN: "https://mcp-dev.vana.org",
    MCP_APPROVAL_URL: "https://web.invalid/approve",
    MCP_STATE_PATH: join(path, "mcp.sealed"),
    MCP_INGRESS_HOST: "127.0.0.1",
    MCP_INGRESS_PORT: "0",
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
      `http://127.0.0.1:${runtime!.ports.admin}/fleet/v1/activate`,
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
    FLEET_CONTROL_PORT: "0",
    FLEET_ADMIN_PORT: "0",
    FLEET_PEER_PORT: "0",
    MCP_PUBLIC_ORIGIN: "https://mcp-dev.vana.org",
    MCP_APPROVAL_URL: "https://web.invalid/approve",
    MCP_STATE_PATH: join(path, "mcp.sealed"),
    MCP_INGRESS_HOST: "127.0.0.1",
    MCP_INGRESS_PORT: "0",
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
    const admin = (route: string, body: unknown = {}) =>
      fetch(`http://127.0.0.1:${runtime!.ports.admin}/fleet/v1/${route}`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${env.FLEET_CONTROLLER_ADMIN_TOKEN}`,
        },
        body: JSON.stringify(body),
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

    // Directory maintenance must not enumerate approved owners or reconcile a
    // newly advanced epoch; ordinary migration quiesce below still must.
    firstOwnerEpoch = 2;
    requestFetch.mockClear();
    const enrolledBeforeMaintenance = structuredClone(enrollments);
    const rowsBeforeMaintenance = runtime.controller.snapshot();
    expect(
      (
        await admin("quiesce", {
          mode: "maintenance",
          maintenanceId: "directory-roll-1",
        })
      ).status,
    ).toBe(200);
    expect(runtime.controller.paused()).toBe(true);
    expect(
      (
        await admin("activate", {
          mode: "maintenance",
          maintenanceId: "wrong-roll-id",
        })
      ).status,
    ).toBe(503);
    expect(runtime.controller.paused()).toBe(true);
    expect(
      (
        await admin("activate", {
          mode: "maintenance",
          maintenanceId: "directory-roll-1",
        })
      ).status,
    ).toBe(200);
    expect(runtime.controller.paused()).toBe(false);
    expect(requestFetch).not.toHaveBeenCalled();
    expect(enrollments).toEqual(enrolledBeforeMaintenance);
    expect(runtime.controller.snapshot()).toEqual(rowsBeforeMaintenance);
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
        live: 0,
        draining: false,
        unavailable: false,
      },
    ]);
    const drain = vi.spyOn(runtime.controller, "drain").mockResolvedValue();
    const quiescing = admin("quiesce");
    let queuedActivation: Promise<Response> | undefined;
    let queuedActivationSettled = false;
    let quiesceResponse: Response | undefined;
    try {
      await lookupStarted;
      queuedActivation = admin("activate", {
        mode: "maintenance",
        maintenanceId: "directory-roll-1",
      }).then((response) => {
        queuedActivationSettled = true;
        return response;
      });
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(queuedActivationSettled).toBe(false);
      expect(runtime.controller.paused()).toBe(true);
      expect(drain).toHaveBeenCalledWith("worker-being-drained");
    } finally {
      releaseIdentity();
      quiesceResponse = await quiescing;
      nodes.mockRestore();
      drain.mockRestore();
    }
    expect(quiesceResponse.status).toBe(200);
    expect((await queuedActivation)?.status).toBe(503);
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
    FLEET_CONTROL_PORT: "0",
    FLEET_ADMIN_PORT: "0",
    FLEET_PEER_PORT: "0",
    MCP_PUBLIC_ORIGIN: "https://mcp-dev.vana.org",
    MCP_APPROVAL_URL: "https://web.invalid/approve",
    MCP_STATE_PATH: join(path, "mcp.sealed"),
    MCP_INGRESS_HOST: "127.0.0.1",
    MCP_INGRESS_PORT: "0",
    MCP_REDIRECT_URIS: '["https://claude.ai/api/mcp/auth_callback"]',
    MCP_MIGRATION_REQUIRED: "0",
  };
}

function signedConfig(
  env: Record<string, string>,
  info: { appId: string; instanceId: string },
  keys: { publicKey: KeyObject; privateKey: KeyObject },
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
        live: 0,
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

    refusal = new Error("Peer runtime events rejected");
    await vi.advanceTimersByTimeAsync(ADMISSION_TICK_MS);
    expect(logEntries(logs, "warn").map((entry) => entry.code)).toEqual([
      "UNAVAILABLE",
      "UNAVAILABLE",
      "PEER_EVENTS_REJECTED",
      "PEER_EVENTS_REJECTED",
    ]);

    const status = (await (
      await fetch(`http://127.0.0.1:${runtime!.ports.admin}/fleet/v1/status`, {
        method: "POST",
        headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
        body: "{}",
      })
    ).json()) as { nodes: { nodeId: string; lastAdmission: unknown }[] };
    expect(status.nodes.map((node) => node.lastAdmission)).toEqual([
      { code: "PEER_EVENTS_REJECTED", since: expect.any(String), attempts: 1 },
      { code: "PEER_EVENTS_REJECTED", since: expect.any(String), attempts: 1 },
    ]);

    // A member that was admitted and has since stopped answering must be
    // demoted by the next re-attest tick; nothing else takes its slots away.
    const worker: FleetWorkerPort = {
      activity: vi.fn(),
      prepare: vi.fn(async () => []),
      readiness: vi.fn(async () => []),
      renew: vi.fn(),
      execute: vi.fn(),
      release: vi.fn(),
    };
    await runtime.controller.admit({
      nodeId: "worker-2",
      nodeIncarnation: "i1",
      capacity: 1,
      worker,
    });
    expect(runtime.controller.nodeStatus()[0]).toMatchObject({
      unavailable: false,
    });

    await vi.advanceTimersByTimeAsync(ADMISSION_TICK_MS);

    expect(runtime.controller.nodeStatus()[0]).toMatchObject({
      unavailable: true,
    });
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
      `http://127.0.0.1:${runtime!.ports.admin}/fleet/v1/status`,
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

it("boots a controller whose signed config names mainnet", async () => {
  const path = await mkdtemp(join(tmpdir(), "central-mainnet-"));
  const dstack = createFakeDstackClient({ appId: "1".repeat(40) });
  const info = await dstack.info();
  const keys = generateKeyPairSync("ed25519");
  const env = {
    CHAIN_ID: String(MAINNET_CHAIN_ID),
    CONTROLLER_TERM: "1",
    NODE_ID: "controller",
    GATEWAY_URL: MAINNET_GATEWAY_ORIGIN,
    FLEET_STATE_PATH: join(path, "placements.json"),
    FLEET_WORKERS_JSON: "[]",
    FLEET_GATEWAY_TOKEN: "g".repeat(32),
    FLEET_CONTROLLER_ADMIN_TOKEN: "a".repeat(32),
    FLEET_CONTROLLER_GATEWAY_TOKEN: "r".repeat(32),
    FLEET_CONTROL_HOST: "127.0.0.1",
    FLEET_ADMIN_HOST: "127.0.0.1",
    FLEET_PEER_HOST: "127.0.0.1",
    FLEET_CONTROL_PORT: "0",
    FLEET_ADMIN_PORT: "0",
    FLEET_PEER_PORT: "0",
    MCP_PUBLIC_ORIGIN: "https://mcp.invalid",
    MCP_APPROVAL_URL: "https://web.invalid/approve",
    MCP_STATE_PATH: join(path, "mcp.sealed"),
    MCP_INGRESS_HOST: "127.0.0.1",
    MCP_INGRESS_PORT: "0",
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
    expiresAt: null,
    env,
  };
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
      vi.fn<typeof fetch>(async () => {
        throw new Error("Must not call Gateway while staged");
      }),
    );

    expect(runtime.identity.nodeId).toBe("controller");
    expect(runtime.controller.paused()).toBe(true);
  } finally {
    await runtime?.close();
    await rm(path, { recursive: true, force: true });
  }
});

it("close drains pending admission before closing services or returning state ownership", async () => {
  const path = await mkdtemp(join(tmpdir(), "central-close-admission-"));
  const dstack = createFakeDstackClient({ appId: CONTROLLER_APP_ID });
  const info = await dstack.info();
  const keys = generateKeyPairSync("ed25519");
  const env = await controllerEnv(path, [workerEntry(2)]);
  let release!: (value: Response) => void;
  let entered!: () => void;
  const admission = new Promise<Response>((resolve) => {
    release = resolve;
  });
  const started = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const requestFetch = vi.fn<typeof fetch>(() => {
    entered();
    return admission;
  });
  const serviceClose = vi.fn();
  const originalStart = mcpService.startMcpRouter;
  const start = vi
    .spyOn(mcpService, "startMcpRouter")
    .mockImplementation(async (...args) => {
      const service = await originalStart(...args);
      if (!service) return service;
      const close = service.close.bind(service);
      return {
        ...service,
        close: async () => {
          serviceClose();
          await close();
        },
      };
    });
  const open = vi.spyOn(fs, "open");
  const mkdir = vi.spyOn(fs, "mkdir");
  // Hold the real markUnavailable persistence at its atomic-rename boundary.
  // Earlier declaration/admission writes must finish normally.
  let holdPersistence = false;
  let persistenceEntered!: () => void;
  let releasePersistence!: () => void;
  const persistenceStarted = new Promise<void>((resolve) => {
    persistenceEntered = resolve;
  });
  const persistence = new Promise<void>((resolve) => {
    releasePersistence = resolve;
  });
  const { rename: originalRename } =
    await vi.importActual<typeof fs>("node:fs/promises");
  const rename = vi.spyOn(fs, "rename").mockImplementation(async (...args) => {
    if (holdPersistence && args[1] === env.FLEET_STATE_PATH) {
      persistenceEntered();
      await persistence;
    }
    return originalRename(...args);
  });
  const logs = vi.spyOn(console, "error").mockImplementation(() => undefined);
  let runtime: Awaited<ReturnType<typeof startFleetCentral>> | undefined;
  let closing: Promise<void> | undefined;
  try {
    runtime = await startFleetCentral(
      signedConfig(env, info, keys),
      dstack,
      requestFetch,
    );
    await started;
    // Initial declaration is already unavailable. Make the pending failure
    // perform a real persisted transition, not an idempotent no-op.
    await runtime.controller.admit({
      nodeId: "worker-2",
      nodeIncarnation: "i1",
      capacity: 1,
      worker: {
        activity: vi.fn(),
        prepare: vi.fn(async () => []),
        readiness: vi.fn(async () => []),
        renew: vi.fn(),
        execute: vi.fn(),
        release: vi.fn(),
      },
    });
    let resolved = false;
    closing = runtime.close().then(() => {
      resolved = true;
    });
    await Promise.resolve();
    expect(resolved).toBe(false);
    // Decisive mutation oracle: without the in-flight await, close invokes
    // mcp.close synchronously even though admission is still held.
    expect(serviceClose).not.toHaveBeenCalled();
    holdPersistence = true;
    release(new Response("admission refused", { status: 503 }));
    await persistenceStarted;
    // Admission has now failed and markUnavailable has written its temporary
    // file, but the new directory snapshot has not been renamed into place.
    expect(resolved).toBe(false);
    expect(serviceClose).not.toHaveBeenCalled();
    expect(
      JSON.parse(await readFile(env.FLEET_STATE_PATH!, "utf8")).nodes[
        "worker-2"
      ].unavailable,
    ).toBe(false);
    releasePersistence();
    await closing;
    expect(resolved).toBe(true);
    expect(serviceClose).toHaveBeenCalledTimes(1);
    expect(runtime.controller.nodeStatus()[0]).toMatchObject({
      unavailable: true,
    });
    const persisted = await readFile(env.FLEET_STATE_PATH!, "utf8");
    expect(JSON.parse(persisted).nodes["worker-2"].unavailable).toBe(true);
    const writes = [
      open.mock.calls.length,
      mkdir.mock.calls.length,
      rename.mock.calls.length,
    ];
    // Cross an event-loop turn, not a delay, after all controlled work settled.
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect([
      open.mock.calls.length,
      mkdir.mock.calls.length,
      rename.mock.calls.length,
    ]).toEqual(writes);
    expect(await readFile(env.FLEET_STATE_PATH!, "utf8")).toBe(persisted);
  } finally {
    release(new Response("admission refused", { status: 503 }));
    releasePersistence();
    if (closing) await closing;
    else await runtime?.close();
    start.mockRestore();
    open.mockRestore();
    mkdir.mockRestore();
    rename.mockRestore();
    logs.mockRestore();
    await rm(path, { recursive: true, force: true });
  }
});

it("joins pending admission and its durable demotion before closing listeners", async () => {
  const path = await mkdtemp(join(tmpdir(), "central-close-admission-"));
  const dstack = createFakeDstackClient({ appId: CONTROLLER_APP_ID });
  const info = await dstack.info();
  const keys = generateKeyPairSync("ed25519");
  const env = await controllerEnv(path, [workerEntry(2)]);
  let rejectAdmission!: (reason: Error) => void;
  let admissionStarted!: () => void;
  const started = new Promise<void>((resolve) => {
    admissionStarted = resolve;
  });
  const admission = new Promise<Response>((_resolve, reject) => {
    rejectAdmission = reject;
  });
  const request = vi.fn<typeof fetch>(() => {
    admissionStarted();
    return admission;
  });
  const closeMcp = vi.fn();
  const startMcp = mcpService.startMcpRouter;
  const startSpy = vi
    .spyOn(mcpService, "startMcpRouter")
    .mockImplementation(async (...args) => {
      const router = await startMcp(...args);
      if (router) {
        const close = router.close.bind(router);
        vi.spyOn(router, "close").mockImplementation(async () => {
          closeMcp();
          await close();
        });
      }
      return router;
    });
  let runtime: Awaited<ReturnType<typeof startFleetCentral>> | undefined;
  let closing: Promise<void> | undefined;
  let closed = false;
  const writesAfterClose: boolean[] = [];
  try {
    runtime = await startFleetCentral(
      signedConfig(env, info, keys),
      dstack,
      request,
    );
    await started;
    // Declare starts unavailable. Make it available so the pending rejection
    // necessarily persists a demotion rather than taking the no-op branch.
    await runtime.controller.admit({
      nodeId: "worker-2",
      nodeIncarnation: "i1",
      capacity: 1,
      worker: {
        activity: vi.fn(),
        prepare: vi.fn(async () => []),
        readiness: vi.fn(async () => []),
        renew: vi.fn(),
        execute: vi.fn(),
        release: vi.fn(),
      },
    });
    const markUnavailable = runtime.controller.markUnavailable.bind(
      runtime.controller,
    );
    vi.spyOn(runtime.controller, "markUnavailable").mockImplementation(
      async (nodeId) => {
        await markUnavailable(nodeId); // includes the atomic snapshot write
        writesAfterClose.push(closed);
      },
    );
    closing = runtime.close().then(() => {
      closed = true;
    });
    expect(closed).toBe(false);
    // This boundary is synchronous without the in-flight await. Unlike a
    // timed wait for sockets, it reliably kills removal of that await.
    expect(closeMcp).not.toHaveBeenCalled();
    rejectAdmission(new Error("controlled admission refusal"));
    await closing;
    expect(closed).toBe(true);
    expect(closeMcp).toHaveBeenCalledTimes(1);
    expect(writesAfterClose).toEqual([false]);
    expect(runtime.controller.nodeStatus()[0]).toMatchObject({
      unavailable: true,
    });
    const { readFile, readdir } = await import("node:fs/promises");
    const persisted = JSON.parse(await readFile(env.FLEET_STATE_PATH!, "utf8"));
    expect(persisted.nodes["worker-2"].unavailable).toBe(true);
    expect(
      (await readdir(path)).filter((name) => name.endsWith(".tmp")),
    ).toEqual([]);
    await rm(path, { recursive: true, force: true });
    await expect(readdir(path)).rejects.toMatchObject({ code: "ENOENT" });
  } finally {
    rejectAdmission(new Error("test cleanup"));
    if (closing) await closing;
    else await runtime?.close();
    startSpy.mockRestore();
    await rm(path, { recursive: true, force: true });
  }
});

it("closes the fleet HTTP listeners even when MCP close rejects", async () => {
  const path = await mkdtemp(join(tmpdir(), "central-mcp-close-error-"));
  const dstack = createFakeDstackClient({ appId: CONTROLLER_APP_ID });
  const info = await dstack.info();
  const keys = generateKeyPairSync("ed25519");
  const env = await controllerEnv(path, []);
  const primary = new Error("synthetic MCP close failure");
  const startMcp = mcpService.startMcpRouter;
  let restoreMcp: (() => void) | undefined;
  const closeMcp = vi.fn();
  const startSpy = vi
    .spyOn(mcpService, "startMcpRouter")
    .mockImplementation(async (...args) => {
      const router = await startMcp(...args);
      if (router) {
        const close = router.close.bind(router);
        const intercepted = vi
          .spyOn(router, "close")
          .mockImplementation(async () => {
            closeMcp();
            await close();
            throw primary;
          });
        restoreMcp = () => intercepted.mockRestore();
      }
      return router;
    });
  let runtime: Awaited<ReturnType<typeof startFleetCentral>> | undefined;
  try {
    runtime = await startFleetCentral(
      signedConfig(env, info, keys),
      dstack,
      async () => {
        throw new Error("unexpected external request");
      },
    );
    expect(restoreMcp).toBeDefined();
    const { admin, control, peer } = runtime.ports;
    await expect(runtime.close()).rejects.toBe(primary);
    expect(closeMcp).toHaveBeenCalledTimes(1);
    for (const port of [admin, control, peer]) {
      await expect(
        fetch(`http://127.0.0.1:${port}/`, {
          signal: AbortSignal.timeout(1_000),
        }),
      ).rejects.toMatchObject({ cause: { code: "ECONNREFUSED" } });
    }
  } finally {
    restoreMcp?.();
    startSpy.mockRestore();
    await runtime?.close().catch(() => undefined);
    await rm(path, { recursive: true, force: true });
  }
});
