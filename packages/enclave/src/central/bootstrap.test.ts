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
