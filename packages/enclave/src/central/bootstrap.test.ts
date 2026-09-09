import { createServer } from "node:net";
import { generateKeyPairSync, sign } from "node:crypto";
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
        FLEET_SIGNED_CONFIG: JSON.stringify({
          payload,
          signature: sign(
            null,
            canonicalFleetConfigPayload(payload),
            keys.privateKey,
          ).toString("base64"),
        }),
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
