import { createServer } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { createMcpConnection } from "@opendatalabs/personal-server-ts-core/mcp";
import { DEFAULTS } from "@opendatalabs/personal-server-ts-core/schemas";
import type { McpDurableState } from "@opendatalabs/personal-server-ts-server/mcp/tee";
import { createFakeDstackClient } from "../dstack/fake.js";
import { startMcpRouter, type McpIngressControl } from "./service.js";
const directories: string[] = [];
const controls: McpIngressControl[] = [];
afterEach(async () => {
  await Promise.all(controls.splice(0).map((c) => c.close()));
  await Promise.all(
    directories.splice(0).map((p) => rm(p, { recursive: true, force: true })),
  );
});
async function freePort() {
  const server = createServer();
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("Expected TCP port");
  await new Promise<void>((r, j) => server.close((e) => (e ? j(e) : r())));
  return address.port;
}
it("returns a restart requirement on rollback and serves preserved state after the explicit source restart", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-service-migration-"));
  directories.push(directory);
  const sourcePort = await freePort(),
    targetPort = await freePort();
  const states = new Map<string, McpDurableState>();
  const start = async (
    name: string,
    port: number,
    appId: string,
    fleetEnabled = "true",
  ) => {
    const control = await startMcpRouter(
      {
        client: createFakeDstackClient({ appId }),
        gatewayUrl: "https://gateway.invalid",
        chainId: 14800,
        contracts: { ...DEFAULTS.gateway.contracts },
        logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
      },
      {
        FLEET_ENABLED: fleetEnabled,
        NODE_ID: "source",
        NODE_SECRET: "s".repeat(32),
        MCP_PUBLIC_ORIGIN: "https://mcp-dev.vana.org",
        MCP_APPROVAL_URL: "https://web.invalid/approve",
        MCP_STATE_PATH: join(directory, `${name}.sealed`),
        MCP_INGRESS_HOST: "127.0.0.1",
        MCP_INGRESS_PORT: String(port),
        MCP_REDIRECT_URIS: '["https://claude.ai/api/mcp/auth_callback"]',
      },
      fetch,
      (state) => {
        states.set(name, state);
        return {
          ownerReady: async () => true,
          dispatch: async () => Response.json({ ok: true }),
        };
      },
    );
    if (!control) throw new Error("Router disabled");
    controls.push(control);
    return control;
  };
  const source = await start("source", sourcePort, "1".repeat(40));
  const target = await start("target", targetPort, "2".repeat(40));
  const created = await createMcpConnection(
    { displayName: "retained Claude" },
    {
      store: states.get("source")!.connections,
      publicOrigin: "https://mcp-dev.vana.org",
    },
  );
  const before = await states
    .get("source")!
    .connections.getById(created.connectionId);
  const outward = await source.exportForMigration({
    migrationId: "outward-1",
    targetPeer: { appId: "2".repeat(40), instanceId: "target" },
  });
  expect((await target.importFromMigration(outward)).restartRequired).toBe(
    false,
  );
  const inward = await target.exportForMigration({
    migrationId: "rollback-1",
    targetPeer: { appId: "1".repeat(40), instanceId: "source" },
  });
  expect((await source.importFromMigration(inward)).restartRequired).toBe(true);
  await expect(
    fetch(
      `http://127.0.0.1:${sourcePort}/.well-known/oauth-protected-resource/mcp`,
    ),
  ).rejects.toThrow();
  await expect(
    start("source", sourcePort, "1".repeat(40), "false"),
  ).rejects.toThrow(/rollback/i);
  expect(await source.prepareRollback("rollback-1")).toMatchObject({
    owners: 0,
    connections: 0,
  });
  const restarted = await start("source", sourcePort, "1".repeat(40), "false");
  expect(await restarted.active()).toBe(true);
  expect(
    await states.get("source")!.connections.getById(created.connectionId),
  ).toEqual(before);
  expect(
    (
      await fetch(
        `http://127.0.0.1:${sourcePort}/.well-known/oauth-protected-resource/mcp`,
      )
    ).status,
  ).toBe(200);
});

it("refuses stale rollback generations and epochs before opening a listener, then boots the preserved approved connection without prewarm", async () => {
  const { privateKeyToAccount } = await import("viem/accounts");
  const { hexToBytes } = await import("viem");
  const { userPsId } = await import("@opendatalabs/vana-sdk/protocol/identity");
  const { deriveEnclaveIdentity } = await import("../identity/wallet.js");
  const { seal } = await import("../sealing/envelope.js");
  const { MASTER_KEY_MESSAGE } = await import("../agent/seal.js");
  const { openMcpDurableState } =
    await import("@opendatalabs/personal-server-ts-server/mcp/tee");
  const directory = await mkdtemp(join(tmpdir(), "mcp-rollback-boot-"));
  directories.push(directory);
  const account = privateKeyToAccount(`0x${"12".repeat(32)}`);
  const binding = { owner: account.address, chainId: 14800 };
  const id = userPsId(14800, binding.owner);
  const client = createFakeDstackClient({ appId: "1".repeat(40) });
  const derived = await deriveEnclaveIdentity(client, id, 2);
  const signature = hexToBytes(
    await account.signMessage({ message: MASTER_KEY_MESSAGE }),
  );
  const identity = {
    userPsId: id,
    epoch: 2,
    enclaveAddress: derived.address,
    enclavePublicKey: derived.publicKey,
    sealedEnvelope: await seal(client, id, 2, signature),
  };
  signature.fill(0);
  const live = {
    state: "sealed",
    sealed: true,
    identity: {
      userPsId: id,
      epoch: 2,
      ownerAddress: binding.owner,
      chainId: 14800,
      address: derived.address,
      publicKey: derived.publicKey,
    },
  };
  const material = {
    owner: { chainId: 14800, userPsId: id, identityEpoch: 2 },
    generation: 4,
    identity,
  };
  let denied = false;
  const gatewayFetch = vi.fn<typeof fetch>(async (input) =>
    new URL(String(input)).pathname === "/v1/identity"
      ? Response.json(live)
      : Response.json(denied ? { error: "denied" } : material, {
          status: denied ? 409 : 200,
        }),
  );
  const central = await openMcpDurableState({
    path: join(directory, "central.sealed"),
    key: new Uint8Array(32).fill(8),
  });
  const created = await createMcpConnection(
    { displayName: "fresh approved fleet owner" },
    { store: central.connections, publicOrigin: "https://mcp-dev.vana.org" },
  );
  await central.bindOwner(created.connectionId, binding);
  await central.connections.update(created.connectionId, {
    status: "approved",
  });
  const preserved = await central.connections.getById(created.connectionId);
  const port = await freePort();
  let state: McpDurableState;
  const start = async (enabled: string) => {
    const control = await startMcpRouter(
      {
        client,
        gatewayUrl: "https://gateway.invalid",
        chainId: 14800,
        contracts: { ...DEFAULTS.gateway.contracts },
        logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
      },
      {
        FLEET_ENABLED: enabled,
        NODE_ID: "source",
        NODE_SECRET: "s".repeat(32),
        MCP_PUBLIC_ORIGIN: "https://mcp-dev.vana.org",
        MCP_APPROVAL_URL: "https://web.invalid/approve",
        MCP_STATE_PATH: join(directory, "source.sealed"),
        MCP_INGRESS_HOST: "127.0.0.1",
        MCP_INGRESS_PORT: String(port),
        MCP_REDIRECT_URIS: '["https://claude.ai/api/mcp/auth_callback"]',
      },
      gatewayFetch,
      (value) => {
        state = value;
        return {
          ownerReady: async () => true,
          dispatch: async () => Response.json({ ok: true }),
        };
      },
    );
    if (!control) throw new Error("Router disabled");
    controls.push(control);
    return control;
  };
  const source = await start("true");
  const bytes = await central.fenceAndExport("rollback-fresh", "source");
  const { createHash } = await import("node:crypto");
  await source.importFromMigration({
    migrationId: "rollback-fresh",
    snapshotBase64: Buffer.from(bytes).toString("base64"),
    digest: createHash("sha256").update(bytes).digest("hex"),
  });
  expect(await state!.getIdentity(id)).toBeNull();
  await source.prepareRollback("rollback-fresh");
  material.generation = 5;
  await expect(start("false")).rejects.toThrow("generation changed");
  material.generation = 4;
  live.identity.epoch = 3;
  await expect(start("false")).rejects.toThrow();
  live.identity.epoch = 2;
  denied = true;
  await expect(start("false")).rejects.toThrow();
  await expect(
    fetch(`http://127.0.0.1:${port}/.well-known/oauth-protected-resource/mcp`),
  ).rejects.toThrow();
  denied = false;
  const restarted = await start("false");
  expect(await restarted.active()).toBe(true);
  expect(await state!.connections.getById(created.connectionId)).toEqual(
    preserved,
  );
  expect(
    (
      await fetch(
        `http://127.0.0.1:${port}/.well-known/oauth-protected-resource/mcp`,
      )
    ).status,
  ).toBe(200);
  const { createServer: createHttpServer } = await import("node:http");
  const { dispatchOwnerMcp } = await import("./dispatch.js");
  let sandboxBody = "";
  const sandbox = createHttpServer(async (request, response) => {
    for await (const chunk of request) sandboxBody += String(chunk);
    response.setHeader("content-type", "application/json");
    response.end(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: { content: [{ type: "text", text: "preserved owner data" }] },
      }),
    );
  });
  await new Promise<void>((resolve) => sandbox.listen(0, "127.0.0.1", resolve));
  const address = sandbox.address();
  if (!address || typeof address === "string")
    throw new Error("Expected sandbox port");
  const registry = {
    acquire: vi.fn(
      async (_key: string, _create: unknown, _signal: unknown) => ({
        handle: { origin: `http://127.0.0.1:${address.port}` },
        accessToken: "sandbox-access",
      }),
    ),
    release: vi.fn(),
  };
  try {
    const response = await dispatchOwnerMcp(
      new Request("https://mcp-dev.vana.org/mcp", {
        method: "POST",
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "read_data",
            arguments: { scope: "spotify.profile" },
          },
        }),
      }),
      {
        ...preserved!,
        grants: [{ grantId: "0xabc", scopes: ["spotify.profile"] }],
      },
      binding,
      {
        client,
        state: state!,
        registry,
        gatewayUrl: "https://gateway.invalid",
        chainId: 14800,
        fetch: gatewayFetch,
      } as never,
    );
    expect((await response.json()).result.content[0].text).toBe(
      "preserved owner data",
    );
    expect(JSON.parse(sandboxBody)).toMatchObject({
      owner: binding.owner,
      connection: { id: created.connectionId },
      request: { method: "tools/call" },
    });
    expect(registry.acquire.mock.calls[0]?.[0]).toBe(`${id}:2`);
    expect(registry.release).toHaveBeenCalledWith(`${id}:2`);
  } finally {
    await new Promise<void>((resolve, reject) =>
      sandbox.close((error) => (error ? reject(error) : resolve())),
    );
  }
  // Ordinary legacy approvals and revocations must not turn the historical
  // imported membership into a permanent restart restriction.
  const legacy = await createMcpConnection(
    { displayName: "new legacy owner" },
    { store: state!.connections, publicOrigin: "https://mcp-dev.vana.org" },
  );
  await state!.bindOwner(legacy.connectionId, {
    owner: "0x2222222222222222222222222222222222222222",
    chainId: 14800,
  });
  await state!.connections.update(legacy.connectionId, { status: "approved" });
  await state!.connections.update(created.connectionId, { status: "revoked" });
  const rotated = await deriveEnclaveIdentity(client, id, 3);
  const rotatedSignature = hexToBytes(
    await account.signMessage({ message: MASTER_KEY_MESSAGE }),
  );
  await state!.rememberIdentity({
    ...identity,
    epoch: 3,
    enclaveAddress: rotated.address,
    enclavePublicKey: rotated.publicKey,
    sealedEnvelope: await seal(client, id, 3, rotatedSignature),
  });
  rotatedSignature.fill(0);
  await restarted.close();
  const legacyRestart = await start("false");
  expect((await state!.getIdentity(id))?.epoch).toBe(3);
  expect(await legacyRestart.active()).toBe(true);
  expect((await state!.connections.getById(legacy.connectionId))?.status).toBe(
    "approved",
  );
  expect((await state!.connections.getById(created.connectionId))?.status).toBe(
    "revoked",
  );
  await legacyRestart.exportForMigration({
    migrationId: "forward-after-rollback",
    targetPeer: { appId: "2".repeat(40), instanceId: "controller" },
  });
  await expect(start("false")).rejects.toThrow("fenced");
  expect(
    gatewayFetch.mock.calls.every(([input]) => !String(input).includes("jobs")),
  ).toBe(true);
});
