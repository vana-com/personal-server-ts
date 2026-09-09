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
  const start = async (name: string, port: number, appId: string) => {
    const control = await startMcpRouter(
      {
        client: createFakeDstackClient({ appId }),
        gatewayUrl: "https://gateway.invalid",
        chainId: 14800,
        contracts: { ...DEFAULTS.gateway.contracts },
        logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
      },
      {
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
  const restarted = await start("source", sourcePort, "1".repeat(40));
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
