/**
 * Call-site guard for the legacy owner key at the bootstrap `masterKey:` sites.
 *
 * The legacy key is the raw 65 signature bytes. The stream key is the same
 * signature in normal form. They differ for a non-canonical signature, and a
 * swap of one for the other at these sites would change every sealed record
 * without any other test failing (canonical signatures give the same bytes).
 *
 * Each test boots the real server with a high-s signature, lets the real
 * factory run, and checks the key it received against the SDK's
 * `deriveMasterKey`, which is independent of the owner module. The factories are
 * wrapped, not replaced, so the boot is otherwise unchanged.
 */

import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer as createHttpServer, type Server } from "node:http";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { deriveMasterKey } from "@opendatalabs/vana-sdk/browser";
import { bytesToHex, type Hex } from "viem";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import * as AdditionsModule from "@opendatalabs/personal-server-ts-core/additions";
import * as HostPortsModule from "@opendatalabs/personal-server-ts-core/replication/host-ports";
import * as ReplicationHostModule from "./storage/pdpp-replication-host.js";
import * as LocalMcpStateModule from "./mcp/local-state.js";
import * as SyncModule from "@opendatalabs/personal-server-ts-core/sync";
import { createServer, type ServerContext } from "./bootstrap.js";

vi.mock(
  "@opendatalabs/personal-server-ts-core/additions",
  async (importOriginal) => {
    const actual = await importOriginal<typeof AdditionsModule>();
    return {
      ...actual,
      createDurableAdditions: vi.fn(actual.createDurableAdditions),
    };
  },
);

vi.mock(
  "@opendatalabs/personal-server-ts-core/replication/host-ports",
  async (importOriginal) => {
    const actual = await importOriginal<typeof HostPortsModule>();
    return {
      ...actual,
      createReplicationNetworkPorts: vi.fn(
        actual.createReplicationNetworkPorts,
      ),
    };
  },
);

vi.mock("./storage/pdpp-replication-host.js", async (importOriginal) => {
  const actual = await importOriginal<typeof ReplicationHostModule>();
  return {
    ...actual,
    createNodeReplication: vi.fn(actual.createNodeReplication),
  };
});

vi.mock(
  "@opendatalabs/personal-server-ts-core/sync",
  async (importOriginal) => {
    const actual = await importOriginal<typeof SyncModule>();
    return {
      ...actual,
      createSyncManager: vi.fn(actual.createSyncManager),
    };
  },
);

vi.mock("./mcp/local-state.js", async (importOriginal) => {
  const actual = await importOriginal<typeof LocalMcpStateModule>();
  return {
    ...actual,
    openLocalMcpState: vi.fn(actual.openLocalMcpState),
  };
});

/** High-s signature (v = 0x1c). Its legacy key is the raw bytes. */
const HIGH_S_SIGNATURE =
  "0x1f5c9b3bafc291e8ea7aa4e0c5700a109e68aa2431fdbea08b49f9bf91b5c7dbd555e6d21a3207991a060a0c6afd5992e4183bad14f5218f2fd6dc20cf515f6c1c" as Hex;

/** The SDK's legacy key for that signature. Independent of the owner module. */
const SDK_LEGACY_KEY = bytesToHex(deriveMasterKey(HIGH_S_SIGNATURE));

const DECLARATION = JSON.stringify({
  source_id: "https://registry.pdpp.dev/connectors/claude",
  source_kind: "connector",
  version: "1",
  streams: [
    {
      name: "profile",
      fields: ["id", "name"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
});

let tempDir: string;
let gateway: Server;
let gatewayUrl: string;
let ctx: ServerContext | undefined;

beforeEach(async () => {
  vi.clearAllMocks();
  tempDir = await mkdtemp(join(tmpdir(), "bootstrap-owner-key-"));
  vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", HIGH_S_SIGNATURE);
  vi.stubEnv("VANA_OWNER_PRIVATE_KEY", "");
  // A gateway that knows nothing; boot needs no real network.
  gateway = createHttpServer((_request, response) => {
    response.statusCode = 404;
    response.setHeader("Content-Type", "application/json");
    response.end(JSON.stringify({ error: "not found" }));
  });
  await new Promise<void>((resolve) => gateway.listen(0, "127.0.0.1", resolve));
  const address = gateway.address();
  if (!address || typeof address === "string") throw new Error("no port");
  gatewayUrl = `http://127.0.0.1:${address.port}`;
});

afterEach(async () => {
  await ctx?.cleanup();
  ctx = undefined;
  await new Promise((resolve) => gateway.close(resolve));
  await rm(tempDir, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

async function boot(
  replication: boolean,
  sync = false,
): Promise<ServerContext> {
  const dir = join(tempDir, "declarations");
  await mkdir(dir, { recursive: true });
  const path = join(dir, "claude.json");
  await writeFile(path, DECLARATION, "utf-8");
  ctx = await createServer(
    ServerConfigSchema.parse({
      gateway: { url: gatewayUrl },
      tunnel: { enabled: false },
      sync: { enabled: sync },
      logging: { level: "fatal", pretty: false },
      replication: { enabled: replication },
      pdpp: {
        enabled: true,
        declarationPaths: [path],
        methods: [{ method_id: "claude", declaration_path: path }],
      },
    }),
    { serverDir: tempDir, dataDir: join(tempDir, "data") },
  );
  return ctx;
}

it("gives the additions writer the legacy master key", async () => {
  await boot(false);
  const calls = vi.mocked(AdditionsModule.createDurableAdditions).mock.calls;
  expect(calls.length).toBeGreaterThan(0);
  expect(bytesToHex(calls.at(-1)![0].masterKey)).toBe(SDK_LEGACY_KEY);
});

it("gives the replication network ports the legacy master key", async () => {
  await boot(true);
  expect(
    vi.mocked(ReplicationHostModule.createNodeReplication).mock.calls.length,
  ).toBeGreaterThan(0);
  const calls = vi.mocked(HostPortsModule.createReplicationNetworkPorts).mock
    .calls;
  expect(calls.length).toBeGreaterThan(0);
  expect(bytesToHex(calls.at(-1)![0].masterKey)).toBe(SDK_LEGACY_KEY);
});

it("opens the local MCP state with the legacy master key", async () => {
  await boot(false);
  const calls = vi.mocked(LocalMcpStateModule.openLocalMcpState).mock.calls;
  expect(calls.length).toBe(1);
  expect(bytesToHex(calls[0]![0].masterKey)).toBe(SDK_LEGACY_KEY);
});

it("gives the sync manager the legacy master key for upload and download", async () => {
  await boot(false, true);
  const calls = vi.mocked(SyncModule.createSyncManager).mock.calls;
  expect(calls.length).toBeGreaterThan(0);
  const [uploadDeps, downloadDeps] = calls.at(-1)!;
  expect(bytesToHex(uploadDeps.masterKey)).toBe(SDK_LEGACY_KEY);
  expect(bytesToHex(downloadDeps.masterKey)).toBe(SDK_LEGACY_KEY);
});
