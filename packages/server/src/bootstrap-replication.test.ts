/**
 * Bootstrap wiring of the replication runtime (plan item A9). Flag off, a
 * boot constructs nothing of it; flag on, it starts with the background
 * services and stops before the database closes.
 */
import { createServer as createHttpServer, type Server } from "node:http";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import Database from "better-sqlite3";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createServer, type ServerContext } from "./bootstrap.js";

const KNOWN_SIG =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";
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
let gatewayRequests = 0;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "bootstrap-replication-"));
  vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", KNOWN_SIG);
  vi.stubEnv("VANA_OWNER_PRIVATE_KEY", "");
  gatewayRequests = 0;
  // A gateway that knows nothing: the server is not registered, so the
  // replication roster cannot establish a writer identity.
  gateway = createHttpServer((_request, response) => {
    gatewayRequests++;
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

async function boot(replication: boolean) {
  const dir = join(tempDir, "declarations");
  await mkdir(dir, { recursive: true });
  const path = join(dir, "claude.json");
  await writeFile(path, DECLARATION, "utf-8");
  ctx = await createServer(
    ServerConfigSchema.parse({
      gateway: { url: gatewayUrl },
      tunnel: { enabled: false },
      sync: { enabled: false },
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

/** Replication tables in the server's own database, by name. */
function replicaTables(): string[] {
  const db = new Database(join(tempDir, "index.db"), { readonly: true });
  try {
    return (
      db
        .prepare(
          "SELECT name FROM sqlite_master WHERE type = 'table' AND (name LIKE 'pdpp_replica%' OR name LIKE 'pdpp_transport%') ORDER BY name",
        )
        .all() as { name: string }[]
    ).map((row) => row.name);
  } finally {
    db.close();
  }
}

it("flag off: no runtime, no replica or transport tables, no replication traffic", async () => {
  const context = await boot(false);
  expect(context.replicationStatus).toEqual({ state: "never" });
  expect(context.replication).toBeUndefined();
  await context.startBackgroundServices();
  const afterStart = gatewayRequests;
  await context.cleanup();
  ctx = undefined;
  expect(replicaTables()).toEqual([]);
  // Background services may ask the gateway for the server registration;
  // nothing replication-shaped runs after them.
  expect(gatewayRequests).toBe(afterStart);
}, 60_000); // a full server boot

it("flag on: the runtime starts with the background services and stops on cleanup", async () => {
  const context = await boot(true);
  expect(context.replicationStatus).toEqual({ state: "on" });
  const runtime = context.replication;
  if (runtime?.state !== "started")
    throw new Error(`replication did not start: ${JSON.stringify(runtime)}`);
  expect(runtime.driver.status().state).toBe("stopped");
  await context.startBackgroundServices();
  expect(runtime.driver.status().state).toBe("running");
  // The first step asks the roster, finds no registration and waits.
  const report = await runtime.driver.trigger();
  expect(report?.waits).toEqual([
    expect.objectContaining({ id: "writer-identity" }),
  ]);
  expect(runtime.driver.status().nextWakeAt).toBeDefined();
  await context.cleanup();
  ctx = undefined;
  expect(runtime.driver.status()).toMatchObject({
    state: "stopped",
    stepping: false,
  });
  expect(runtime.driver.status().nextWakeAt).toBeUndefined();
  // No baseline without a writer identity.
  const db = new Database(join(tempDir, "index.db"), { readonly: true });
  try {
    expect(
      db.prepare("SELECT 1 FROM pdpp_replica_settings WHERE id = 1").get(),
    ).toBeUndefined();
  } finally {
    db.close();
  }
}, 60_000);
