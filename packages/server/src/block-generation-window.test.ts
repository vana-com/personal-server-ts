/**
 * A non-owner block read serves only blocks of the version it authorized.
 *
 * Real Node storage and the real MCP route. Each window test changes the
 * stored version between two file reads of one block read: the manifest read
 * and a block read, or a block read and the old-sidecar envelope check. The
 * file-read hook is the only fake. A live chain grant must never receive the
 * PDPP bytes, and the owner must still read an old sidecar.
 */
import type * as FsPromises from "node:fs/promises";
import { readFile as readFileOriginal, writeFile } from "node:fs/promises";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Hono } from "hono";
import pino from "pino";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  Builder,
  DataFileEnvelope,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";
import {
  approveMcpConnection,
  createInMemoryMcpConnectionStore,
  createMcpConnection,
} from "@opendatalabs/personal-server-ts-core/mcp";
import { createTestWallet } from "@opendatalabs/personal-server-ts-core/test-utils";
import { buildDataBlocksAsync } from "@opendatalabs/personal-server-ts-core/storage/blocks";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import { initializeDatabase } from "./storage/index-schema.js";
import { createIndexManager } from "./storage/index-manager.js";
import { createNodeDataStorage } from "./storage/node-data-storage.js";
import { mcpStreamableHttpRoutes } from "./routes/mcp.js";

const race = vi.hoisted(() => ({
  afterRead: undefined as
    undefined | ((path: string, value: unknown) => Promise<void>),
}));
vi.mock("node:fs/promises", async (importOriginal) => {
  const original = await importOriginal<typeof FsPromises>();
  return {
    ...original,
    readFile: async (...args: Parameters<typeof original.readFile>) => {
      const value = await (
        original.readFile as (...a: unknown[]) => Promise<unknown>
      )(...args);
      await race.afterRead?.(String(args[0]), value);
      return value;
    },
  };
});

const logger = pino({ level: "silent" });
const ORIGIN = "http://localhost:8080";
const owner = createTestWallet(0);
const GRANT_ID = "grant-probe";
const SECRET = "pdpp-only-score-99";
const AT = "2026-09-01T00:00:00.000Z";
const gatewayConfig = {
  chainId: 14800,
  contracts: {
    dataRegistry: "0x0000000000000000000000000000000000000001",
    dataPortabilityPermissions: "0x0000000000000000000000000000000000000002",
    dataPortabilityServer: "0x0000000000000000000000000000000000000003",
    dataPortabilityGrantees: "0x0000000000000000000000000000000000000004",
  },
} as const;

/** Native PDPP bytes: `$pdpp` import metadata inside `data`. */
function nativeEnvelope(scope: string): DataFileEnvelope {
  return {
    version: "1.0",
    scope,
    collectedAt: AT,
    data: {
      id: "a1",
      score: SECRET,
      $pdpp: { version: 1, sourceId: "https://registry.pdpp.dev/oura" },
    },
  } as DataFileEnvelope;
}

function legacyEnvelope(scope: string): DataFileEnvelope {
  return {
    version: "1.0",
    scope,
    collectedAt: AT,
    data: { id: "legacy-row" },
  } as DataFileEnvelope;
}

let dataDir: string;
let indexManager: IndexManager;
let storage: DataStoragePort;

function gatewayFor(granteeAddress: `0x${string}`): GatewayClient {
  const grant = {
    id: GRANT_ID,
    grantorAddress: owner.address,
    granteeId: granteeAddress,
    scopes: ["oura.*"],
    status: "confirmed",
    addedAt: "2026-01-21T10:00:00.000Z",
    expiresAt: null,
    expired: false,
    revokedAt: null,
    paymentStatus: "paid",
    grantVersion: "1",
  } as unknown as GatewayGrantResponse;
  const registered: Builder = {
    id: granteeAddress,
    ownerAddress: owner.address,
    granteeAddress,
    publicKey: "0x04",
    appUrl: "https://app.test",
    addedAt: "2026-01-21T10:00:00.000Z",
  };
  return {
    isRegisteredBuilder: vi.fn().mockResolvedValue(true),
    getBuilder: vi.fn().mockResolvedValue(registered),
    getGrant: vi.fn().mockResolvedValue(grant),
    listGrantsByUser: vi.fn().mockResolvedValue([]),
    getSchemaForScope: vi.fn().mockResolvedValue(null),
    getServer: vi.fn().mockResolvedValue(null),
    getDataPoint: vi.fn().mockResolvedValue(null),
    listDataPointsByOwner: vi
      .fn()
      .mockResolvedValue({ dataPoints: [], cursor: null }),
    getSchema: vi.fn().mockResolvedValue(null),
    registerServer: vi.fn().mockResolvedValue({ alreadyRegistered: false }),
    registerDataPoint: vi.fn().mockResolvedValue({ dataPointId: "0xdp" }),
    createGrant: vi.fn().mockResolvedValue({ grantId: GRANT_ID }),
    revokeGrant: vi.fn().mockResolvedValue(undefined),
  } as unknown as GatewayClient;
}

/**
 * Publish and index a version with its block sidecar, as sync does.
 * `unbound` writes the sidecar as it was before manifests recorded provenance
 * or a binding to the envelope; `preChangeRow` indexes the row as it was
 * before rows recorded provenance or a generation.
 */
async function put(
  envelope: DataFileEnvelope,
  unbound = false,
  preChangeRow = unbound,
) {
  const written = await storage.writeEnvelope(envelope);
  const built = await buildDataBlocksAsync({
    scope: envelope.scope,
    collectedAt: envelope.collectedAt,
    content: envelope,
  });
  if (unbound) {
    const manifest = built.manifest as unknown as Record<string, unknown>;
    delete manifest.pdppOrigin;
    delete manifest.envelopeDigest;
    for (const ref of built.manifest.blocks) {
      delete (ref as unknown as Record<string, unknown>).digest;
    }
  }
  await storage.writeBlockManifest!(
    envelope.scope,
    envelope.collectedAt,
    built.manifest,
    built.blocks,
  );
  const entry = {
    fileId: null,
    path: written.relativePath,
    scope: envelope.scope,
    collectedAt: envelope.collectedAt,
    sizeBytes: written.sizeBytes,
  };
  return preChangeRow ? indexManager.insert(entry) : storage.insertEntry(entry);
}

/** Delete a version and publish other bytes at the same scope+collectedAt. */
async function replaceAt(next: DataFileEnvelope) {
  const fileId = "file-replaced";
  storage.updateFileId(
    indexManager.findClosestByScope(next.scope, next.collectedAt)!.path,
    fileId,
  );
  await storage.deleteByFileId(fileId);
  await put(next);
}

function blockFile(scope: string, blockId: string): string {
  return join(dataDir, "blocks", ...scope.split("."), AT, `${blockId}.json`);
}

beforeEach(async () => {
  dataDir = await mkdtemp(join(tmpdir(), "block-generation-"));
  indexManager = createIndexManager(initializeDatabase(":memory:"));
  storage = createNodeDataStorage({
    indexManager,
    hierarchyOptions: { dataDir },
  });
});

afterEach(async () => {
  race.afterRead = undefined;
  indexManager.close();
  await rm(dataDir, { recursive: true, force: true });
});

/** A grantee's MCP `read_scope` call over the real streamable HTTP route. */
async function mcpTool(name: string, args: Record<string, unknown>) {
  const connections = createInMemoryMcpConnectionStore();
  const created = await createMcpConnection(
    { displayName: "Review" },
    { store: connections, publicOrigin: ORIGIN },
  );
  const record = (await connections.getById(created.connectionId))!;
  await approveMcpConnection(
    {
      connectionId: created.connectionId,
      grants: [{ grantId: GRANT_ID, scopes: ["oura.*"] }],
    },
    { store: connections },
  );
  const root = new Hono();
  root.route(
    "/mcp",
    mcpStreamableHttpRoutes({
      logger,
      serverOrigin: ORIGIN,
      serverOwner: owner.address,
      gateway: gatewayFor(record.granteeAddress),
      gatewayConfig,
      accessLogWriter: { write: async () => undefined },
      connectionStore: connections,
      indexManager,
      hierarchyOptions: { dataDir },
    }),
  );
  return async () => {
    const response = await root.request(
      `/mcp/${encodeURIComponent(created.connectionToken)}`,
      {
        method: "POST",
        headers: {
          Accept: "application/json, text/event-stream",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name, arguments: args },
        }),
      },
    );
    return response.text();
  };
}

function mcpReadScope(scope: string) {
  return mcpTool("read_scope", { scope });
}

function manifestFile(scope: string): string {
  return join(dataDir, "blocks", ...scope.split("."), AT, "manifest.json");
}

describe("a non-owner block read is pinned to the version it authorized", () => {
  it("block window a: a version republished as PDPP after a legacy manifest read is refused", async () => {
    await put(legacyEnvelope("oura.activity"));
    const call = await mcpReadScope("oura.activity");
    // Control: the legacy version is readable before the swap.
    expect(await call()).toContain("legacy-row");
    let fired = false;
    race.afterRead = async (path) => {
      if (!path.endsWith("manifest.json")) return;
      race.afterRead = undefined;
      fired = true;
      await replaceAt(nativeEnvelope("oura.activity"));
    };
    const text = await call();
    expect(fired).toBe(true);
    expect(text).not.toContain(SECRET);
    expect(text).toContain("block_digest_mismatch");
  });

  it("refuses other legacy bytes republished after the manifest read: the generation, not provenance, decides", async () => {
    await put(legacyEnvelope("oura.activity"));
    const call = await mcpReadScope("oura.activity");
    expect(await call()).toContain("legacy-row");
    race.afterRead = async (path) => {
      if (!path.endsWith("manifest.json")) return;
      race.afterRead = undefined;
      await replaceAt({
        ...legacyEnvelope("oura.activity"),
        data: { id: "other-legacy-row" },
      } as DataFileEnvelope);
    };
    const text = await call();
    expect(text).not.toContain("other-legacy-row");
    expect(text).toContain("block_digest_mismatch");
  });

  it("block window b: PDPP blocks of an old sidecar are not authorized by a later legacy envelope", async () => {
    const scope = "oura.raw";
    await put(nativeEnvelope(scope), true);
    const call = await mcpReadScope(scope);
    let fired = false;
    race.afterRead = async (path) => {
      if (!path.endsWith("block-000002.json")) return;
      race.afterRead = undefined;
      fired = true;
      await replaceAt(legacyEnvelope(scope));
    };
    const text = await call();
    expect(fired).toBe(true);
    expect(text).not.toContain(SECRET);
    // The row had no generation, so the read decided on one full read of the
    // envelope, which now holds the legacy bytes it then served.
    expect(text).toContain("legacy-row");
  });

  it("refuses an old sidecar's fallback when the version changed after authorization", async () => {
    const scope = "oura.raw";
    await put(legacyEnvelope(scope), true, false);
    const call = await mcpReadScope(scope);
    let fired = false;
    race.afterRead = async (path) => {
      if (!path.endsWith("block-000002.json")) return;
      race.afterRead = undefined;
      fired = true;
      await replaceAt(nativeEnvelope(scope));
    };
    const text = await call();
    expect(fired).toBe(true);
    expect(text).not.toContain(SECRET);
    expect(text).toContain("generation_mismatch");
  });

  it("never trusts a pre-binding manifest's pdppOrigin:false for PDPP bytes", async () => {
    // A historical sidecar and row that call PDPP bytes legacy (for example
    // a derivative envelope a later classifier counts as PDPP). Only the
    // bytes decide: the non-owner read is refused, never served the blocks.
    const scope = "oura.raw";
    const envelope = nativeEnvelope(scope);
    const written = await storage.writeEnvelope(envelope);
    const built = await buildDataBlocksAsync({
      scope,
      collectedAt: AT,
      content: envelope,
    });
    const manifest = built.manifest as unknown as Record<string, unknown>;
    manifest.pdppOrigin = false;
    delete manifest.envelopeDigest;
    for (const ref of built.manifest.blocks) {
      delete (ref as unknown as Record<string, unknown>).digest;
    }
    await storage.writeBlockManifest!(scope, AT, built.manifest, built.blocks);
    indexManager.insert({
      fileId: null,
      path: written.relativePath,
      scope,
      collectedAt: AT,
      sizeBytes: written.sizeBytes,
      pdppOrigin: false,
    });
    const read = await (await mcpReadScope(scope))();
    expect(read).not.toContain(SECRET);
    expect(read).toContain("GRANT_REQUIRED");
    const listed = await (await mcpTool("list_scope_blocks", { scope }))();
    expect(listed).toContain("GRANT_REQUIRED");
  });

  it("refuses a block whose bytes differ from the manifest digest", async () => {
    await put(legacyEnvelope("oura.activity"));
    const call = await mcpReadScope("oura.activity");
    expect(await call()).toContain("legacy-row");
    const path = blockFile("oura.activity", "block-000002");
    const block = JSON.parse(await readFileOriginal(path, "utf8"));
    block.value = { id: "tampered-row" };
    await writeFile(path, JSON.stringify(block), "utf8");
    const text = await call();
    expect(text).not.toContain("tampered-row");
    expect(text).toContain("BOUNDED_DATA_UNAVAILABLE");
  });

  it("serves a legacy old sidecar to a grantee and rebinds it to the row's generation", async () => {
    const entry = await put(legacyEnvelope("oura.raw"), true, false);
    const call = await mcpReadScope("oura.raw");
    expect(await call()).toContain("legacy-row");
    const repaired = JSON.parse(
      await readFileOriginal(manifestFile("oura.raw"), "utf8"),
    );
    expect(repaired.envelopeDigest).toBe(entry.generation);
    expect(await call()).toContain("legacy-row");
  });

  it("serves a grantee's table of contents without digests, and refuses a PDPP old sidecar's", async () => {
    await put(legacyEnvelope("oura.activity"));
    const listed = await (
      await mcpTool("list_scope_blocks", { scope: "oura.activity" })
    )();
    expect(listed).toContain("block-000002");
    expect(listed).not.toContain("igest");

    await put(nativeEnvelope("oura.raw"), true);
    const refused = await (
      await mcpTool("list_scope_blocks", { scope: "oura.raw" })
    )();
    expect(refused).toContain("GRANT_REQUIRED");
  });

  it("the owner still reads an old sidecar", async () => {
    await put(nativeEnvelope("oura.raw"), true);
    const result = await storage.readScopeBlocks!("oura.raw", AT, {
      maxBytes: 65_536,
    });
    expect(JSON.stringify(result.blocks)).toContain(SECRET);
  });
});
