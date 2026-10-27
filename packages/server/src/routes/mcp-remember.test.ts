/**
 * The `remember` MCP tool, end to end through the `/mcp/:token` route: an
 * agent saves a memory under a `write:` grant on its own connection, the
 * record lands through the same delegated-write path as a builder write
 * (live write policy, `$writtenBy` stamp, access log), and a later
 * `read_scope` recalls it.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { pino } from "pino";
import { Hono } from "hono";
import {
  approveMcpConnection,
  createInMemoryMcpConnectionStore,
  createMcpConnection,
  type McpConnectionStore,
} from "@opendatalabs/personal-server-ts-core/mcp";
import type {
  Builder,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/node";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { HierarchyManagerOptions } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  WRITER_ATTRIBUTION_KEY,
  createInMemoryWriteSessionStore,
  verifyStoredWriterAttribution,
} from "@opendatalabs/personal-server-ts-core/write";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import { dataRoutes } from "./data.js";
import { mcpStreamableHttpRoutes } from "./mcp.js";

const SERVER_ORIGIN = "http://localhost:8080";
const ownerWallet = createTestWallet(9);
const logger = pino({ level: "silent" });
const GRANT_ID = "grant-memory-1";
const MEMORY_SCOPE = "memory.claude";

function makeGateway(granteeAddress: `0x${string}`, scopes: string[]) {
  let grant = {
    id: GRANT_ID,
    grantorAddress: ownerWallet.address,
    granteeId: granteeAddress,
    scopes,
    status: "confirmed",
    addedAt: "2026-10-27T10:00:00.000Z",
    expiresAt: null,
    expired: false,
    revokedAt: null,
    revocationSignature: null,
    paymentStatus: "paid",
    paidAt: null,
    paidBy: null,
    grantVersion: "1",
  } as unknown as GatewayGrantResponse;
  const builder: Builder = {
    id: granteeAddress,
    ownerAddress: ownerWallet.address,
    granteeAddress,
    publicKey: "0x04",
    appUrl: "https://claude.test",
    addedAt: "2026-10-27T10:00:00.000Z",
  };
  const gateway = {
    isRegisteredBuilder: vi.fn().mockResolvedValue(true),
    getBuilder: vi.fn().mockResolvedValue(builder),
    getGrant: vi.fn(async () => grant),
    listGrantsByUser: vi.fn().mockResolvedValue([]),
    getServer: vi.fn().mockResolvedValue(null),
    getDataPoint: vi.fn().mockResolvedValue(null),
    getSchemaForScope: vi.fn().mockResolvedValue(null),
  } as unknown as GatewayClient;
  return {
    gateway,
    revoke() {
      grant = { ...grant, revokedAt: "2026-10-27T11:00:00.000Z" };
    },
  };
}

function createAccessLog(): AccessLogWriter & {
  entries: Array<Record<string, unknown>>;
} {
  const entries: Array<Record<string, unknown>> = [];
  return {
    entries,
    async write(entry) {
      entries.push(entry as unknown as Record<string, unknown>);
    },
  };
}

describe("MCP remember tool", () => {
  let dataDir: string;
  let hierarchyOptions: HierarchyManagerOptions;
  let indexManager: IndexManager;
  let store: McpConnectionStore;

  beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), "mcp-remember-test-"));
    hierarchyOptions = { dataDir };
    indexManager = createIndexManager(initializeDatabase(":memory:"));
    store = createInMemoryMcpConnectionStore();
  });

  afterEach(async () => {
    indexManager.close();
    await rm(dataDir, { recursive: true, force: true });
  });

  async function setup(scopes: string[]) {
    const created = await createMcpConnection(
      { displayName: "Claude" },
      { store, publicOrigin: SERVER_ORIGIN },
    );
    const record = (await store.getById(created.connectionId))!;
    const { gateway, revoke } = makeGateway(record.granteeAddress, scopes);
    await approveMcpConnection(
      {
        connectionId: created.connectionId,
        grants: [{ grantId: GRANT_ID, scopes }],
      },
      { store },
    );
    const accessLogWriter = createAccessLog();
    // Mounted like createApp: the data route redeems write sessions from the
    // same store the MCP write client puts its session into.
    const writeSessionStore = createInMemoryWriteSessionStore();
    const root = new Hono();
    root.route(
      "/v1/data",
      dataRoutes({
        indexManager,
        hierarchyOptions,
        logger,
        serverOrigin: SERVER_ORIGIN,
        serverOwner: ownerWallet.address,
        gateway,
        accessLogWriter,
        writeSessionStore,
        mountPath: "/v1/data",
      }),
    );
    root.route(
      "/mcp",
      mcpStreamableHttpRoutes({
        logger,
        serverOrigin: SERVER_ORIGIN,
        serverOwner: ownerWallet.address,
        gateway,
        accessLogWriter,
        connectionStore: store,
        indexManager,
        hierarchyOptions,
        mcpWrites: {
          sessionStore: writeSessionStore,
          dispatch: async (request) => root.fetch(request),
        },
      }),
    );

    async function callTool(name: string, args: Record<string, unknown>) {
      const res = await root.request(
        `/mcp/${encodeURIComponent(created.connectionToken)}`,
        {
          method: "POST",
          headers: {
            Accept: "application/json, text/event-stream",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: "1",
            method: "tools/call",
            params: { name, arguments: args },
          }),
        },
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        result: { isError?: boolean; content: Array<{ text: string }> };
      };
      return {
        isError: body.result.isError === true,
        payload: JSON.parse(body.result.content[0]!.text) as Record<
          string,
          unknown
        >,
      };
    }

    async function ownerRead(scope: string) {
      const auth = await buildWeb3SignedHeader({
        wallet: ownerWallet,
        aud: SERVER_ORIGIN,
        method: "GET",
        uri: `/v1/data/${scope}`,
      });
      return root.request(`/v1/data/${scope}`, {
        headers: { Authorization: auth },
      });
    }

    async function ownerWrite(scope: string, data: unknown) {
      const body = JSON.stringify(data);
      const auth = await buildWeb3SignedHeader({
        wallet: ownerWallet,
        aud: SERVER_ORIGIN,
        method: "POST",
        uri: `/v1/data/${scope}`,
        body: new TextEncoder().encode(body),
      });
      return root.request(`/v1/data/${scope}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: auth },
        body,
      });
    }

    return {
      callTool,
      ownerRead,
      ownerWrite,
      revoke,
      accessLogWriter,
      granteeAddress: record.granteeAddress,
    };
  }

  it("saves a memory as the connection grantee with a verifiable $writtenBy", async () => {
    const t = await setup([`write:${MEMORY_SCOPE}`]);

    const result = await t.callTool("remember", {
      scope: MEMORY_SCOPE,
      text: "Prefers TypeScript and pnpm for new projects.",
    });

    expect(result.isError).toBe(false);
    expect(result.payload).toMatchObject({
      saved: true,
      scope: MEMORY_SCOPE,
      memoryCount: 1,
    });

    const read = await t.ownerRead(MEMORY_SCOPE);
    expect(read.status).toBe(200);
    const envelope = (await read.json()) as {
      scope: string;
      data: Record<string, unknown>;
    };
    // Stored as a PDPP records body; each record names the agent that wrote it.
    expect(Object.keys(envelope.data).sort()).toEqual([
      WRITER_ATTRIBUTION_KEY,
      "records",
    ]);
    expect(envelope.data.records).toEqual([
      expect.objectContaining({
        id: result.payload.id,
        content: "Prefers TypeScript and pnpm for new projects.",
        written_by: t.granteeAddress,
      }),
    ]);
    const writtenBy = envelope.data[WRITER_ATTRIBUTION_KEY] as {
      builder: string;
      grantId: string;
    };
    expect(writtenBy.builder.toLowerCase()).toBe(
      t.granteeAddress.toLowerCase(),
    );
    expect(writtenBy.grantId).toBe(GRANT_ID);
    const verified = await verifyStoredWriterAttribution(envelope as never);
    expect(verified.builder.toLowerCase()).toBe(t.granteeAddress.toLowerCase());

    const write = t.accessLogWriter.entries.find((e) => e.action === "write");
    expect(write).toMatchObject({ scope: MEMORY_SCOPE, grantId: GRANT_ID });
    expect(String(write?.builder).toLowerCase()).toBe(
      t.granteeAddress.toLowerCase(),
    );
  });

  it("appends memories and replaces one saved again under the same key", async () => {
    const t = await setup([`write:${MEMORY_SCOPE}`]);

    await t.callTool("remember", {
      scope: MEMORY_SCOPE,
      text: "Works on the Personal Server.",
    });
    await t.callTool("remember", {
      scope: MEMORY_SCOPE,
      text: "Editor: VS Code.",
      key: "editor",
    });
    const replaced = await t.callTool("remember", {
      scope: MEMORY_SCOPE,
      text: "Editor: Zed.",
      key: "editor",
    });

    expect(replaced.isError).toBe(false);
    expect(replaced.payload).toMatchObject({ replaced: true, memoryCount: 2 });
    const envelope = (await (await t.ownerRead(MEMORY_SCOPE)).json()) as {
      data: { records: Array<{ id: string; content: string; key?: string }> };
    };
    expect(envelope.data.records.map((m) => m.content)).toEqual([
      "Works on the Personal Server.",
      "Editor: Zed.",
    ]);
  });

  it("keeps a memory's id when a save under the same key replaces it", async () => {
    const t = await setup([`write:${MEMORY_SCOPE}`]);

    const first = await t.callTool("remember", {
      scope: MEMORY_SCOPE,
      text: "Editor: VS Code.",
      key: "editor",
    });
    const second = await t.callTool("remember", {
      scope: MEMORY_SCOPE,
      text: "Editor: Zed.",
      key: "editor",
    });

    expect(second.payload.id).toBe(first.payload.id);
  });

  it("does not save the same memory twice", async () => {
    const t = await setup([`write:${MEMORY_SCOPE}`]);
    const first = await t.callTool("remember", { text: "Lives in Poland." });

    const again = await t.callTool("remember", { text: "Lives in Poland." });

    expect(again.isError).toBe(false);
    expect(again.payload).toMatchObject({
      saved: false,
      duplicate: true,
      id: first.payload.id,
    });
    const envelope = (await (await t.ownerRead(MEMORY_SCOPE)).json()) as {
      data: { records: unknown[] };
    };
    expect(envelope.data.records).toHaveLength(1);
  });

  it("forgets a memory by key, and reports a miss without writing", async () => {
    const t = await setup([`write:${MEMORY_SCOPE}`]);
    await t.callTool("remember", { text: "Editor: Zed.", key: "editor" });
    const kept = await t.callTool("remember", { text: "Lives in Poland." });

    const forgotten = await t.callTool("forget", { key: "editor" });
    const miss = await t.callTool("forget", { key: "editor" });

    expect(forgotten.payload).toMatchObject({
      forgotten: true,
      memoryCount: 1,
    });
    expect(miss.isError).toBe(true);
    expect(miss.payload.error).toBe("not_found");
    const envelope = (await (await t.ownerRead(MEMORY_SCOPE)).json()) as {
      data: { records: Array<{ id: string }> };
    };
    expect(envelope.data.records.map((r) => r.id)).toEqual([kept.payload.id]);
  });

  it("converts an earlier memories list to records, keeping ids", async () => {
    const t = await setup([`write:${MEMORY_SCOPE}`]);
    expect(
      (
        await t.ownerWrite(MEMORY_SCOPE, {
          memories: [
            {
              id: "legacy-1",
              text: "Prefers pnpm.",
              savedAt: "2026-10-27T10:00:00.000Z",
            },
          ],
        })
      ).status,
    ).toBe(201);

    await t.callTool("remember", { text: "Lives in Poland." });

    const envelope = (await (await t.ownerRead(MEMORY_SCOPE)).json()) as {
      data: { records: Array<{ id: string; content: string }> };
    };
    expect(envelope.data.records.map((r) => [r.id, r.content])).toEqual([
      ["legacy-1", "Prefers pnpm."],
      [expect.any(String), "Lives in Poland."],
    ]);
  });

  it("defaults to the only writable scope when the agent names none", async () => {
    const t = await setup([`write:${MEMORY_SCOPE}`]);

    const result = await t.callTool("remember", { text: "Lives in Poland." });

    expect(result.isError).toBe(false);
    expect(result.payload.scope).toBe(MEMORY_SCOPE);
  });

  it("refuses a scope the connection holds no write grant for and names the scope to request", async () => {
    const t = await setup([MEMORY_SCOPE]);

    const result = await t.callTool("remember", {
      scope: MEMORY_SCOPE,
      text: "should not land",
    });

    expect(result.isError).toBe(true);
    expect(result.payload).toMatchObject({
      error: "scope_not_granted",
      requestScope: `write:${MEMORY_SCOPE}`,
    });
    expect((await t.ownerRead(MEMORY_SCOPE)).status).toBe(404);
  });

  it("re-checks the live grant, so a revoked grant stops the next save", async () => {
    const t = await setup([`write:${MEMORY_SCOPE}`]);
    t.revoke();

    const result = await t.callTool("remember", {
      scope: MEMORY_SCOPE,
      text: "should not land",
    });

    expect(result.isError).toBe(true);
    expect(result.payload.error).toBe("unauthorized");
    expect((await t.ownerRead(MEMORY_SCOPE)).status).toBe(404);
  });

  it("checks the live grant before reading, so a revoked grant learns nothing about the scope", async () => {
    const t = await setup([`write:${MEMORY_SCOPE}`]);
    expect(
      (await t.ownerWrite(MEMORY_SCOPE, { notes: "owner data" })).status,
    ).toBe(201);
    t.revoke();

    const result = await t.callTool("remember", {
      scope: MEMORY_SCOPE,
      text: "probe",
    });

    expect(result.isError).toBe(true);
    // Not scope_not_memory: that would reveal what the scope holds.
    expect(result.payload.error).toBe("unauthorized");
  });

  it("honors only an exact write grant, never a write wildcard", async () => {
    const t = await setup(["write:memory.*"]);

    const result = await t.callTool("remember", {
      scope: MEMORY_SCOPE,
      text: "should not land",
    });

    expect(result.isError).toBe(true);
    expect(result.payload.error).toBe("scope_not_granted");
    expect((await t.ownerRead(MEMORY_SCOPE)).status).toBe(404);
  });

  it("will not overwrite a scope that does not hold memories", async () => {
    const t = await setup([`write:${MEMORY_SCOPE}`]);
    await t.callTool("remember", { scope: MEMORY_SCOPE, text: "first" });
    // The owner replaces the scope with something that is not a memory list.
    const ownerWrite = await t.ownerWrite(MEMORY_SCOPE, {
      notes: "owner data",
    });
    expect(ownerWrite.status).toBe(201);

    const result = await t.callTool("remember", {
      scope: MEMORY_SCOPE,
      text: "second",
    });

    expect(result.isError).toBe(true);
    expect(result.payload.error).toBe("scope_not_memory");
  });

  it("lets a connection with a read grant recall what was saved", async () => {
    const t = await setup([`write:${MEMORY_SCOPE}`, "memory.*"]);
    await t.callTool("remember", {
      scope: MEMORY_SCOPE,
      text: "Allergic to peanuts.",
    });

    const recalled = await t.callTool("read_scope", { scope: MEMORY_SCOPE });

    expect(recalled.isError).toBe(false);
    const text = JSON.stringify(recalled.payload);
    expect(text).toContain("Allergic to peanuts.");
    // Server-stamped attribution is never served to a grantee.
    expect(text).not.toContain(WRITER_ATTRIBUTION_KEY);
  });

  it("lists write grants apart from readable scopes", async () => {
    const t = await setup([`write:${MEMORY_SCOPE}`, "memory.*"]);

    const listed = await t.callTool("list_granted_scopes", {});

    const scopes = (listed.payload.scopes as Array<{ scope: string }>).map(
      (s) => s.scope,
    );
    expect(scopes).toEqual(["memory.*"]);
    expect(listed.payload.writableScopes).toEqual([MEMORY_SCOPE]);
  });
});
