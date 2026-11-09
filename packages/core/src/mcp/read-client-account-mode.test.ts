import { describe, expect, it, vi } from "vitest";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createAccountStorageMode } from "../api/account-storage-mode.js";
import { ProtocolError } from "../errors/catalog.js";
import { Fixture, masterKey } from "../stream-sync-read/service-fixture.js";
import { testOwnerKey } from "../stream-sync-read/testing.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { buildDataBlocksAsync } from "../storage/blocks/build.js";
import { readBuiltScopeBlocks } from "../storage/blocks/page.js";
import { createMcpDataReadClient, McpDataReadError } from "./read-client.js";
import { createMcpSessionAuthPort } from "./session.js";
import { createMcpDataWriteClient } from "./write-client.js";
import { MCP_TOOLS } from "./tools.js";
import { readRawScopeResource } from "./resources.js";
import type { McpConnectionRecord } from "./types.js";
import type { McpDataReadClient } from "./read-client.js";

/**
 * MCP reads follow the account's storage mode, never the presence of a stream
 * reader. A switched account is answered from stream data only: no call
 * reaches legacy storage, and what streams cannot answer is refused with a
 * typed error. An unswitched account behaves as before the switch existed.
 *
 * Every MCP entry is driven through production code against a storage spy that
 * records each call, holding legacy data that no stream carries.
 */

const SERVER_ORIGIN = "https://personal-server.test";
const OWNER = "0x0000000000000000000000000000000000000aaa";
const BUILDER = "0x2222222222222222222222222222222222222222" as const;
const GRANT_ID = `0x${"ab".repeat(32)}`;
const LEGACY_SCOPE = "instagram.profile";
const LEGACY_TEXT = "legacy-only-marker-7731";
const STREAM_SCOPE = "pdpp.acme.items";
const COLLECTED_AT = "2026-06-05T00:00:00Z";
const T = Date.parse("2026-11-01T00:00:00Z");
const RECORDS = Array.from({ length: 3 }, (_, i) => ({
  id: `item-${i}`,
  text: `stream record ${i} with a few words of body text`,
}));
const ASSET = "0x0000000000000000000000000000000000000fee";
const GATEWAY_CONFIG = {
  chainId: 14800,
  contracts: {
    dataRegistry: "0x0000000000000000000000000000000000000001",
    dataPortabilityPermissions: "0x0000000000000000000000000000000000000002",
    dataPortabilityServer: "0x0000000000000000000000000000000000000003",
    dataPortabilityGrantees: "0x0000000000000000000000000000000000000004",
  },
} as never;

type ModeKind = "switched" | "unswitched" | "unknown" | "unwired";
type ReaderKind = "stream" | "pass" | "absent";

function granteeAccount() {
  return {
    address: "0x1111111111111111111111111111111111111111" as const,
    publicKey: "0x04deadbeef" as const,
    signTypedData: vi.fn(),
    signMessage: vi.fn().mockResolvedValue(`0x${"11".repeat(65)}`),
  };
}

function connection(scopes: string[]): McpConnectionRecord {
  return {
    id: "conn-1",
    displayName: "Test client",
    granteeAddress: "0x1111111111111111111111111111111111111111",
    granteePublicKey: "0x04deadbeef",
    encryptedGranteePrivateKey: { kind: "plaintext", privateKey: "0x22" },
    tokenHash: "token-hash",
    status: "approved",
    grants: [{ grantId: GRANT_ID, scopes }],
    createdAt: COLLECTED_AT,
    approvedAt: COLLECTED_AT,
  } as never;
}

/** Every function call on the wrapped storage, by method name. */
function spyOn<T extends object>(inner: T) {
  const calls: string[] = [];
  const spy = new Proxy(inner, {
    get(target, prop) {
      const value = Reflect.get(target, prop, target);
      if (typeof value !== "function") return value;
      return (...args: unknown[]) => {
        calls.push(String(prop));
        return (value as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
  });
  return { spy, calls };
}

async function harness(
  options: {
    mode?: ModeKind;
    reader?: ReaderKind;
    legacy?: boolean;
  } = {},
) {
  const mode = options.mode ?? "switched";
  const reader = options.reader ?? "stream";
  const inner = createMemoryDataStorage();
  const envelope = {
    version: "1.0",
    scope: LEGACY_SCOPE,
    collectedAt: COLLECTED_AT,
    data: { items: [{ id: "legacy-0", text: LEGACY_TEXT }] },
  };
  Object.assign(inner, {
    hasScopeBlocks: async () => true,
    readScopeBlocks: async (
      scope: string,
      collectedAt: string,
      opts: Parameters<typeof readBuiltScopeBlocks>[1],
    ) =>
      readBuiltScopeBlocks(
        await buildDataBlocksAsync({ scope, collectedAt, content: envelope }),
        opts,
      ),
    readBlockManifest: async (scope: string, collectedAt: string) =>
      (await buildDataBlocksAsync({ scope, collectedAt, content: envelope }))
        .manifest,
  });
  if (options.legacy ?? true) {
    const written = await inner.writeEnvelope(envelope as never);
    inner.insertEntry({
      fileId: "file-1",
      path: written.path,
      scope: LEGACY_SCOPE,
      collectedAt: COLLECTED_AT,
      sizeBytes: written.sizeBytes,
      dataPointId: null,
    } as never);
  }
  const { spy: storage, calls } = spyOn(inner);

  let streamSyncRead: unknown;
  if (reader === "stream") {
    const f = new Fixture(await testOwnerKey(masterKey(341)));
    const ns = await f.key.ns("acme", "account-1");
    await f.activate("acme", ns);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: RECORDS,
      observedAt: T - 1000,
      profileVersion: "1.0.0",
    });
    const service = await f.service();
    await f.sync(service);
    streamSyncRead = service;
  } else if (reader === "pass") {
    streamSyncRead = { resolve: async () => ({ kind: "pass" }) };
  }

  const accessLogWrite = vi.fn();
  const auth = {
    authorizeOwner: vi.fn(),
    authorizeBuilderList: async () => ({
      grantedScopes: [LEGACY_SCOPE, STREAM_SCOPE, "instagram.*", "pdpp.*"],
    }),
    authorizeBuilderRead: async () => ({ builder: BUILDER, grantId: GRANT_ID }),
  };
  const accountStorageMode =
    mode === "unwired"
      ? undefined
      : createAccountStorageMode({
          source: () => {
            if (mode === "unknown") throw new Error("account unreachable");
            return mode === "switched";
          },
        });
  const deps = {
    storage,
    ...(streamSyncRead ? { streamSyncRead } : {}),
    ...(accountStorageMode ? { accountStorageMode } : {}),
    auth,
    accessLogWriter: { write: accessLogWrite },
    serverOwner: OWNER,
  } as never as Parameters<typeof createMcpDataReadClient>[0]["dataApiDeps"];
  const client = createMcpDataReadClient({
    serverOrigin: SERVER_ORIGIN,
    granteeAccount: granteeAccount() as never,
    dataApiDeps: deps,
  });
  return { client, deps, calls, storage, accessLogWrite, accountStorageMode };
}

type Harness = Awaited<ReturnType<typeof harness>>;

/** Every read entry of the client, aimed at the legacy-only scope. */
const LEGACY_ENTRIES: Record<
  string,
  (client: McpDataReadClient) => Promise<unknown>
> = {
  getScopeMetadata: (c) => c.getScopeMetadata(LEGACY_SCOPE, GRANT_ID),
  readScopeBlocks: (c) =>
    c.readScopeBlocks({ scope: LEGACY_SCOPE, grantId: GRANT_ID }),
  readBlockManifest: (c) =>
    c.readBlockManifest!({ scope: LEGACY_SCOPE, grantId: GRANT_ID }),
  readRawScopeFile: (c) =>
    c.readRawScopeFile({ scope: LEGACY_SCOPE, grantId: GRANT_ID }),
  readRawScopeFileAt: (c) =>
    c.readRawScopeFile({
      scope: LEGACY_SCOPE,
      grantId: GRANT_ID,
      at: COLLECTED_AT,
      fileId: "file-1",
    }),
  listScopes: (c) => c.listScopes({ grantId: GRANT_ID }),
};

/** The outcome of an entry, whatever it is, as text. */
async function outcome(run: () => Promise<unknown>): Promise<string> {
  try {
    return JSON.stringify(await run());
  } catch (err) {
    return err instanceof McpDataReadError
      ? `${err.status} ${JSON.stringify(err.body)}`
      : String(err);
  }
}

function textOf(result: { content: { type: string; text?: string }[] }) {
  return result.content.map((part) => part.text ?? "").join("\n");
}

function tool(name: string) {
  const found = MCP_TOOLS.find((candidate) => candidate.name === name);
  if (!found) throw new Error(`missing tool ${name}`);
  return found;
}

describe("LEGACY_ON_SWITCH_MCP: a switched account never reads legacy storage", () => {
  for (const [name, run] of Object.entries(LEGACY_ENTRIES)) {
    it(`${name}: stream reader wired, data only in legacy storage`, async () => {
      const h = await harness({ mode: "switched", reader: "pass" });
      const result = await outcome(() => run(h.client));
      expect(h.calls).toEqual([]);
      expect(result).not.toContain(LEGACY_TEXT);
    });

    it(`${name}: no stream reader is a typed refusal, not legacy`, async () => {
      const h = await harness({ mode: "switched", reader: "absent" });
      const result = await outcome(() => run(h.client));
      expect(h.calls).toEqual([]);
      expect(result).toContain("STREAM_SYNC_READS_UNAVAILABLE");
      expect(result).not.toContain(LEGACY_TEXT);
    });

    it(`${name}: an unknown mode is the selector's retryable refusal`, async () => {
      const h = await harness({ mode: "unknown", reader: "stream" });
      const result = await outcome(() => run(h.client));
      expect(h.calls).toEqual([]);
      expect(result).toContain("ACCOUNT_MODE_UNKNOWN");
    });
  }

  it("a legacy-only scope is absent from discovery and from the listing", async () => {
    const h = await harness({ mode: "switched", reader: "pass" });
    await expect(
      h.client.getScopeMetadata(LEGACY_SCOPE, GRANT_ID),
    ).resolves.toBeNull();
    const listed = await h.client.listScopes({ grantId: GRANT_ID });
    expect(listed.scopes.map((s) => s.scope)).not.toContain(LEGACY_SCOPE);
    expect(h.calls).toEqual([]);
  });

  describe("through the tools and resources", () => {
    const scopes = [LEGACY_SCOPE, "instagram.*"];
    const run = async (
      h: Harness,
      name: string,
      args: Record<string, unknown>,
      readClient: McpDataReadClient = h.client,
    ) =>
      textOf(
        (await tool(name).handler(args, {
          connection: connection(scopes),
          readClient,
        })) as never,
      );

    it("list_granted_scopes reports nothing ready for a legacy-only scope", async () => {
      const h = await harness({ mode: "switched", reader: "pass" });
      const text = await run(h, "list_granted_scopes", {});
      expect(h.calls).toEqual([]);
      expect(text).not.toContain(LEGACY_TEXT);
      expect(text).not.toContain('"dataStatus":"ready"');
    });

    it("read_scope and list_scope_blocks serve nothing from legacy", async () => {
      const h = await harness({ mode: "switched", reader: "pass" });
      const read = await run(h, "read_scope", { scope: LEGACY_SCOPE });
      const blocks = await run(h, "list_scope_blocks", { scope: LEGACY_SCOPE });
      expect(h.calls).toEqual([]);
      expect(read).not.toContain(LEGACY_TEXT);
      expect(blocks).not.toContain(LEGACY_TEXT);
    });

    it("get_scope_file and resources/read serve nothing from legacy", async () => {
      const h = await harness({ mode: "switched", reader: "pass" });
      const file = await run(h, "get_scope_file", { scope: LEGACY_SCOPE });
      const resource = await readRawScopeResource(
        new URL(`vana://scope/${LEGACY_SCOPE}/raw`),
        { connection: connection(scopes), readClient: h.client },
      ).then(
        (r) => JSON.stringify(r),
        (e) => String(e?.message ?? e),
      );
      expect(h.calls).toEqual([]);
      expect(file).not.toContain(LEGACY_TEXT);
      expect(resource).not.toContain(LEGACY_TEXT);
    });

    it("search_personal_context, wildcard and named, never reaches legacy or the index shortcut", async () => {
      const h = await harness({ mode: "switched", reader: "pass" });
      const searchScopeIndex = vi.fn().mockResolvedValue({
        status: "hit",
        hits: [{ preview: LEGACY_TEXT, blockRef: "b", score: 1, terms: [] }],
      });
      const indexed = { ...h.client, searchScopeIndex } as McpDataReadClient;
      for (const scope of scopes) {
        const text = await run(
          h,
          "search_personal_context",
          { query: "marker", scopes: [scope] },
          indexed,
        );
        expect(text).not.toContain(LEGACY_TEXT);
      }
      expect(searchScopeIndex).not.toHaveBeenCalled();
      expect(h.calls).toEqual([]);
    });
  });

  describe("settlement of a paid session", () => {
    async function session(mode: ModeKind) {
      const h = await harness({ mode, reader: "stream" });
      const serverAccount = privateKeyToAccount(generatePrivateKey());
      const gatewayGrant = {
        id: GRANT_ID,
        grantorAddress: OWNER,
        granteeId: BUILDER,
        scopes: [LEGACY_SCOPE, STREAM_SCOPE],
        revokedAt: null,
        expiresAt: null,
        paymentStatus: "paid",
        fee: { totalDue: "100", asset: ASSET },
      };
      const gateway = {
        getBuilder: async () => ({ id: BUILDER }),
        getGrant: async () => gatewayGrant,
      };
      const paymentDeps = {
        ...h.deps,
        serverAddress: serverAccount.address,
        serverSigner: {
          signRecordDataAccess: async () => `0x${"11".repeat(65)}`,
        },
        paymentFetch: vi.fn(async () => new Response("{}", { status: 200 })),
      } as never;
      const port = createMcpSessionAuthPort({
        builderAddress: BUILDER,
        grantId: GRANT_ID,
        authSessionVerifier: gateway as never,
        grantVerifier: gateway as never,
        serverOwner: OWNER,
        payment: {
          dataApiDeps: paymentDeps,
          gateway: gateway as never,
          gatewayConfig: GATEWAY_CONFIG,
          gatewayUrl: "https://gateway.test",
        },
      });
      const request = new Request(`${SERVER_ORIGIN}/v1/data/${STREAM_SCOPE}`);
      return { h, port, request };
    }

    it("names the served stream head and looks nothing up in legacy storage", async () => {
      const { h, port, request } = await session("switched");
      const error = await port
        .authorizeBuilderRead({
          request,
          scope: STREAM_SCOPE,
          grantId: GRANT_ID,
          servedEntry: { scope: STREAM_SCOPE, version: 3 },
        } as never)
        .catch((e) => e);
      // The paid read is challenged against the head it will serve.
      expect(error).toBeInstanceOf(ProtocolError);
      expect((error as ProtocolError).errorCode).toBe("PAYMENT_REQUIRED");
      expect(h.calls).toEqual([]);
    });

    it("refuses a settlement that names no served head instead of finding a legacy entry", async () => {
      const { h, port, request } = await session("switched");
      const error = await port
        .authorizeBuilderRead({
          request,
          scope: LEGACY_SCOPE,
          grantId: GRANT_ID,
        } as never)
        .catch((e) => e);
      expect(error).toBeInstanceOf(ProtocolError);
      expect((error as ProtocolError).errorCode).not.toBe("PAYMENT_REQUIRED");
      expect(h.calls).toEqual([]);
    });

    it("an unknown mode refuses a settlement with no served head", async () => {
      const { h, port, request } = await session("unknown");
      const error = await port
        .authorizeBuilderRead({
          request,
          scope: LEGACY_SCOPE,
          grantId: GRANT_ID,
        } as never)
        .catch((e) => e);
      expect((error as ProtocolError).errorCode).toBe("ACCOUNT_MODE_UNKNOWN");
      expect(h.calls).toEqual([]);
    });

    it("an unswitched session still binds the payment to the legacy entry", async () => {
      const { h, port, request } = await session("unswitched");
      const error = await port
        .authorizeBuilderRead({
          request,
          scope: LEGACY_SCOPE,
          grantId: GRANT_ID,
        } as never)
        .catch((e) => e);
      expect((error as ProtocolError).errorCode).toBe("PAYMENT_REQUIRED");
      expect(h.calls).toContain("findEntry");
    });
  });
});

describe("STREAM_SERVED_MCP: a switched account is answered from its stream head", () => {
  it("serves metadata, blocks and the manifest from the stream, with no legacy call", async () => {
    const h = await harness({ mode: "switched", reader: "stream" });
    const meta = await h.client.getScopeMetadata(STREAM_SCOPE, GRANT_ID);
    const page = await h.client.readScopeBlocks({
      scope: STREAM_SCOPE,
      grantId: GRANT_ID,
    });
    const manifest = await h.client.readBlockManifest!({
      scope: STREAM_SCOPE,
      grantId: GRANT_ID,
    });
    expect(meta).toMatchObject({ scope: STREAM_SCOPE, hasBlocks: true });
    expect(JSON.stringify(page)).toContain("stream record 0");
    expect(manifest?.blocks.length).toBeGreaterThan(0);
    expect(h.calls).toEqual([]);
  });

  it("serves the tools from the stream: read_scope, list_scope_blocks, list_granted_scopes", async () => {
    const h = await harness({ mode: "switched", reader: "stream" });
    const ctx = {
      connection: connection([STREAM_SCOPE]),
      readClient: h.client,
    };
    const read = textOf(
      (await tool("read_scope").handler({ scope: STREAM_SCOPE }, ctx)) as never,
    );
    const toc = textOf(
      (await tool("list_scope_blocks").handler(
        { scope: STREAM_SCOPE },
        ctx,
      )) as never,
    );
    const listed = textOf(
      (await tool("list_granted_scopes").handler({}, ctx)) as never,
    );
    expect(read).toContain("stream record 0");
    expect(toc).toContain(STREAM_SCOPE);
    expect(listed).toContain('"dataStatus":"ready"');
    expect(h.calls).toEqual([]);
  });

  it("search_personal_context finds stream records without the index shortcut", async () => {
    const h = await harness({ mode: "switched", reader: "stream" });
    const searchScopeIndex = vi.fn();
    const text = textOf(
      (await tool("search_personal_context").handler(
        { query: "stream record 1", scopes: [STREAM_SCOPE] },
        {
          connection: connection([STREAM_SCOPE]),
          readClient: { ...h.client, searchScopeIndex } as McpDataReadClient,
        },
      )) as never,
    );
    expect(text).toContain("stream record 1");
    expect(searchScopeIndex).not.toHaveBeenCalled();
    expect(h.calls).toEqual([]);
  });
});

describe("UNSWITCHED_PARITY_MCP: before the switch nothing changes", () => {
  it.each<[string, ModeKind]>([
    ["an unswitched account", "unswitched"],
    ["a host with no mode wired", "unwired"],
  ])(
    "%s reads legacy storage when no stream reader is wired",
    async (_n, mode) => {
      const h = await harness({ mode, reader: "absent" });
      const meta = await h.client.getScopeMetadata(LEGACY_SCOPE, GRANT_ID);
      const page = await h.client.readScopeBlocks({
        scope: LEGACY_SCOPE,
        grantId: GRANT_ID,
      });
      const manifest = await h.client.readBlockManifest!({
        scope: LEGACY_SCOPE,
        grantId: GRANT_ID,
      });
      expect(meta).toMatchObject({ scope: LEGACY_SCOPE, hasBlocks: true });
      expect(JSON.stringify(page)).toContain(LEGACY_TEXT);
      expect(manifest).not.toBeNull();
      expect(h.calls).toEqual(
        expect.arrayContaining(["findEntry", "readScopeBlocks"]),
      );
    },
  );

  it("an unswitched account with a stream reader still takes the reader's path, as before", async () => {
    const h = await harness({ mode: "unswitched", reader: "stream" });
    const page = await h.client.readScopeBlocks({
      scope: STREAM_SCOPE,
      grantId: GRANT_ID,
    });
    expect(JSON.stringify(page)).toContain("stream record 0");
  });

  it("an unswitched account keeps the index shortcut", async () => {
    const h = await harness({ mode: "unswitched", reader: "absent" });
    const searchScopeIndex = vi.fn().mockResolvedValue({
      status: "hit",
      hits: [{ preview: "indexed hit", blockRef: "b", score: 1, terms: [] }],
    });
    const text = textOf(
      (await tool("search_personal_context").handler(
        { query: "indexed", scopes: [LEGACY_SCOPE] },
        {
          connection: connection([LEGACY_SCOPE]),
          readClient: { ...h.client, searchScopeIndex } as McpDataReadClient,
        },
      )) as never,
    );
    expect(searchScopeIndex).toHaveBeenCalled();
    expect(text).toContain("indexed hit");
  });

  it("an unknown mode skips the index shortcut", async () => {
    const h = await harness({ mode: "unknown", reader: "stream" });
    const searchScopeIndex = vi.fn();
    await tool("search_personal_context").handler(
      { query: "x", scopes: [LEGACY_SCOPE] },
      {
        connection: connection([LEGACY_SCOPE]),
        readClient: { ...h.client, searchScopeIndex } as McpDataReadClient,
      },
    );
    expect(searchScopeIndex).not.toHaveBeenCalled();
  });
});

describe("MEMORY_READBACK: remember and forget read back through the account mode", () => {
  async function writer(mode: ModeKind) {
    const h = await harness({ mode, reader: "stream" });
    const dispatch = vi.fn(
      async () =>
        new Response(JSON.stringify({ collectedAt: COLLECTED_AT }), {
          status: 201,
        }),
    );
    const create = vi.fn();
    const client = createMcpDataWriteClient({
      serverOrigin: SERVER_ORIGIN,
      granteeAccount: granteeAccount() as never,
      storage: h.storage,
      sessionStore: { create } as never,
      dispatch,
      authorize: async () => {},
      accountStorage: { accountStorageMode: h.accountStorageMode },
    } as never);
    return { h, client, dispatch, create };
  }

  it("a switched account is refused before legacy storage is read or anything is written", async () => {
    const { h, client, dispatch, create } = await writer("switched");
    const update = vi.fn(() => ({}));
    await expect(
      client.updateScope({ scope: LEGACY_SCOPE, grantId: GRANT_ID, update }),
    ).rejects.toMatchObject({
      status: 409,
      body: { error: { errorCode: "STREAM_SYNC_WRITE_UNAVAILABLE" } },
    });
    expect(h.calls).toEqual([]);
    expect(update).not.toHaveBeenCalled();
    expect(dispatch).not.toHaveBeenCalled();
    expect(create).not.toHaveBeenCalled();
  });

  it("an unknown mode is the selector's retryable refusal", async () => {
    const { h, client, dispatch } = await writer("unknown");
    await expect(
      client.updateScope({
        scope: LEGACY_SCOPE,
        grantId: GRANT_ID,
        update: () => ({}),
      }),
    ).rejects.toMatchObject({
      status: 503,
      body: { error: { errorCode: "ACCOUNT_MODE_UNKNOWN" } },
    });
    expect(h.calls).toEqual([]);
    expect(dispatch).not.toHaveBeenCalled();
  });

  it("an unswitched account reads the legacy record and writes, as before", async () => {
    const { h, client, dispatch } = await writer("unswitched");
    const update = vi.fn(
      (current: { data: Record<string, unknown> | null }) => ({
        seen: JSON.stringify(current.data),
      }),
    );
    const result = await client.updateScope({
      scope: LEGACY_SCOPE,
      grantId: GRANT_ID,
      update,
    });
    expect(result.status).toBe(201);
    expect(update.mock.results[0]?.value.seen).toContain(LEGACY_TEXT);
    expect(h.calls).toEqual(
      expect.arrayContaining(["findEntry", "readEnvelope"]),
    );
    expect(dispatch).toHaveBeenCalledTimes(1);
  });
});
