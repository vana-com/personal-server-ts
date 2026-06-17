import { describe, expect, it, vi } from "vitest";
import { createMcpDataReadClient, McpDataReadError } from "./read-client.js";
import { encodeDataBlockCursor } from "../storage/blocks/index.js";
import { buildBinaryEnvelopeData } from "../contracts/binary.js";

const SERVER_ORIGIN = "https://personal-server.test";

function createAccount() {
  return {
    address: "0x1111111111111111111111111111111111111111" as const,
    publicKey: "0x04deadbeef" as const,
    signTypedData: vi.fn(),
    signMessage: vi.fn().mockResolvedValue(`0x${"11".repeat(65)}`),
  };
}

describe("mcp/read-client", () => {
  it("reports metadata as block-ready only when the manifest exists", async () => {
    const hasScopeBlocks = vi.fn().mockResolvedValue(false);
    const client = createMcpDataReadClient({
      serverOrigin: SERVER_ORIGIN,
      granteeAccount: createAccount(),
      dataApiDeps: {
        storage: {
          kind: "custom",
          listScopes: () => ({ scopes: [], total: 0 }),
          listVersions: vi.fn(),
          countVersions: vi.fn(),
          findEntry: () =>
            ({
              scope: "instagram.profile",
              collectedAt: "2026-06-05T00:00:00Z",
              fileId: "file-1",
              sizeBytes: 10,
            }) as never,
          findByFileId: vi.fn(),
          findUnsynced: vi.fn(),
          readEnvelope: vi.fn(),
          readScopeBlocks: vi.fn(),
          hasScopeBlocks,
          writeEnvelope: vi.fn(),
          insertEntry: vi.fn(),
          updateFileId: vi.fn(),
          deleteScope: vi.fn(),
          deleteByFileId: vi.fn(),
        },
        auth: {
          authorizeOwner: vi.fn(),
          authorizeBuilderList: vi.fn(),
          authorizeBuilderRead: vi.fn(),
        },
        accessLogWriter: { write: vi.fn() },
      },
    });

    await expect(
      client.getScopeMetadata("instagram.profile"),
    ).resolves.toMatchObject({
      scope: "instagram.profile",
      hasBlocks: false,
    });
    expect(hasScopeBlocks).toHaveBeenCalledWith(
      "instagram.profile",
      "2026-06-05T00:00:00Z",
    );
  });

  it("returns a typed unavailable error when bounded scope data is missing", async () => {
    const readEnvelope = vi.fn();
    const client = createMcpDataReadClient({
      serverOrigin: SERVER_ORIGIN,
      granteeAccount: createAccount(),
      dataApiDeps: {
        storage: {
          kind: "custom",
          listScopes: () => ({ scopes: [], total: 0 }),
          listVersions: vi.fn(),
          countVersions: vi.fn(),
          findEntry: () =>
            ({
              scope: "instagram.profile",
              collectedAt: "2026-06-05T00:00:00Z",
              fileId: "file-1",
              sizeBytes: 10,
            }) as never,
          findByFileId: vi.fn(),
          findUnsynced: vi.fn(),
          readEnvelope,
          writeEnvelope: vi.fn(),
          insertEntry: vi.fn(),
          updateFileId: vi.fn(),
          deleteScope: vi.fn(),
          deleteByFileId: vi.fn(),
        },
        auth: {
          authorizeOwner: vi.fn(),
          authorizeBuilderList: vi.fn(),
          authorizeBuilderRead: vi.fn(),
        },
        accessLogWriter: { write: vi.fn() },
      },
    });

    await expect(
      client.readScopeBlocks({
        scope: "instagram.profile",
        grantId: "grant-1",
      }),
    ).rejects.toBeInstanceOf(McpDataReadError);

    try {
      await client.readScopeBlocks({
        scope: "instagram.profile",
        grantId: "grant-1",
      });
    } catch (err) {
      expect(err).toBeInstanceOf(McpDataReadError);
      expect((err as McpDataReadError).status).toBe(503);
      expect((err as McpDataReadError).body).toMatchObject({
        error: "BOUNDED_DATA_UNAVAILABLE",
      });
    }
    expect(readEnvelope).not.toHaveBeenCalled();
  });

  it("authorizes and access-logs successful bounded block reads", async () => {
    const accessLogWrite = vi.fn();
    const readFulfillmentReport = vi.fn().mockResolvedValue(undefined);
    const authorizeBuilderRead = vi
      .fn()
      .mockResolvedValue({ grantId: "grant-1", builder: "0x2222" });
    const readScopeBlocks = vi.fn().mockResolvedValue({
      scope: "instagram.profile",
      collectedAt: "2026-06-05T00:00:00Z",
      contentKind: "json",
      blocks: [
        {
          id: "block-1",
          path: "$.data",
          mediaType: "application/json",
          value: { username: "tim" },
          sizeBytes: 18,
        },
      ],
      warnings: [],
    });

    const client = createMcpDataReadClient({
      serverOrigin: SERVER_ORIGIN,
      granteeAccount: createAccount(),
      dataApiDeps: {
        storage: {
          kind: "custom",
          listScopes: () => ({ scopes: [], total: 0 }),
          listVersions: vi.fn(),
          countVersions: vi.fn(),
          findEntry: () =>
            ({
              scope: "instagram.profile",
              collectedAt: "2026-06-05T00:00:00Z",
              fileId: "file-1",
              sizeBytes: 10,
            }) as never,
          findByFileId: vi.fn(),
          findUnsynced: vi.fn(),
          readEnvelope: vi.fn(),
          readScopeBlocks,
          writeEnvelope: vi.fn(),
          insertEntry: vi.fn(),
          updateFileId: vi.fn(),
          deleteScope: vi.fn(),
          deleteByFileId: vi.fn(),
        },
        auth: {
          authorizeOwner: vi.fn(),
          authorizeBuilderList: vi.fn(),
          authorizeBuilderRead,
        },
        accessLogWriter: { write: accessLogWrite },
        readFulfillmentReporter: { report: readFulfillmentReport },
        now: () => new Date("2026-06-05T00:00:00Z"),
        createLogId: () => "log-1",
      },
    });

    await expect(
      client.readScopeBlocks({
        scope: "instagram.profile",
        grantId: "grant-1",
        maxBytes: 4096,
      }),
    ).resolves.toMatchObject({
      scope: "instagram.profile",
      blocks: [{ id: "block-1" }],
    });

    expect(authorizeBuilderRead).toHaveBeenCalledWith(
      expect.objectContaining({
        scope: "instagram.profile",
        grantId: "grant-1",
        fileId: "file-1",
      }),
    );
    expect(readScopeBlocks).toHaveBeenCalledWith(
      "instagram.profile",
      "2026-06-05T00:00:00Z",
      { cursor: undefined, maxBytes: 4096 },
    );
    expect(accessLogWrite).toHaveBeenCalledWith(
      expect.objectContaining({
        logId: "log-1",
        grantId: "grant-1",
        builder: "0x2222",
        action: "read",
        scope: "instagram.profile",
        timestamp: "2026-06-05T00:00:00.000Z",
      }),
    );
    expect(readFulfillmentReport).toHaveBeenCalledWith(
      expect.objectContaining({
        builder: "0x2222",
        fileId: "file-1",
        grantId: "grant-1",
        logId: "log-1",
        scope: "instagram.profile",
        servedAt: "2026-06-05T00:00:00.000Z",
      }),
    );
  });

  it("does not report fulfillment for partial bounded block pages", async () => {
    const accessLogWrite = vi.fn();
    const readFulfillmentReport = vi.fn().mockResolvedValue(undefined);
    const authorizeBuilderRead = vi
      .fn()
      .mockResolvedValue({ grantId: "grant-1", builder: "0x2222" });
    const nextCursor = encodeDataBlockCursor({
      scope: "instagram.profile",
      collectedAt: "2026-06-05T00:00:00Z",
      blockIndex: 1,
    });
    const readScopeBlocks = vi.fn().mockResolvedValue({
      scope: "instagram.profile",
      collectedAt: "2026-06-05T00:00:00Z",
      contentKind: "json",
      blocks: [],
      nextCursor,
      warnings: [],
    });

    const client = createMcpDataReadClient({
      serverOrigin: SERVER_ORIGIN,
      granteeAccount: createAccount(),
      dataApiDeps: {
        storage: {
          kind: "custom",
          listScopes: () => ({ scopes: [], total: 0 }),
          listVersions: vi.fn(),
          countVersions: vi.fn(),
          findEntry: () =>
            ({
              scope: "instagram.profile",
              collectedAt: "2026-06-05T00:00:00Z",
              fileId: "file-1",
              sizeBytes: 10,
            }) as never,
          findByFileId: vi.fn(),
          findUnsynced: vi.fn(),
          readEnvelope: vi.fn(),
          readScopeBlocks,
          writeEnvelope: vi.fn(),
          insertEntry: vi.fn(),
          updateFileId: vi.fn(),
          deleteScope: vi.fn(),
          deleteByFileId: vi.fn(),
        },
        auth: {
          authorizeOwner: vi.fn(),
          authorizeBuilderList: vi.fn(),
          authorizeBuilderRead,
        },
        accessLogWriter: { write: accessLogWrite },
        readFulfillmentReporter: { report: readFulfillmentReport },
      },
    });

    await expect(
      client.readScopeBlocks({
        scope: "instagram.profile",
        grantId: "grant-1",
        maxBytes: 4096,
      }),
    ).resolves.toMatchObject({ nextCursor });

    expect(accessLogWrite).toHaveBeenCalledTimes(1);
    expect(readFulfillmentReport).not.toHaveBeenCalled();
  });

  it("pins cursor reads to the version encoded in the cursor", async () => {
    const oldCollectedAt = "2026-06-05T00:00:00Z";
    const latestCollectedAt = "2026-06-06T00:00:00Z";
    const cursor = encodeDataBlockCursor({
      scope: "instagram.profile",
      collectedAt: oldCollectedAt,
      blockIndex: 1,
    });
    const findEntry = vi.fn(
      ({ at }: { at?: string }) =>
        ({
          scope: "instagram.profile",
          collectedAt: at ?? latestCollectedAt,
          fileId: at === oldCollectedAt ? "file-old" : "file-latest",
          sizeBytes: 10,
        }) as never,
    );
    const readScopeBlocks = vi.fn().mockResolvedValue({
      scope: "instagram.profile",
      collectedAt: oldCollectedAt,
      contentKind: "json",
      blocks: [],
      warnings: [],
    });

    const client = createMcpDataReadClient({
      serverOrigin: SERVER_ORIGIN,
      granteeAccount: createAccount(),
      dataApiDeps: {
        storage: {
          kind: "custom",
          listScopes: () => ({ scopes: [], total: 0 }),
          listVersions: vi.fn(),
          countVersions: vi.fn(),
          findEntry,
          findByFileId: vi.fn(),
          findUnsynced: vi.fn(),
          readEnvelope: vi.fn(),
          readScopeBlocks,
          writeEnvelope: vi.fn(),
          insertEntry: vi.fn(),
          updateFileId: vi.fn(),
          deleteScope: vi.fn(),
          deleteByFileId: vi.fn(),
        },
        auth: {
          authorizeOwner: vi.fn(),
          authorizeBuilderList: vi.fn(),
          authorizeBuilderRead: vi
            .fn()
            .mockResolvedValue({ grantId: "grant-1", builder: "0x2222" }),
        },
        accessLogWriter: { write: vi.fn() },
      },
    });

    await client.readScopeBlocks({
      scope: "instagram.profile",
      grantId: "grant-1",
      cursor,
    });

    expect(findEntry).toHaveBeenCalledWith({
      scope: "instagram.profile",
      at: oldCollectedAt,
    });
    expect(readScopeBlocks).toHaveBeenCalledWith(
      "instagram.profile",
      oldCollectedAt,
      { cursor, maxBytes: 16_384 },
    );
  });

  it("reads raw binary scopes through the grant-gated data API path", async () => {
    const bytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
    const authorizeBuilderRead = vi
      .fn()
      .mockResolvedValue({ grantId: "grant-1", builder: "0x2222" });
    const accessLogWrite = vi.fn();
    const client = createMcpDataReadClient({
      serverOrigin: SERVER_ORIGIN,
      granteeAccount: createAccount(),
      dataApiDeps: {
        storage: {
          kind: "custom",
          listScopes: () => ({ scopes: [], total: 0 }),
          listVersions: vi.fn(),
          countVersions: vi.fn(),
          findEntry: () =>
            ({
              scope: "manual.document",
              collectedAt: "2026-06-05T00:00:00Z",
              fileId: "file-1",
              sizeBytes: bytes.byteLength,
            }) as never,
          findByFileId: vi.fn(),
          findUnsynced: vi.fn(),
          readEnvelope: vi.fn().mockResolvedValue({
            $schema: "https://example.test/schema.json",
            version: "1.0",
            scope: "manual.document",
            schemaId: "schema-1",
            collectedAt: "2026-06-05T00:00:00Z",
            data: buildBinaryEnvelopeData({
              bytes,
              mimeType: "application/pdf",
              filename: "scan.pdf",
              contentHash: `0x${"1".repeat(64)}`,
              metadata: { source: "manual" },
            }),
          } as never),
          readScopeBlocks: vi.fn(),
          writeEnvelope: vi.fn(),
          insertEntry: vi.fn(),
          updateFileId: vi.fn(),
          deleteScope: vi.fn(),
          deleteByFileId: vi.fn(),
        },
        auth: {
          authorizeOwner: vi.fn(),
          authorizeBuilderList: vi.fn(),
          authorizeBuilderRead,
        },
        accessLogWriter: { write: accessLogWrite },
        now: () => new Date("2026-06-05T00:00:00Z"),
        createLogId: () => "log-1",
      },
    });

    await expect(
      client.readRawScopeFile({
        scope: "manual.document",
        grantId: "grant-1",
      }),
    ).resolves.toMatchObject({
      scope: "manual.document",
      mimeType: "application/pdf",
      filename: "scan.pdf",
      sizeBytes: bytes.byteLength,
      contentBase64: "JVBERg==",
      metadata: { source: "manual" },
    });
    expect(authorizeBuilderRead).toHaveBeenCalledWith(
      expect.objectContaining({
        scope: "manual.document",
        grantId: "grant-1",
        fileId: "file-1",
      }),
    );
    expect(accessLogWrite).toHaveBeenCalledWith(
      expect.objectContaining({
        logId: "log-1",
        grantId: "grant-1",
        builder: "0x2222",
        action: "read",
        scope: "manual.document",
      }),
    );
  });
});
