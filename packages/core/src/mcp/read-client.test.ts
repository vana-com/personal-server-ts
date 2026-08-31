import { describe, expect, it, vi } from "vitest";
import { createMcpDataReadClient, McpDataReadError } from "./read-client.js";
import { encodeDataBlockCursor } from "../storage/blocks/index.js";
import { buildBinaryEnvelopeData } from "../contracts/binary.js";
import { createScopeDeletionTracker } from "../sync/scope-deletions.js";

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

  it("passes blockIds to storage and does not report a block-addressed read as fulfillment", async () => {
    const accessLogWrite = vi.fn();
    const readFulfillmentReport = vi.fn().mockResolvedValue(undefined);
    const readScopeBlocks = vi.fn().mockResolvedValue({
      scope: "instagram.profile",
      collectedAt: "2026-06-05T00:00:00Z",
      contentKind: "json",
      blocks: [
        {
          id: "block-42",
          path: "$.items[41]",
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
          authorizeBuilderRead: vi
            .fn()
            .mockResolvedValue({ grantId: "grant-1", builder: "0x2222" }),
        },
        accessLogWriter: { write: accessLogWrite },
        readFulfillmentReporter: { report: readFulfillmentReport },
      },
    });

    await client.readScopeBlocks({
      scope: "instagram.profile",
      grantId: "grant-1",
      maxBytes: 4096,
      blockIds: ["block-42"],
    });

    expect(readScopeBlocks).toHaveBeenCalledWith(
      "instagram.profile",
      "2026-06-05T00:00:00Z",
      { cursor: undefined, maxBytes: 4096, blockIds: ["block-42"] },
    );
    expect(accessLogWrite).toHaveBeenCalledTimes(1);
    expect(readFulfillmentReport).not.toHaveBeenCalled();
  });

  it("grant-gates and access-logs block manifest reads", async () => {
    const accessLogWrite = vi.fn();
    const authorizeBuilderRead = vi
      .fn()
      .mockResolvedValue({ grantId: "grant-1", builder: "0x2222" });
    const manifest = {
      version: 1 as const,
      scope: "instagram.profile",
      collectedAt: "2026-06-05T00:00:00Z",
      contentKind: "json" as const,
      blocks: [
        {
          id: "block-1",
          path: "$.items[0]",
          mediaType: "application/json",
          sizeBytes: 18,
        },
      ],
      warnings: [],
    };

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
          readBlockManifest: vi.fn().mockResolvedValue(manifest),
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
      },
    });

    await expect(
      client.readBlockManifest?.({
        scope: "instagram.profile",
        grantId: "grant-1",
      }),
    ).resolves.toMatchObject({ blocks: [{ id: "block-1" }] });

    expect(authorizeBuilderRead).toHaveBeenCalledWith(
      expect.objectContaining({
        scope: "instagram.profile",
        grantId: "grant-1",
      }),
    );
    expect(accessLogWrite).toHaveBeenCalledWith(
      expect.objectContaining({ action: "read", scope: "instagram.profile" }),
    );
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

  it("does not report fulfillment for cursor bounded block reads", async () => {
    const accessLogWrite = vi.fn();
    const readFulfillmentReport = vi.fn().mockResolvedValue(undefined);
    const authorizeBuilderRead = vi
      .fn()
      .mockResolvedValue({ grantId: "grant-1", builder: "0x2222" });
    const cursor = encodeDataBlockCursor({
      scope: "instagram.profile",
      collectedAt: "2026-06-05T00:00:00Z",
      blockIndex: 99,
    });
    const readScopeBlocks = vi.fn().mockResolvedValue({
      scope: "instagram.profile",
      collectedAt: "2026-06-05T00:00:00Z",
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
        cursor,
      }),
    ).resolves.toMatchObject({
      blocks: [],
    });

    expect(accessLogWrite).toHaveBeenCalledTimes(1);
    expect(readFulfillmentReport).not.toHaveBeenCalled();
  });

  it("pins cursor reads to the version encoded in the cursor", async () => {
    const authorizeBuilderRead = vi
      .fn()
      .mockResolvedValue({ grantId: "grant-1", builder: "0x2222" });
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
          authorizeBuilderRead,
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
    // The auth port sees the pinned version too, so a payment-enforcing port
    // (paid self-signing session) settles against the version actually served.
    expect(authorizeBuilderRead).toHaveBeenCalledWith(
      expect.objectContaining({ at: oldCollectedAt }),
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

describe("mcp/read-client deletion gate", () => {
  const SCOPE = "instagram.profile";

  function deletedScopeClient() {
    const tracker = createScopeDeletionTracker({
      serverOwner: "0x2222222222222222222222222222222222222222",
    });
    // What the sync feed (or this replica's own delete) recorded.
    tracker.markDeleted(SCOPE, {
      deletedAt: "2099-01-01T00:00:00.000Z",
      version: "4",
    });
    const authorizeBuilderRead = vi.fn();
    const readScopeBlocks = vi.fn();
    const readBlockManifest = vi.fn();
    const client = createMcpDataReadClient({
      serverOrigin: SERVER_ORIGIN,
      granteeAccount: createAccount(),
      dataApiDeps: {
        storage: {
          kind: "custom",
          listScopes: () => ({ scopes: [], total: 0 }),
          listVersions: vi.fn(),
          countVersions: vi.fn(),
          // A stale local copy from before the deletion.
          findEntry: () =>
            ({
              scope: SCOPE,
              collectedAt: "2026-06-05T00:00:00Z",
              createdAt: "2026-06-05T00:00:00Z",
              fileId: "file-1",
              sizeBytes: 10,
              version: 1,
              dataPointId: null,
            }) as never,
          findByFileId: vi.fn(),
          findUnsynced: vi.fn(),
          readEnvelope: vi.fn(),
          readScopeBlocks,
          readBlockManifest,
          hasScopeBlocks: vi.fn().mockResolvedValue(true),
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
        accessLogWriter: { write: vi.fn() },
        serverOwner: "0x2222222222222222222222222222222222222222",
        scopeDeletions: tracker,
      },
    });
    return { client, authorizeBuilderRead, readScopeBlocks, readBlockManifest };
  }

  it("reports a deleted scope as absent for discovery", async () => {
    const { client } = deletedScopeClient();
    await expect(client.getScopeMetadata(SCOPE)).resolves.toBeNull();
  });

  it("refuses bounded reads of a deleted scope before auth or payment run", async () => {
    const { client, authorizeBuilderRead, readScopeBlocks } =
      deletedScopeClient();

    await expect(
      client.readScopeBlocks({ scope: SCOPE, grantId: "grant-1" }),
    ).rejects.toMatchObject({
      status: 410,
      body: { error: { errorCode: "DATA_DELETED" } },
    });
    expect(authorizeBuilderRead).not.toHaveBeenCalled();
    expect(readScopeBlocks).not.toHaveBeenCalled();
  });

  it("refuses the block manifest of a deleted scope", async () => {
    const { client, authorizeBuilderRead, readBlockManifest } =
      deletedScopeClient();

    await expect(
      client.readBlockManifest({ scope: SCOPE, grantId: "grant-1" }),
    ).rejects.toMatchObject({ status: 410 });
    expect(authorizeBuilderRead).not.toHaveBeenCalled();
    expect(readBlockManifest).not.toHaveBeenCalled();
  });

  describe("server-stamped key redaction on block reads", () => {
    const STAMPED_BLOCKS = [
      {
        id: "b-data",
        path: "$.data",
        mediaType: "application/json",
        value: {
          note: "hello",
          lineage: ["0xsource"],
          metadata: { description: "d", lineage: ["0xsource"] },
          $lineage: { sources: ["0xsource"], writtenAt: "2026-06-05" },
          $writtenBy: { builder: "0xbeef", grantId: "g-w" },
        },
        sizeBytes: 200,
      },
      {
        id: "b-written",
        path: "$.data.$writtenBy",
        mediaType: "application/json",
        value: { builder: "0xbeef", grantId: "g-w" },
        sizeBytes: 40,
      },
      {
        id: "b-lin",
        path: "$.data.$lineage.sources[0:1]",
        mediaType: "application/json",
        value: ["0xsource"],
        sizeBytes: 20,
      },
      {
        id: "b-caller-lin",
        path: "$.data.lineage",
        mediaType: "application/json",
        value: ["0xsource"],
        sizeBytes: 20,
      },
      {
        id: "b-group",
        path: "$.data.{$lineage:note}",
        mediaType: "application/json",
        value: {
          $lineage: { sources: ["0xsource"] },
          lineage: ["0xsource"],
          note: "grouped",
        },
        sizeBytes: 80,
      },
      {
        id: "b-meta",
        path: "$.data.metadata",
        mediaType: "application/json",
        value: { description: "d", lineage: ["0xsource"] },
        sizeBytes: 40,
      },
      {
        id: "b-plain",
        path: "$.data.note[chars 0:5]",
        mediaType: "application/json",
        value: "hello",
        sizeBytes: 7,
      },
    ];

    function makeClient(
      authResult: { grantId: string; builder?: string },
      options: {
        data?: Record<string, unknown>;
        blocks?: unknown[];
        envelopeError?: Error;
      } = {},
    ) {
      const envelopeData = options.data ?? {
        note: "hello",
        lineage: ["0xsource"],
        metadata: { description: "d", lineage: ["0xsource"] },
        $lineage: { sources: ["0xsource"], writtenAt: "2026-06-05" },
        $writtenBy: { builder: "0xbeef", grantId: "g-w" },
      };
      const readEnvelope = options.envelopeError
        ? vi.fn().mockRejectedValue(options.envelopeError)
        : vi.fn().mockResolvedValue({
            version: "1.0",
            scope: "spine.health.summary",
            collectedAt: "2026-06-05T00:00:00Z",
            data: envelopeData,
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
                scope: "spine.health.summary",
                collectedAt: "2026-06-05T00:00:00Z",
                fileId: "file-1",
                sizeBytes: 10,
              }) as never,
            findByFileId: vi.fn(),
            findUnsynced: vi.fn(),
            readEnvelope,
            readScopeBlocks: vi.fn().mockResolvedValue({
              scope: "spine.health.summary",
              collectedAt: "2026-06-05T00:00:00Z",
              contentKind: "vana-envelope",
              blocks: structuredClone(options.blocks ?? STAMPED_BLOCKS),
              warnings: [],
            }),
            readBlockManifest: vi.fn().mockResolvedValue({
              version: 1 as const,
              scope: "spine.health.summary",
              collectedAt: "2026-06-05T00:00:00Z",
              contentKind: "vana-envelope" as const,
              blocks: STAMPED_BLOCKS.map(({ id, path, sizeBytes }) => ({
                id,
                path,
                mediaType: "application/json",
                sizeBytes,
              })),
              warnings: [],
            }),
            writeEnvelope: vi.fn(),
            insertEntry: vi.fn(),
            updateFileId: vi.fn(),
            deleteScope: vi.fn(),
            deleteByFileId: vi.fn(),
          },
          auth: {
            authorizeOwner: vi.fn(),
            authorizeBuilderList: vi.fn(),
            authorizeBuilderRead: vi.fn().mockResolvedValue(authResult),
          },
          accessLogWriter: { write: vi.fn() },
        },
      });
      return { client, readEnvelope };
    }

    it("redacts stamped keys and the consumed lineage from a grantee block read", async () => {
      const { client } = makeClient({ grantId: "grant-1", builder: "0x2222" });
      const result = await client.readScopeBlocks({
        scope: "spine.health.summary",
        grantId: "grant-1",
        maxBytes: 4096,
      });

      const paths = result.blocks.map((b) => b.path);
      expect(paths).not.toContain("$.data.$writtenBy");
      expect(paths).not.toContain("$.data.$lineage.sources[0:1]");
      expect(paths).not.toContain("$.data.lineage");
      expect(paths).toContain("$.data");
      expect(paths).toContain("$.data.note[chars 0:5]");

      const dataBlock = result.blocks.find((b) => b.path === "$.data");
      // JSON record: the consumed caller field is TOP-LEVEL `lineage`;
      // `metadata.lineage` on a JSON record is user data and stays.
      expect(dataBlock?.value).toEqual({
        note: "hello",
        metadata: { description: "d", lineage: ["0xsource"] },
      });
      // Group labels naming a stamped key are sanitized, values stripped.
      const groupBlock = result.blocks.find(
        (b) => b.path === "$.data.{…:note}",
      );
      expect(groupBlock?.value).toEqual({ note: "grouped" });
      expect(paths).not.toContain("$.data.{$lineage:note}");
      const metaBlock = result.blocks.find((b) => b.path === "$.data.metadata");
      expect(metaBlock?.value).toEqual({
        description: "d",
        lineage: ["0xsource"],
      });
    });

    it("keeps an unstamped record's lineage field on a grantee block read", async () => {
      // No `$lineage` evidence in the served blocks, so the decision comes
      // from the stored envelope — which is unstamped.
      const { client } = makeClient(
        { grantId: "grant-1", builder: "0x2222" },
        {
          data: { note: "hello", lineage: ["user-data"] },
          blocks: [
            {
              id: "b-data",
              path: "$.data",
              mediaType: "application/json",
              value: { note: "hello", lineage: ["user-data"] },
              sizeBytes: 60,
            },
            {
              id: "b-caller-lin",
              path: "$.data.lineage",
              mediaType: "application/json",
              value: ["user-data"],
              sizeBytes: 20,
            },
          ],
        },
      );
      const result = await client.readScopeBlocks({
        scope: "spine.health.summary",
        grantId: "grant-1",
        maxBytes: 4096,
      });
      const callerLineage = result.blocks.find(
        (b) => b.path === "$.data.lineage",
      );
      expect(callerLineage?.value).toEqual(["user-data"]);
      const dataBlock = result.blocks.find((b) => b.path === "$.data");
      expect(dataBlock?.value).toEqual({
        note: "hello",
        lineage: ["user-data"],
      });
    });

    it("does not read the envelope when the served blocks carry no lineage-shaped content", async () => {
      const { client, readEnvelope } = makeClient(
        { grantId: "grant-1", builder: "0x2222" },
        {
          blocks: [
            {
              id: "b-items",
              path: "$.data.conversations[0:2]",
              mediaType: "application/json",
              value: [{ n: 1 }, { n: 2 }],
              sizeBytes: 40,
            },
          ],
        },
      );
      const result = await client.readScopeBlocks({
        scope: "spine.health.summary",
        grantId: "grant-1",
        maxBytes: 4096,
      });
      expect(result.blocks).toHaveLength(1);
      expect(readEnvelope).not.toHaveBeenCalled();
    });

    it("drops metadata lineage from a stamped binary record's block read", async () => {
      const { client } = makeClient(
        { grantId: "grant-1", builder: "0x2222" },
        {
          data: {
            $binary: true,
            mimeType: "application/pdf",
            sizeBytes: 10,
            contentHash: "0xhash",
            metadata: { description: "d", lineage: ["0xsource"] },
            $lineage: { sources: ["0xsource"] },
          },
          blocks: [
            {
              id: "b-bin",
              path: "$.data",
              mediaType: "application/json",
              value: {
                contentKind: "document",
                mimeType: "application/pdf",
                metadata: { description: "d", lineage: ["0xsource"] },
              },
              sizeBytes: 90,
            },
          ],
        },
      );
      const result = await client.readScopeBlocks({
        scope: "spine.health.summary",
        grantId: "grant-1",
        maxBytes: 4096,
      });
      const dataBlock = result.blocks.find((b) => b.path === "$.data");
      expect(dataBlock?.value).toEqual({
        contentKind: "document",
        mimeType: "application/pdf",
        metadata: { description: "d" },
      });
    });

    it("fails closed to full redaction when the envelope cannot be read", async () => {
      // Lineage-shaped content with no visible $lineage evidence forces the
      // envelope read; when that fails, both caller-lineage locations drop.
      const { client, readEnvelope } = makeClient(
        { grantId: "grant-1", builder: "0x2222" },
        {
          envelopeError: new Error("gone"),
          blocks: [
            {
              id: "b-caller-lin",
              path: "$.data.lineage",
              mediaType: "application/json",
              value: ["0xsource"],
              sizeBytes: 20,
            },
            {
              id: "b-meta",
              path: "$.data.metadata",
              mediaType: "application/json",
              value: { lineage: ["0xsource"], description: "d" },
              sizeBytes: 40,
            },
          ],
        },
      );
      const result = await client.readScopeBlocks({
        scope: "spine.health.summary",
        grantId: "grant-1",
        maxBytes: 4096,
      });
      expect(readEnvelope).toHaveBeenCalled();
      const paths = result.blocks.map((b) => b.path);
      expect(paths).not.toContain("$.data.lineage");
      const metaBlock = result.blocks.find((b) => b.path === "$.data.metadata");
      expect(metaBlock?.value).toEqual({ description: "d" });
    });

    it("serves the owner's block read unredacted", async () => {
      const { client } = makeClient({ grantId: "owner", builder: "0xowner" });
      const result = await client.readScopeBlocks({
        scope: "spine.health.summary",
        grantId: "owner",
        maxBytes: 4096,
      });
      expect(result.blocks).toEqual(STAMPED_BLOCKS);
    });

    it("hides stamped-key entries from a grantee manifest read", async () => {
      const { client } = makeClient({ grantId: "grant-1", builder: "0x2222" });
      const manifest = await client.readBlockManifest?.({
        scope: "spine.health.summary",
        grantId: "grant-1",
      });
      const paths = (manifest?.blocks ?? []).map((b) => b.path);
      expect(paths).not.toContain("$.data.$writtenBy");
      expect(paths).not.toContain("$.data.$lineage.sources[0:1]");
      expect(paths).not.toContain("$.data.lineage");
      expect(paths).not.toContain("$.data.{$lineage:note}");
      expect(paths).toContain("$.data.{…:note}");
      expect(paths).toContain("$.data");
      expect(paths).toContain("$.data.note[chars 0:5]");
    });

    it("keeps the owner's manifest read unredacted", async () => {
      const { client } = makeClient({ grantId: "owner" });
      const manifest = await client.readBlockManifest?.({
        scope: "spine.health.summary",
        grantId: "owner",
      });
      expect((manifest?.blocks ?? []).map((b) => b.path)).toContain(
        "$.data.$writtenBy",
      );
    });
  });
});
