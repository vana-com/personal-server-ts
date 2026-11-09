import { deriveMasterKey } from "@opendatalabs/vana-sdk/browser";
import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  buildTestHead,
  testOwnerKey,
} from "../../core/src/stream-sync-read/testing.js";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, it, vi } from "vitest";
import {
  StreamSyncReadService,
  createMemoryStreamSyncReadFiles,
} from "@opendatalabs/personal-server-ts-core/stream-sync-read";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
} from "./test-support/memory.js";
import { loadOrCreatePsLiteServerIdentity } from "./state.js";
import { createIndexedDbStreamSyncFiles } from "./stream-sync-files.js";
import { createPsLiteSyncManager } from "./sync.js";

/** PS-Lite hands a run intake to its host only when `streamSync.write` is on. */
const factory = new IDBFactory();
async function manager(
  streamSync: { write?: boolean; read?: boolean } | undefined,
  read?: { files?: ReturnType<typeof createMemoryStreamSyncReadFiles> },
  ownerByte = "12",
  gatewayUrl?: string,
) {
  const owner = privateKeyToAccount(`0x${ownerByte.repeat(32)}`);
  const OWNER_SIGNATURE = await owner.signMessage({
    message: "vana-master-key-v1",
  });
  const stateStore = createMemoryPsLiteStateStore();
  const identity = await loadOrCreatePsLiteServerIdentity({
    store: stateStore,
    ownerSignature: OWNER_SIGNATURE,
  });
  const result = await createPsLiteSyncManager({
    streamSyncDeclaredStreams: () => [],
    config: ServerConfigSchema.parse({
      sync: { enabled: true },
      ...(gatewayUrl ? { gateway: { url: gatewayUrl } } : {}),
      ...(streamSync ? { streamSync } : {}),
    }),
    storage: createMemoryPsLiteStorage(),
    stateStore,
    ownerSignature: OWNER_SIGNATURE,
    serverAccount: identity.account,
    ownerSyncSigner: {
      address: owner.address,
      signMessage: (message: string) => owner.signMessage({ message }),
      signAddData: vi.fn(),
      signLineageAttestation: vi.fn(),
    },
    gateway: { getServer: vi.fn().mockResolvedValue(null) } as never,
    dataPointFeed: {
      getDataPoint: async () => null,
      listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
    },
    ...(read ? { streamSyncRead: read } : {}),
    streamSyncFiles: (id) =>
      createIndexedDbStreamSyncFiles({
        dbName: id,
        factory,
        keyRange: IDBKeyRange,
      }),
  });
  await result.syncManager.stop();
  return { ...result, owner: owner.address };
}

describe("PS Lite run intake", () => {
  it("is absent with streamSync.write off", async () => {
    expect((await manager(undefined)).streamSyncIntake).toBeNull();
    expect((await manager({ write: false })).streamSyncIntake).toBeNull();
  });

  it("is the in-process API when streamSync.write is on", async () => {
    const result = await manager({ write: true });
    expect(result.streamSyncWriter).not.toBeNull();
    // No connector artifact is resolvable by default: begin says so.
    await expect(
      result.streamSyncIntake!.begin("r1", {
        connector: "c",
        artifactDigest: "sha256:" + "ab".repeat(32),
        owner: { address: result.owner, leaseId: null },
        observedAt: Date.now(),
      } as never),
    ).rejects.toMatchObject({ code: "unknown_artifact" });
  });
});

describe("PS Lite stream-sync reader", () => {
  it("keeps its default read files across a restart", async () => {
    const open = vi.spyOn(StreamSyncReadService, "open");
    try {
      const first = await manager({ write: true, read: true }, {});
      const probe = new TextEncoder().encode("imported view");
      await open.mock.calls[0]![0].files.write("views/probe", probe);
      await first.closeStreamSync();
      const second = await manager({ write: true, read: true }, {});
      expect(await open.mock.calls[1]![0].files.read("views/probe")).toEqual(
        probe,
      );
      await second.closeStreamSync();
    } finally {
      open.mockRestore();
    }
  });
});

it("serves an imported head after an offline restart", async () => {
  const owner = privateKeyToAccount(`0x${"12".repeat(32)}`);
  const signature = await owner.signMessage({ message: "vana-master-key-v1" });
  const key = await testOwnerKey(deriveMasterKey(signature));
  const ns = await key.ns("acme", "fixture");
  const built = await buildTestHead({
    key,
    connector: "acme",
    ns,
    stream: "items",
    generation: 1,
    primaryKey: ["id"],
    records: [{ id: "one" }],
    observedAt: Date.now(),
  });
  const control = await key.control();
  const original = StreamSyncReadService.open;
  const open = vi
    .spyOn(StreamSyncReadService, "open")
    .mockImplementation((options) =>
      original({
        ...options,
        blobs: { get: async (name) => built.blobs.get(name) ?? null },
      }),
    );
  try {
    const first = await manager({ write: true, read: true }, {});
    const row = {
      expectedVersion: "1",
      addedAt: new Date().toISOString(),
      deletedAt: null,
    };
    await first.streamSyncRead!.observe(
      [
        {
          ...row,
          scope: controlScope("acme", ns),
          dataHash: control.active.dataHash,
          metadataHash: control.active.metadataHash,
        },
        {
          ...row,
          scope: built.scope,
          dataHash: built.dataHash,
          metadataHash: `0x${"ab".repeat(32)}`,
        },
      ],
      { fromStart: true, lastPage: true },
    );
    await first.streamSyncRead!.importPending();
    await first.closeStreamSync();
    open.mockImplementation((options) =>
      original({ ...options, blobs: { get: async () => null } }),
    );
    const second = await manager({ write: true, read: true }, {});
    const decision = await second.streamSyncRead!.resolve({
      scope: "pdpp.acme.items",
      connection: null,
      cursor: null,
      legacyFile: false,
    });
    expect(decision.kind).toBe("view");
    if (decision.kind === "view")
      expect((await new Response(decision.body).json()).data.records).toEqual([
        { id: "one" },
      ]);
    await second.closeStreamSync();
  } finally {
    open.mockRestore();
  }
});

it("isolates owners and networks, honors injected files, and uses memory for read-only mode", async () => {
  const open = vi.spyOn(StreamSyncReadService, "open");
  try {
    const first = await manager({ write: true, read: true }, {});
    const probe = new TextEncoder().encode("probe");
    await open.mock.calls.at(-1)![0].files.write("views/isolation", probe);
    await first.closeStreamSync();
    const otherOwner = await manager({ write: true, read: true }, {}, "34");
    expect(
      await open.mock.calls.at(-1)![0].files.read("views/isolation"),
    ).toBeNull();
    await otherOwner.closeStreamSync();
    const otherNetwork = await manager(
      { write: true, read: true },
      {},
      "12",
      "https://other.example",
    );
    expect(
      await open.mock.calls.at(-1)![0].files.read("views/isolation"),
    ).toBeNull();
    await otherNetwork.closeStreamSync();
    const injected = createMemoryStreamSyncReadFiles();
    const custom = await manager(
      { write: true, read: true },
      { files: injected },
    );
    expect(open.mock.calls.at(-1)![0].files).toBe(injected);
    await custom.closeStreamSync();
    const readonly = await manager({ write: false, read: true }, {});
    await open.mock.calls.at(-1)![0].files.write("views/read-only", probe);
    await readonly.closeStreamSync();
    const restarted = await manager({ write: false, read: true }, {});
    expect(
      await open.mock.calls.at(-1)![0].files.read("views/read-only"),
    ).toBeNull();
    await restarted.closeStreamSync();
  } finally {
    open.mockRestore();
  }
});
