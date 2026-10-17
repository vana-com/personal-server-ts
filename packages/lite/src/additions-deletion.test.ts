import { afterEach, expect, it, vi } from "vitest";
import {
  AdditionsBudget,
  additionsLedgerScope,
} from "@opendatalabs/personal-server-ts-core/additions";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { deriveDataPointId } from "@opendatalabs/vana-sdk/browser";
import { IDBFactory } from "fake-indexeddb";
import { createPsLiteAdditionsTransport } from "./additions-transport.js";
import { createPsLiteAdditionsSession } from "./additions-session.js";
import { createIndexedDbPsLiteStateStore } from "./state.js";
const owner = "0x1111111111111111111111111111111111111111";
const scope = "vana.system.additions.instagram.posts";
afterEach(() => vi.unstubAllGlobals());
function fixture(fetcher: typeof fetch) {
  vi.stubGlobal("indexedDB", new IDBFactory());
  const dbName = crypto.randomUUID();
  const stateStore = createIndexedDbPsLiteStateStore({ dbName });
  const signer = {
    signMessageBounded: vi.fn(async () => "0x1234" as const),
    signAddDataBounded: vi.fn(async () => "0x5678" as const),
  };
  const options = {
    config: ServerConfigSchema.parse({
      gateway: { url: "https://gateway.example" },
    }),
    ownerAddress: owner,
    masterKey: new Uint8Array(32),
    stateStore,
    ownerSigner: signer,
    fetch: fetcher,
  };
  const transport = createPsLiteAdditionsTransport(options);
  const restart = () =>
    createPsLiteAdditionsTransport({
      ...options,
      stateStore: createIndexedDbPsLiteStateStore({ dbName }),
    });
  return { transport, signer, restart };
}
it("cancels the actual registry lookup and permits a later retry", async () => {
  let entered!: () => void;
  const started = new Promise<void>((resolve) => {
    entered = resolve;
  });
  let received: AbortSignal | null | undefined;
  const fetcher = vi.fn<typeof fetch>(
    (_, init) =>
      new Promise((_, reject) => {
        received = init?.signal;
        received?.addEventListener("abort", () => reject(received?.reason), {
          once: true,
        });
        entered();
      }),
  );
  const { transport } = fixture(fetcher);
  const controller = new AbortController();
  const pending = transport.tombstone(
    scope,
    new AdditionsBudget(100_000, 10_000, controller.signal),
  );
  const settled = expect(pending).rejects.toThrow("cancel deletion");
  await started;
  controller.abort(new Error("cancel deletion"));
  await settled;
  expect(received?.aborted).toBe(true);
  fetcher.mockResolvedValueOnce(
    Response.json({
      data: {
        dataPointId: deriveDataPointId(owner, scope),
        ownerAddress: owner,
        scope,
        head: null,
        versions: [],
      },
      pagination: { limit: 1, hasMore: false, nextAfter: null },
    }),
  );
  await expect(
    transport.tombstone(scope, new AdditionsBudget(100_000, 10_000)),
  ).resolves.toMatchObject({ status: "not-registered" });
});
it("registers an owner-signed system tombstone without unbounded blob deletion", async () => {
  const hash = `0x${"ab".repeat(32)}`;
  const fetcher = vi.fn<typeof fetch>(async (_, init) =>
    init?.method === "DELETE"
      ? Response.json({
          expectedVersion: "3",
          deletedAt: "2026-10-17T00:00:00.000Z",
        })
      : Response.json({
          data: {
            dataPointId: deriveDataPointId(owner, scope),
            ownerAddress: owner,
            scope,
            head: {
              expectedVersion: "2",
              dataHash: hash,
              metadataHash: hash,
              status: "confirmed",
              deletedAt: null,
            },
            versions: [],
          },
          pagination: { limit: 1, hasMore: false, nextAfter: null },
        }),
  );
  const { transport, signer } = fixture(fetcher);
  await transport.tombstone(scope, new AdditionsBudget(100_000, 10_000));
  expect(signer.signAddDataBounded).toHaveBeenCalledWith(
    expect.objectContaining({
      ownerAddress: owner,
      scope,
      expectedVersion: 3n,
    }),
    expect.any(AbortSignal),
  );
  expect(fetcher).toHaveBeenCalledTimes(2);
  expect(fetcher.mock.calls[1][0]).toBe(
    `https://gateway.example/v1/data/${deriveDataPointId(owner, scope)}`,
  );
  expect(fetcher.mock.calls[1][1]?.signal).toBeInstanceOf(AbortSignal);
  await expect(
    transport.tombstone("instagram.posts", new AdditionsBudget()),
  ).rejects.toThrow("limited to additions");
});

it("bounds the session lock and registers both metrics tombstones", async () => {
  const seen: string[] = [];
  const fetcher = vi.fn<typeof fetch>(async (url, init) => {
    if (init?.method === "DELETE")
      return Response.json({
        expectedVersion: "3",
        deletedAt: "2026-10-17T00:00:00.000Z",
      });
    const path = new URL(String(url));
    const target = path.searchParams.get("scope")!;
    seen.push(target);
    return Response.json({
      data: {
        dataPointId: deriveDataPointId(owner, target),
        ownerAddress: owner,
        scope: target,
        head: {
          expectedVersion: "2",
          dataHash: `0x${"ab".repeat(32)}`,
          metadataHash: `0x${"ab".repeat(32)}`,
          status: "confirmed",
          deletedAt: null,
        },
        versions: [],
      },
      pagination: { limit: 1, hasMore: false, nextAfter: null },
    });
  });
  const { transport } = fixture(fetcher);
  const lock = vi.fn(async (_name, options, callback) => {
    options.signal.throwIfAborted();
    return callback();
  });
  vi.stubGlobal("navigator", { locks: { request: lock } });
  const ordinary = vi.fn(async () => {});
  const service = createPsLiteAdditionsSession({
    init: {
      ownerAddress: owner,
      network: "vana:14800:https://gateway.example",
      gatewayUrl: "https://gateway.example",
      storageEndpoint: "https://storage.example",
      masterKey: new Uint8Array(32),
      byteBudget: 100_000,
      timeBudgetMs: 10_000,
    },
    transport,
    deleteSystemScope: ordinary,
  });
  await service.deleteScope("instagram.posts", { durableOnly: true });
  expect(seen).toEqual([scope, "vana.system.additions"]);
  expect(lock.mock.calls[0][1].signal).toBeInstanceOf(AbortSignal);
  expect(ordinary).not.toHaveBeenCalled();
  const controller = new AbortController();
  controller.abort(new Error("cancel queued deletion"));
  await expect(
    service.deleteScope("instagram.posts", {
      durableOnly: true,
      signal: controller.signal,
    }),
  ).rejects.toThrow("cancel queued deletion");
  expect(seen).toHaveLength(2);
});

it("admits the canonical hashed checkpoint for a long source scope", async () => {
  const target = additionsLedgerScope("instagram." + "a".repeat(240));
  expect(target).toMatch(/^vana\.system\.additions-hash\.[0-9a-f]{64}$/);
  const { transport } = fixture(async () =>
    Response.json({
      data: {
        dataPointId: deriveDataPointId(owner, target),
        ownerAddress: owner,
        scope: target,
        head: null,
        versions: [],
      },
      pagination: { limit: 1, hasMore: false, nextAfter: null },
    }),
  );
  await expect(
    transport.tombstone(target, new AdditionsBudget(100_000, 10_000)),
  ).resolves.toMatchObject({ status: "not-registered" });
});

it("retries interrupted summary invalidation and then preserves rebuilt summaries", async () => {
  let ledgerDeleted = false;
  let fail = true;
  const summaryDeletes = vi.fn();
  const fetcher = vi.fn<typeof fetch>(async (url, init) => {
    if (init?.method === "DELETE") {
      const ledger = String(url).includes(deriveDataPointId(owner, scope));
      if (ledger) ledgerDeleted = true;
      else {
        summaryDeletes();
        if (fail) throw new Error("summary deletion interrupted");
      }
      return Response.json({
        expectedVersion: "3",
        deletedAt: "2026-10-17T00:00:00.000Z",
      });
    }
    const target = new URL(String(url)).searchParams.get("scope")!;
    return Response.json({
      data: {
        dataPointId: deriveDataPointId(owner, target),
        ownerAddress: owner,
        scope: target,
        head: {
          expectedVersion: "2",
          dataHash: `0x${"ab".repeat(32)}`,
          metadataHash: `0x${"ab".repeat(32)}`,
          status: "confirmed",
          deletedAt:
            target === scope && ledgerDeleted
              ? "2026-10-17T00:00:00.000Z"
              : null,
        },
        versions: [],
      },
      pagination: { limit: 1, hasMore: false, nextAfter: null },
    });
  });
  const { transport, restart } = fixture(fetcher);
  await expect(
    transport.deleteScope(
      "instagram.posts",
      new AdditionsBudget(100_000, 10_000),
    ),
  ).rejects.toThrow("summary deletion interrupted");
  fail = false;
  const restarted = restart();
  await restarted.deleteScope(
    "instagram.posts",
    new AdditionsBudget(100_000, 10_000),
  );
  expect(summaryDeletes).toHaveBeenCalledTimes(2);
  await restarted.deleteScope(
    "instagram.posts",
    new AdditionsBudget(100_000, 10_000),
  );
  expect(summaryDeletes).toHaveBeenCalledTimes(2);
});
