import { describe, expect, it, vi } from "vitest";
import { createVersionInventoryClient } from "./version-inventory.js";

const owner = "0x1111111111111111111111111111111111111111";
const id = "0xc4514b17500f374e6ba098810bfeb0855719335bc2de26fa3038d0a0e5ffc2ce";

describe("owner version inventory", () => {
  it("signs the canonical owner URI with defaults, preserving scope whitespace", async () => {
    const signRequest = vi.fn().mockResolvedValue("Web3Signed owner-proof");
    const fetcher = vi.fn().mockImplementation(
      async () =>
        new Response(
          JSON.stringify({
            data: {
              dataPointId: id,
              ownerAddress: owner,
              scope: " scope ",
              head: null,
              versions: [],
            },
            pagination: { limit: 100, hasMore: false, nextAfter: null },
          }),
        ),
    );
    const client = createVersionInventoryClient({
      gatewayUrl: "https://gateway.example/",
      ownerAddress: owner,
      ownerSigner: { signRequest },
      fetch: fetcher,
    });
    await client.page(" scope ");
    expect(signRequest).toHaveBeenCalledWith({
      aud: "https://gateway.example",
      method: "GET",
      nonce: expect.any(String),
      uri: `/v1/data/${id}/versions?user=${owner}&scope=+scope+&after=0&limit=100`,
    });
    expect(fetcher.mock.calls[0]?.[1].headers.Authorization).toBe(
      "Web3Signed owner-proof",
    );
  });
});

const hashA = `0x${"a".repeat(64)}`;
const hashB = `0x${"b".repeat(64)}`;
const version = (expectedVersion: string) => ({
  expectedVersion,
  dataHash: hashA,
  metadataHash: hashB,
  status: "confirmed",
  addedAt: "2026-10-01T00:00:00.000Z",
  isTombstone: false,
});
function response(
  versions: ReturnType<typeof version>[],
  nextAfter: string | null = null,
) {
  return {
    data: {
      dataPointId: id,
      ownerAddress: owner,
      scope: " scope ",
      head: null,
      versions,
    },
    pagination: { limit: 100, hasMore: nextAfter !== null, nextAfter },
  };
}
function harness(payloads: unknown[]) {
  const fetcher = vi
    .fn()
    .mockImplementation(
      async () => new Response(JSON.stringify(payloads.shift())),
    );
  const signRequest = vi.fn().mockResolvedValue("Web3Signed fresh-proof");
  return {
    client: createVersionInventoryClient({
      gatewayUrl: "https://gateway.example",
      ownerAddress: owner,
      ownerSigner: { signRequest },
      fetch: fetcher,
    }),
    fetcher,
    signRequest,
  };
}

it("pages with exact decimal cursors above JS safe integers, signing each page", async () => {
  const { client, signRequest } = harness([
    response([version("9007199254740993")], "9007199254740993"),
    response([version("9007199254740994")]),
  ]);
  const result = await client.list(" scope ");
  expect(result.versions.map((row) => row.expectedVersion)).toEqual([
    "9007199254740993",
    "9007199254740994",
  ]);
  expect(signRequest.mock.calls[1]?.[0].uri).toContain(
    "after=9007199254740993&limit=100",
  );
});

it.each([
  [
    "wrong owner",
    (data: ReturnType<typeof response>) => {
      data.data.ownerAddress = "0x2222222222222222222222222222222222222222";
    },
  ],
  [
    "wrong scope",
    (data: ReturnType<typeof response>) => {
      data.data.scope = "scope";
    },
  ],
  [
    "wrong id",
    (data: ReturnType<typeof response>) => {
      data.data.dataPointId = hashA;
    },
  ],
  [
    "false tombstone",
    (data: ReturnType<typeof response>) => {
      const row = data.data.versions[0];
      if (row) row.isTombstone = true;
    },
  ],
  [
    "repeated cursor",
    (data: ReturnType<typeof response>) => {
      data.pagination.hasMore = true;
      data.pagination.nextAfter = "0";
    },
  ],
  [
    "numeric version",
    (data: ReturnType<typeof response>) => {
      Object.assign(data.data.versions[0] ?? {}, { expectedVersion: 1 });
    },
  ],
  [
    "invalid hash",
    (data: ReturnType<typeof response>) => {
      const row = data.data.versions[0];
      if (row) row.metadataHash = "0xabc";
    },
  ],
])("rejects %s before returning observations", async (_name, mutate) => {
  const payload = response([version("1")]);
  mutate(payload);
  const { client } = harness([payload]);
  await expect(client.list(" scope ")).rejects.toThrow();
});

it("preserves failed and unknown lifecycle observations for unresolved coverage", async () => {
  const failed = { ...version("1"), status: "failed" };
  const unknown = { ...version("2"), status: "future-status" };
  const { client } = harness([response([failed, unknown])]);
  expect((await client.list(" scope ")).versions).toEqual([failed, unknown]);
});

it("refuses changed head across pages and enforces a page budget", async () => {
  const changed = {
    ...response([version("2")]),
    data: {
      ...response([]).data,
      head: {
        expectedVersion: "2",
        dataHash: hashA,
        metadataHash: hashB,
        status: "pending",
        deletedAt: null,
      },
      versions: [version("2")],
    },
  };
  const { client } = harness([response([version("1")], "1"), changed]);
  await expect(client.list(" scope ")).rejects.toThrow("head changed");
  const bounded = harness([response([version("1")], "1")]);
  await expect(bounded.client.list(" scope ", { maxPages: 1 })).rejects.toThrow(
    "budget exceeded",
  );
});

it("re-reads replaced same-version commitments instead of caching the inventory", async () => {
  const original = response([version("1")]);
  const replaced = response([{ ...version("1"), dataHash: hashB }]);
  const { client } = harness([original, replaced]);
  expect((await client.list(" scope ")).versions[0]?.dataHash).toBe(hashA);
  expect((await client.list(" scope ")).versions[0]?.dataHash).toBe(hashB);
});

it("discovers deleted source scopes from the public includeDeleted paged feed", async () => {
  const row = {
    id,
    ownerAddress: owner,
    scope: " scope ",
    deletedAt: "2026-10-01T00:00:00.000Z",
  };
  const { client, fetcher, signRequest } = harness([
    {
      data: { dataPoints: [row] },
      pagination: { limit: 100, hasMore: true, nextCursor: "next-page" },
    },
    {
      data: { dataPoints: [] },
      pagination: { limit: 100, hasMore: false, nextCursor: null },
    },
  ]);
  expect(await client.listScopes()).toEqual([" scope "]);
  expect(fetcher.mock.calls[0]?.[0]).toBe(
    `https://gateway.example/v1/data?user=${owner}&includeDeleted=true&limit=100`,
  );
  expect(fetcher.mock.calls[1]?.[0]).toContain("cursor=next-page");
  expect(signRequest).not.toHaveBeenCalled();
});

it("passes cancellation and rejects HTTP failures", async () => {
  const controller = new AbortController();
  const fetcher = vi
    .fn()
    .mockResolvedValue(new Response("unauthorized", { status: 403 }));
  const client = createVersionInventoryClient({
    gatewayUrl: "https://gateway.example",
    ownerAddress: owner,
    ownerSigner: { signRequest: async () => "Web3Signed owner" },
    fetch: fetcher,
  });
  await expect(
    client.page(" scope ", { signal: controller.signal }),
  ).rejects.toThrow("403");
  expect(fetcher.mock.calls[0]?.[1].signal).toBe(controller.signal);
  controller.abort();
  await expect(
    client.page(" scope ", { signal: controller.signal }),
  ).rejects.toThrow();
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it("includes canonical tombstones regardless of lifecycle status", async () => {
  const tombstone = {
    ...version("7"),
    dataHash:
      "0x30c45ee72fe56d1927701316925ab7ceacd3b6f9267061735d59396f075c6222",
    metadataHash:
      "0xc5255a141acd6a2ae55971b62c0a85977c2511989dc114ad2abc2b7644f57d90",
    status: "failed",
    isTombstone: true,
  };
  const { client } = harness([response([tombstone])]);
  expect((await client.list(" scope ")).versions).toEqual([tombstone]);
});

it("rejects lexicographic ordering and malformed head commitments", async () => {
  const { client } = harness([response([version("10"), version("2")])]);
  await expect(client.page(" scope ")).rejects.toThrow("strictly increasing");
  const invalidHead = {
    ...response([]),
    data: {
      ...response([]).data,
      head: {
        expectedVersion: "2",
        dataHash: "not-a-hash",
        metadataHash: hashB,
        status: "pending",
        deletedAt: null,
      },
    },
  };
  await expect(harness([invalidHead]).client.page(" scope ")).rejects.toThrow();
});

it("rejects leading zeros, uint256 overflow, and invalid scope byte lengths without fetching", async () => {
  const { client, fetcher } = harness([]);
  for (const after of ["01", "-1", (2n ** 256n).toString()]) {
    await expect(client.page(" scope ", { after })).rejects.toThrow();
  }
  await expect(client.page("é".repeat(129))).rejects.toThrow();
  expect(fetcher).not.toHaveBeenCalled();
});

it("rejects foreign-owner discovery and cyclic scope cursors", async () => {
  const row = { id, ownerAddress: owner, scope: " scope ", deletedAt: null };
  const foreign = {
    data: {
      dataPoints: [
        { ...row, ownerAddress: "0x2222222222222222222222222222222222222222" },
      ],
    },
    pagination: { limit: 100, hasMore: false, nextCursor: null },
  };
  await expect(harness([foreign]).client.listScopes()).rejects.toThrow(
    "owner scope",
  );
  const loop = {
    data: { dataPoints: [row] },
    pagination: { limit: 100, hasMore: true, nextCursor: "same-cursor" },
  };
  await expect(harness([loop, loop]).client.listScopes()).rejects.toThrow(
    "did not advance",
  );
});

describe("version inventory head", () => {
  function client(head: unknown) {
    const fetcher = vi.fn().mockImplementation(
      async () =>
        new Response(
          JSON.stringify({
            data: {
              dataPointId: id,
              ownerAddress: owner,
              scope: " scope ",
              head,
              versions: [],
            },
            pagination: { limit: 1, hasMore: false, nextAfter: null },
          }),
        ),
    );
    const signRequest = vi.fn().mockResolvedValue("Web3Signed server-proof");
    return {
      fetcher,
      signRequest,
      inventory: createVersionInventoryClient({
        gatewayUrl: "https://gateway.example",
        ownerAddress: owner,
        ownerSigner: { signRequest },
        fetch: fetcher,
      }),
    };
  }

  it("returns the head's version and deleted state from one signed page", async () => {
    const { inventory, fetcher, signRequest } = client({
      expectedVersion: "23",
      dataHash: hashA,
      metadataHash: hashB,
      status: "finalized",
      deletedAt: null,
    });
    expect(await inventory.head(" scope ")).toEqual({
      expectedVersion: "23",
      deletedAt: null,
    });
    expect(signRequest).toHaveBeenCalledTimes(1);
    expect(String(fetcher.mock.calls[0]![0])).toContain("limit=1");
  });

  it("returns null for a point the gateway never registered", async () => {
    expect(await client(null).inventory.head(" scope ")).toBeNull();
  });
});
