import {
  encodeAbiParameters,
  keccak256,
  createPublicClient,
  custom,
  parseAbiParameters,
} from "viem";
import { replicaRegistrationState, replicaChainCommitment } from "./dpv2.js";
import { expect, it, vi } from "vitest";
import { createReplicaEvidenceAdapter } from "./evidence.js";

const owner = "0x0000000000000000000000000000000000000001";
const registry = "0x0000000000000000000000000000000000000002";
const block = {
  number: 123n,
  hash: `0x${"a".repeat(64)}` as const,
  timestamp: 1000n,
};

it("pins all registry reads to the same fresh finalized block and proves genuine absence", async () => {
  const rpc = {
    getChainId: vi.fn(async () => 1480),
    getBlock: vi.fn(async () => block),
    readContract: vi.fn(async ({ functionName }) =>
      functionName === "currentVersion"
        ? 0n
        : functionName === "dataPoints"
          ? info(0n)
          : `0x${"0".repeat(64)}`,
    ),
  };
  const fetcher = vi.fn(async () =>
    Response.json({ error: "Data point not found" }, { status: 404 }),
  );
  const evidence = await createReplicaEvidenceAdapter({
    owner,
    registry,
    chainId: 1480,
    rpc,
    gatewayUrl: "https://gateway.invalid",
    fetch: fetcher,
    now: () => 1010_000,
  })("scope");
  expect(evidence).toMatchObject({
    head: null,
    chain: {
      currentVersion: "0",
      commitment: `0x${"0".repeat(64)}`,
      blockNumber: 123n,
      blockHash: block.hash,
    },
    pending: false,
  });
  expect(rpc.getBlock).toHaveBeenCalledWith({ blockTag: "finalized" });
  expect(rpc.readContract.mock.calls.map(([args]) => args)).toEqual([
    expect.objectContaining({
      functionName: "currentVersion",
      args: [owner, "scope"],
      blockNumber: 123n,
    }),
    expect.objectContaining({
      functionName: "dataCommitment",
      args: [owner, "scope", 1n],
      blockNumber: 123n,
    }),
    expect.objectContaining({
      functionName: "dataPoints",
      args: [owner, "scope"],
      blockNumber: 123n,
    }),
  ]);
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(fetcher.mock.calls[0]?.[0]).toMatch(
    /\/v1\/data\/0x[0-9a-f]{64}\?includeDeleted=true$/,
  );
});

const scope = "scope";
const dataHash = `0x${"1".repeat(64)}` as const;
const metadataHash = `0x${"2".repeat(64)}` as const;
const id = keccak256(
  encodeAbiParameters(
    [{ type: "address" }, { type: "string" }],
    [owner, scope],
  ),
);
function info(version = 1n, status = version === 0n ? 0 : 1) {
  return {
    id,
    owner: version ? owner : `0x${"0".repeat(40)}`,
    scope: version ? scope : "",
    status,
    currentVersion: version,
    currentCommitment: version
      ? replicaChainCommitment(dataHash, metadataHash)
      : `0x${"0".repeat(64)}`,
    createdAt: 0n,
    modifiedAt: 0n,
    totalAccesses: 0n,
  };
}
const head = {
  id,
  ownerAddress: owner,
  scope,
  expectedVersion: "1",
  dataHash,
  metadataHash,
  deletedAt: null,
};
function fixture() {
  const rpc = {
    getChainId: vi.fn(async () => 14800),
    getBlock: vi.fn(async () => block),
    readContract: vi.fn(async ({ functionName }) =>
      functionName === "currentVersion"
        ? 1n
        : functionName === "dataPoints"
          ? info()
          : replicaChainCommitment(dataHash, metadataHash),
    ),
  };
  const fetcher = vi.fn(async () => Response.json({ data: head }));
  const read = () =>
    createReplicaEvidenceAdapter({
      owner,
      registry,
      chainId: 14800,
      rpc,
      gatewayUrl: "https://gateway.invalid",
      fetch: fetcher,
      now: () => 1010_000,
      maxFinalizedAgeSeconds: 300,
    })(scope);
  return { rpc, fetcher, read };
}
it("verifies head preimages against the independent commitment, including the false head 9 case", async () => {
  const f = fixture();
  expect(replicaRegistrationState(await f.read(), { owner, scope })).toBe(
    "confirmed",
  );
  for (const patch of [
    { expectedVersion: "9" },
    { dataHash: `0x${"3".repeat(64)}` },
    { metadataHash: `0x${"3".repeat(64)}` },
    { deletedAt: "2026-10-20T00:00:00Z" },
  ]) {
    f.fetcher.mockImplementation(async () =>
      Response.json({ data: { ...head, ...patch } }),
    );
    expect(replicaRegistrationState(await f.read(), { owner, scope })).toBe(
      "pending",
    );
  }
});
it("treats missing head and unsettled head as propagation lag", async () => {
  const f = fixture();
  f.fetcher.mockImplementation(async () =>
    Response.json({ error: "Data point not found" }, { status: 404 }),
  );
  expect(replicaRegistrationState(await f.read(), { owner, scope })).toBe(
    "pending",
  );
  f.fetcher.mockImplementation(async () => Response.json({ data: head }));
  f.rpc.readContract.mockImplementation(async ({ functionName }) =>
    functionName === "currentVersion"
      ? 0n
      : functionName === "dataPoints"
        ? info(0n)
        : `0x${"0".repeat(64)}`,
  );
  expect(replicaRegistrationState(await f.read(), { owner, scope })).toBe(
    "pending",
  );
});
it("keeps later chain versions conflicting even when the head still claims version 1", async () => {
  const f = fixture();
  f.rpc.readContract.mockImplementation(async ({ functionName }) =>
    functionName === "currentVersion"
      ? 2n
      : functionName === "dataPoints"
        ? info(2n)
        : replicaChainCommitment(dataHash, metadataHash),
  );
  expect(replicaRegistrationState(await f.read(), { owner, scope })).toBe(
    "conflict",
  );
});
it("retains a 410 tombstone body and rejects bare 410 as retryable", async () => {
  const f = fixture();
  f.fetcher.mockImplementation(async () =>
    Response.json(
      { data: { ...head, deletedAt: "2026-10-20T00:00:00Z" } },
      { status: 410 },
    ),
  );
  expect(replicaRegistrationState(await f.read(), { owner, scope })).toBe(
    "pending",
  );
  f.fetcher.mockImplementation(async () => new Response(null, { status: 410 }));
  await expect(f.read()).rejects.toMatchObject({ retryable: true });
});
it("fails closed and retryably for network, finality, decode, identity and transport failures", async () => {
  for (const fault of [
    (f: ReturnType<typeof fixture>) => f.rpc.getChainId.mockResolvedValue(1),
    (f: ReturnType<typeof fixture>) =>
      f.rpc.getBlock.mockRejectedValue(new Error("finalized unsupported")),
    (f: ReturnType<typeof fixture>) =>
      f.rpc.getBlock.mockResolvedValue({ ...block, hash: null } as never),
    (f: ReturnType<typeof fixture>) =>
      f.rpc.getBlock.mockResolvedValue({ ...block, number: null } as never),
    (f: ReturnType<typeof fixture>) =>
      f.rpc.getBlock.mockResolvedValue({ ...block, timestamp: 0n }),
    (f: ReturnType<typeof fixture>) =>
      f.rpc.getBlock.mockResolvedValue({ ...block, timestamp: 2000n }),
    (f: ReturnType<typeof fixture>) =>
      f.rpc.getBlock
        .mockResolvedValueOnce(block)
        .mockResolvedValue({ ...block, hash: `0x${"b".repeat(64)}` }),
    (f: ReturnType<typeof fixture>) =>
      f.rpc.readContract.mockRejectedValue(new Error("RPC unavailable")),
    (f: ReturnType<typeof fixture>) =>
      f.rpc.readContract.mockResolvedValue("0x"),
    (f: ReturnType<typeof fixture>) =>
      f.fetcher.mockRejectedValue(new Error("offline")),
    (f: ReturnType<typeof fixture>) =>
      f.fetcher.mockResolvedValue(new Response(null, { status: 500 })),
    (f: ReturnType<typeof fixture>) =>
      f.fetcher.mockResolvedValue(
        Response.json({ data: { ...head, dataHash: "0xaa" } }),
      ),
    ...[
      { id: `0x${"f".repeat(64)}` },
      { ownerAddress: registry },
      { scope: "other" },
    ].map(
      (patch) => (f: ReturnType<typeof fixture>) =>
        f.fetcher.mockResolvedValue(
          Response.json({ data: { ...head, ...patch } }),
        ),
    ),
  ]) {
    const f = fixture();
    fault(f);
    await expect(f.read()).rejects.toMatchObject({
      name: "ReplicaEvidenceUnavailableError",
      retryable: true,
    });
  }
});
it("uses a configurable freshness window that allows ordinary finality lag", async () => {
  const f = fixture();
  const read = (maxFinalizedAgeSeconds?: number) =>
    createReplicaEvidenceAdapter({
      owner,
      registry,
      chainId: 14800,
      rpc: f.rpc,
      gatewayUrl: "https://gateway.invalid",
      fetch: f.fetcher,
      now: () => 1400_000,
      maxFinalizedAgeSeconds,
    })(scope);
  expect(replicaRegistrationState(await read(), { owner, scope })).toBe(
    "confirmed",
  );
  await expect(read(300)).rejects.toMatchObject({ retryable: true });
});
it("accepts an injected viem client and uses real ABI RPC decoding", async () => {
  const requests: { method: string; params?: unknown }[] = [];
  const rpc = createPublicClient({
    transport: custom({
      async request(request) {
        requests.push(request);
        if (request.method === "eth_chainId") return "0x39d0";
        if (request.method === "eth_getBlockByNumber")
          return { number: "0x7b", hash: block.hash, timestamp: "0x3e8" };
        if (request.method === "eth_call") {
          const call = (request.params as [{ data: string }])[0];
          // dataPoints(address,string) selector, independently computed from the contract signature.
          if (call.data.startsWith("0x2fcf9dd7"))
            return encodeAbiParameters(
              parseAbiParameters(
                "(bytes32 id,address owner,string scope,uint8 status,uint256 currentVersion,bytes32 currentCommitment,uint256 createdAt,uint256 modifiedAt,uint256 totalAccesses)",
              ),
              [info(0n) as never],
            );
          return `0x${"0".repeat(64)}`;
        }
        throw new Error(`unexpected ${request.method}`);
      },
    }),
  });
  const evidence = await createReplicaEvidenceAdapter({
    owner,
    registry,
    chainId: 14800,
    rpc,
    gatewayUrl: "https://gateway.invalid",
    fetch: async () =>
      Response.json({ error: "Data point not found" }, { status: 404 }),
    now: () => 1010_000,
  })(scope);
  expect(replicaRegistrationState(evidence, { owner, scope })).toBe("absent");
  expect(
    requests.filter((r) => r.method === "eth_call").map((r) => r.params?.[1]),
  ).toEqual(["0x7b", "0x7b", "0x7b"]);
});

it("holds chain-only soft deletion pending at version 1 and validates all nine tuple fields", async () => {
  for (const status of [2, 3]) {
    const f = fixture();
    f.rpc.readContract.mockImplementation(async ({ functionName }) =>
      functionName === "currentVersion"
        ? 1n
        : functionName === "dataPoints"
          ? info(1n, status)
          : replicaChainCommitment(dataHash, metadataHash),
    );
    const evidence = await f.read();
    expect(evidence.head?.deleted).toBe(false);
    expect(replicaRegistrationState(evidence, { owner, scope })).toBe(
      "pending",
    );
  }
  for (const patch of [
    { status: 4 },
    { scope: "other" },
    { owner: registry },
    { currentVersion: 2n },
    { currentCommitment: `0x${"a".repeat(64)}` },
    { totalAccesses: -1n },
  ]) {
    const f = fixture();
    f.rpc.readContract.mockImplementation(async ({ functionName }) =>
      functionName === "currentVersion"
        ? 1n
        : functionName === "dataPoints"
          ? { ...info(), ...patch }
          : replicaChainCommitment(dataHash, metadataHash),
    );
    await expect(f.read()).rejects.toMatchObject({ retryable: true });
  }
});

it("keeps Gateway lifecycle refusal pending before deletedAt is populated", async () => {
  const f = fixture();
  for (const state of ["inactive", "unavailable", "deleted"]) {
    f.fetcher.mockImplementation(async () =>
      Response.json({ data: { ...head, state, deletedAt: null } }),
    );
    const evidence = await f.read();
    expect(evidence.head?.deleted).toBe(true);
    expect(
      replicaRegistrationState(evidence, {
        owner,
        scope,
        dataHash,
        metadataHash,
      }),
    ).toBe("pending");
  }
  f.fetcher.mockImplementation(async () =>
    Response.json({ data: { ...head, state: "active" } }),
  );
  expect(
    replicaRegistrationState(await f.read(), {
      owner,
      scope,
      dataHash,
      metadataHash,
    }),
  ).toBe("confirmed");
  f.fetcher.mockImplementation(async () =>
    Response.json({ data: { ...head, state: "unknown" } }),
  );
  await expect(f.read()).rejects.toMatchObject({ retryable: true });
});

it("matches the DataRegistryV2 abi.encode hash-pair golden commitment", () => {
  expect(replicaChainCommitment(dataHash, metadataHash)).toBe(
    "0x3e92e0db88d6afea9edc4eedf62fffa4d92bcdfc310dccbe943747fe8302e871",
  );
});

it("does not treat a missing Gateway route as authoritative head absence", async () => {
  const f = fixture();
  f.rpc.readContract.mockImplementation(async ({ functionName }) =>
    functionName === "currentVersion"
      ? 0n
      : functionName === "dataPoints"
        ? info(0n)
        : `0x${"0".repeat(64)}`,
  );
  for (const response of [
    new Response("NOT_FOUND", { status: 404 }),
    Response.json(
      { error: "Not found", path: "/wrong-route" },
      { status: 404 },
    ),
  ]) {
    f.fetcher.mockImplementation(async () => response);
    await expect(f.read()).rejects.toMatchObject({ retryable: true });
  }
  f.fetcher.mockImplementation(async () =>
    Response.json({ error: "Data point not found" }, { status: 404 }),
  );
  expect(replicaRegistrationState(await f.read(), { owner, scope })).toBe(
    "absent",
  );
});
