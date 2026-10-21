import { expect, it } from "vitest";
import { fragmentReplicaPayload, replicaScope } from "./transport.js";

it("fragments a large export without changing bytes or exceeding encrypted cap", async () => {
  const bytes = new TextEncoder().encode("😺large JSON record".repeat(2000));
  const parts = await fragmentReplicaPayload({
    owner: "owner",
    writer: "a".repeat(32),
    batch: "b".repeat(32),
    sequence: 1,
    previous: null,
    bytes,
    collectedAt: "2026-10-20T00:00:00Z",
    encrypt: async (_scope, bytes) =>
      new Uint8Array([...bytes, ...new Uint8Array(100)]),
    maxBlobBytes: 4096,
    targetChunkBytes: 8000,
  });
  expect(parts.length).toBeGreaterThan(1);
  expect(parts.every((p) => p.encrypted.length <= 4096)).toBe(true);
  expect(parts.map((p) => p.scope)).toEqual(
    parts.map((_, i) => replicaScope("a".repeat(32), "b".repeat(32), i)),
  );
});

it("reassembles byte-identical content and rejects missing, overlapping, swapped or tampered frames", async () => {
  const { assembleReplicaPayload, decodeReplicaFragment } =
    await import("./transport.js");
  const bytes = new TextEncoder().encode("a JSON record 😺".repeat(300));
  const parts = await fragmentReplicaPayload({
    owner: "owner",
    writer: "a".repeat(32),
    batch: "b".repeat(32),
    sequence: 1,
    previous: null,
    bytes,
    collectedAt: "2026-10-20T00:00:00.000Z",
    targetChunkBytes: 1500,
    encrypt: async (_scope, bytes) => bytes,
  });
  const fragments = parts.map((p) =>
    decodeReplicaFragment(p.plaintext, p.scope, "owner"),
  );
  expect(assembleReplicaPayload([...fragments].reverse())).toEqual(bytes);
  expect(() =>
    assembleReplicaPayload(
      fragments.map((f) => ({ ...f, digest: `sha256:${"0".repeat(64)}` })),
    ),
  ).toThrow();
  expect(() => assembleReplicaPayload(fragments.slice(1))).toThrow();
  expect(() =>
    assembleReplicaPayload([fragments[0]!, ...fragments.slice(0, -1)]),
  ).toThrow();
  for (const mutation of [
    { offset: 1 },
    { totalBytes: Number.MAX_SAFE_INTEGER },
    { batch: "c".repeat(32) },
    { content: "YQ==" },
    { count: fragments.length + 1 },
  ]) {
    expect(() =>
      assembleReplicaPayload([
        { ...fragments[0]!, ...mutation },
        ...fragments.slice(1),
      ]),
    ).toThrow();
  }
  expect(() =>
    decodeReplicaFragment(parts[0]!.plaintext, parts[0]!.scope, "other-owner"),
  ).toThrow();
});

it("reduces fragment size using actual DPv2 encryption overhead", async () => {
  const { encryptWithPassword, decryptWithPassword } =
    await import("@opendatalabs/vana-sdk/browser");
  const { assembleReplicaPayload, decodeReplicaFragment } =
    await import("./transport.js");
  const bytes = crypto.getRandomValues(new Uint8Array(6500));
  const parts = await fragmentReplicaPayload({
    owner: "owner",
    writer: "a".repeat(32),
    batch: "b".repeat(32),
    sequence: 1,
    previous: null,
    bytes,
    collectedAt: "2026-10-20T00:00:00.000Z",
    targetChunkBytes: 6500,
    maxBlobBytes: 4096,
    encrypt: (_scope, bytes) => encryptWithPassword(bytes, "test-password"),
  });
  expect(parts.length).toBeGreaterThan(1);
  expect(parts.every((p) => p.encrypted.length <= 4096)).toBe(true);
  const decoded = await Promise.all(
    parts.map(async (p) =>
      decodeReplicaFragment(
        await decryptWithPassword(p.encrypted, "test-password"),
        p.scope,
        "owner",
      ),
    ),
  );
  expect(assembleReplicaPayload(decoded)).toEqual(bytes);
}, 30000);

it("keeps Gateway disagreement pending and quarantines only finalized immutable slot conflicts", async () => {
  const { replicaRegistrationState, replicaChainCommitment } =
    await import("./dpv2.js");
  const row = {
    owner: "owner",
    scope: "scope",
    version: "1",
    dataHash: `0x${"a".repeat(64)}` as const,
    metadataHash: `0x${"b".repeat(64)}` as const,
    deleted: false,
  };
  const chain = {
    owner: row.owner,
    scope: row.scope,
    version: "1" as const,
    currentVersion: "1",
    status: "Active" as const,
    commitment: replicaChainCommitment(row.dataHash, row.metadataHash),
    chainId: 14800,
    registry: `0x${"1".repeat(40)}` as const,
    blockNumber: 123n,
    blockHash: `0x${"c".repeat(64)}` as const,
    blockTimestamp: 1000n,
  };
  const expected = {
    owner: row.owner,
    scope: row.scope,
    dataHash: row.dataHash,
    metadataHash: row.metadataHash,
  };
  const evidence = { head: row, chain, pending: false };
  expect(
    replicaRegistrationState(
      { ...evidence, head: { ...row, version: "9" } },
      expected,
    ),
  ).toBe("pending");
  expect(replicaRegistrationState(evidence, expected)).toBe("confirmed");
  const absentChain = {
    ...chain,
    currentVersion: "0",
    status: "None" as const,
    commitment: `0x${"0".repeat(64)}` as const,
  };
  expect(
    replicaRegistrationState(
      { head: null, chain: absentChain, pending: false },
      expected,
    ),
  ).toBe("absent");
  const uncertain = [
    { chain: null },
    { head: null },
    { pending: true },
    { chain: absentChain },
    { head: { ...row, version: "9" } },
    { head: { ...row, owner: "other" } },
    { head: { ...row, scope: "other" } },
    { head: { ...row, deleted: true } },
    { head: { ...row, dataHash: `0x${"c".repeat(64)}` } },
    { head: { ...row, metadataHash: `0x${"c".repeat(64)}` } },
    { chain: { ...chain, status: "Unavailable" as const } },
    { chain: { ...chain, status: "Inactive" as const } },
  ];
  for (const patch of uncertain) {
    expect(replicaRegistrationState({ ...evidence, ...patch }, expected)).toBe(
      "pending",
    );
    expect(
      replicaRegistrationState(
        { ...evidence, ...patch },
        { owner: row.owner, scope: row.scope },
      ),
    ).toBe("pending");
  }
  expect(
    replicaRegistrationState(
      { head: null, chain: null, pending: false },
      expected,
    ),
  ).toBe("pending");
  for (const patch of [
    { chain: { ...chain, currentVersion: "2" } },
    { chain: { ...chain, commitment: `0x${"c".repeat(64)}` as const } },
  ]) {
    expect(replicaRegistrationState({ ...evidence, ...patch }, expected)).toBe(
      "conflict",
    );
  }
  // Without durable expected hashes, a head/chain mismatch is not terminal evidence.
  expect(
    replicaRegistrationState(
      { ...evidence, chain: { ...chain, commitment: `0x${"d".repeat(64)}` } },
      { owner: row.owner, scope: row.scope },
    ),
  ).toBe("pending");
});

it("quarantines a finalized tombstone-at-version-1 against the durable replica hashes", async () => {
  const { replicaRegistrationState, replicaChainCommitment } =
    await import("./dpv2.js");
  const { keccak256, stringToHex } = await import("viem");
  const dataHash = keccak256(stringToHex("vana.data-point.tombstone.v1"));
  const metadataHash = keccak256(
    stringToHex("vana.data-point.tombstone.metadata.v1"),
  );
  const evidence = {
    head: null,
    chain: {
      owner: "owner",
      scope: "scope",
      version: "1" as const,
      currentVersion: "1",
      status: "Active" as const,
      commitment: replicaChainCommitment(dataHash, metadataHash),
      chainId: 14800,
      registry: "0x1" as const,
      blockNumber: 1n,
      blockHash: "0x1" as const,
      blockTimestamp: 1n,
    },
    pending: false,
  };
  expect(
    replicaRegistrationState(evidence, {
      owner: "owner",
      scope: "scope",
      dataHash: `0x${"a".repeat(64)}`,
      metadataHash: `0x${"b".repeat(64)}`,
    }),
  ).toBe("conflict");
});
