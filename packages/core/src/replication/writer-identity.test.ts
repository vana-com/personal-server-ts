import { describe, expect, it } from "vitest";
import {
  authorizeReplicaBatch,
  deriveReplicaWriterId,
  deriveReplicaWriters,
  replicaFragmentListDigest,
  replicaOperationWriterRefusal,
  signReplicaBatch,
  type ReplicaBatchFacts,
  type ReplicaPartition,
  type ReplicaWriterSeed,
} from "./writer-identity.js";
import {
  createTestReplicaRoster,
  createTestReplicaSigner,
} from "./writer-identity.test-utils.js";

const owner = "0x00000000000000000000000000000000000000aa";
const partition: ReplicaPartition = {
  owner,
  chainId: 14800,
  environment: "dev",
};
const fragment = (n: string, bytes = 500) => ({
  digest: `sha256:${n.repeat(64)}`,
  bytes,
});
const facts: ReplicaBatchFacts = {
  version: 7,
  batch: "b".repeat(32),
  sequence: 2,
  previous: { batch: "c".repeat(32), digest: `sha256:${"d".repeat(64)}` },
  collectedAt: "2026-10-20T00:00:00.000Z",
  digest: `sha256:${"e".repeat(64)}`,
  totalBytes: 1234,
  fragments: [fragment("1"), fragment("2"), fragment("3", 234)],
};

describe("writer id derivation", () => {
  const seed: ReplicaWriterSeed = {
    owner,
    server: `0x${"1".repeat(40)}`,
    serverId: `0x${"2".repeat(64)}`,
    writerNonce: `0x${"3".repeat(32)}`,
  };

  // Vector computed independently with Python hashlib over the same framing.
  it("pins the length-prefixed SHA-256 vector for both roles", () => {
    expect(deriveReplicaWriters(seed)).toEqual({
      transport: "1695f9e189dfdd503be7ffe5e1028bae",
      operation: "9ca7795843cebd27a7ddaed5c78945f9",
    });
  });

  it("changes with every input and accepts only canonical lowercase hex", () => {
    const base = deriveReplicaWriterId(seed, "transport");
    expect(base).toMatch(/^[a-f0-9]{32}$/);
    for (const patch of [
      { owner: `0x${"9".repeat(40)}` },
      { server: `0x${"9".repeat(40)}` },
      { serverId: `0x${"9".repeat(64)}` },
      { writerNonce: `0x${"9".repeat(32)}` },
    ])
      expect(
        deriveReplicaWriterId({ ...seed, ...patch }, "transport"),
      ).not.toBe(base);
    expect(() =>
      deriveReplicaWriterId(
        { ...seed, server: `0x${"A".repeat(40)}` },
        "transport",
      ),
    ).toThrow();
  });
});

describe("fragment list digest", () => {
  // Vector computed independently with Python hashlib and struct.pack(">Q").
  it("pins SHA-256 over each 32-byte digest and 8-byte big-endian length", () => {
    expect(replicaFragmentListDigest(facts.fragments)).toBe(
      "0x55fdda17e6672797025caf134f8291b3343c80ccbf4bfd9d738221320cb8a17b",
    );
  });
});

async function registeredDevice(
  roster = createTestReplicaRoster(),
  wallet = owner,
) {
  const signer = createTestReplicaSigner();
  const serverId = roster.register(signer.address, wallet);
  const seed: ReplicaWriterSeed = {
    owner: wallet.toLowerCase(),
    server: signer.address.toLowerCase(),
    serverId,
    writerNonce: `0x${"4".repeat(32)}`,
  };
  const authority = await signReplicaBatch({
    signer,
    partition: { ...partition, owner: wallet },
    seed,
    facts,
  });
  return {
    roster,
    signer,
    seed,
    authority,
    writers: deriveReplicaWriters(seed),
  };
}

describe("authorizeReplicaBatch", () => {
  const check = (
    device: Awaited<ReturnType<typeof registeredDevice>>,
    patch: Partial<Parameters<typeof authorizeReplicaBatch>[0]> = {},
  ) =>
    authorizeReplicaBatch({
      authority: device.authority,
      facts,
      transportWriter: device.writers.transport,
      receiver: partition,
      roster: (server) => device.roster.port.server(server),
      ...patch,
    });

  it("authorizes a registered signer and returns its derived writers", async () => {
    const device = await registeredDevice();
    await expect(check(device)).resolves.toEqual({
      tag: "authorized",
      seed: device.seed,
      writers: device.writers,
    });
  });

  it("refuses a statement that is tampered, forged or does not cover the batch", async () => {
    const device = await registeredDevice();
    const other = createTestReplicaSigner();
    const forged = await signReplicaBatch({
      signer: other,
      partition,
      seed: { ...device.seed, server: other.address.toLowerCase() },
      facts,
    });
    for (const authority of [
      {
        ...device.authority,
        statement: { ...device.authority.statement, totalBytes: 1 },
      },
      // Another key claims to be the registered server.
      {
        ...forged,
        statement: { ...forged.statement, server: device.seed.server },
      },
      { ...device.authority, signature: `0x${"0".repeat(130)}` },
      { ...device.authority, version: 9 },
      null,
    ])
      await expect(check(device, { authority })).resolves.toEqual({
        tag: "refused",
        reason: "signature_invalid",
      });
    for (const patch of [
      { version: 8 },
      { sequence: 3 },
      { previous: null },
      { previous: { ...facts.previous!, batch: "f".repeat(32) } },
      { collectedAt: "2026-10-21T00:00:00.000Z" },
      { digest: `sha256:${"0".repeat(64)}` },
      { batch: "f".repeat(32) },
      // The fragment list: one more, one fewer, reordered, resized, replaced.
      { fragments: [...facts.fragments, fragment("4")] },
      { fragments: facts.fragments.slice(0, 2) },
      { fragments: [...facts.fragments].reverse() },
      { fragments: [fragment("1"), fragment("2"), fragment("3", 235)] },
      { fragments: [fragment("1"), fragment("2"), fragment("4", 234)] },
      { fragments: [] },
    ])
      await expect(
        check(device, { facts: { ...facts, ...patch } }),
      ).resolves.toEqual({ tag: "refused", reason: "signature_invalid" });
    expect(device.roster.reads).toBe(0);
  });

  it("refuses another owner, chain or environment before reading the roster", async () => {
    const device = await registeredDevice();
    for (const receiver of [
      { ...partition, owner: `0x${"b".repeat(40)}` },
      { ...partition, chainId: 1480 },
      { ...partition, environment: "prod" as const },
    ])
      await expect(check(device, { receiver })).resolves.toEqual({
        tag: "refused",
        reason: "partition_mismatch",
      });
    // Owner comparison ignores address case.
    await expect(
      check(device, {
        receiver: {
          ...partition,
          owner: owner.toUpperCase().replace("0X", "0x"),
        },
      }),
    ).resolves.toMatchObject({ tag: "authorized" });
    expect(device.roster.reads).toBe(1);
  });

  it("checks the roster: registered now, this incarnation, this owner", async () => {
    const device = await registeredDevice();
    const { roster, signer } = device;
    roster.deregister(signer.address);
    await expect(check(device)).resolves.toEqual({
      tag: "refused",
      reason: "server_not_registered",
    });
    // Re-registration is a new incarnation; the old statement names the old id.
    roster.register(signer.address, owner);
    await expect(check(device)).resolves.toEqual({
      tag: "refused",
      reason: "server_not_registered",
    });
    const unknown = await registeredDevice(createTestReplicaRoster());
    await expect(check(unknown, { roster: async () => null })).resolves.toEqual(
      { tag: "refused", reason: "server_not_registered" },
    );
  });

  it("refuses a server registered under another wallet signing into this partition", async () => {
    const roster = createTestReplicaRoster();
    const signer = createTestReplicaSigner();
    const serverId = roster.register(signer.address, `0x${"f".repeat(40)}`);
    const seed = {
      owner,
      server: signer.address.toLowerCase(),
      serverId,
      writerNonce: `0x${"4".repeat(32)}`,
    };
    const authority = await signReplicaBatch({
      signer,
      partition,
      seed,
      facts,
    });
    await expect(
      authorizeReplicaBatch({
        authority,
        facts,
        transportWriter: deriveReplicaWriters(seed).transport,
        receiver: partition,
        roster: (server) => roster.port.server(server),
      }),
    ).resolves.toEqual({ tag: "refused", reason: "roster_owner_mismatch" });
  });

  it("refuses a carrier writer that the signer does not derive", async () => {
    const victim = await registeredDevice();
    const attacker = await registeredDevice(victim.roster);
    await expect(
      check(attacker, { transportWriter: victim.writers.transport }),
    ).resolves.toEqual({ tag: "refused", reason: "writer_mismatch" });
  });

  it("waits when the roster cannot answer", async () => {
    const device = await registeredDevice();
    device.roster.setAvailable(false);
    await expect(check(device)).resolves.toEqual({
      tag: "wait",
      server: device.seed.server,
    });
  });

  it("requires every operation to name the derived operation writer", async () => {
    const { writers } = await registeredDevice();
    const op = (writerId: string) => ({ revision: { writerId } });
    expect(
      replicaOperationWriterRefusal([op(writers.operation)], writers),
    ).toBeUndefined();
    expect(
      replicaOperationWriterRefusal(
        [op(writers.operation), op(writers.transport)],
        writers,
      ),
    ).toBe("writer_mismatch");
  });

  it("will not sign for a seed whose server is another key", async () => {
    const device = await registeredDevice();
    await expect(
      signReplicaBatch({
        signer: createTestReplicaSigner(),
        partition,
        seed: device.seed,
        facts,
      }),
    ).rejects.toThrow();
  });
});
