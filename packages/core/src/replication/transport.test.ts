import { expect, it } from "vitest";
import {
  decodeReplicaFragment,
  decodeReplicaManifest,
  fragmentMatchesManifest,
  fragmentReplicaPayload,
  prepareReplicaManifest,
  replicaDigest,
  replicaFragmentKey,
  replicaManifestKey,
  replicaScope,
  replicaWriterOf,
  replicaManifestFacts,
  ReplicaManifestUnsigned,
  fromBase64,
} from "./transport.js";
import { canonicalJson } from "./envelope.js";
import { unsignedReplicaBatch } from "./writer-identity.test-utils.js";

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
  // Every fragment is encrypted under its writer's one stable scope and is
  // addressed by the digest of its own ciphertext.
  expect(new Set(parts.map((p) => p.scope))).toEqual(
    new Set([replicaScope("a".repeat(32))]),
  );
  expect(parts.map((p) => p.index)).toEqual(parts.map((_, i) => i));
  expect(parts.map((p) => p.digest)).toEqual(
    parts.map((p) => replicaDigest(p.encrypted)),
  );
});

it("binds a manifest to its owner, writer scope and version, and its fragments to the manifest", async () => {
  const writer = "a".repeat(32);
  const bytes = new TextEncoder().encode("a JSON record 😺".repeat(300));
  const base = {
    owner: "owner",
    writer,
    batch: "b".repeat(32),
    sequence: 2,
    previous: {
      batch: "c".repeat(32),
      digest: replicaDigest(new Uint8Array([1])),
    },
    collectedAt: "2026-10-20T00:00:00.000Z",
  };
  const parts = await fragmentReplicaPayload({
    ...base,
    bytes,
    targetChunkBytes: 1500,
    encrypt: async (_scope, bytes) => bytes,
  });
  const manifest = await prepareReplicaManifest({
    ...base,
    version: 2,
    digest: replicaDigest(bytes),
    totalBytes: bytes.length,
    fragments: parts.map((p) => ({
      digest: p.digest,
      bytes: p.encrypted.length,
    })),
    sign: unsignedReplicaBatch,
    encrypt: async (_scope, bytes) => bytes,
  });
  const scope = replicaScope(writer);
  expect(manifest).toMatchObject({ scope, version: 2 });
  expect(replicaManifestKey(scope, 2)).toBe(`${scope}/2`);
  expect(replicaFragmentKey(scope, parts[0]!.digest)).toBe(
    `${scope}/fragments/${parts[0]!.digest.slice(7)}`,
  );
  expect(replicaWriterOf(scope)).toBe(writer);
  expect(replicaWriterOf(`${scope}.0`)).toBeUndefined();
  const decoded = decodeReplicaManifest(manifest.plaintext, scope, "owner");
  expect(decoded.fragments).toHaveLength(parts.length);
  // The statement is signed over this manifest at its version.
  expect(decoded.authority).toEqual(
    await unsignedReplicaBatch(replicaManifestFacts(decoded, 2)),
  );
  // Without a statement the manifest is unsigned, not malformed.
  const { authority: _authority, ...bare } = decoded;
  const wrapper = JSON.parse(new TextDecoder().decode(manifest.plaintext));
  expect(() =>
    decodeReplicaManifest(
      new TextEncoder().encode(
        canonicalJson({ ...wrapper, data: { manifest: bare } }),
      ),
      scope,
      "owner",
    ),
  ).toThrow(ReplicaManifestUnsigned);
  expect(() =>
    decodeReplicaManifest(manifest.plaintext, scope, "other"),
  ).toThrow();
  expect(() =>
    decodeReplicaManifest(
      manifest.plaintext,
      replicaScope("d".repeat(32)),
      "owner",
    ),
  ).toThrow();
  const fragments = parts.map((p) =>
    decodeReplicaFragment(p.plaintext, p.scope, "owner"),
  );
  expect(
    fragments.every((f, i) => fragmentMatchesManifest(f, decoded, i)),
  ).toBe(true);
  expect(fragmentMatchesManifest(fragments[1]!, decoded, 0)).toBe(false);
  expect(
    fragmentMatchesManifest(
      { ...fragments[0]!, digest: replicaDigest(new Uint8Array([2])) },
      decoded,
      0,
    ),
  ).toBe(false);
});

it("reduces fragment size using actual DPv2 encryption overhead", async () => {
  const { encryptWithPassword, decryptWithPassword } =
    await import("@opendatalabs/vana-sdk/browser");
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
  expect(decoded.map((fragment) => fragment.index)).toEqual(
    parts.map((part) => part.index),
  );
  expect(
    decoded.reduce(
      (size, fragment) => size + fromBase64(fragment.content).length,
      0,
    ),
  ).toBe(bytes.length);
}, 30000);

it("keeps Gateway disagreement pending and quarantines only a finalized slot commitment conflict", async () => {
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
    version: 1,
    dataHash: row.dataHash,
    metadataHash: row.metadataHash,
  };
  const evidence = { head: row, chain, pending: false };
  // A later head and a later finalized version are appends, not conflicts.
  expect(
    replicaRegistrationState(
      { ...evidence, head: { ...row, version: "9" } },
      expected,
    ),
  ).toBe("confirmed");
  expect(
    replicaRegistrationState(
      { ...evidence, chain: { ...chain, currentVersion: "2" } },
      expected,
    ),
  ).toBe("confirmed");
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
    { chain: { ...chain, version: "2" } },
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
        { owner: row.owner, scope: row.scope, version: 1 },
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
    { chain: { ...chain, commitment: `0x${"c".repeat(64)}` as const } },
    {
      chain: {
        ...chain,
        currentVersion: "5",
        commitment: `0x${"c".repeat(64)}` as const,
      },
    },
  ]) {
    expect(replicaRegistrationState({ ...evidence, ...patch }, expected)).toBe(
      "conflict",
    );
  }
  // Without durable expected hashes, a head/chain mismatch is not terminal evidence.
  expect(
    replicaRegistrationState(
      { ...evidence, chain: { ...chain, commitment: `0x${"d".repeat(64)}` } },
      { owner: row.owner, scope: row.scope, version: 1 },
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
      version: 1,
      dataHash: `0x${"a".repeat(64)}`,
      metadataHash: `0x${"b".repeat(64)}`,
    }),
  ).toBe("conflict");
});

it("decodes a binary replica payload within a 192 MiB Node heap", async () => {
  const { spawnSync } = await import("node:child_process");
  const url = new URL("./transport.ts", import.meta.url).href;
  const child = spawnSync(
    process.execPath,
    [
      "--max-old-space-size=192",
      "--import",
      "tsx",
      "--input-type=module",
      "-e",
      `import {fromBase64} from ${JSON.stringify(url)};
     import {createHash} from 'node:crypto';
     const original = Buffer.alloc(64 * 1024 * 1024, 31);
     const actual = fromBase64(original.toString('base64'));
     const hash = bytes => createHash('sha256').update(bytes).digest('hex');
     if(hash(actual) !== hash(original)) throw new Error('binary digest changed');
     console.log(JSON.stringify({bytes:actual.length,peakRssKiB:process.resourceUsage().maxRSS}));`,
    ],
    { encoding: "utf8", timeout: 30000, maxBuffer: 16384 },
  );
  expect(child.status, child.stderr.slice(-2000)).toBe(0);
  const result = JSON.parse(child.stdout) as {
    bytes: number;
    peakRssKiB: number;
  };
  expect(result.bytes).toBe(64 * 1024 * 1024);
  expect(result.peakRssKiB).toBeLessThan(512 * 1024);
}, 35000);

it("keeps canonical base64 validation when decoding binary payloads", () => {
  expect(fromBase64("YQ==")).toEqual(new Uint8Array([97]));
  for (const value of ["YQ", "YR==", "YQ==\n"])
    expect(() => fromBase64(value)).toThrow("noncanonical base64");
});

it("preserves canonical base64 for every final byte and rejects all nonzero pad bits", () => {
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  expect(fromBase64("")).toEqual(new Uint8Array());
  for (let lastByte = 0; lastByte < 256; lastByte++) {
    for (const input of [[lastByte], [0, lastByte]]) {
      const encoded = Buffer.from(input).toString("base64");
      expect(fromBase64(encoded)).toEqual(new Uint8Array(input));
      const padding = input.length === 1 ? 2 : 1;
      const index = encoded.length - padding - 1;
      const canonical = alphabet.indexOf(encoded[index]!);
      for (let bits = 1; bits < (padding === 2 ? 16 : 4); bits++) {
        const malformed =
          encoded.slice(0, index) +
          alphabet[canonical | bits] +
          encoded.slice(index + 1);
        expect(() => fromBase64(malformed)).toThrow("noncanonical base64");
      }
    }
  }
});

it("rejects atob's optional padding and whitespace forms", () => {
  // These have zero pad bits, and whitespace replaces padding without changing
  // the canonical encoded length. Each independent grammar check must reject.
  for (const value of [
    "YQ  ",
    "YWI ",
    "YQ\n\n",
    "YQ\t\t",
    "YQ\r\r",
    "YQ\f\f",
    "AAA",
    "QUE",
  ]) {
    expect(btoa(atob(value))).not.toBe(value);
    expect(() => fromBase64(value)).toThrow("noncanonical base64");
  }
  for (const input of [[], [0], [0, 255], [0, 255, 127]]) {
    const encoded = Buffer.from(input).toString("base64");
    expect(fromBase64(encoded)).toEqual(new Uint8Array(input));
    for (const whitespace of [" ", "\t", "\n", "\r", "\f"]) {
      for (let position = 0; position <= encoded.length; position++) {
        const malformed =
          encoded.slice(0, position) + whitespace + encoded.slice(position);
        expect(() => fromBase64(malformed)).toThrow("noncanonical base64");
      }
    }
    if (encoded.endsWith("="))
      expect(() => fromBase64(encoded.replace(/=+$/, ""))).toThrow(
        "noncanonical base64",
      );
  }
});

it("continues to reject non-string runtime arguments", () => {
  for (const value of [null, undefined, [], ["YQ=="], {}, 1234, true])
    expect(() => Reflect.apply(fromBase64, null, [value])).toThrow();
});
