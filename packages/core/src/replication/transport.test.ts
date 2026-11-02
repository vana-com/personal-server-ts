import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import {
  decodeReplicaFragment,
  decodeReplicaManifest,
  fragmentMatchesManifest,
  fragmentReplicaPayload,
  prepareReplicaManifest,
  replicaDigest,
  replicaFragmentKey,
  replicaLegacyFragmentKey,
  replicaManifestKey,
  replicaScope,
  replicaWriterOf,
  replicaManifestFacts,
  ReplicaManifestUnsigned,
  fromBase64,
} from "./transport.js";
import { canonicalJson } from "./envelope.js";
import {
  createTestReplicaRoster,
  createTestReplicaSigner,
  unsignedReplicaBatch,
} from "./writer-identity.test-utils.js";
import { assembleReplicaStream } from "./stream.js";
import {
  authorizeReplicaBatch,
  deriveReplicaWriters,
  signReplicaBatch,
} from "./writer-identity.js";

it("runs the pinned published receive boundary against authenticated v1 and v2 manifests", async () => {
  const fixture =
    "./fixtures/published-reader-08d612f4061b7fed592b688993d8ec44381f4d1/";
  const blobHash = (bytes: Uint8Array) =>
    createHash("sha1")
      .update(`blob ${bytes.length}\0`)
      .update(bytes)
      .digest("hex");
  const sourceBlobs = {
    "transport.ts": "f557cbd676f12d45e615459fef16a7de731a2ffc",
    "receive.ts": "b054605bc6bea5cb6cfd73f3818adfdf8bdb705f",
    "outcome.ts": "c1eacc9bdf85f027f01ee63fd0153f8a0b4e4281",
    "envelope.ts": "6db62d3503eba9be14c9781634730657d20aebaa",
    "limits.ts": "1c318af921358f2c58a45a131cfee08f911dc0af",
    "writer-identity.ts": "0958dff0e274970e81150e552a76c027a00207c4",
    "namespace.ts": "ff2c2adeb775783e8dcfd2ed32c43bc4e89e5de0",
    "roster.ts": "bf76f3da60baa8aeb5f7fc20e70657ca4ce5e050",
    "../../coordinator.ts": "3364140d2f314f678fcdbcfd435dfcae9f50172b",
    "../../../pdpp/declaration.ts": "52b81afabd5d6ccef124066bda381980f4ea7826",
  };
  for (const [path, expected] of Object.entries(sourceBlobs))
    expect(
      blobHash(readFileSync(new URL(`${fixture}${path}`, import.meta.url))),
      path,
    ).toBe(expected);
  expect(
    readFileSync(
      new URL("./fixtures/pdpp/declaration.ts", import.meta.url),
      "utf8",
    ),
  ).toContain("MAX_DECLARATION_BYTES = 256 * 1024");

  // The published lock and this runtime lock have identical integrity entries
  // for the three external modules the exact source imports.
  const lock = JSON.parse(
    readFileSync(
      new URL("../../../../package-lock.json", import.meta.url),
      "utf8",
    ),
  ) as { packages: Record<string, { version: string; integrity: string }> };
  expect(lock.packages["node_modules/zod"]).toMatchObject({
    version: "4.4.3",
    integrity:
      "sha512-ytENFjIJFl2UwYglde2jchW2Hwm4GJFLDiSXWdTrJQBIN9Fcyp7n4DhxJEiWNAJMV1/BqWfW/kkg71UDcHJyTQ==",
  });
  expect(lock.packages["node_modules/viem"]).toMatchObject({
    version: "2.54.2",
    integrity:
      "sha512-o0+5dEAUekBMTbixXy2mKbSDPnwsCJ+8+mOeMBDjkuS9iM4fcr3yKUWb2zlOy2NKInkg3anl1W11sxYspLiXig==",
  });
  expect(lock.packages["node_modules/@opendatalabs/vana-sdk"]).toMatchObject({
    version: "3.23.0-pr.211.36da1d8",
    integrity:
      "sha512-+US129OCbyQAtKu6VGOQmITuw7XXP+JgFs2gV+G33yneyN1n/qrZ2Ips9ZmPbbXxXpwDXo0ei9yyKqkhF2sRNQ==",
  });

  const oldReader = await import(`${fixture}receive.js`);
  const oldDecoder = await import(`${fixture}transport.js`);
  const newReader = await import("./receive.js");
  const owner = "0x00000000000000000000000000000000000000aa";
  const signer = createTestReplicaSigner("published-reader-format-gate");
  const seed = {
    owner,
    server: signer.address.toLowerCase(),
    serverId: `0x${"1".repeat(64)}`,
    writerNonce: `0x${"2".repeat(32)}`,
  };
  const roster = createTestReplicaRoster();
  roster.register(signer.address, owner, seed.serverId);
  const writer = deriveReplicaWriters(seed).transport;
  const collectedAt = "2026-10-20T00:00:00.000Z";
  const sign = (facts: Parameters<typeof signReplicaBatch>[0]["facts"]) =>
    signReplicaBatch({
      signer,
      partition: { owner, chainId: 14800, environment: "dev" },
      seed,
      facts,
    });
  const oldPayload = new TextEncoder().encode("published v1 baseline");
  const oldFragments = await fragmentReplicaPayload({
    owner,
    writer,
    batch: "c".repeat(32),
    sequence: 1,
    previous: null,
    bytes: oldPayload,
    collectedAt,
    targetChunkBytes: 12,
    encrypt: async (_scope, bytes) => bytes,
  });
  const oldV1 = await oldDecoder.prepareReplicaManifest({
    owner,
    writer,
    version: 1,
    batch: "c".repeat(32),
    sequence: 1,
    previous: null,
    collectedAt,
    digest: replicaDigest(oldPayload),
    totalBytes: oldPayload.length,
    fragments: oldFragments.map((fragment) => ({
      digest: fragment.digest,
      bytes: fragment.encrypted.length,
    })),
    sign,
    encrypt: async (_scope, bytes) => bytes,
  });
  const oldV1Receipt = await oldReader.receiveReplicaManifest({
    scope: oldV1.scope,
    owner,
    maxBytes: 64 * 1024,
    read: async () => oldV1.encrypted,
    decrypt: async (bytes) => bytes,
    committed: (dataHash, metadataHash) =>
      dataHash === oldV1.dataHash && metadataHash === oldV1.metadataHash,
  });
  expect(oldV1Receipt.tag).toBe("manifest");
  const decodedV1 = decodeReplicaManifest(oldV1.plaintext, oldV1.scope, owner);
  expect(decodedV1.version).toBe(1);
  expect(
    await authorizeReplicaBatch({
      authority: decodedV1.authority,
      facts: replicaManifestFacts(decodedV1, 1),
      transportWriter: writer,
      receiver: { owner, chainId: 14800, environment: "dev" },
      roster: roster.port.server,
    }),
  ).toMatchObject({ tag: "authorized" });
  expect(
    (
      await newReader.receiveReplicaManifest({
        scope: oldV1.scope,
        owner,
        maxBytes: 64 * 1024,
        read: async () => oldV1.encrypted,
        decrypt: async (bytes) => bytes,
        committed: (dataHash, metadataHash) =>
          dataHash === oldV1.dataHash && metadataHash === oldV1.metadataHash,
      })
    ).tag,
  ).toBe("manifest");

  const newPayload = new TextEncoder().encode("new signed v2 batch");
  const newFragments = await fragmentReplicaPayload({
    owner,
    writer,
    batch: "b".repeat(32),
    sequence: 2,
    previous: {
      batch: "c".repeat(32),
      digest: replicaDigest(oldPayload),
    },
    bytes: newPayload,
    collectedAt,
    targetChunkBytes: 12,
    encrypt: async (_scope, bytes) => bytes,
  });
  const newV2 = await prepareReplicaManifest({
    owner,
    writer,
    version: 2,
    batch: "b".repeat(32),
    sequence: 2,
    previous: {
      batch: "c".repeat(32),
      digest: replicaDigest(oldPayload),
    },
    collectedAt,
    digest: replicaDigest(newPayload),
    totalBytes: newPayload.length,
    fragments: newFragments.map((fragment) => ({
      digest: fragment.digest,
      bytes: fragment.encrypted.length,
    })),
    sign,
    encrypt: async (_scope, bytes) => bytes,
  });
  expect(newV2.version).toBe(2);
  const oldV2Receipt = await oldReader.receiveReplicaManifest({
    scope: newV2.scope,
    owner,
    maxBytes: 64 * 1024,
    read: async () => newV2.encrypted,
    decrypt: async (bytes) => bytes,
    committed: (dataHash, metadataHash) =>
      dataHash === newV2.dataHash && metadataHash === newV2.metadataHash,
  });
  expect(oldV2Receipt).toEqual({ tag: "refused", reason: "manifest_invalid" });
  const decodedV2 = decodeReplicaManifest(newV2.plaintext, newV2.scope, owner);
  expect(
    await authorizeReplicaBatch({
      authority: decodedV2.authority,
      facts: replicaManifestFacts(decodedV2, 2),
      transportWriter: writer,
      receiver: { owner, chainId: 14800, environment: "dev" },
      roster: roster.port.server,
    }),
  ).toMatchObject({ tag: "authorized" });
  const v2CurrentReceipt = await newReader.receiveReplicaManifest({
    scope: newV2.scope,
    owner,
    maxBytes: 64 * 1024,
    read: async () => newV2.encrypted,
    decrypt: async (bytes) => bytes,
    committed: (dataHash, metadataHash) =>
      dataHash === newV2.dataHash && metadataHash === newV2.metadataHash,
  });
  expect(v2CurrentReceipt.tag).toBe("manifest");
  expect(
    v2CurrentReceipt.tag === "manifest" && v2CurrentReceipt.manifest.authority,
  ).toEqual(decodedV2.authority);
  // A refused receive has no manifest to admit, so the old path cannot read
  // its fragments or create an import receipt from this slot.
  const oldFragmentReads: string[] = [];
  const oldImportReceipts: string[] = [];
  if (oldV2Receipt.tag === "manifest") {
    for (const fragment of oldV2Receipt.manifest.fragments)
      oldFragmentReads.push(fragment.digest);
    oldImportReceipts.push(oldV2Receipt.manifest.batch);
  }
  expect(oldFragmentReads).toEqual([]);
  expect(oldImportReceipts).toEqual([]);
  expect("manifest" in oldV2Receipt).toBe(false);
});

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
  const assembled: Uint8Array[] = [];
  for await (const chunk of assembleReplicaStream(async function* () {
    for (const part of parts)
      yield decodeReplicaFragment(part.plaintext, part.scope, "owner");
  }))
    assembled.push(chunk);
  expect(Buffer.concat(assembled)).toEqual(Buffer.from(bytes));
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
    `${scope}/fragments-${parts[0]!.digest.slice(7)}`,
  );
  expect(replicaLegacyFragmentKey(scope, parts[0]!.digest)).toBe(
    `${scope}/fragments/${parts[0]!.digest.slice(7)}`,
  );
  expect(replicaWriterOf(scope)).toBe(writer);
  expect(replicaWriterOf(`${scope}.0`)).toBeUndefined();
  const decoded = decodeReplicaManifest(manifest.plaintext, scope, "owner");
  expect(decoded.version).toBe(2);
  const legacyEnvelope = JSON.parse(
    new TextDecoder().decode(manifest.plaintext),
  );
  legacyEnvelope.data.manifest.version = 1;
  expect(
    decodeReplicaManifest(
      new TextEncoder().encode(canonicalJson(legacyEnvelope)),
      scope,
      "owner",
    ).version,
  ).toBe(1);
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
