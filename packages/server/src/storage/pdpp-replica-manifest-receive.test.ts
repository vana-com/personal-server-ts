/**
 * What a receiver reads for a finalized manifest, and how it ends a manifest
 * that can never be valid (host contract §3.4, §6). Reads are bounded before
 * bytes are kept, compressed messages are refused before they inflate, and
 * fragment reads are charged to the step's byte budget. A manifest whose bytes
 * match the finalized commitment but fail a check is a typed quarantine, never
 * a retry. Real workers and receivers over the contract network.
 */
import { randomUUID } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";
import { bytesToHex, keccak256 } from "viem";
import * as openpgp from "openpgp";
import { deriveScopeKey } from "@opendatalabs/vana-sdk/browser";
import {
  canonicalJson,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  prepareReplicaManifest,
  replicaDigest,
  replicaManifestFacts,
  replicaFragmentKey,
  replicaMetadataHash,
  replicaScope,
} from "@opendatalabs/personal-server-ts-core/replication/transport";
import {
  at,
  binding,
  cleanupHarness,
  cycles,
  injectReplicaBatch,
  network,
  owner,
  slotKey,
  sourceId,
  transportDevice,
  type Network,
  type TransportDevice,
} from "./pdpp-replica-contract.test-utils.js";
import { remoteReplicaTestWriter } from "./pdpp-replica-writer-identity.test-utils.js";

afterEach(cleanupHarness);

/** A record upsert of key "a", as a device's own capture would write it. */
function upsert(writerId: string, text: string) {
  return {
    kind: "upsert",
    owner,
    sourceId,
    connectionId: "conn",
    methodId: "export",
    generation: 1,
    declaration: binding,
    recordKey: "a",
    emittedAt: at,
    data: { id: "a", text },
    blobs: [],
    revision: { counter: 1000, writerId, operationId: randomUUID() },
  } as ReplicaOperation;
}
/** The receiver's manifest row of a slot. */
function rowOf(d: TransportDevice, slot: string) {
  return d.db
    .prepare(
      "SELECT state,outcome,reason FROM pdpp_transport_manifests_in WHERE slot=?",
    )
    .get(slot) as
    | { state: string; outcome: string | null; reason: string | null }
    | undefined;
}
/** Fragment reads under a scope. */
const fragmentReads = (net: Network, scope: string) =>
  net.calls.gets.filter((key) => key.startsWith(`${scope}/fragments/`));
/** Fragment entries the receiver admitted for a slot. */
const admitted = (d: TransportDevice, slot: string) =>
  (
    d.db
      .prepare(
        "SELECT count(*) AS count FROM pdpp_transport_fragments_in WHERE slot=?",
      )
      .get(slot) as { count: number }
  ).count;
/**
 * Register `plaintext` at `scope`/`version` with a commitment that matches it,
 * as an owner-registered peer can.
 */
async function registerPlaintext(
  net: Network,
  scope: string,
  version: number,
  plaintext: Uint8Array,
  encrypted?: Uint8Array,
) {
  const stored = encrypted ?? (await net.port.encrypt(scope, plaintext));
  const manifest = {
    scope,
    version,
    plaintext,
    encrypted: stored,
    dataHash: keccak256(plaintext),
    metadataHash: replicaMetadataHash(scope, at, stored.length),
  };
  net.blobs.set(slotKey(scope, version), stored);
  await net.port.register(manifest);
  return slotKey(scope, version);
}
/** A manifest wrapper as a writer encodes it. */
const encode = (wrapper: unknown) =>
  new TextEncoder().encode(canonicalJson(wrapper));
const wrapperOf = (plaintext: Uint8Array) =>
  JSON.parse(new TextDecoder().decode(plaintext));

it("a truthful manifest signed for another owner is partition_mismatch, with no fragment fetched", async () => {
  const net = network();
  const receiver = transportDevice(net);
  const foreign = `0x${"f".repeat(40)}`;
  const r = remoteReplicaTestWriter(net.roster, foreign);
  const scope = replicaScope(r.writers.transport);
  const manifest = await prepareReplicaManifest({
    owner: foreign,
    writer: r.writers.transport,
    version: 1,
    batch: "b".repeat(32),
    sequence: 1,
    previous: null,
    collectedAt: at,
    digest: replicaDigest(new Uint8Array([1])),
    totalBytes: 1,
    fragments: [{ digest: replicaDigest(new Uint8Array([1])), bytes: 1 }],
    sign: r.sign,
    encrypt: net.port.encrypt,
  });
  await net.port.put(manifest);
  await net.port.register(manifest);
  await cycles([receiver], 2);
  expect(rowOf(receiver, slotKey(scope, 1))).toMatchObject({
    state: "quarantined",
    reason: "partition_mismatch",
  });
  expect(fragmentReads(net, scope)).toEqual([]);
  expect(receiver.get()).toBeUndefined();
});

it("a manifest with malformed signed facts or a non-canonical wrapper is manifest_invalid, with no fragment admitted", async () => {
  const net = network();
  const receiver = transportDevice(net);
  const r = remoteReplicaTestWriter(net.roster, owner);
  const signed = await injectReplicaBatch(net, {
    writer: r.writers.transport,
    operations: [upsert(r.writers.operation, "signed")],
    sign: r.sign,
  });
  const scope = signed.manifest.scope;
  // A zero fragment length under a well-formed statement.
  const zero = wrapperOf(signed.manifest.plaintext);
  zero.data.manifest.fragments[0].bytes = 0;
  const zeroSlot = await registerPlaintext(net, scope, 2, encode(zero));
  // The same manifest with a key the envelope does not have.
  const extra = wrapperOf(signed.manifest.plaintext);
  const nonCanonical = encode({ ...extra, unexpected: true });
  const extraSlot = await registerPlaintext(net, scope, 3, nonCanonical);
  await cycles([receiver], 3);
  for (const slot of [zeroSlot, extraSlot]) {
    expect(rowOf(receiver, slot)).toMatchObject({
      state: "quarantined",
      reason: "manifest_invalid",
    });
    expect(admitted(receiver, slot)).toBe(0);
  }
  expect(receiver.get()).toEqual({ id: "a", text: "signed" });
});

it("a manifest whose envelope names another scope is writer_mismatch, with no fragment fetched", async () => {
  const net = network();
  const receiver = transportDevice(net);
  const r = remoteReplicaTestWriter(net.roster, owner);
  const v = remoteReplicaTestWriter(net.roster, owner);
  const signed = await injectReplicaBatch(net, {
    writer: r.writers.transport,
    operations: [upsert(r.writers.operation, "for r")],
    sign: r.sign,
  });
  // R's exact plaintext, registered in V's scope under V's key.
  const victim = replicaScope(v.writers.transport);
  const slot = await registerPlaintext(
    net,
    victim,
    1,
    signed.manifest.plaintext,
  );
  await cycles([receiver], 3);
  expect(rowOf(receiver, slot)).toMatchObject({
    state: "quarantined",
    reason: "writer_mismatch",
  });
  expect(fragmentReads(net, victim)).toEqual([]);
});

it("stored bytes that do not match the finalized commitment stay a retry", async () => {
  const net = network();
  const receiver = transportDevice(net);
  const r = remoteReplicaTestWriter(net.roster, owner);
  const signed = await injectReplicaBatch(net, {
    writer: r.writers.transport,
    operations: [upsert(r.writers.operation, "real")],
    sign: r.sign,
  });
  const real = net.blobs.get(signed.slot)!;
  // Storage serves bytes the registration never committed to.
  const replaced = wrapperOf(signed.manifest.plaintext);
  replaced.data.manifest.fragments[0].bytes = 0;
  net.blobs.set(
    signed.slot,
    await net.port.encrypt(signed.manifest.scope, encode(replaced)),
  );
  await cycles([receiver], 2);
  expect(rowOf(receiver, signed.slot)).toMatchObject({
    state: "ready",
    outcome: "retry",
    reason: "commitment_mismatch",
  });
  expect(fragmentReads(net, signed.manifest.scope)).toEqual([]);
  net.blobs.set(signed.slot, real);
  await cycles([receiver], 4);
  expect(receiver.get()).toEqual({ id: "a", text: "real" });
});

it("a stored manifest over the cap is manifest_invalid, and the read stops at the bound", async () => {
  const cap = 8192;
  const net = network({ cap });
  const receiver = transportDevice(net, { cap });
  const r = remoteReplicaTestWriter(net.roster, owner);
  const signed = await injectReplicaBatch(net, {
    writer: r.writers.transport,
    operations: [upsert(r.writers.operation, "small")],
    sign: r.sign,
  });
  const wrapper = wrapperOf(signed.manifest.plaintext);
  const oversize = encode({
    ...wrapper,
    data: { ...wrapper.data, padding: "A".repeat(4 * cap) },
  });
  const slot = await registerPlaintext(net, signed.manifest.scope, 2, oversize);
  await cycles([receiver], 3);
  expect(rowOf(receiver, slot)).toMatchObject({
    state: "quarantined",
    reason: "manifest_invalid",
  });
  expect(admitted(receiver, slot)).toBe(0);
});

it("a compressed manifest is refused before it inflates: manifest_invalid under real crypto", async () => {
  const cap = 8192;
  const net = network({ cap, realCrypto: true });
  const receiver = transportDevice(net, { cap });
  const r = remoteReplicaTestWriter(net.roster, owner);
  const manifest = await prepareReplicaManifest({
    owner,
    writer: r.writers.transport,
    version: 1,
    batch: "b".repeat(32),
    sequence: 1,
    previous: null,
    collectedAt: at,
    digest: replicaDigest(new Uint8Array([1])),
    totalBytes: 1,
    fragments: [{ digest: replicaDigest(new Uint8Array([1])), bytes: 1 }],
    sign: r.sign,
    encrypt: net.port.encrypt,
  });
  const wrapper = wrapperOf(manifest.plaintext);
  wrapper.data.padding = "A".repeat(4 * 1024 * 1024);
  const plaintext = encode(wrapper);
  const password = bytesToHex(
    deriveScopeKey(new Uint8Array(32).fill(5), manifest.scope),
  ).slice(2);
  const encrypted = await openpgp.encrypt({
    message: await openpgp.createMessage({ binary: plaintext }),
    passwords: [password],
    format: "binary",
    config: {
      preferredCompressionAlgorithm: openpgp.enums.compression.zlib,
    },
  });
  expect(encrypted.length).toBeLessThan(cap);
  const slot = await registerPlaintext(
    net,
    manifest.scope,
    1,
    plaintext,
    encrypted,
  );
  await receiver.step({ units: 100 });
  expect(rowOf(receiver, slot)).toMatchObject({
    state: "quarantined",
    reason: "manifest_invalid",
  });
  expect(fragmentReads(net, manifest.scope)).toEqual([]);
}, 30000);

it("a manifest naming more fragment bytes than its payload needs is manifest_invalid, with nothing admitted", async () => {
  const net = network({ cap: 100 * 1024 * 1024 });
  const receiver = transportDevice(net, {
    cap: 100 * 1024 * 1024,
    worker: { quantum: { fetch: 0 } },
  });
  const r = remoteReplicaTestWriter(net.roster, owner);
  const signed = await injectReplicaBatch(net, {
    writer: r.writers.transport,
    operations: [upsert(r.writers.operation, "small")],
    sign: r.sign,
  });
  // A thousand 100 MiB entries for a 1000-byte payload, correctly signed.
  const wrapper = wrapperOf(signed.manifest.plaintext);
  const { authority: _authority, ...unsigned } = wrapper.data.manifest;
  const claimed = {
    ...unsigned,
    batch: "c".repeat(32),
    totalBytes: 1000,
    fragments: Array.from({ length: 1000 }, () => ({
      digest: replicaDigest(new Uint8Array([1])),
      bytes: 100 * 1024 * 1024,
    })),
  };
  const fanout = {
    ...wrapper,
    data: {
      manifest: {
        ...claimed,
        authority: await r.sign(replicaManifestFacts(claimed, 2)),
      },
    },
  };
  const slot = await registerPlaintext(
    net,
    signed.manifest.scope,
    2,
    encode(fanout),
  );
  await receiver.step({ units: 100, bytes: 1 }); // smallest budget; every fragment is larger
  expect(rowOf(receiver, slot)).toMatchObject({
    state: "quarantined",
    reason: "manifest_invalid",
  });
  expect(admitted(receiver, slot)).toBe(0);
}, 30000);

it("fragment reads are charged to the step's byte budget", async () => {
  const net = network();
  const receiver = transportDevice(net);
  const r = remoteReplicaTestWriter(net.roster, owner);
  const signed = await injectReplicaBatch(net, {
    writer: r.writers.transport,
    operations: [upsert(r.writers.operation, "budgeted")],
    sign: r.sign,
  });
  const scope = signed.manifest.scope;
  await receiver.step({ units: 100, bytes: 1 }); // smallest budget; every fragment is larger
  // The manifest is read and its fragments admitted, but none is fetched.
  expect(admitted(receiver, signed.slot)).toBeGreaterThan(0);
  expect(fragmentReads(net, scope)).toEqual([]);
  await cycles([receiver], 4);
  expect(fragmentReads(net, scope).length).toBeGreaterThan(0);
  expect(receiver.get()).toEqual({ id: "a", text: "budgeted" });
});

it("a stored manifest asking for a 1 GiB Argon2 KDF is manifest_invalid, and the KDF never runs", async () => {
  const net = network({ realCrypto: true });
  const receiver = transportDevice(net);
  const r = remoteReplicaTestWriter(net.roster, owner);
  const signed = await injectReplicaBatch(net, {
    writer: r.writers.transport,
    operations: [upsert(r.writers.operation, "signed")],
    sign: r.sign,
  });
  // A 166-byte message whose Argon2 S2K asks for 2^20 KiB: the memory
  // exponent is the last byte of the S2K specifier.
  const small = await openpgp.encrypt({
    message: await openpgp.createMessage({ binary: new Uint8Array([1]) }),
    passwords: ["not-the-scope-key"],
    format: "binary",
    config: {
      aeadProtect: true,
      s2kType: openpgp.enums.s2k.argon2,
      s2kArgon2Params: { passes: 1, parallelism: 1, memoryExponent: 10 },
    },
  });
  const s2k = (
    (await openpgp.readMessage({ binaryMessage: small }))
      .packets[0] as unknown as {
      s2k: { write(): Uint8Array; produceKey(): unknown };
    }
  ).s2k;
  const specifier = s2k.write();
  const hostile = new Uint8Array(small);
  hostile[
    Buffer.from(small).indexOf(Buffer.from(specifier)) + specifier.length - 1
  ] = 20;
  const kdf = vi
    .spyOn(
      Object.getPrototypeOf(s2k) as { produceKey(): unknown },
      "produceKey",
    )
    .mockImplementation(() => {
      throw new Error("the KDF ran");
    });
  try {
    net.blobs.set(signed.slot, hostile);
    await cycles([receiver], 2);
    expect(kdf).not.toHaveBeenCalled();
  } finally {
    kdf.mockRestore();
  }
  // No writer makes these bytes, and the commitment cannot be checked
  // without running the KDF, so they are refused before it.
  expect(rowOf(receiver, signed.slot)).toMatchObject({
    state: "quarantined",
    reason: "manifest_invalid",
  });
  expect(fragmentReads(net, signed.manifest.scope)).toEqual([]);
}, 30000);

it("an authentic wrapper nested 6000 arrays deep is manifest_invalid, not a retry", async () => {
  const cap = 32768;
  const net = network({ cap });
  const receiver = transportDevice(net, { cap });
  const r = remoteReplicaTestWriter(net.roster, owner);
  const signed = await injectReplicaBatch(net, {
    writer: r.writers.transport,
    operations: [upsert(r.writers.operation, "signed")],
    sign: r.sign,
  });
  const scope = signed.manifest.scope;
  const plaintext = new TextEncoder().encode(
    `{"collectedAt":${JSON.stringify(at)},"data":{"manifest":null,"padding":${"[".repeat(6000)}0${"]".repeat(6000)}},"scope":${JSON.stringify(scope)},"version":"1.0"}`,
  );
  const slot = await registerPlaintext(net, scope, 2, plaintext);
  await cycles([receiver], 2);
  expect(rowOf(receiver, slot)).toMatchObject({
    state: "quarantined",
    reason: "manifest_invalid",
  });
  expect(admitted(receiver, slot)).toBe(0);
  expect(receiver.get()).toMatchObject({ text: "signed" });
});

it("random and mutated manifests that match their commitment never retry as download_failed", async () => {
  const cap = 65536;
  const net = network({ cap });
  const receiver = transportDevice(net, { cap });
  const r = remoteReplicaTestWriter(net.roster, owner);
  const signed = await injectReplicaBatch(net, {
    writer: r.writers.transport,
    operations: [upsert(r.writers.operation, "signed")],
    sign: r.sign,
  });
  const scope = signed.manifest.scope;
  const honest = new TextDecoder().decode(signed.manifest.plaintext);
  // mulberry32, seeded so a failure replays.
  let seed = 27;
  const next = () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const hostile = [
    `${"[".repeat(3000)}0${"]".repeat(3000)}`,
    `[${"0,".repeat(20000)}0]`,
    "null",
    "0",
    "-1",
    "1e308",
    '"x"',
    "[]",
    "{}",
    JSON.stringify("x".repeat(5000)),
    JSON.stringify(`sha256:${"f".repeat(64)}`),
    JSON.stringify(owner),
  ];
  const slots: string[] = [];
  for (let version = 2; version < 42; version++) {
    // Replace one value of the honest text, keeping the top-level collectedAt
    // so the receiver can rebuild the commitment.
    const values = [...honest.matchAll(/:(?:"[^"]*"|-?\d+|null|true|false)/g)];
    const target = values[1 + Math.floor(next() * (values.length - 1))]!;
    const replacement = hostile[Math.floor(next() * hostile.length)]!;
    const text =
      honest.slice(0, target.index + 1) +
      replacement +
      honest.slice(target.index + target[0].length);
    slots.push(
      await registerPlaintext(
        net,
        scope,
        version,
        new TextEncoder().encode(text),
      ),
    );
  }
  await cycles([receiver], 6);
  const rows = slots.map((slot) => rowOf(receiver, slot));
  for (const [index, row] of rows.entries())
    expect(row, slots[index]).toMatchObject({ state: "quarantined" });
  expect(rows.some((row) => row?.reason === "download_failed")).toBe(false);
}, 60000);

it("fragment JSON crosses the same bounded parse before allocation as manifest JSON", async () => {
  const net = network({ cap: 32768 });
  const receiver = transportDevice(net, { cap: 32768 });
  const r = remoteReplicaTestWriter(net.roster, owner);
  const signed = await injectReplicaBatch(net, {
    writer: r.writers.transport,
    operations: [upsert(r.writers.operation, "signed")],
    sign: r.sign,
  });
  const text = `{"collectedAt":${JSON.stringify(at)},"data":{"fragment":null,"padding":${"[".repeat(6000)}0${"]".repeat(6000)}},"scope":${JSON.stringify(signed.manifest.scope)},"version":"1.0"}`;
  const encrypted = await net.port.encrypt(
    signed.manifest.scope,
    new TextEncoder().encode(text),
  );
  const wrapper = wrapperOf(signed.manifest.plaintext);
  const manifest = wrapper.data.manifest;
  manifest.batch = "c".repeat(32);
  manifest.fragments = [
    { digest: replicaDigest(encrypted), bytes: encrypted.length },
  ];
  // Make the framed bound large enough, independently of the invalid JSON.
  manifest.totalBytes = 32768;
  manifest.authority = await r.sign(replicaManifestFacts(manifest, 2));
  net.blobs.set(
    replicaFragmentKey(signed.manifest.scope, replicaDigest(encrypted)),
    encrypted,
  );
  const slot = await registerPlaintext(
    net,
    signed.manifest.scope,
    2,
    encode(wrapper),
  );
  const parse = vi.spyOn(JSON, "parse");
  try {
    await cycles([receiver], 3);
    expect(rowOf(receiver, slot)).toMatchObject({
      state: "quarantined",
      reason: "fragment_mismatch",
    });
    expect(parse.mock.calls.some(([input]) => input === text)).toBe(false);
  } finally {
    parse.mockRestore();
  }
});

it("a deep inbox processes at most fifty manifests per step even with a larger host quantum", async () => {
  const net = network();
  const receiver = transportDevice(net, {
    worker: {
      quantum: {
        retain: 0,
        prepare: 0,
        publish: 0,
        discover: 0,
        download: 1000,
        fetch: 0,
        import: 0,
        revalidate: 0,
        reconcile: 0,
      },
    },
  });
  // Seed already-discovered slots. This tests processing independently of the
  // feed's page size and the separate discovery admission bound.
  const writer = "a".repeat(32);
  const scope = replicaScope(writer);
  for (let version = 1; version <= 151; version++) {
    receiver.db
      .prepare(
        "INSERT INTO pdpp_transport_manifests_in (slot,scope,version,writer) VALUES (?,?,?,?)",
      )
      .run(slotKey(scope, version), scope, version, writer);
  }
  await receiver.step({ units: 1_000 }); // larger than the 151 seeded slots
  expect(
    net.calls.evidence.filter((key) => key.startsWith(`${scope}/`)),
  ).toHaveLength(50);
});

it("fragment outcomes distinguish definitive absence, transient failure, and committed invalid bytes", async () => {
  for (const kind of ["missing", "offline", "corrupt", "invalid"] as const) {
    const net = network();
    const receiver = transportDevice(net);
    const r = remoteReplicaTestWriter(net.roster, owner);
    const signed = await injectReplicaBatch(net, {
      writer: r.writers.transport,
      operations: [upsert(r.writers.operation, kind)],
      sign: r.sign,
    });
    const entry = wrapperOf(signed.manifest.plaintext).data.manifest
      .fragments[0];
    const key = replicaFragmentKey(signed.manifest.scope, entry.digest);
    const original = net.blobs.get(key)!;
    if (kind === "missing") net.blobs.delete(key);
    if (kind === "offline")
      net.faults.get = (url) =>
        url.includes("/fragments/") ? new Error("offline") : undefined;
    if (kind === "corrupt") net.blobs.set(key, new Uint8Array(original.length));
    let slot = signed.slot;
    if (kind === "invalid") {
      const encrypted = await net.port.encrypt(
        signed.manifest.scope,
        new TextEncoder().encode("not JSON"),
      );
      const wrapper = wrapperOf(signed.manifest.plaintext);
      wrapper.data.manifest.batch = "c".repeat(32);
      wrapper.data.manifest.fragments = [
        { digest: replicaDigest(encrypted), bytes: encrypted.length },
      ];
      wrapper.data.manifest.authority = await r.sign(
        replicaManifestFacts(wrapper.data.manifest, 2),
      );
      net.blobs.set(
        replicaFragmentKey(signed.manifest.scope, replicaDigest(encrypted)),
        encrypted,
      );
      slot = await registerPlaintext(
        net,
        signed.manifest.scope,
        2,
        encode(wrapper),
      );
    }
    await cycles([receiver], 3);
    if (kind === "offline") {
      expect(rowOf(receiver, slot)).toMatchObject({ state: "ready" });
      expect(
        receiver.db
          .prepare(
            "SELECT outcome,reason FROM pdpp_transport_fragments_in WHERE slot=?",
          )
          .get(slot),
      ).toMatchObject({ outcome: "retry", reason: "download_failed" });
      net.faults.get = undefined;
      await cycles([receiver], 4);
      expect(receiver.get()).toMatchObject({ text: kind });
    } else
      expect(rowOf(receiver, slot), kind).toMatchObject({
        state: "quarantined",
        reason: kind === "missing" ? "fragment_missing" : "fragment_mismatch",
      });
  }
});

it("committed fragment profiles are refused before an Argon2 KDF runs", async () => {
  const net = network({ realCrypto: true });
  const receiver = transportDevice(net);
  const r = remoteReplicaTestWriter(net.roster, owner);
  const signed = await injectReplicaBatch(net, {
    writer: r.writers.transport,
    operations: [upsert(r.writers.operation, "honest")],
    sign: r.sign,
  });
  const encrypted = await openpgp.encrypt({
    message: await openpgp.createMessage({ binary: new Uint8Array([1]) }),
    passwords: ["not-the-scope-key"],
    format: "binary",
    config: {
      aeadProtect: true,
      s2kType: openpgp.enums.s2k.argon2,
      s2kArgon2Params: { passes: 1, parallelism: 1, memoryExponent: 10 },
    },
  });
  const s2k = (
    (await openpgp.readMessage({ binaryMessage: encrypted }))
      .packets[0] as unknown as { s2k: { produceKey(): unknown } }
  ).s2k;
  const wrapper = wrapperOf(signed.manifest.plaintext);
  wrapper.data.manifest.batch = "c".repeat(32);
  wrapper.data.manifest.fragments = [
    { digest: replicaDigest(encrypted), bytes: encrypted.length },
  ];
  wrapper.data.manifest.authority = await r.sign(
    replicaManifestFacts(wrapper.data.manifest, 2),
  );
  net.blobs.set(
    replicaFragmentKey(signed.manifest.scope, replicaDigest(encrypted)),
    encrypted,
  );
  const slot = await registerPlaintext(
    net,
    signed.manifest.scope,
    2,
    encode(wrapper),
  );
  const kdf = vi
    .spyOn(
      Object.getPrototypeOf(s2k) as { produceKey(): unknown },
      "produceKey",
    )
    .mockImplementation(() => {
      throw new Error("the fragment KDF ran");
    });
  try {
    await cycles([receiver], 3);
    expect(rowOf(receiver, slot)).toMatchObject({
      state: "quarantined",
      reason: "fragment_mismatch",
    });
    expect(kdf).not.toHaveBeenCalled();
  } finally {
    kdf.mockRestore();
  }
}, 30000);
