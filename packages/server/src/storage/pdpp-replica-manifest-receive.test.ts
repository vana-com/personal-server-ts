/**
 * What a receiver reads for a finalized manifest, and how it ends a manifest
 * that can never be valid (host contract §3.4, §6). Reads are bounded before
 * bytes are kept, compressed messages are refused before they inflate, and
 * fragment reads are charged to the step's byte budget. A manifest whose bytes
 * match the finalized commitment but fail a check is a typed quarantine, never
 * a retry. Real workers and receivers over the contract network.
 */
import { randomUUID } from "node:crypto";
import { afterEach, expect, it } from "vitest";
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
  await receiver.step({ units: 100, bytes: 0 });
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
  await receiver.step({ units: 100, bytes: 0 });
  // The manifest is read and its fragments admitted, but none is fetched.
  expect(admitted(receiver, signed.slot)).toBeGreaterThan(0);
  expect(fragmentReads(net, scope)).toEqual([]);
  await cycles([receiver], 4);
  expect(fragmentReads(net, scope).length).toBeGreaterThan(0);
  expect(receiver.get()).toEqual({ id: "a", text: "budgeted" });
});
