/**
 * Who may write, on the manifest carrier (host contract §3.4). Each manifest
 * carries the batch statement that its writer's server key signed over the
 * manifest and the slot it registers. A receiver checks the statement, the
 * roster and the writer binding against the finalized slot before it fetches
 * any fragment. Real workers and receivers over the contract network.
 */
import { randomUUID } from "node:crypto";
import { afterEach, expect, it } from "vitest";
import { keccak256 } from "viem";
import {
  canonicalJson,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  decodeReplicaManifest,
  replicaMetadataHash,
  replicaScope,
} from "@opendatalabs/personal-server-ts-core/replication/transport";
import { deriveReplicaWriters } from "@opendatalabs/personal-server-ts-core/replication/writer-identity";
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
import {
  currentReplicaWriterIdentity,
  rotateReplicaWriterIdentity,
} from "./pdpp-replica-writer-identity.js";
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
/** What a receiver did with a slot: its quarantine reason, else its state. */
function outcomeOf(d: TransportDevice, slot: string) {
  const row = d.db
    .prepare(
      "SELECT state,reason FROM pdpp_transport_manifests_in WHERE slot=?",
    )
    .get(slot) as { state: string; reason: string | null } | undefined;
  return row?.state === "quarantined" ? row.reason : row?.state;
}
/** Fragment reads under a scope. A refused manifest causes none. */
const fragmentReads = (net: Network, scope: string) =>
  net.calls.gets.filter((key) => key.startsWith(`${scope}/fragments/`));
/** Register the stored bytes of slot `from` again at `scope`/`version`. */
async function reregister(
  net: Network,
  from: string,
  scope: string,
  version: number,
) {
  const encrypted = net.blobs.get(from)!;
  const { dataHash, metadataHash } = net.head.get(from)!;
  const manifest = {
    scope,
    version,
    plaintext: await net.port.decrypt(scope, encrypted),
    encrypted,
    dataHash: dataHash as `0x${string}`,
    metadataHash: metadataHash as `0x${string}`,
  };
  await net.port.put(manifest);
  await net.port.register(manifest);
  return slotKey(scope, version);
}
const identity = (d: TransportDevice) => currentReplicaWriterIdentity(d.db)!;

it("a bad or missing signature is refused before any fragment is fetched", async () => {
  const net = network();
  const receiver = transportDevice(net);
  const r = remoteReplicaTestWriter(net.roster, owner);
  const scope = replicaScope(r.writers.transport);
  const forged = await injectReplicaBatch(net, {
    writer: r.writers.transport,
    operations: [upsert(r.writers.operation, "forged")],
    sign: async (facts) => {
      const authority = await r.sign(facts);
      const flipped = authority.signature[10] === "0" ? "1" : "0";
      return {
        ...authority,
        signature: `${authority.signature.slice(0, 10)}${flipped}${authority.signature.slice(11)}`,
      };
    },
  });
  // The same manifest without its statement, at the next version.
  const wrapper = JSON.parse(
    new TextDecoder().decode(forged.manifest.plaintext),
  );
  const { authority: _authority, ...bare } = wrapper.data.manifest;
  const plaintext = new TextEncoder().encode(
    canonicalJson({ ...wrapper, data: { manifest: bare } }),
  );
  const encrypted = await net.port.encrypt(scope, plaintext);
  const unsigned = {
    scope,
    version: 2,
    plaintext,
    encrypted,
    dataHash: keccak256(plaintext),
    metadataHash: replicaMetadataHash(scope, at, encrypted.length),
  };
  await net.port.put(unsigned);
  await net.port.register(unsigned);
  await cycles([receiver], 3);
  expect(outcomeOf(receiver, forged.slot)).toBe("signature_invalid");
  expect(outcomeOf(receiver, slotKey(scope, 2))).toBe("signature_invalid");
  expect(fragmentReads(net, scope)).toEqual([]);
  expect(receiver.get()).toBeUndefined();
  // The same server's next, honestly signed manifest imports.
  const honest = await injectReplicaBatch(net, {
    writer: r.writers.transport,
    operations: [upsert(r.writers.operation, "honest")],
    sign: r.sign,
  });
  await cycles([receiver], 3);
  expect(outcomeOf(receiver, honest.slot)).toBe("imported");
  expect(receiver.get()).toEqual({ id: "a", text: "honest" });
});

it("a valid signature over a different fragment list is refused before any fragment is fetched", async () => {
  const net = network();
  const receiver = transportDevice(net);
  const r = remoteReplicaTestWriter(net.roster, owner);
  const scope = replicaScope(r.writers.transport);
  const otherDigest = await injectReplicaBatch(net, {
    writer: r.writers.transport,
    operations: [upsert(r.writers.operation, "other digest")],
    sign: (facts) =>
      r.sign({
        ...facts,
        fragments: facts.fragments.map((f) => ({
          ...f,
          digest: `sha256:${"0".repeat(64)}`,
        })),
      }),
  });
  const otherLength = await injectReplicaBatch(net, {
    writer: r.writers.transport,
    operations: [upsert(r.writers.operation, "other length")],
    sign: (facts) =>
      r.sign({
        ...facts,
        fragments: facts.fragments.map((f) => ({ ...f, bytes: f.bytes + 1 })),
      }),
  });
  await cycles([receiver], 3);
  expect(outcomeOf(receiver, otherDigest.slot)).toBe("signature_invalid");
  expect(outcomeOf(receiver, otherLength.slot)).toBe("signature_invalid");
  expect(fragmentReads(net, scope)).toEqual([]);
  expect(receiver.get()).toBeUndefined();
});

it("a signed manifest registered at another version or in another scope is refused", async () => {
  const net = network();
  const receiver = transportDevice(net);
  const r = remoteReplicaTestWriter(net.roster, owner);
  const v = remoteReplicaTestWriter(net.roster, owner);
  const scope = replicaScope(r.writers.transport);
  const signed = await injectReplicaBatch(net, {
    writer: r.writers.transport,
    operations: [upsert(r.writers.operation, "signed for version 1")],
    sign: r.sign,
  });
  await cycles([receiver], 3);
  expect(outcomeOf(receiver, signed.slot)).toBe("imported");
  // The same bytes at the scope's next version.
  const otherVersion = await reregister(net, signed.slot, scope, 2);
  // The same statement in V's scope: the manifest re-encoded under V's
  // writer, registered at V's version 1 like the original.
  const victim = replicaScope(v.writers.transport);
  const wrapper = JSON.parse(
    new TextDecoder().decode(signed.manifest.plaintext),
  );
  const plaintext = new TextEncoder().encode(
    canonicalJson({
      ...wrapper,
      scope: victim,
      data: {
        manifest: { ...wrapper.data.manifest, writer: v.writers.transport },
      },
    }),
  );
  const encrypted = await net.port.encrypt(victim, plaintext);
  const moved = {
    scope: victim,
    version: 1,
    plaintext,
    encrypted,
    dataHash: keccak256(plaintext),
    metadataHash: replicaMetadataHash(victim, at, encrypted.length),
  };
  await net.port.put(moved);
  await net.port.register(moved);
  await cycles([receiver], 3);
  expect(outcomeOf(receiver, otherVersion)).toBe("signature_invalid");
  expect(outcomeOf(receiver, slotKey(victim, 1))).toBe("writer_mismatch");
  expect(fragmentReads(net, victim)).toEqual([]);
  expect(receiver.get()).toEqual({ id: "a", text: "signed for version 1" });
});

it("a writer not bound to the signing server is refused, in the scope and in the operations", async () => {
  const net = network();
  const receiver = transportDevice(net);
  const r = remoteReplicaTestWriter(net.roster, owner);
  // The same server and registration, another writer nonce: a writer the
  // statement does not derive.
  const unbound = deriveReplicaWriters({
    ...r.seed,
    writerNonce: `0x${"9".repeat(32)}`,
  });
  const inScope = await injectReplicaBatch(net, {
    writer: unbound.transport,
    operations: [upsert(unbound.operation, "unbound scope")],
    sign: r.sign,
  });
  const inOperations = await injectReplicaBatch(net, {
    writer: r.writers.transport,
    operations: [upsert(unbound.operation, "unbound operation")],
    sign: r.sign,
  });
  await cycles([receiver], 4);
  expect(outcomeOf(receiver, inScope.slot)).toBe("writer_mismatch");
  expect(fragmentReads(net, replicaScope(unbound.transport))).toEqual([]);
  expect(outcomeOf(receiver, inOperations.slot)).toBe("writer_mismatch");
  expect(receiver.get()).toBeUndefined();
});

it("a server that is not registered is refused before any fragment is fetched", async () => {
  const net = network();
  const receiver = transportDevice(net);
  const stranger = remoteReplicaTestWriter(net.roster, owner);
  net.roster.deregister(stranger.signer.address);
  const scope = replicaScope(stranger.writers.transport);
  const { slot } = await injectReplicaBatch(net, {
    writer: stranger.writers.transport,
    operations: [upsert(stranger.writers.operation, "stranger")],
    sign: stranger.sign,
  });
  await cycles([receiver], 3);
  expect(outcomeOf(receiver, slot)).toBe("server_not_registered");
  expect(fragmentReads(net, scope)).toEqual([]);
  expect(receiver.get()).toBeUndefined();
});

it("after rotation the old scope gets no new version and the new scope publishes signed manifests", async () => {
  const net = network();
  const a = transportDevice(net, { preexisting: "before rotation" });
  const peer = transportDevice(net);
  await cycles([a, peer], 3);
  const old = identity(a);
  const oldScope = replicaScope(old.transportWriter);
  const published = net.registrationsOf(oldScope);
  expect(published).toBeGreaterThan(0);
  rotateReplicaWriterIdentity(a.db);
  const next = identity(a);
  a.put("after rotation");
  await cycles([a, peer], 5);
  expect(net.registrationsOf(oldScope)).toBe(published);
  const newScope = replicaScope(next.transportWriter);
  const versions = net.registrationsOf(newScope);
  expect(versions).toBeGreaterThan(0);
  // A's server key signs every new manifest for the rotated writer, at the
  // slot it is registered at; the rebaseline is version 1.
  for (let version = 1; version <= versions; version++) {
    const plaintext = await net.port.decrypt(
      newScope,
      net.blobs.get(slotKey(newScope, version))!,
    );
    const manifest = decodeReplicaManifest(plaintext, newScope, owner);
    expect(manifest.authority.statement).toMatchObject({
      server: a.authority.signer.address.toLowerCase(),
      serverId: next.seed.serverId,
      writerNonce: next.seed.writerNonce,
      version,
    });
    expect(outcomeOf(peer, slotKey(newScope, version))).toBe("imported");
  }
  expect(peer.get()).toEqual({ id: "a", text: "after rotation" });
  // The old writer's last manifest, registered again at the old scope's
  // next version, is not a new version of that scope.
  const replayed = await reregister(
    net,
    slotKey(oldScope, published),
    oldScope,
    published + 1,
  );
  await cycles([peer], 3);
  expect(outcomeOf(peer, replayed)).toBe("signature_invalid");
  expect(peer.get()).toEqual({ id: "a", text: "after rotation" });
});
