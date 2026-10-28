/**
 * Who may write (host contract §3): attacks on writer identity against real
 * workers, receivers and SQLite stores over the contract network. The PR tier
 * runs one case per attack; REPLICA_ORACLE_NIGHTLY=1 adds the variants.
 */
import Database from "better-sqlite3";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { ReplicaOperation } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import { REPLICA_ROSTER_MAX_AGE_MS } from "@opendatalabs/personal-server-ts-core/replication/roster";
import { compareRevisions } from "@opendatalabs/personal-server-ts-core/replication/revision";
import { ReplicationRefusedError } from "@opendatalabs/personal-server-ts-core/replication/door";
import {
  deriveReplicaWriters,
  replicaBatchTypedData,
  signReplicaBatch,
  type ReplicaBatchFacts,
} from "@opendatalabs/personal-server-ts-core/replication/writer-identity";
import {
  createTestReplicaSigner,
  unsignedReplicaBatch,
} from "@opendatalabs/personal-server-ts-core/replication/writer-identity.test-utils";
import {
  binding,
  at,
  cleanupHarness,
  clock,
  credential,
  cycles,
  expected,
  injectReplicaBatch,
  network,
  owner,
  scratchDirectory,
  sourceId,
  transportDevice,
  type Network,
  type TransportDevice,
} from "./pdpp-replica-contract.test-utils.js";
import { createReplicaRecordStore } from "./pdpp-replica-canonical-port.js";
import {
  currentReplicaWriterIdentity,
  rotateReplicaWriterIdentity,
} from "./pdpp-replica-writer-identity.js";
import {
  remoteReplicaTestWriter,
  replicaTestAuthority,
} from "./pdpp-replica-writer-identity.test-utils.js";
import { replicationAdmitted } from "./pdpp-replication-door.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";
import { createReplicaTransportWorker } from "./pdpp-replication-transport.js";

const nightly = process.env.REPLICA_ORACLE_NIGHTLY === "1";
afterEach(cleanupHarness);

const hex = (bytes: number) =>
  randomUUID()
    .replaceAll("-", "")
    .padEnd(bytes * 2, "0")
    .slice(0, bytes * 2);

/** A record upsert of key "a", as a device's own capture would write it. */
function upsert(writerId: string, text: string, counter = 1000) {
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
    revision: { counter, writerId, operationId: randomUUID() },
  } as ReplicaOperation;
}

/** Publish a hand-built batch straight to the network; its registered slot. */
async function inject(
  net: Network,
  input: Parameters<typeof injectReplicaBatch>[1],
) {
  return [(await injectReplicaBatch(net, input)).slot];
}

const inbox = (d: TransportDevice) =>
  d.db
    .prepare("SELECT slot,state,reason,error FROM pdpp_transport_manifests_in")
    .all() as {
    slot: string;
    state: string;
    reason: string | null;
    error: string | null;
  }[];
/** The quarantine reason a receiver recorded for each of these slots. */
const refusals = (d: TransportDevice, slots: string[]) =>
  slots.map((slot) => {
    const row = inbox(d).find((r) => r.slot === slot);
    return row?.state === "quarantined"
      ? (row.error ?? row.reason)
      : row?.state;
  });
const identity = (d: TransportDevice) => currentReplicaWriterIdentity(d.db)!;
const importedWriters = (d: TransportDevice) =>
  (
    d.db
      .prepare("SELECT DISTINCT writer FROM pdpp_transport_imported")
      .all() as { writer: string }[]
  ).map((r) => r.writer);

/** A's manifests that the gateway refused because another object holds their slot. */
const blocked = (d: TransportDevice) =>
  d.db
    .prepare(
      "SELECT version FROM pdpp_transport_manifests_out WHERE state='quarantined' AND reason='immutable_registration_conflict'",
    )
    .all();

it("first contact: another server's batch under A's transport writer is refused, and can only block A's version", async () => {
  const net = network();
  const a = transportDevice(net, { preexisting: "real" });
  const receiver = transportDevice(net);
  // A registered server of the same owner signs honestly for itself, but
  // publishes first under A's transport writer to take A's sequence 1.
  const attacker = remoteReplicaTestWriter(net.roster, owner);
  const forged = await inject(net, {
    writer: identity(a).transportWriter,
    operations: [upsert(attacker.writers.operation, "forged")],
    sign: attacker.sign,
  });
  await cycles([receiver], 2);
  expect(refusals(receiver, forged)).toEqual(["writer_mismatch"]);
  await cycles([a, receiver], 3);
  // The forged manifest holds version 1 of A's scope, so A's own version 1
  // is refused at registration (host contract §3.6). Nothing forged imports.
  expect(blocked(a)).toEqual([{ version: 1 }]);
  expect(receiver.get()).toBeUndefined();
  expect(importedWriters(receiver)).not.toContain(identity(a).transportWriter);
});

it.runIf(nightly)(
  "first contact variants: a stolen server claim, an invalid signature and an unregistered signer",
  async () => {
    const net = network();
    const a = transportDevice(net, { preexisting: "real" });
    const receiver = transportDevice(net);
    const writer = identity(a).transportWriter;
    const operations = [upsert(identity(a).operationWriter, "forged")];
    // Signs with its own key but names A as the server: recovery disagrees.
    const thief = createTestReplicaSigner();
    const claimsA = await inject(net, {
      writer,
      operations,
      sign: async (facts: ReplicaBatchFacts) => {
        const statement = (await unsignedReplicaBatch(facts)).statement;
        const forged = {
          ...statement,
          owner,
          server: identity(a).seed.server,
          serverId: identity(a).seed.serverId,
          writerNonce: identity(a).seed.writerNonce,
        };
        return {
          chainId: 14800,
          statement: forged,
          signature: (
            await thief.signTypedData(replicaBatchTypedData(14800, forged))
          ).toLowerCase(),
        };
      },
    });
    const unsigned = await inject(net, {
      writer,
      operations,
      sign: unsignedReplicaBatch,
    });
    // A real key that was never registered.
    const stranger = remoteReplicaTestWriter(net.roster, owner);
    net.roster.deregister(stranger.signer.address);
    const unregistered = await inject(net, {
      writer: stranger.writers.transport,
      operations: [upsert(stranger.writers.operation, "stranger")],
      sign: stranger.sign,
    });
    await cycles([receiver], 2);
    expect(refusals(receiver, claimsA)).toEqual(["signature_invalid"]);
    expect(refusals(receiver, unsigned)).toEqual(["signature_invalid"]);
    expect(refusals(receiver, unregistered)).toEqual(["server_not_registered"]);
    await cycles([a, receiver], 3);
    expect(blocked(a)).toEqual([{ version: 1 }]);
    expect(receiver.get()).toBeUndefined();
  },
);

it("operation-writer reuse: a registered server's batch naming A's operation writer is refused", async () => {
  const net = network();
  const a = transportDevice(net, { preexisting: "real" });
  const receiver = transportDevice(net);
  await cycles([a, receiver], 3);
  expect(receiver.get()).toEqual({ id: "a", text: "real" });
  // B signs correctly under its own transport writer, but its operations
  // claim A's operation writer, with a counter that would win.
  const b = remoteReplicaTestWriter(net.roster, owner);
  const reused = await inject(net, {
    writer: b.writers.transport,
    operations: [upsert(identity(a).operationWriter, "hijacked", 10 ** 9)],
    sign: b.sign,
  });
  await cycles([receiver], 3);
  expect(refusals(receiver, reused)).toEqual(["writer_mismatch"]);
  expect(receiver.get()).toEqual({ id: "a", text: "real" });
  // A keeps writing and still imports.
  a.put("real again");
  await cycles([a, receiver], 3);
  expect(receiver.get()).toEqual({ id: "a", text: "real again" });
});

it("foreign wallet: a server registered under another owner cannot sign into this partition", async () => {
  const net = network();
  const receiver = transportDevice(net);
  const foreign = `0x${"f".repeat(40)}`;
  // Registered under the foreign wallet, then signs as if for this owner.
  const signer = createTestReplicaSigner();
  const serverId = net.roster.register(signer.address, foreign);
  const seed = {
    owner,
    server: signer.address.toLowerCase(),
    serverId,
    writerNonce: `0x${hex(16)}`,
  };
  const writers = deriveReplicaWriters(seed);
  const intoVictim = await inject(net, {
    writer: writers.transport,
    operations: [upsert(writers.operation, "foreign")],
    sign: (facts) =>
      signReplicaBatch({
        signer,
        partition: { owner, chainId: 14800, environment: "dev" },
        seed,
        facts,
      }),
  });
  // Statement honest about its own wallet: wrong partition.
  const ownSeed = { ...seed, owner: foreign };
  const ownWriters = deriveReplicaWriters(ownSeed);
  const ownPartition = await inject(net, {
    writer: ownWriters.transport,
    operations: [upsert(ownWriters.operation, "foreign")],
    sign: (facts) =>
      signReplicaBatch({
        signer,
        partition: { owner: foreign, chainId: 14800, environment: "dev" },
        seed: ownSeed,
        facts,
      }),
  });
  await cycles([receiver], 2);
  expect(refusals(receiver, intoVictim)).toEqual(["roster_owner_mismatch"]);
  expect(refusals(receiver, ownPartition)).toEqual(["partition_mismatch"]);
  expect(receiver.get()).toBeUndefined();
});

it("deregistration mid-stream: imported data stays, unimported batches are refused within the roster bound", async () => {
  const net = network();
  const a = transportDevice(net, { preexisting: "before removal" });
  const receiver = transportDevice(net);
  await cycles([a, receiver], 3);
  expect(receiver.get()).toEqual({ id: "a", text: "before removal" });
  // A publishes once more; the owner removes A before the receiver imports it.
  a.put("published, not imported");
  await cycles([a], 2);
  const late = net.calls.registrations.filter((s) =>
    s.includes(identity(a).transportWriter),
  );
  net.roster.deregister(a.authority.signer.address);
  clock.advance(REPLICA_ROSTER_MAX_AGE_MS);
  await cycles([receiver], 3);
  expect(receiver.get()).toEqual({ id: "a", text: "before removal" });
  const unimported = late.filter(
    (slot) =>
      !inbox(receiver).some((r) => r.slot === slot && r.state === "imported"),
  );
  expect(unimported.length).toBeGreaterThan(0);
  expect(new Set(refusals(receiver, unimported))).toEqual(
    new Set(["server_not_registered"]),
  );
  // A removed server stops: its worker waits on its own registration.
  const report = (await a.step()) as { waits: { dependency: unknown }[] };
  expect(report.waits).toEqual([
    expect.objectContaining({
      dependency: {
        kind: "roster",
        key: a.authority.signer.address.toLowerCase(),
      },
    }),
  ]);
});

it.runIf(nightly)(
  "deregistration after download: the import recheck refuses once the cached answer expires",
  async () => {
    const net = network();
    const a = transportDevice(net, { preexisting: "first" });
    const receiver = transportDevice(net);
    await cycles([a, receiver], 3);
    a.put("held at finality");
    await cycles([a], 2);
    const held = net.calls.registrations.filter(
      (s) =>
        s.includes(identity(a).transportWriter) &&
        !inbox(receiver).some((r) => r.slot === s),
    );
    // Downloaded and authorized, but not finalized: the import waits.
    for (const slot of held) {
      net.chain.delete(slot);
      net.pending.add(slot);
    }
    await cycles([receiver], 2);
    expect(refusals(receiver, held).every((s) => s === "ready")).toBe(true);
    net.roster.deregister(a.authority.signer.address);
    net.finalizeAll();
    clock.advance(REPLICA_ROSTER_MAX_AGE_MS);
    await cycles([receiver], 3);
    expect(receiver.get()).toEqual({ id: "a", text: "first" });
    expect(new Set(refusals(receiver, held))).toEqual(
      new Set(["server_not_registered"]),
    );
  },
);

it("re-registration is a new incarnation: old batches stay refused, new writers import", async () => {
  const net = network();
  const a = transportDevice(net, { preexisting: "first life" });
  const receiver = transportDevice(net);
  await cycles([a, receiver], 3);
  const old = identity(a);
  a.put("old incarnation, unimported");
  await cycles([a], 2);
  const unimported = net.calls.registrations.filter(
    (s) =>
      s.includes(old.transportWriter) &&
      !inbox(receiver).some((r) => r.slot === s),
  );
  net.roster.deregister(a.authority.signer.address);
  net.roster.register(a.authority.signer.address, owner);
  clock.advance(REPLICA_ROSTER_MAX_AGE_MS);
  await a.step();
  const next = identity(a);
  expect(next.incarnation).toBe(old.incarnation + 1);
  expect(next.seed.serverId).not.toBe(old.seed.serverId);
  expect(next.transportWriter).not.toBe(old.transportWriter);
  a.put("second life");
  await cycles([a, receiver], 4);
  expect(receiver.get()).toEqual({ id: "a", text: "second life" });
  expect(new Set(refusals(receiver, unimported))).toEqual(
    new Set(["server_not_registered"]),
  );
  expect(importedWriters(receiver)).toEqual(
    expect.arrayContaining([old.transportWriter, next.transportWriter]),
  );
});

it("restore with a copied nonce: a rotated restore imports under new writers", async () => {
  const net = network();
  const a = transportDevice(net, { preexisting: "v1" });
  const receiver = transportDevice(net);
  await cycles([a, receiver], 3);
  const image = a.image();
  a.put("v2");
  await cycles([a, receiver], 3);
  expect(receiver.get()).toEqual({ id: "a", text: "v2" });
  const copied = identity(a);
  a.restore(image);
  expect(identity(a).seed.writerNonce).toBe(copied.seed.writerNonce);
  rotateReplicaWriterIdentity(a.db);
  const rotated = identity(a);
  expect(rotated.seed.writerNonce).not.toBe(copied.seed.writerNonce);
  a.put("v3 after restore");
  await cycles([a, receiver], 4);
  expect(importedWriters(receiver)).toContain(rotated.transportWriter);
  expect(
    (
      receiver.db
        .prepare(
          "SELECT count(*) AS n FROM pdpp_transport_import_work WHERE outcome='quarantine'",
        )
        .get() as { n: number }
    ).n,
  ).toBe(0);
  expect(receiver.get()).toEqual(a.get());
});

// A new identity's first publication is a full current-state baseline. Each
// case below leaves a peer without some of the old writer's batches and
// never writes the affected record again: only that baseline can deliver it.
describe("a new writer identity republishes the current state", () => {
  /** Re-register A at the gateway and let A's next step rotate to it. */
  async function reRegister(a: TransportDevice) {
    net!.roster.deregister(a.authority.signer.address);
    net!.roster.register(a.authority.signer.address, owner);
    clock.advance(REPLICA_ROSTER_MAX_AGE_MS);
  }
  let net: Network | undefined;

  it("old published batches refused after re-registration", async () => {
    net = network();
    const a = transportDevice(net, { preexisting: "kept" });
    a.put("only in refused batches", "b");
    await cycles([a], 3);
    const old = identity(a);
    const published = net.calls.registrations.filter((s) =>
      s.includes(old.transportWriter),
    );
    expect(published.length).toBeGreaterThan(0);
    // The peer first appears after A re-registered.
    await reRegister(a);
    await a.step();
    const peer = transportDevice(net);
    await cycles([a, peer], 4);
    expect(new Set(refusals(peer, published))).toEqual(
      new Set(["server_not_registered"]),
    );
    expect(peer.get("b")).toEqual({ id: "b", text: "only in refused batches" });
    expect(peer.get()).toEqual({ id: "a", text: "kept" });
  });

  it("old batches with a tombstone, a blob and a completion", async () => {
    net = network();
    const a = transportDevice(net, { preexisting: "kept" });
    a.put("deleted later", "b");
    const peer = transportDevice(net);
    await cycles([a, peer], 3);
    expect(peer.get("b")).toEqual({ id: "b", text: "deleted later" });
    // Replace the stream: b becomes a tombstone, k carries a blob, and the
    // stream gets a completion. The peer misses all of it.
    const blob = a.store.storeBlobBytesForInstance({
      instance: a.instance,
      method: "export",
      generation: 1,
      bytes: new Uint8Array([1, 2, 3]),
      mimeType: "application/octet-stream",
    });
    const k = {
      id: "k",
      blob_ref: {
        blob_id: blob.blobId,
        mime_type: blob.mimeType,
        size_bytes: 3,
      },
    };
    a.store.replaceStream({
      instance: a.instance,
      stream: "messages",
      method: "export",
      generation: 1,
      emittedAt: at,
      envelopes: [
        {
          instance: a.instance,
          stream: "messages",
          key: "a",
          data: { id: "a", text: "kept" },
          emitted_at: at,
        },
        {
          instance: a.instance,
          stream: "messages",
          key: "k",
          data: k,
          emitted_at: at,
        },
      ],
      primaryKey: ["id"],
      sourceCollectedAt: at,
    });
    await cycles([a], 3);
    await reRegister(a);
    await a.step();
    await cycles([a, peer], 5);
    const completion = (d: TransportDevice) =>
      d.db
        .prepare(
          "SELECT live_count, snapshot_sha256 FROM pdpp_stream_completion WHERE stream='messages'",
        )
        .get();
    expect(a.get("b")).toBeUndefined();
    expect(peer.get("b")).toBeUndefined();
    expect(peer.get("k")).toEqual(k);
    expect(peer.store.getBlobBytes(blob.blobId)).toEqual(
      new Uint8Array([1, 2, 3]),
    );
    expect(completion(a)).toMatchObject({ live_count: 2 });
    expect(completion(peer)).toEqual(completion(a));
  });

  it("old batches never published", async () => {
    net = network();
    const a = transportDevice(net, { preexisting: "kept" });
    const peer = transportDevice(net);
    await cycles([a, peer], 3);
    // Retained and prepared, but the network refuses every upload.
    net.faults.encrypt = () => new Error("offline");
    a.put("never published", "b");
    await cycles([a], 2);
    const old = identity(a);
    expect(
      a.db
        .prepare(
          "SELECT count(*) AS n FROM pdpp_transport_batches WHERE prepared=0",
        )
        .get(),
    ).toEqual({ n: 1 });
    const oldScopes = () =>
      net!.calls.registrations.filter((s) => s.includes(old.transportWriter));
    const before = oldScopes().length;
    // A host reset rotates the nonce; the old writer's batch is abandoned.
    rotateReplicaWriterIdentity(a.db);
    net.faults.encrypt = undefined;
    await cycles([a, peer], 4);
    expect(oldScopes()).toHaveLength(before);
    expect(peer.get("b")).toEqual({ id: "b", text: "never published" });
  });

  it("writes between re-registration and the next step", async () => {
    net = network();
    const a = transportDevice(net, { preexisting: "kept" });
    const peer = transportDevice(net);
    await cycles([a, peer], 3);
    await reRegister(a);
    // The gateway changed; A's worker has not stepped yet.
    a.put("written before the rotation", "b");
    await cycles([a, peer], 4);
    expect(identity(a).incarnation).toBe(2);
    expect(peer.get("b")).toEqual({
      id: "b",
      text: "written before the rotation",
    });
  });

  it("a crash in the middle of the baseline resumes it", async () => {
    net = network();
    const a = transportDevice(net, { preexisting: "kept", pageSize: 2 });
    for (const id of ["b", "c", "d", "e", "f"]) a.put(`value ${id}`, id);
    await cycles([a], 3);
    await reRegister(a);
    // One retain page of the new baseline, then the process dies.
    await a.step({ units: 1 });
    const state = a.db
      .prepare(
        "SELECT baseline_done, baseline_cursor FROM pdpp_transport_state",
      )
      .get() as { baseline_done: number; baseline_cursor: number };
    expect(state.baseline_done).toBe(0);
    a.crashReopen();
    const peer = transportDevice(net);
    await cycles([a, peer], 8);
    for (const id of ["b", "c", "d", "e", "f"])
      expect(peer.get(id)).toEqual({ id, text: `value ${id}` });
  });

  it("a restored copy republishes its state without overriding a newer write", async () => {
    net = network();
    const a = transportDevice(net, { preexisting: "v1" });
    const peer = transportDevice(net);
    await cycles([a, peer], 3);
    const image = a.image();
    a.put("v2");
    await cycles([a, peer], 3);
    a.restore(image);
    rotateReplicaWriterIdentity(a.db);
    // A peer that never saw A's old batches.
    const late = transportDevice(net);
    await cycles([a, peer, late], 5);
    // v1 is republished at its own counter, so the newer v2 still wins.
    for (const d of [a, peer, late])
      expect(d.get()).toEqual({ id: "a", text: "v2" });
  });

  // A's write and another device's write share a counter, so writer ids
  // break the tie. A's write is retained but never published; A then
  // rotates to a writer id on the other side of the other device's. The
  // peer sees only the other write and A's re-issue, which must tie as A's
  // original did.
  it.each([
    ["record", "record"],
    ["record", "tombstone"],
    ["tombstone", "record"],
  ] as const)(
    "an equal-counter tie: A's %s against another device's %s",
    async (mine, theirs) => {
      net = network();
      const a = transportDevice(net, { preexisting: "kept" });
      const peer = transportDevice(net);
      await cycles([a, peer], 3);
      net.faults.encrypt = () => new Error("offline");
      if (mine === "record") a.put("from A");
      else
        a.store.replaceStream({
          instance: a.instance,
          stream: "messages",
          method: "export",
          generation: 1,
          emittedAt: at,
          envelopes: [],
          primaryKey: ["id"],
          sourceCollectedAt: at,
        });
      await cycles([a], 2);
      const original = (
        a.db
          .prepare(
            "SELECT operation_json FROM pdpp_replica_operations WHERE json_extract(operation_json,'$.recordKey')='a' ORDER BY sequence DESC LIMIT 1",
          )
          .get() as { operation_json: string }
      ).operation_json;
      const theirOp = (counter: number, writerId: string) => {
        const op = upsert(writerId, "from the other device", counter);
        if (theirs === "record") return op;
        const {
          data: _data,
          blobs: _blobs,
          ...rest
        } = op as Extract<ReplicaOperation, { kind: "upsert" }>;
        return { ...rest, kind: "delete", deletedAt: at } as ReplicaOperation;
      };
      const mineOp = JSON.parse(original) as ReplicaOperation;
      const other = remoteReplicaTestWriter(net.roster, owner);
      const old = identity(a);
      const theirWriter = other.writers.operation;
      // The first nonce whose operation writer sorts on the other side of
      // theirs from A's old one.
      let nonce = "";
      for (let i = 1; !nonce; i++) {
        const candidate = `0x${i.toString(16).padStart(32, "0")}`;
        const next = deriveReplicaWriters({
          ...old.seed,
          writerNonce: candidate,
        }).operation;
        if (next < theirWriter !== old.operationWriter < theirWriter)
          nonce = candidate;
      }
      rotateReplicaWriterIdentity(a.db, { nonce });
      net.faults.encrypt = undefined;
      const op = theirOp(mineOp.revision.counter, theirWriter);
      await inject(net, {
        writer: other.writers.transport,
        operations: [op],
        sign: other.sign,
      });
      await cycles([a, peer], 5);
      const expected =
        compareRevisions(mineOp.revision, op.revision) > 0
          ? mine === "record"
            ? { id: "a", text: "from A" }
            : undefined
          : theirs === "record"
            ? { id: "a", text: "from the other device" }
            : undefined;
      expect(identity(a).seed.writerNonce).toBe(nonce);
      expect(a.get()).toEqual(expected);
      expect(peer.get()).toEqual(expected);
    },
  );
});

it("a write outside capture closes the door: the next step publishes nothing", async () => {
  const net = network();
  const a = transportDevice(net, { preexisting: "kept" });
  await cycles([a], 3);
  // A rotation the worker has not acted on yet.
  rotateReplicaWriterIdentity(a.db);
  a.put("captured before the door closed", "b");
  const published = net.calls.registrations.length;
  const transport = () =>
    a.db.prepare("SELECT writer, sequence FROM pdpp_transport_state").get();
  const before = transport();
  expect(replicationAdmitted(a.db)).toBe(true);
  a.db
    .prepare(
      "UPDATE pdpp_records SET emitted_at = emitted_at WHERE record_key='a'",
    )
    .run();
  expect(replicationAdmitted(a.db)).toBe(false);
  // Rotation, the restore path, refuses too and writes nothing.
  const incarnation = identity(a).incarnation;
  expect(() => rotateReplicaWriterIdentity(a.db)).toThrow(
    ReplicationRefusedError,
  );
  expect(identity(a).incarnation).toBe(incarnation);
  await cycles([a], 3);
  expect(net.calls.registrations).toHaveLength(published);
  // No identity or rebaseline work either.
  expect(transport()).toEqual(before);
});

it("the door closes while the roster read is pending: no new identity, nothing published", async () => {
  const net = network();
  const a = transportDevice(net, { preexisting: "kept" });
  await cycles([a], 3);
  // Re-registered at the gateway: the next roster answer differs from the
  // stored identity.
  net.roster.deregister(a.authority.signer.address);
  net.roster.register(a.authority.signer.address, owner);
  clock.advance(REPLICA_ROSTER_MAX_AGE_MS);
  const read = net.roster.port.server.bind(net.roster.port);
  let release!: () => void;
  const held = new Promise<void>((resolve) => (release = resolve));
  let asked!: () => void;
  const reading = new Promise<void>((resolve) => (asked = resolve));
  net.roster.port.server = async (...args) => {
    asked();
    await held;
    return read(...args);
  };
  const identities = () =>
    a.db
      .prepare("SELECT count(*) AS n FROM pdpp_replica_writer_identity")
      .get();
  const before = identities();
  const published = net.calls.registrations.length;
  const step = a.step();
  await reading;
  a.db
    .prepare(
      "UPDATE pdpp_records SET emitted_at = emitted_at WHERE record_key='a'",
    )
    .run();
  release();
  await step;
  expect(identities()).toEqual(before);
  expect(net.calls.registrations).toHaveLength(published);
});

it.runIf(nightly)(
  "restore with a copied nonce, not rotated: the reused version is refused at registration and the first batch stays",
  async () => {
    const net = network();
    const a = transportDevice(net, { preexisting: "v1" });
    const receiver = transportDevice(net);
    await cycles([a, receiver], 3);
    const image = a.image();
    a.put("v2");
    await cycles([a, receiver], 3);
    const registered = [...net.head.keys()];
    a.restore(image);
    a.put("v2 from the restored copy");
    await cycles([a, receiver], 4);
    expect(receiver.get()).toEqual({ id: "a", text: "v2" });
    // The copy signs the scope version the original already registered, so
    // the gateway keeps the original and the copy quarantines its manifest.
    expect([...net.head.keys()]).toEqual(registered);
    expect(
      a.db
        .prepare(
          "SELECT reason FROM pdpp_transport_manifests_out WHERE state='quarantined'",
        )
        .all(),
    ).toEqual([{ reason: "immutable_registration_conflict" }]);
  },
);

/** A worker over a fresh database whose server may not be registered yet. */
function unregisteredDevice(net: Network) {
  const db = new Database(
    join(scratchDirectory("replica-identity"), "r.sqlite"),
  );
  const store = createReplicaRecordStore(db);
  store.registerConnection({
    instance: "conn",
    sourceId,
    method: "export",
    label: "C",
  });
  const authority = replicaTestAuthority(net.roster);
  const worker = createReplicaTransportWorker({
    db,
    enabled: true,
    expected: () => expected,
    exporter: store.replication,
    receiver: createReplicaReceiver({
      db,
      store,
      owner,
      authenticate: (c) => (c === credential ? owner : undefined),
      declarations: () => [],
    }),
    credential,
    transport: net.port,
    authority,
    now: clock.now,
  });
  return { db, store, authority, worker, close: () => store.close() };
}

it("enable waits until the server is registered, and a journal captured before identity starts fresh", async () => {
  const net = network();
  const d = unregisteredDevice(net);
  try {
    const waiting = await d.worker.step();
    expect(waiting.waits).toEqual([
      expect.objectContaining({
        dependency: {
          kind: "roster",
          key: d.authority.signer.address.toLowerCase(),
        },
      }),
    ]);
    expect(currentReplicaWriterIdentity(d.db)).toBeUndefined();
    expect(net.calls.registrations).toEqual([]);
    // Capture under the installation writer, then register: refused.
    d.store.replication.beginBaseline(expected);
    net.roster.register(d.authority.signer.address, owner);
    clock.advance(REPLICA_ROSTER_MAX_AGE_MS);
    await expect(d.worker.step()).rejects.toMatchObject({
      code: "replica_identity_requires_fresh_journal",
    });
    expect(net.calls.registrations).toEqual([]);
  } finally {
    d.close();
  }
});

it("flag off: no roster reads, no identity work, no network", async () => {
  const net = network();
  const a = transportDevice(net, { preexisting: "local", enabled: false });
  await cycles([a], 3);
  expect(net.roster.reads).toBe(0);
  expect(net.calls.registrations).toEqual([]);
  expect(a.db.prepare("SELECT * FROM pdpp_transport_state").all()).toEqual([]);
});
