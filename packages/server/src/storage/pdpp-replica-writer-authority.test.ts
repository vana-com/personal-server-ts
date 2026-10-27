/**
 * Who may write (host contract §3): attacks on writer identity against real
 * workers, receivers and SQLite stores over the contract network. The PR tier
 * runs one case per attack; REPLICA_ORACLE_NIGHTLY=1 adds the variants.
 */
import Database from "better-sqlite3";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  canonicalJson,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  fragmentReplicaPayload,
  type Predecessor,
} from "@opendatalabs/personal-server-ts-core/replication/transport";
import { REPLICA_ROSTER_MAX_AGE_MS } from "@opendatalabs/personal-server-ts-core/replication/roster";
import {
  deriveReplicaWriters,
  replicaBatchTypedData,
  signReplicaBatch,
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
  envelope,
  expected,
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

/** Publish a hand-built batch straight to the network, as another device could. */
async function inject(
  net: Network,
  input: {
    writer: string;
    operations: ReplicaOperation[];
    sign: Parameters<typeof fragmentReplicaPayload>[0]["sign"];
    sequence?: number;
    previous?: Predecessor | null;
  },
) {
  const batch = hex(16);
  const parts = await fragmentReplicaPayload({
    owner,
    writer: input.writer,
    batch,
    sequence: input.sequence ?? 1,
    previous: input.previous ?? null,
    collectedAt: at,
    bytes: Buffer.from(
      canonicalJson({ envelope: envelope(input.operations, batch), blobs: [] }),
    ),
    sign: input.sign,
    encrypt: net.port.encrypt,
  });
  for (const part of parts) {
    await net.port.put(part);
    await net.port.register(part);
  }
  return parts.map((part) => part.scope);
}

const inbox = (d: TransportDevice) =>
  d.db
    .prepare("SELECT scope,state,reason,error FROM pdpp_transport_inbox")
    .all() as {
    scope: string;
    state: string;
    reason: string | null;
    error: string | null;
  }[];
/** The quarantine reason a receiver recorded for each of these scopes. */
const refusals = (d: TransportDevice, scopes: string[]) =>
  scopes.map((scope) => {
    const row = inbox(d).find((r) => r.scope === scope);
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

it("first contact: another server's batch under A's transport writer is refused, and A's real batches import", async () => {
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
  expect(receiver.get()).toEqual({ id: "a", text: "real" });
  expect(importedWriters(receiver)).toContain(identity(a).transportWriter);
});

it.runIf(nightly)(
  "first contact variants: a stolen server claim, an unsigned fragment and an unregistered signer",
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
      sign: async (facts) => {
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
    expect(receiver.get()).toEqual({ id: "a", text: "real" });
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
    (scope) =>
      !inbox(receiver).some((r) => r.scope === scope && r.state === "imported"),
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
        !inbox(receiver).some((r) => r.scope === s),
    );
    // Downloaded and authorized, but not finalized: the import waits.
    for (const scope of held) {
      net.chain.delete(scope);
      net.pending.add(scope);
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
      !inbox(receiver).some((r) => r.scope === s),
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
});

it.runIf(nightly)(
  "restore with a copied nonce, not rotated: the reused sequence is equivocation and the first batch stays",
  async () => {
    const net = network();
    const a = transportDevice(net, { preexisting: "v1" });
    const receiver = transportDevice(net);
    await cycles([a, receiver], 3);
    const image = a.image();
    a.put("v2");
    await cycles([a, receiver], 3);
    a.restore(image);
    a.put("v2 from the restored copy");
    await cycles([a, receiver], 4);
    expect(receiver.get()).toEqual({ id: "a", text: "v2" });
    expect(
      receiver.db
        .prepare(
          "SELECT reason FROM pdpp_transport_import_work WHERE outcome='quarantine'",
        )
        .all(),
    ).toEqual([{ reason: "batch_equivocation" }]);
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
