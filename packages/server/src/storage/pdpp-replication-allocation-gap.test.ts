import { afterEach, expect, it, vi } from "vitest";
import { randomBytes } from "node:crypto";
import {
  signReplicaBatch,
  type ReplicaBatchFacts,
} from "@opendatalabs/personal-server-ts-core/replication/writer-identity";
import {
  canonicalJson,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  fragmentReplicaPayload,
  prepareReplicaManifest,
  replicaScope,
  replicaDigest,
} from "@opendatalabs/personal-server-ts-core/replication/transport";
import { currentReplicaWriterIdentity } from "./pdpp-replica-writer-identity.js";
import { binaryWriter } from "./pdpp-binary-chunks.js";
import {
  cleanupHarness,
  injectReplicaBatch,
  network,
  owner,
  transportDevice,
  clock,
  type TransportDevice,
  type Network,
} from "./pdpp-replica-contract.test-utils.js";

afterEach(() => {
  vi.restoreAllMocks();
  cleanupHarness();
});
async function run(d: TransportDevice, n = 1) {
  for (let i = 0; i < n; i++) {
    clock.advance(10_000);
    await d.step();
  }
}
function sign(d: TransportDevice) {
  return (facts: ReplicaBatchFacts) =>
    signReplicaBatch({
      signer: d.authority.signer,
      partition: { owner, chainId: 14800, environment: "dev" },
      seed: currentReplicaWriterIdentity(d.db)!.seed,
      facts,
    });
}
async function squat(net: Network, d: TransportDevice, ownKey = false) {
  const attacker = ownKey ? d : transportDevice(net);
  return injectReplicaBatch(net, {
    writer: currentReplicaWriterIdentity(d.db)!.transportWriter,
    operations: d.store.replication.readBaselinePage({ limit: 100 }).operations,
    sign: sign(attacker),
  });
}
/** A retained legacy successor: the new claim gate does not manufacture this backlog. */
async function successor(net: Network, d: TransportDevice, prepared = false) {
  const prior = d.db
    .prepare("SELECT * FROM pdpp_transport_batches WHERE sequence=1")
    .get() as { batch: string; digest: string; collected_at: string };
  d.put("later", "later");
  const cursor = d.db
    .prepare(
      "SELECT coalesce(tail_cursor,baseline_cursor) AS cursor FROM pdpp_transport_state",
    )
    .get() as { cursor: number };
  const page = d.store.replication.readTailPage({
    afterSequence: cursor.cursor,
    limit: 100,
  });
  const batch = randomBytes(16).toString("hex");
  const payload = Buffer.from(
    canonicalJson({
      blobs: [],
      envelope: {
        format: "vana-pdpp-replica",
        version: 1,
        owner,
        batchId: batch,
        operations: page.operations,
      },
    }),
  );
  const previous = { batch: prior.batch, digest: prior.digest };
  const digest = replicaDigest(payload);
  const out = binaryWriter(d.db, "payload", batch);
  out.write(payload);
  out.finish();
  d.db
    .prepare(
      "INSERT INTO pdpp_transport_batches (batch,sequence,previous_json,collected_at,digest,total_bytes) VALUES (?,2,?,?,?,?)",
    )
    .run(
      batch,
      canonicalJson(previous),
      prior.collected_at,
      digest,
      payload.length,
    );
  d.db
    .prepare(
      "INSERT INTO pdpp_transport_preparation (batch,version,state) VALUES (?,2,'preparing')",
    )
    .run(batch);
  const insert = d.db.prepare(
    "INSERT INTO pdpp_transport_operation_outcomes (batch,position,operation_json) VALUES (?,?,?)",
  );
  page.operations.forEach((op: ReplicaOperation, i: number) =>
    insert.run(batch, i, canonicalJson(op)),
  );
  d.db
    .prepare(
      "UPDATE pdpp_transport_state SET sequence=2,previous_json=?,tail_cursor=?",
    )
    .run(canonicalJson({ batch, digest }), page.nextAfterSequence);
  if (prepared) {
    const statement = {
      owner,
      writer: currentReplicaWriterIdentity(d.db)!.transportWriter,
      batch,
      sequence: 2,
      previous,
      collectedAt: prior.collected_at,
    };
    const fragments = await fragmentReplicaPayload({
      ...statement,
      bytes: payload,
      encrypt: net.port.encrypt,
      maxBlobBytes: 8192,
      targetChunkBytes: 4000,
    });
    const manifest = await prepareReplicaManifest({
      ...statement,
      digest,
      totalBytes: payload.length,
      version: 2,
      fragments: fragments.map((f) => ({
        digest: f.digest,
        bytes: f.encrypted.length,
      })),
      sign: sign(d),
      encrypt: net.port.encrypt,
    });
    for (const f of fragments)
      d.db
        .prepare(
          "INSERT INTO pdpp_transport_fragments_out (batch,position,digest,encrypted) VALUES (?,?,?,?)",
        )
        .run(batch, f.index, f.digest, f.encrypted);
    d.db
      .prepare(
        "INSERT INTO pdpp_transport_manifests_out (batch,scope,version,plaintext,encrypted,data_hash,metadata_hash) VALUES (?,?,?,?,?,?,?)",
      )
      .run(
        batch,
        manifest.scope,
        manifest.version,
        manifest.plaintext,
        manifest.encrypted,
        manifest.dataHash,
        manifest.metadataHash,
      );
    d.db
      .prepare("UPDATE pdpp_transport_batches SET prepared=1 WHERE batch=?")
      .run(batch);
    d.db
      .prepare(
        "UPDATE pdpp_transport_preparation SET state='prepared' WHERE batch=?",
      )
      .run(batch);
    return { batch, fragments, manifest };
  }
  return { batch };
}

it("A12b edge-1 Amendment 1 moves unaccepted claims 1 and 2 to 2 and 3, imports the chain and refuses foreign version 1", async () => {
  const net = network();
  const quantum = { prepare: 0, publish: 0 };
  const d = transportDevice(net, {
    preexisting: "honest",
    worker: { quantum },
  });
  await run(d);
  const later = await successor(net, d);
  const before = d.db
    .prepare(
      "SELECT batch,sequence FROM pdpp_transport_batches ORDER BY sequence",
    )
    .all();
  expect(
    d.db
      .prepare(
        "SELECT version FROM pdpp_transport_preparation ORDER BY version",
      )
      .all(),
  ).toEqual([{ version: 1 }, { version: 2 }]);
  const foreign = await squat(net, d);
  quantum.prepare = 50;
  quantum.publish = 50;
  d.reopen();
  await run(d, 8);
  expect(
    d.db
      .prepare(
        "SELECT batch,version,state FROM pdpp_transport_manifests_out ORDER BY version",
      )
      .all(),
  ).toEqual([
    {
      batch: (before[0] as { batch: string }).batch,
      version: 2,
      state: "published",
    },
    { batch: later.batch, version: 3, state: "published" },
  ]);
  expect(
    d.db
      .prepare(
        "SELECT batch,sequence FROM pdpp_transport_batches ORDER BY sequence",
      )
      .all(),
  ).toEqual(before);
  const receiver = transportDevice(net);
  await run(receiver, 8);
  expect(receiver.get()).toEqual({ id: "a", text: "honest" });
  expect(receiver.get("later")).toEqual({ id: "later", text: "later" });
  expect(
    receiver.db
      .prepare(
        "SELECT state,reason FROM pdpp_transport_manifests_in WHERE slot=?",
      )
      .get(foreign.slot),
  ).toEqual({ state: "quarantined", reason: "writer_mismatch" });
  expect(
    net.calls.registrations.filter((slot) =>
      slot.startsWith(
        replicaScope(currentReplicaWriterIdentity(d.db)!.transportWriter),
      ),
    ),
  ).toHaveLength(3);
});

it("A12b edge-2 our key with a different digest records a terminal own_key_conflict wait without re-signing", async () => {
  const net = network();
  const d = transportDevice(net, { preexisting: "honest" });
  await squat(net, d, true);
  await run(d, 3);
  const bytes = d.db
    .prepare(
      "SELECT version,hex(encrypted) AS bytes FROM pdpp_transport_manifests_out",
    )
    .all();
  expect(
    d.db
      .prepare("SELECT state FROM pdpp_transport_registration_recovery")
      .get(),
  ).toEqual({ state: "own_key_conflict" });
  expect(
    d.db
      .prepare(
        "SELECT outcome,reason,next_attempt FROM pdpp_transport_manifests_out",
      )
      .get(),
  ).toEqual({
    outcome: "wait",
    reason: "own_key_conflict",
    next_attempt: Number.MAX_SAFE_INTEGER,
  });
  const count = net.calls.encrypts;
  d.reopen();
  d.put("blocked", "later");
  const report = await d.worker.step();
  expect(report.waits).toContainEqual(
    expect.objectContaining({
      dependency: expect.objectContaining({
        kind: "registration",
        reason: "own_key_conflict",
      }),
    }),
  );
  await run(d, 10);
  expect(net.calls.encrypts).toBe(count);
  expect(
    d.db
      .prepare(
        "SELECT version,hex(encrypted) AS bytes FROM pdpp_transport_manifests_out",
      )
      .all(),
  ).toEqual(bytes);
});

it("A12b edge-3 and R3 repeated squats exhaust the writer bound, back off, and require owner acknowledgement", async () => {
  const net = network();
  const quantum = { publish: 0 };
  const d = transportDevice(net, {
    preexisting: "honest",
    worker: { quantum },
  });
  await run(d);
  // Root fragments are already stored when registration discovers the squat.
  for (const f of d.db
    .prepare("SELECT digest,encrypted FROM pdpp_transport_fragments_out")
    .all() as { digest: string; encrypted: Buffer }[])
    await net.port.putFragment({
      scope: replicaScope(currentReplicaWriterIdentity(d.db)!.transportWriter),
      ...f,
    });
  d.db.prepare("UPDATE pdpp_transport_fragments_out SET state='stored'").run();
  quantum.publish = 50;
  d.reopen();
  for (let i = 0; i <= 8; i++) {
    await squat(net, d);
    clock.advance(60_000);
    await d.step();
  }
  expect(
    d.db
      .prepare("SELECT count(*) AS n FROM pdpp_transport_version_squats")
      .get(),
  ).toEqual({ n: 8 });
  expect(
    d.db
      .prepare("SELECT outcome,reason FROM pdpp_transport_manifests_out")
      .get(),
  ).toEqual({ outcome: "wait", reason: "version_squat" });
  expect(d.worker.retryVersionSquats()).toBe(0);
  const calls = net.calls.gets.length;
  clock.advance(3_600_001);
  await d.step();
  expect(net.calls.gets).toHaveLength(calls);
  expect(
    d.db.prepare("SELECT next_attempt FROM pdpp_transport_manifests_out").get(),
  ).toEqual({ next_attempt: clock.now() + 600_000 });
  clock.advance(600_000);
  expect(d.worker.retryVersionSquats()).toBe(1);
  await run(d, 4);
  expect(
    d.db
      .prepare("SELECT version,state FROM pdpp_transport_manifests_out")
      .get(),
  ).toEqual({ version: 10, state: "published" });
});

it("A12b R1 crash after squat record before re-sign commit allocates once after reopen", async () => {
  const { CrashController } =
    await import("./pdpp-replica-contract.test-utils.js");
  const crash = new CrashController();
  const net = network();
  const quantum = { publish: 0 };
  const d = transportDevice(net, {
    preexisting: "honest",
    crash,
    worker: { quantum },
  });
  await run(d);
  await squat(net, d);
  quantum.publish = 50;
  d.reopen();
  const image = d.image();
  crash.arm();
  await run(d);
  const point = crash.trace.indexOf(
    "before-update:pdpp_transport_version_squats",
  );
  expect(point).toBeGreaterThanOrEqual(0);
  crash.disarm();
  d.restore(image);
  crash.arm(point);
  await expect(run(d)).rejects.toThrow();
  expect(crash.dead).toBe(true);
  d.crashReopen();
  await run(d, 8);
  expect(
    d.db
      .prepare("SELECT count(*) AS n FROM pdpp_transport_version_squats")
      .get(),
  ).toEqual({ n: 1 });
  expect(
    d.db
      .prepare("SELECT version,state FROM pdpp_transport_manifests_out")
      .get(),
  ).toEqual({ version: 2, state: "published" });
  expect(
    net.calls.registrations.filter((key) => key.endsWith("/2")),
  ).toHaveLength(1);
});

it.each([false, true])(
  "A12b R2 later fragment upload in flight preserves bytes; accepted=%s never moves",
  async (accepted) => {
    const net = network();
    const quantum = { publish: 0 };
    const d = transportDevice(net, {
      preexisting: "honest",
      worker: { quantum },
    });
    await run(d);
    const later = await successor(net, d, true);
    await squat(net, d);
    const f = later.fragments![0]!;
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    d.db
      .prepare(
        "INSERT INTO pdpp_transport_upload_attempts VALUES (?,'fragment',0,?)",
      )
      .run(later.batch, clock.now());
    d.db
      .prepare(
        "UPDATE pdpp_transport_fragments_out SET next_attempt=? WHERE batch=?",
      )
      .run(clock.now() + 3_600_000, later.batch);
    const upload = held.then(() => net.port.putFragment(f));
    if (accepted) {
      for (const fragment of later.fragments!)
        await net.port.putFragment(fragment);
      await net.port.put(later.manifest!);
      await net.port.register(later.manifest!);
    }
    const ciphertext = d.db
      .prepare(
        "SELECT digest,hex(encrypted) AS bytes FROM pdpp_transport_fragments_out WHERE batch=?",
      )
      .all(later.batch);
    const manifest = d.db
      .prepare(
        "SELECT version,hex(encrypted) AS bytes FROM pdpp_transport_manifests_out WHERE batch=?",
      )
      .get(later.batch);
    quantum.publish = 50;
    d.reopen();
    await run(d);
    expect(
      d.db
        .prepare(
          "SELECT digest,hex(encrypted) AS bytes FROM pdpp_transport_fragments_out WHERE batch=?",
        )
        .all(later.batch),
    ).toEqual(ciphertext);
    if (accepted)
      expect(
        d.db
          .prepare(
            "SELECT version,hex(encrypted) AS bytes FROM pdpp_transport_manifests_out WHERE batch=?",
          )
          .get(later.batch),
      ).toEqual(manifest);
    else
      expect(
        d.db
          .prepare(
            "SELECT version FROM pdpp_transport_manifests_out WHERE batch=?",
          )
          .get(later.batch),
      ).toEqual({ version: 3 });
    expect(
      d.db
        .prepare(
          "SELECT started_at FROM pdpp_transport_upload_attempts WHERE batch=? AND kind='fragment'",
        )
        .get(later.batch),
    ).toBeDefined();
    release();
    await upload;
    d.db
      .prepare(
        "UPDATE pdpp_transport_fragments_out SET next_attempt=0 WHERE batch=?",
      )
      .run(later.batch);
    await run(d, 8);
    expect(
      d.db
        .prepare("SELECT state FROM pdpp_transport_manifests_out WHERE batch=?")
        .get(
          (
            d.db
              .prepare(
                "SELECT batch FROM pdpp_transport_batches WHERE sequence=1",
              )
              .get() as { batch: string }
          ).batch,
        ),
    ).toEqual({ state: "published" });
  },
);

it("A12b R4 door closes mid re-sign: no registration and unchanged durable claims", async () => {
  const { createReplicaTransportWorker } =
    await import("./pdpp-replication-transport.js");
  const { credential, sourceId, binding } =
    await import("./pdpp-replica-contract.test-utils.js");
  const net = network();
  const d = transportDevice(net, {
    preexisting: "honest",
    worker: { quantum: { publish: 0 } },
  });
  await run(d);
  await squat(net, d);
  const before = d.db
    .prepare(
      "SELECT version,hex(encrypted) AS bytes FROM pdpp_transport_manifests_out",
    )
    .all();
  let enabled = true;
  const worker = createReplicaTransportWorker({
    db: d.db,
    get enabled() {
      return enabled;
    },
    exporter: d.store.replication,
    receiver: d.receiver,
    credential,
    expected: () => ({ owner, declarations: [{ sourceId, binding }] }),
    authority: d.authority,
    transport: net.port,
    now: clock.now,
    maxBlobBytes: 8192,
    targetChunkBytes: 4000,
  });
  const encrypt = net.port.encrypt;
  const spy = vi
    .spyOn(net.port, "encrypt")
    .mockImplementation(async (...args) => {
      const bytes = await encrypt(...args);
      enabled = false;
      return bytes;
    });
  await expect(worker.step()).rejects.toThrow();
  expect(
    d.db
      .prepare(
        "SELECT version,hex(encrypted) AS bytes FROM pdpp_transport_manifests_out",
      )
      .all(),
  ).toEqual(before);
  expect(net.calls.registrations).toHaveLength(1);
  spy.mockRestore();
  enabled = true;
  for (let i = 0; i < 6; i++) {
    clock.advance(10_000);
    await worker.step();
  }
  expect(
    d.db
      .prepare("SELECT version,state FROM pdpp_transport_manifests_out")
      .get(),
  ).toEqual({ version: 2, state: "published" });
});

it("A12b R5 a successful own registration with a lost response commits the same digest without re-signing", async () => {
  const net = network();
  net.faults.loseRegistrationResponse = true;
  const d = transportDevice(net, { preexisting: "honest" });
  await run(d);
  const before = d.db
    .prepare(
      "SELECT version,hex(encrypted) AS bytes FROM pdpp_transport_manifests_out",
    )
    .all();
  d.reopen();
  await run(d, 4);
  expect(
    d.db
      .prepare(
        "SELECT version,hex(encrypted) AS bytes FROM pdpp_transport_manifests_out",
      )
      .all(),
  ).toEqual(before);
  expect(
    d.db.prepare("SELECT state FROM pdpp_transport_manifests_out").get(),
  ).toEqual({ state: "published" });
  expect(
    d.db.prepare("SELECT * FROM pdpp_transport_version_squats").all(),
  ).toEqual([]);
  expect(net.calls.registrations).toHaveLength(1);
});

it("A12b edge-5 flag off is byte-identical with no recovery schema or work", async () => {
  const net = network();
  const d = transportDevice(net, { enabled: false });
  const before = d.image();
  await run(d, 3);
  expect(d.image()).toEqual(before);
  expect(
    d.db
      .prepare(
        "SELECT name FROM sqlite_master WHERE name IN ('pdpp_transport_version_squats','pdpp_transport_registration_recovery')",
      )
      .all(),
  ).toEqual([]);
  expect(net.calls.puts).toHaveLength(0);
  expect(net.calls.registrations).toHaveLength(0);
  expect(net.calls.encrypts).toBe(0);
});

it("A12b D2 an old intent cannot resubmit after re-sign; the new version gets a fresh ciphertext intent", async () => {
  const net = network();
  const quantum = { publish: 0 };
  const d = transportDevice(net, {
    preexisting: "honest",
    worker: { quantum },
  });
  await run(d);
  const original = d.db
    .prepare("SELECT scope,version,encrypted FROM pdpp_transport_manifests_out")
    .get() as { scope: string; version: number; encrypted: Buffer };
  const oldHash = replicaDigest(original.encrypted);
  d.db
    .prepare(
      `INSERT INTO pdpp_transport_registration_intents
    (scope,version,owner,manifest_hash,request_id,created_at,attempted_at) VALUES (?,1,?,?,?,0,0)`,
    )
    .run(original.scope, owner, oldHash, "old-intent");
  await squat(net, d);
  quantum.publish = 50;
  d.reopen();
  await run(d);
  expect(
    d.db.prepare("SELECT version FROM pdpp_transport_manifests_out").get(),
  ).toEqual({ version: 2 });
  expect(
    d.db
      .prepare(
        "SELECT * FROM pdpp_transport_registration_intents WHERE version=1",
      )
      .all(),
  ).toEqual([]);
  // Even a stale durable intent restored by an older component has no old
  // manifest row to publish. The moved batch can submit only its new bytes.
  d.db
    .prepare(
      `INSERT INTO pdpp_transport_registration_intents
    (scope,version,owner,manifest_hash,request_id,created_at,attempted_at) VALUES (?,1,?,?,?,0,0)`,
    )
    .run(original.scope, owner, oldHash, "old-intent");
  await run(d, 5);
  const fresh = d.db
    .prepare(
      "SELECT version,request_id,manifest_hash,status FROM pdpp_transport_registration_intents WHERE version=2",
    )
    .get() as { request_id: string; manifest_hash: string; status: string };
  expect(fresh).toMatchObject({ version: 2, status: "confirmed" });
  expect(fresh.request_id).not.toBe("old-intent");
  expect(fresh.manifest_hash).not.toBe(oldHash);
  expect(
    net.calls.registrations.filter((key) => key === `${original.scope}/1`),
  ).toHaveLength(1);
  expect(
    net.calls.registrations.filter((key) => key === `${original.scope}/2`),
  ).toHaveLength(1);
});
