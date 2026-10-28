import { afterEach, expect, it, vi } from "vitest";
import * as replicaStream from "@opendatalabs/personal-server-ts-core/replication/stream";
import { ReplicaResourceLimitError } from "@opendatalabs/personal-server-ts-core/replication/limits";
import { ReplicaFramingUnsupported } from "@opendatalabs/personal-server-ts-core/replication/outcome";
import { canonicalJson } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import { createReplicaTransportWorker } from "./pdpp-replication-transport.js";
import { replicaDigest } from "@opendatalabs/personal-server-ts-core/replication/transport";
import * as binaryChunks from "./pdpp-binary-chunks.js";
import { binaryWriter, readBinary } from "./pdpp-binary-chunks.js";
import {
  CrashController,
  cleanupHarness,
  clock,
  network,
  transportDevice,
  owner,
  sourceId,
  binding,
  credential,
  type TransportDevice,
} from "./pdpp-replica-contract.test-utils.js";
import {
  classifyReplicaPreparationError,
  ReplicaPreparationInputError,
} from "./pdpp-replication-preparation.js";

const limits = { maxOperationBytes: 1200 };
const state = (d: TransportDevice) =>
  d.db
    .prepare(
      "SELECT * FROM pdpp_transport_preparation ORDER BY rowid DESC LIMIT 1",
    )
    .get() as {
    batch: string;
    version: number;
    state: string;
    wait_json: string | null;
  };
const unsupported = (d: TransportDevice) =>
  d.db
    .prepare(
      "SELECT batch,position,outcome,reason FROM pdpp_transport_operation_outcomes WHERE outcome='unsupported' ORDER BY batch,position",
    )
    .all();
async function run(d: TransportDevice, count = 1) {
  for (let i = 0; i < count; i++) {
    clock.advance(10_000);
    await d.step();
  }
}
async function rebuilding(crash?: CrashController) {
  const net = network();
  const d = transportDevice(net, { crash, worker: { resourceLimits: limits } });
  await run(d, 3);
  d.put("old retained value", "a");
  d.put("x".repeat(2000), "bad");
  await run(d);
  expect(state(d)).toMatchObject({
    version: 2,
    state: "prep_failed_permanent",
  });
  await run(d);
  expect(state(d)).toMatchObject({ version: 2, state: "rebuilding" });
  return { net, d };
}
afterEach(() => {
  vi.restoreAllMocks();
  cleanupHarness();
});

it("A5b-R1 crash after Unsupported before rebuild commit resumes once at the same version", async () => {
  const crash = new CrashController();
  const { net, d } = await rebuilding(crash);
  const before = state(d);
  const outcomes = unsupported(d);
  const image = d.image();
  crash.arm();
  await run(d);
  const index = crash.trace.indexOf("before-update:pdpp_transport_batches");
  expect(index).toBeGreaterThanOrEqual(0);
  crash.disarm();
  d.restore(image);
  crash.arm(index);
  await expect(run(d)).rejects.toThrow();
  expect(crash.dead).toBe(true);
  d.crashReopen();
  expect(state(d)).toEqual(before);
  expect(unsupported(d)).toEqual(outcomes);
  await run(d, 5);
  const rebuilt = state(d);
  expect(rebuilt).toMatchObject({
    batch: before.batch,
    version: 2,
    state: "prepared",
  });
  expect(unsupported(d)).toEqual(outcomes);
  const payload = readBinary(d.db, "payload", before.batch);
  d.reopen();
  await run(d, 4);
  expect(readBinary(d.db, "payload", before.batch)).toEqual(payload);
  expect(unsupported(d)).toEqual(outcomes);
  expect(
    net.calls.registrations.filter((slot) => slot.endsWith("/2")),
  ).toHaveLength(1);
});

it("A5b-R2 a new local write for the same record during rebuild stays in a later batch", async () => {
  const { net, d } = await rebuilding();
  const claim = state(d);
  const encode = replicaStream.encodeReplicaPayload;
  let writes = 0;
  vi.spyOn(replicaStream, "encodeReplicaPayload").mockImplementation(
    async function* (...args) {
      if (args[0].batchId === claim.batch && writes === 0) {
        writes++;
        d.put("new local value", "a");
      }
      yield* encode(...args);
    },
  );
  await run(d);
  expect(writes).toBe(1);
  expect(state(d)).toMatchObject({
    batch: claim.batch,
    version: 2,
    state: "preparing",
  });
  const retained = JSON.parse(
    new TextDecoder().decode(readBinary(d.db, "payload", claim.batch)),
  ) as { envelope: { operations: unknown[] } };
  expect(canonicalJson(retained)).toContain("old retained value");
  expect(canonicalJson(retained)).not.toContain("new local value");
  await run(d); // v2 commits before v3 may be retained in the same step
  const receiver = transportDevice(net);
  await run(receiver, 4);
  expect(receiver.get()).toEqual({ id: "a", text: "new local value" });
  const later = d.db
    .prepare(
      "SELECT b.batch FROM pdpp_transport_batches b JOIN pdpp_transport_manifests_out m ON m.batch=b.batch WHERE m.version=3",
    )
    .get() as { batch: string };
  const laterPayload = new TextDecoder().decode(
    readBinary(d.db, "payload", later.batch),
  );
  expect(laterPayload).toContain("new local value");
  expect(laterPayload).not.toContain("old retained value");
  await run(d, 3);
  await run(receiver, 4);
  expect(receiver.get()).toEqual({ id: "a", text: "new local value" });
  expect(
    d.db
      .prepare(
        "SELECT version,state FROM pdpp_transport_manifests_out ORDER BY version",
      )
      .all(),
  ).toEqual([
    { version: 1, state: "published" },
    { version: 2, state: "published" },
    { version: 3, state: "published" },
  ]);
});

it("A5b-R3 flag off during rebuild uploads nothing and resumes durable state on the next enable", async () => {
  const { net, d } = await rebuilding();
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
    transport: net.port,
    authority: d.authority,
    now: clock.now,
    maxBlobBytes: 8192,
    targetChunkBytes: 4000,
    resourceLimits: limits,
  });
  const before = state(d);
  const outcomes = unsupported(d);
  const puts = net.calls.puts.length;
  const encode = replicaStream.encodeReplicaPayload;
  const spy = vi
    .spyOn(replicaStream, "encodeReplicaPayload")
    .mockImplementation(async function* (...args) {
      yield* encode(...args);
      enabled = false;
    });
  await expect(worker.step()).rejects.toThrow();
  expect(enabled).toBe(false);
  expect(state(d)).toEqual(before);
  expect(unsupported(d)).toEqual(outcomes);
  await worker.step();
  expect(net.calls.puts).toHaveLength(puts);
  spy.mockRestore();
  enabled = true;
  await worker.step();
  await run(d, 4);
  expect(state(d)).toMatchObject({
    batch: before.batch,
    version: 2,
    state: "prepared",
  });
  expect(unsupported(d)).toEqual(outcomes);
});

it.each(["started upload", "stored fragment", "registration intent"])(
  "A5b-R4 permanent failure after %s never rebuilds and exposes a typed wait",
  async (evidence) => {
    const net = network();
    net.faults.put = () => new Error("upload response lost");
    const d = transportDevice(net, {
      preexisting: "retain original ciphertext",
    });
    await run(d);
    const claim = state(d);
    expect(claim.state).toBe("prepared");
    expect(
      d.db
        .prepare("SELECT 1 FROM pdpp_transport_upload_attempts WHERE batch=?")
        .get(claim.batch),
    ).toBeDefined();
    const payload = readBinary(d.db, "payload", claim.batch);
    const ciphertext = d.db
      .prepare(
        "SELECT hex(encrypted) AS bytes FROM pdpp_transport_fragments_out WHERE batch=? ORDER BY position",
      )
      .all(claim.batch);
    if (evidence !== "started upload")
      d.db.prepare("DELETE FROM pdpp_transport_upload_attempts").run();
    if (evidence === "stored fragment")
      d.db
        .prepare(
          "UPDATE pdpp_transport_fragments_out SET state='stored' WHERE batch=?",
        )
        .run(claim.batch);
    if (evidence === "registration intent") {
      d.db
        .prepare(
          "UPDATE pdpp_transport_fragments_out SET attempts=0,outcome=NULL WHERE batch=?",
        )
        .run(claim.batch);
      const manifest = d.db
        .prepare(
          "SELECT scope,version FROM pdpp_transport_manifests_out WHERE batch=?",
        )
        .get(claim.batch) as { scope: string; version: number };
      d.db
        .prepare(
          "INSERT INTO pdpp_transport_registration_intents (scope,version,owner,manifest_hash,request_id,created_at,attempted_at) VALUES (?,?,?,?,?,?,?)",
        )
        .run(
          manifest.scope,
          manifest.version,
          owner,
          "sha256:" + "0".repeat(64),
          "intent-only",
          clock.now(),
          clock.now(),
        );
    }
    // Exercise recovery of a retained/legacy preparation retry after I/O began.
    d.db
      .prepare(
        "UPDATE pdpp_transport_batches SET prepared=0,next_attempt=0 WHERE batch=?",
      )
      .run(claim.batch);
    d.db
      .prepare(
        "UPDATE pdpp_transport_preparation SET state='preparing' WHERE batch=?",
      )
      .run(claim.batch);
    net.faults.encrypt = () =>
      new ReplicaResourceLimitError("aggregate_ciphertext_bytes", 9000, 8192);
    const puts = net.calls.puts.length;
    await run(d);
    expect(state(d)).toMatchObject({
      batch: claim.batch,
      version: claim.version,
      state: "prep_failed_permanent",
    });
    expect(JSON.parse(state(d).wait_json!)).toEqual({
      tag: "wait",
      dependency: {
        kind: "preparation",
        key: claim.batch,
        reason: "upload_started",
      },
    });
    expect(unsupported(d)).toEqual([]);
    expect(readBinary(d.db, "payload", claim.batch)).toEqual(payload);
    expect(
      d.db
        .prepare(
          "SELECT hex(encrypted) AS bytes FROM pdpp_transport_fragments_out WHERE batch=? ORDER BY position",
        )
        .all(claim.batch),
    ).toEqual(ciphertext);
    d.reopen();
    d.put("later", "later");
    await run(d, 4);
    expect(net.calls.puts).toHaveLength(puts);
    expect(
      d.db.prepare("SELECT count(*) AS n FROM pdpp_transport_batches").get(),
    ).toEqual({ n: 1 });
  },
);

it("A5b-6 flag off adds no preparation schema or background work and preserves the database bytes", async () => {
  const net = network();
  const d = transportDevice(net, { enabled: false });
  const before = d.image();
  await run(d, 3);
  expect(d.image()).toEqual(before);
  expect(
    d.db
      .prepare(
        "SELECT name FROM sqlite_master WHERE name IN ('pdpp_transport_preparation','pdpp_transport_operation_outcomes','pdpp_transport_upload_attempts')",
      )
      .all(),
  ).toEqual([]);
  expect(net.calls.encrypts).toBe(0);
  expect(net.calls.puts).toHaveLength(0);
  expect(net.calls.registrations).toHaveLength(0);
});

it.each([
  new Error("replica resource limit exceeded"),
  new RangeError("operation_bytes"),
  new ReplicaResourceLimitError("unknown_future_limit", 2, 1),
])("A5b classifier leaves unknown failures retryable: %s", (error) => {
  expect(classifyReplicaPreparationError(error)).toEqual({ kind: "unknown" });
});
it("A5b classifier accepts only the closed sender input and H4 cap errors", () => {
  expect(
    classifyReplicaPreparationError(new ReplicaPreparationInputError([2])),
  ).toMatchObject({
    kind: "permanent",
    positions: [2],
    admission: { reason: "operation_encoding_unsupported" },
  });
  for (const limit of [
    "operation_count",
    "operation_bytes",
    "single_blob_bytes",
    "aggregate_blob_bytes",
    "aggregate_ciphertext_bytes",
    "total_bytes",
  ])
    expect(
      classifyReplicaPreparationError(
        new ReplicaResourceLimitError(limit, 2, 1),
      ),
    ).toMatchObject({
      kind: "permanent",
      admission: { reason: "resource_unsupported", limit },
    });
});

it("A5b unknown failure during rebuild uses P backoff before resuming the same version", async () => {
  const { d } = await rebuilding();
  const before = state(d);
  const outcomes = unsupported(d);
  const encode = replicaStream.encodeReplicaPayload;
  let fails = 1;
  vi.spyOn(replicaStream, "encodeReplicaPayload").mockImplementation(
    async function* (...args) {
      if (fails-- > 0) throw new RangeError("temporary rebuild failure");
      yield* encode(...args);
    },
  );
  await run(d);
  expect(state(d)).toMatchObject({
    batch: before.batch,
    version: 2,
    state: "prep_failed_unknown",
  });
  const row = d.db
    .prepare(
      "SELECT attempts,next_attempt,outcome FROM pdpp_transport_batches WHERE batch=?",
    )
    .get(before.batch) as {
    attempts: number;
    next_attempt: number;
    outcome: string;
  };
  expect(row).toMatchObject({
    attempts: 1,
    next_attempt: clock.now() + 1000,
    outcome: "retry",
  });
  const report = await d.worker.step();
  expect(report.nextWake).toBe(row.next_attempt);
  expect(state(d).state).toBe("prep_failed_unknown");
  clock.advance(1000);
  await d.worker.step();
  await run(d, 4);
  expect(state(d)).toMatchObject({
    batch: before.batch,
    version: 2,
    state: "prepared",
  });
  expect(unsupported(d)).toEqual(outcomes);
});

it("A5b an input that cannot be encoded is Unsupported without rejecting its valid batch peers", async () => {
  const net = network();
  const d = transportDevice(net);
  await run(d, 3);
  d.put("valid", "good");
  d.put("invalid encoding", "bad");
  const read = d.store.replication.readTailPage.bind(d.store.replication);
  vi.spyOn(d.store.replication, "readTailPage").mockImplementation((input) => {
    const page = read(input);
    return {
      ...page,
      operations: page.operations.map((op) =>
        op.kind === "upsert" && op.data.id === "bad"
          ? { ...op, data: { id: "bad", text: NaN } }
          : op,
      ),
    };
  });
  await run(d, 8);
  const refused = d.db
    .prepare(
      "SELECT position,writer_id,operation_id,outcome,reason FROM pdpp_transport_operation_outcomes WHERE outcome IS NOT NULL",
    )
    .all();
  expect(refused).toEqual([
    {
      position: 1,
      writer_id: expect.any(String),
      operation_id: expect.any(String),
      outcome: "unsupported",
      reason: "operation_encoding_unsupported",
    },
  ]);
  const receiver = transportDevice(net);
  await run(receiver, 4);
  expect(receiver.get("good")).toEqual(d.get("good"));
  expect(receiver.get("bad")).toBeUndefined();
});

it("F1 an empty legacy batch waits without renumbering its unsigned successor", async () => {
  const net = network();
  const quantum = { prepare: 50 };
  const d = transportDevice(net, {
    worker: { resourceLimits: limits, quantum },
  });
  await run(d, 3);
  quantum.prepare = 0;
  d.reopen();
  d.put("x".repeat(2000), "bad");
  await run(d);
  const bad = d.db
    .prepare("SELECT * FROM pdpp_transport_batches WHERE sequence=2")
    .get() as { batch: string; digest: string; collected_at: string };
  d.put("legacy successor", "good");
  const cursor = (
    d.db.prepare("SELECT tail_cursor FROM pdpp_transport_state").get() as {
      tail_cursor: number;
    }
  ).tail_cursor;
  const page = d.store.replication.readTailPage({
    afterSequence: cursor,
    limit: 100,
  });
  const chunks: Uint8Array[] = [];
  for await (const bytes of replicaStream.encodeReplicaPayload(
    {
      format: "vana-pdpp-replica",
      version: 1,
      owner,
      batchId: "abcdef0123456789abcdef0123456789",
      operations: page.operations,
    },
    async function* () {},
  ))
    chunks.push(bytes);
  const bytes = Buffer.concat(chunks);
  const writer = binaryWriter(
    d.db,
    "payload",
    "abcdef0123456789abcdef0123456789",
  );
  writer.write(bytes);
  writer.finish();
  const digest = replicaDigest(bytes);
  d.db
    .prepare(
      "INSERT INTO pdpp_transport_batches (batch,sequence,previous_json,collected_at,digest,total_bytes) VALUES (?,3,?,?,?,?)",
    )
    .run(
      "abcdef0123456789abcdef0123456789",
      canonicalJson({ batch: bad.batch, digest: bad.digest }),
      bad.collected_at,
      digest,
      bytes.length,
    );
  d.db
    .prepare(
      "UPDATE pdpp_transport_state SET sequence=3,previous_json=?,tail_cursor=? WHERE id=1",
    )
    .run(
      canonicalJson({ batch: "abcdef0123456789abcdef0123456789", digest }),
      page.nextAfterSequence,
    );
  quantum.prepare = 50;
  d.reopen();
  await run(d, 8);
  expect(
    d.db
      .prepare("SELECT sequence FROM pdpp_transport_batches ORDER BY sequence")
      .all(),
  ).toEqual([{ sequence: 1 }, { sequence: 2 }, { sequence: 3 }]);
  expect(
    d.db
      .prepare(
        "SELECT version,state FROM pdpp_transport_manifests_out ORDER BY version",
      )
      .all(),
  ).toEqual([{ version: 1, state: "published" }]);
  const wait = d.db
    .prepare("SELECT wait_json FROM pdpp_transport_preparation WHERE batch=?")
    .get(bad.batch) as { wait_json: string };
  expect(JSON.parse(wait.wait_json)).toEqual({
    tag: "wait",
    dependency: {
      kind: "preparation",
      key: bad.batch,
      reason: "all_ops_unsupported",
    },
  });
  expect(d.get("good")).toEqual({ id: "good", text: "legacy successor" });
});

it("A5b resumes a legacy retain resource Unsupported from the unchanged journal cursor", async () => {
  const net = network();
  const d = transportDevice(net, { worker: { resourceLimits: limits } });
  await run(d, 3);
  d.put("x".repeat(2000), "bad");
  d.db
    .prepare(
      "UPDATE pdpp_transport_phase_state SET outcome='unsupported',reason='resource_unsupported',next_attempt=? WHERE phase='retain'",
    )
    .run(Number.MAX_SAFE_INTEGER);
  d.reopen();
  await run(d, 8);
  expect(
    unsupported(d),
    JSON.stringify({
      batches: d.db
        .prepare(
          "SELECT batch,prepared,outcome,reason,cause_json,next_attempt FROM pdpp_transport_batches",
        )
        .all(),
      preparation: d.db
        .prepare("SELECT * FROM pdpp_transport_preparation")
        .all(),
      phase: d.db
        .prepare(
          "SELECT * FROM pdpp_transport_phase_state WHERE phase='retain'",
        )
        .all(),
    }),
  ).toHaveLength(1);
  d.put("after legacy refusal", "good");
  await run(d, 4);
  expect(
    d.db
      .prepare(
        "SELECT version,state FROM pdpp_transport_manifests_out ORDER BY version",
      )
      .all(),
  ).toEqual([
    { version: 1, state: "published" },
    { version: 2, state: "published" },
  ]);
});

it("A5b resumes a legacy prepared=-2 resource Unsupported from its frozen payload", async () => {
  const net = network();
  const quantum = { prepare: 50 };
  const d = transportDevice(net, {
    worker: { resourceLimits: limits, quantum },
  });
  await run(d, 3);
  quantum.prepare = 0;
  d.reopen();
  d.put("x".repeat(2000), "bad");
  await run(d);
  d.db
    .prepare(
      "UPDATE pdpp_transport_batches SET prepared=-2,outcome='unsupported',reason='resource_unsupported',next_attempt=? WHERE sequence=2",
    )
    .run(Number.MAX_SAFE_INTEGER);
  d.db.exec(
    "DROP TABLE pdpp_transport_preparation; DROP TABLE pdpp_transport_operation_outcomes; DROP TABLE pdpp_transport_upload_attempts;",
  );
  quantum.prepare = 50;
  d.reopen();
  await run(d, 8);
  expect(
    unsupported(d),
    JSON.stringify({
      batches: d.db
        .prepare(
          "SELECT batch,prepared,outcome,reason,cause_json,next_attempt FROM pdpp_transport_batches",
        )
        .all(),
      preparation: d.db
        .prepare("SELECT * FROM pdpp_transport_preparation")
        .all(),
      phase: d.db
        .prepare(
          "SELECT * FROM pdpp_transport_phase_state WHERE phase='retain'",
        )
        .all(),
    }),
  ).toHaveLength(1);
  d.put("after legacy refusal", "good");
  await run(d, 4);
  expect(
    d.db
      .prepare(
        "SELECT version,state FROM pdpp_transport_manifests_out ORDER BY version",
      )
      .all(),
  ).toEqual([
    { version: 1, state: "published" },
    { version: 2, state: "published" },
  ]);
});

it("A5b preserves explicit framing readmission after a successor already published", async () => {
  const net = network();
  const options = { maxBlobBytes: 8192 };
  const d = transportDevice(net, {
    preexisting: "first batch",
    worker: options,
  });
  const encrypt = net.port.encrypt;
  let refusedBatch: string | undefined;
  let refuse = true;
  net.port.encrypt = async (scope, bytes) => {
    const value = JSON.parse(new TextDecoder().decode(bytes)) as {
      data: { fragment?: { batch: string }; manifest?: { batch: string } };
    };
    const batch = (value.data.fragment ?? value.data.manifest)!.batch;
    refusedBatch ??= batch;
    if (refuse && batch === refusedBatch)
      throw new ReplicaFramingUnsupported(9000, 8192, "manifest_bytes");
    return encrypt(scope, bytes);
  };
  await run(d);
  expect(state(d).state).toBe("released");
  d.put("successor", "next");
  await run(d, 3);
  expect(
    d.db
      .prepare("SELECT version,state FROM pdpp_transport_manifests_out")
      .all(),
  ).toEqual([{ version: 1, state: "published" }]);
  refuse = false;
  options.maxBlobBytes = 16384;
  d.reopen();
  expect(d.worker.readmitUnsupported()).toBe(1);
  await run(d, 4);
  expect(
    d.db
      .prepare(
        "SELECT version,state FROM pdpp_transport_manifests_out ORDER BY version",
      )
      .all(),
  ).toEqual([
    { version: 1, state: "published" },
    { version: 2, state: "published" },
  ]);
  const receiver = transportDevice(net);
  await run(receiver, 4);
  expect(receiver.get()).toEqual(d.get());
  expect(receiver.get("next")).toEqual(d.get("next"));
});

it("F1 non-tail all-bad readmission preserves A-B-C claims and parks later D", async () => {
  const net = network();
  const options = {
    maxBlobBytes: 8192,
    resourceLimits: { maxAggregateCiphertextBytes: 100_000 },
  };
  const d = transportDevice(net, { preexisting: "A", worker: options });
  const encrypt = net.port.encrypt;
  let allowA = false;
  net.port.encrypt = async (scope, bytes) => {
    const value = JSON.parse(new TextDecoder().decode(bytes)) as {
      data: {
        fragment?: { sequence: number };
        manifest?: { sequence: number };
      };
    };
    const sequence = (value.data.fragment ?? value.data.manifest)!.sequence;
    if (sequence === 2 || (sequence === 1 && !allowA))
      throw new ReplicaFramingUnsupported(
        options.maxBlobBytes + 1,
        options.maxBlobBytes,
        "manifest_bytes",
      );
    return encrypt(scope, bytes);
  };
  await run(d);
  const a = state(d).batch;
  d.put("B", "b");
  await run(d);
  const b = state(d).batch;
  d.put("C", "c");
  await run(d, 3);
  const c = d.db
    .prepare(
      "SELECT b.batch,b.sequence,m.plaintext FROM pdpp_transport_batches b JOIN pdpp_transport_manifests_out m ON m.batch=b.batch WHERE m.version=1",
    )
    .get() as { batch: string; sequence: number; plaintext: Buffer };
  const signedC = JSON.parse(c.plaintext.toString()) as {
    data: { manifest: { sequence: number; previous: { batch: string } } };
  };
  expect(c.sequence).toBe(3);
  expect(signedC.data.manifest).toMatchObject({
    sequence: 3,
    previous: { batch: b },
  });
  options.maxBlobBytes = 16384;
  options.resourceLimits.maxAggregateCiphertextBytes = 1;
  allowA = true;
  d.reopen();
  expect(d.worker.readmitUnsupported()).toBeGreaterThan(0);
  await run(d, 10);
  options.resourceLimits.maxAggregateCiphertextBytes = 100_000;
  d.reopen();
  d.put("D", "d");
  await run(d, 5);
  expect(
    d.db
      .prepare("SELECT sequence FROM pdpp_transport_batches WHERE batch=?")
      .get(c.batch),
  ).toEqual({ sequence: 3 });
  const published = d.db
    .prepare(
      "SELECT b.sequence,m.plaintext FROM pdpp_transport_batches b JOIN pdpp_transport_manifests_out m ON m.batch=b.batch WHERE m.state='published'",
    )
    .all() as { sequence: number; plaintext: Buffer }[];
  const signedSequences = published.map(
    (row) =>
      (
        JSON.parse(row.plaintext.toString()) as {
          data: { manifest: { sequence: number } };
        }
      ).data.manifest.sequence,
  );
  expect(new Set(signedSequences).size).toBe(signedSequences.length);
  expect(
    published.every((row, index) => row.sequence === signedSequences[index]),
  ).toBe(true);
  const wait = d.db
    .prepare("SELECT wait_json FROM pdpp_transport_preparation WHERE batch=?")
    .get(a) as { wait_json: string };
  expect(JSON.parse(wait.wait_json)).toEqual({
    tag: "wait",
    dependency: { kind: "preparation", key: a, reason: "all_ops_unsupported" },
  });
  expect(d.get("d")).toEqual({ id: "d", text: "D" });
  expect(
    d.db.prepare("SELECT count(*) AS n FROM pdpp_transport_batches").get(),
  ).toEqual({ n: 3 });
});

it("F2 readmission defers to an unsigned successor claim and never signs a stale version", async () => {
  const net = network();
  const options = { maxBlobBytes: 8192 };
  const d = transportDevice(net, { preexisting: "A", worker: options });
  const encrypt = net.port.encrypt;
  let refuseA = true;
  let holdB = true;
  net.port.encrypt = async (scope, bytes) => {
    const value = JSON.parse(new TextDecoder().decode(bytes)) as {
      data: {
        fragment?: { sequence: number };
        manifest?: { sequence: number };
      };
    };
    const sequence = (value.data.fragment ?? value.data.manifest)!.sequence;
    if (sequence === 1 && refuseA)
      throw new ReplicaFramingUnsupported(
        options.maxBlobBytes + 1,
        options.maxBlobBytes,
        "manifest_bytes",
      );
    if (sequence === 2 && holdB)
      throw new Error("unknown B preparation failure");
    return encrypt(scope, bytes);
  };
  await run(d);
  const a = state(d).batch;
  d.put("B", "b");
  await run(d);
  const b = state(d).batch;
  expect(state(d)).toMatchObject({ version: 1, state: "prep_failed_unknown" });
  const sign = d.authority.signer.signTypedData.bind(d.authority.signer);
  const stale: { sequence: string; version: string; next: number }[] = [];
  vi.spyOn(d.authority.signer, "signTypedData").mockImplementation(
    async (input) => {
      const next = (
        d.db
          .prepare(
            "SELECT coalesce(max(version),0)+1 AS next FROM pdpp_transport_manifests_out",
          )
          .get() as { next: number }
      ).next;
      if (Number(input.message.version) !== next)
        stale.push({
          sequence: String(input.message.sequence),
          version: String(input.message.version),
          next,
        });
      return sign(input);
    },
  );
  options.maxBlobBytes = 16384;
  refuseA = false;
  d.reopen();
  const readmittedWhileClaimed = d.worker.readmitUnsupported();
  await run(d, 2);
  holdB = false;
  await run(d, 8);
  expect(stale).toEqual([]);
  expect(readmittedWhileClaimed).toBe(0);
  expect(
    d.db
      .prepare(
        "SELECT version,state FROM pdpp_transport_manifests_out WHERE batch=?",
      )
      .get(b),
  ).toEqual({ version: 1, state: "published" });
  expect(d.worker.readmitUnsupported()).toBe(1);
  await run(d, 4);
  expect(
    d.db
      .prepare(
        "SELECT version,state FROM pdpp_transport_manifests_out WHERE batch=?",
      )
      .get(a),
  ).toEqual({ version: 2, state: "published" });
  expect(net.calls.registrations).toHaveLength(2);
  expect(new Set(net.calls.registrations).size).toBe(2);
  d.put("D", "d");
  await run(d, 3);
  expect(
    d.db
      .prepare(
        "SELECT version,state FROM pdpp_transport_manifests_out ORDER BY version",
      )
      .all(),
  ).toEqual([
    { version: 1, state: "published" },
    { version: 2, state: "published" },
    { version: 3, state: "published" },
  ]);
});

it.each(["payload bytes", "ciphertext bytes"])(
  "F3 aggregate attribution is bounded at 10000 ops: %s",
  async (kind) => {
    const net = network();
    const d = transportDevice(net);
    const seed = d.store.replication.readBaselinePage({ limit: 1 })
      .operations[0]!;
    const n = 10_000;
    const operations = Array.from({ length: n }, (_, index) => ({
      ...seed,
      revision: {
        ...seed.revision,
        counter: index + 1,
        operationId: index.toString(16).padStart(32, "0"),
      },
    }));
    const fullBytes = replicaStream.replicaPayloadByteLength({
      format: "vana-pdpp-replica",
      version: 1,
      owner,
      batchId: "0".repeat(32),
      operations,
    });
    const cap = fullBytes - 1;
    const logarithm = Math.ceil(Math.log2(n));
    const bound =
      n * (kind === "payload bytes" ? logarithm + 2 : 2 * logarithm + 3);
    const chunkBytes = 4 * 1024 * 1024;
    let ciphertextLimit = 0;
    if (kind === "ciphertext bytes") {
      const envelope = {
        format: "vana-pdpp-replica" as const,
        version: 1 as const,
        owner,
        batchId: "0".repeat(32),
        operations,
      };
      const bytes = () =>
        replicaStream.encodeReplicaPayload(envelope, async function* () {});
      const payload = await replicaStream.hashReplicaBytes(bytes);
      const parts = [];
      for await (const fragment of replicaStream.fragmentReplicaStream({
        owner,
        writer: "a".repeat(32),
        batch: envelope.batchId,
        sequence: 1,
        previous: null,
        collectedAt: new Date(clock.now()).toISOString(),
        ...payload,
        bytes,
        encrypt: net.port.encrypt,
        maxBlobBytes: 16 * 1024 * 1024,
        targetChunkBytes: chunkBytes,
      }))
        parts.push(fragment);
      expect(parts).toHaveLength(1);
      ciphertextLimit = parts[0]!.encrypted.length - 1;
    }
    let encrypts = 0;
    const encrypt = net.port.encrypt;
    net.port.encrypt = async (...args) => {
      encrypts++;
      if (kind === "ciphertext bytes" && encrypts > logarithm + 3)
        throw new Error("ciphertext trial count exceeded");
      return encrypt(...args);
    };
    let visits = 0;
    const encode = replicaStream.encodeReplicaPayload;
    const length = replicaStream.replicaPayloadByteLength;
    const account = (count: number) => {
      visits += count;
      if (visits > bound) throw new Error("aggregate work bound exceeded");
    };
    vi.spyOn(replicaStream, "encodeReplicaPayload").mockImplementation(
      (envelope, readBlob) => {
        account(envelope.operations.length);
        return encode(envelope, readBlob);
      },
    );
    vi.spyOn(replicaStream, "replicaPayloadByteLength").mockImplementation(
      (envelope) => {
        account(envelope.operations.length);
        return length(envelope);
      },
    );
    const worker = createReplicaTransportWorker({
      db: d.db,
      enabled: true,
      receiver: d.receiver,
      credential,
      expected: () => ({ owner, declarations: [{ sourceId, binding }] }),
      transport: net.port,
      authority: d.authority,
      now: clock.now,
      exporter: {
        ...d.store.replication,
        readBaselinePage({ afterSequence = 0, limit }) {
          const selected = operations.slice(
            afterSequence,
            afterSequence + limit,
          );
          return {
            operations: selected,
            nextAfterSequence: afterSequence + selected.length,
            hasMore: afterSequence + selected.length < n,
          };
        },
        acknowledgeBaselinePage() {},
      },
      maxBlobBytes: 16 * 1024 * 1024,
      targetChunkBytes: chunkBytes,
      resourceLimits:
        kind === "payload bytes"
          ? { maxTotalBytes: cap }
          : { maxAggregateCiphertextBytes: ciphertextLimit },
    });
    await worker.step();
    expect(visits).toBeLessThanOrEqual(bound);
    if (kind === "ciphertext bytes")
      expect(encrypts).toBeLessThanOrEqual(logarithm + 3);
    expect(unsupported(d)).toEqual([
      {
        batch: expect.any(String),
        position: n - 1,
        outcome: "unsupported",
        reason: "resource_unsupported",
      },
    ]);
    expect(net.calls.puts).toHaveLength(0);
    expect(net.calls.registrations).toHaveLength(0);
  },
  60_000,
);

it("F4 attribution makes zero payload-store writes and never PUTs or registers", async () => {
  const net = network();
  const d = transportDevice(net, {
    preexisting: "x".repeat(5000),
    worker: { resourceLimits: { maxAggregateCiphertextBytes: 4000 } },
  });
  const encrypt = net.port.encrypt;
  let preparing = false;
  net.port.encrypt = async (...args) => {
    preparing = true;
    return encrypt(...args);
  };
  let writes = 0;
  const writer = binaryChunks.binaryWriter;
  vi.spyOn(binaryChunks, "binaryWriter").mockImplementation((...args) => {
    const sink = writer(...args);
    return {
      ...sink,
      write(bytes) {
        if (preparing && args[1] === "payload") writes++;
        sink.write(bytes);
      },
    };
  });
  await d.worker.step();
  expect(writes).toBe(0);
  expect(unsupported(d)).toHaveLength(1);
  expect(net.calls.puts).toHaveLength(0);
  expect(net.calls.registrations).toHaveLength(0);
});

it("F3 unknown attribution errors stay Retry without dropping an operation", async () => {
  const net = network();
  const d = transportDevice(net, {
    preexisting: "x".repeat(5000),
    worker: { resourceLimits: { maxAggregateCiphertextBytes: 4000 } },
  });
  const encrypt = net.port.encrypt;
  net.port.encrypt = async (scope, bytes) => {
    const payload = JSON.parse(new TextDecoder().decode(bytes)) as {
      data: { fragment?: { totalBytes: number } };
    };
    const full = d.db
      .prepare(
        "SELECT total_bytes FROM pdpp_transport_batches ORDER BY sequence LIMIT 1",
      )
      .get() as { total_bytes: number };
    if (
      payload.data.fragment &&
      payload.data.fragment.totalBytes < full.total_bytes
    )
      throw new RangeError("trial encryption temporarily failed");
    return encrypt(scope, bytes);
  };
  const report = await d.worker.step();
  expect(report.problems).toContainEqual(
    expect.objectContaining({
      phase: "prepare",
      problem: "prepare_failed",
      nextEligible: clock.now() + 1000,
    }),
  );
  expect(state(d).state).toBe("prep_failed_unknown");
  expect(unsupported(d)).toEqual([]);
  expect(net.calls.puts).toHaveLength(0);
  net.port.encrypt = encrypt;
  await run(d, 8);
  expect(unsupported(d)).toHaveLength(1);
  expect(
    d.db.prepare("SELECT state FROM pdpp_transport_manifests_out").get(),
  ).toEqual({ state: "published" });
});

it("Q1 all encoding-invalid retained ops become durable Unsupported rather than Retry", async () => {
  const net = network();
  const d = transportDevice(net);
  const read = d.store.replication.readBaselinePage.bind(d.store.replication);
  vi.spyOn(d.store.replication, "readBaselinePage").mockImplementation(
    (input) => {
      const page = read(input);
      return {
        ...page,
        operations: page.operations.map((op) => ({ ...op, owner: "" })),
      };
    },
  );
  const report = await d.worker.step();
  expect(report.problems).toEqual([]);
  expect(report.unsupported).toContainEqual(
    expect.objectContaining({
      phase: "prepare",
      admission: { reason: "operation_encoding_unsupported" },
    }),
  );
  expect(unsupported(d)).toEqual([
    {
      batch: expect.any(String),
      position: 0,
      outcome: "unsupported",
      reason: "operation_encoding_unsupported",
    },
  ]);
  await run(d, 4);
  expect(state(d).state).toBe("released");
  expect(
    d.db
      .prepare("SELECT 1 FROM pdpp_transport_batches WHERE outcome='retry'")
      .get(),
  ).toBeUndefined();
  expect(net.calls.puts).toHaveLength(0);
  expect(net.calls.registrations).toHaveLength(0);
});

it("F2 a conflicting durable claim is rejected before signing", async () => {
  const net = network();
  const d = transportDevice(net, { preexisting: "claim recheck" });
  const sign = vi.spyOn(d.authority.signer, "signTypedData");
  const encrypt = net.port.encrypt;
  let conflicted = false;
  net.port.encrypt = async (...args) => {
    if (!conflicted) {
      conflicted = true;
      const claim = state(d);
      d.db
        .prepare(
          "INSERT INTO pdpp_transport_preparation (batch,version,state) VALUES (?,?,'preparing')",
        )
        .run("f".repeat(32), claim.version);
    }
    return encrypt(...args);
  };
  const report = await d.worker.step();
  expect(conflicted).toBe(true);
  expect(sign).not.toHaveBeenCalled();
  expect(report.problems).toContainEqual(
    expect.objectContaining({ phase: "prepare", problem: "prepare_failed" }),
  );
  expect(
    d.db.prepare("SELECT 1 FROM pdpp_transport_manifests_out").get(),
  ).toBeUndefined();
  expect(net.calls.puts).toHaveLength(0);
  expect(net.calls.registrations).toHaveLength(0);
});
