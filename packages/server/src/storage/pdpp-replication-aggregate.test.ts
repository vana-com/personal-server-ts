import { afterEach, expect, it, vi } from "vitest";
import * as stream from "@opendatalabs/personal-server-ts-core/replication/stream";
import { canonicalJson } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import * as binary from "./pdpp-binary-chunks.js";
import { createReplicaTransportWorker } from "./pdpp-replication-transport.js";
import {
  cleanupHarness,
  network,
  transportDevice,
  owner,
  credential,
  sourceId,
  binding,
  clock,
} from "./pdpp-replica-contract.test-utils.js";

afterEach(() => {
  vi.restoreAllMocks();
  cleanupHarness();
});
it.each(["total_bytes", "aggregate_ciphertext_bytes"])(
  "A5c finds every crossing among 10000 operations in one pass with linear encode/encrypt work: %s",
  async (limit) => {
    const net = network({ cap: 16 * 1024 * 1024 });
    const d = transportDevice(net, { preexisting: "seed" });
    const seed = d.store.replication
      .readBaselinePage({ limit: 10 })
      .operations.find((op) => op.kind === "upsert")!;
    const n = 10_000,
      half = n / 2;
    const operations = Array.from({ length: n }, (_, index) => ({
      ...seed,
      ...(seed.kind === "upsert" && {
        data: {
          id: String(index),
          text: index >= half && index < n - 1 ? "x".repeat(6000) : "fit",
        },
      }),
      revision: {
        ...seed.revision,
        counter: index + 1,
        operationId: index.toString(16).padStart(32, "0"),
      },
    }));
    const envelope = {
      format: "vana-pdpp-replica" as const,
      version: 1 as const,
      owner,
      batchId: "0".repeat(32),
      operations,
    };
    const acceptedEnvelope = {
      ...envelope,
      operations: [...operations.slice(0, half), operations[n - 1]!],
    };
    const payloadLimit = stream.replicaPayloadByteLength(acceptedEnvelope);
    const bytes = () =>
      stream.encodeReplicaPayload(acceptedEnvelope, async function* () {});
    const payload = await stream.hashReplicaBytes(bytes);
    let ciphertextLimit = 0;
    for await (const fragment of stream.fragmentReplicaStream({
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
      targetChunkBytes: 4 * 1024 * 1024,
    }))
      ciphertextLimit += fragment.encrypted.length;
    const inputBytes = Buffer.byteLength(canonicalJson(envelope));
    let encodeCalls = 0,
      visits = 0,
      encodeBytes = 0,
      encryptCalls = 0,
      encryptBytes = 0,
      writes = 0,
      attribution = false;
    const encode = stream.encodeReplicaPayload;
    const length = stream.replicaPayloadByteLength;
    const hash = stream.hashReplicaBytes;
    const crossings = stream.replicaPayloadOperationCrossings;
    const textEncode = TextEncoder.prototype.encode;
    let framingEncodeCalls = 0,
      framingEncodeBytes = 0;
    vi.spyOn(stream, "replicaPayloadOperationCrossings").mockImplementation(
      (...args) => {
        attribution = true;
        return crossings(...args);
      },
    );
    vi.spyOn(TextEncoder.prototype, "encode").mockImplementation(function (
      this: TextEncoder,
      value,
    ) {
      const bytes = textEncode.call(this, value);
      if (attribution) {
        framingEncodeCalls++;
        framingEncodeBytes += bytes.length;
      }
      return bytes;
    });
    const encrypt = net.port.encrypt;
    vi.spyOn(stream, "encodeReplicaPayload").mockImplementation(
      async function* (...args) {
        encodeCalls++;
        visits += args[0].operations.length;
        for await (const bytes of encode(...args)) {
          encodeBytes += bytes.length;
          yield bytes;
        }
      },
    );
    vi.spyOn(stream, "replicaPayloadByteLength").mockImplementation((value) => {
      attribution = true;
      visits += value.operations.length;
      return length(value);
    });
    vi.spyOn(stream, "hashReplicaBytes").mockImplementation((...args) => {
      attribution = true;
      return hash(...args);
    });
    net.port.encrypt = async (...args) => {
      encryptCalls++;
      encryptBytes += args[1].length;
      return encrypt(...args);
    };
    const realWriter = binary.binaryWriter;
    vi.spyOn(binary, "binaryWriter").mockImplementation((...args) => {
      const writer = realWriter(...args);
      return {
        ...writer,
        write(bytes) {
          if (attribution && args[1] === "payload") writes++;
          writer.write(bytes);
        },
      };
    });
    const worker = createReplicaTransportWorker({
      db: d.db,
      enabled: true,
      receiver: d.receiver,
      credential,
      authority: d.authority,
      expected: () => ({ owner, declarations: [{ sourceId, binding }] }),
      transport: net.port,
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
      targetChunkBytes: 4 * 1024 * 1024,
      maxBatchBytes: inputBytes * 2,
      maxBatchOperations: n,
      resourceLimits:
        limit === "total_bytes"
          ? { maxTotalBytes: payloadLimit }
          : { maxAggregateCiphertextBytes: ciphertextLimit },
    });
    const report = await worker.step();
    expect(report.problems).toEqual([]);
    expect(
      d.db
        .prepare("SELECT count(*) AS n FROM pdpp_transport_operation_outcomes")
        .get(),
    ).toEqual({ n });
    const unsupported = d.db
      .prepare(
        "SELECT position FROM pdpp_transport_operation_outcomes WHERE outcome='unsupported' ORDER BY position",
      )
      .all();
    expect(unsupported).toEqual(
      Array.from({ length: half - 1 }, (_, i) => ({ position: half + i })),
    );
    // At most eight visits per input op, 16 complete encodes, and 8x the
    // input bytes through either codec. These constants do not grow with n.
    expect(visits).toBeLessThanOrEqual(8 * n);
    expect(encodeCalls).toBeLessThanOrEqual(16);
    expect(encodeBytes).toBeLessThanOrEqual(8 * inputBytes);
    expect(framingEncodeCalls).toBeLessThanOrEqual(8 * n);
    expect(framingEncodeBytes).toBeLessThanOrEqual(8 * inputBytes);
    expect(encryptCalls).toBeLessThanOrEqual(16);
    expect(encryptBytes).toBeLessThanOrEqual(8 * inputBytes);
    expect(writes).toBe(0);
    expect(net.calls.puts).toHaveLength(0);
    expect(net.calls.registrations).toHaveLength(0);
  },
  60_000,
);

it("A5c an unknown ciphertext sizing capability stays Retry without discarding operations", async () => {
  const net = network();
  delete net.port.encryptedByteLength;
  const d = transportDevice(net, {
    preexisting: "x".repeat(5000),
    worker: { resourceLimits: { maxAggregateCiphertextBytes: 4000 } },
  });
  const report = await d.worker.step();
  expect(report.problems).toContainEqual(
    expect.objectContaining({
      phase: "prepare",
      problem: "prepare_failed",
      nextEligible: clock.now() + 1000,
    }),
  );
  expect(
    d.db
      .prepare(
        "SELECT outcome FROM pdpp_transport_operation_outcomes WHERE outcome IS NOT NULL",
      )
      .all(),
  ).toEqual([]);
  expect(net.calls.puts).toHaveLength(0);
  expect(net.calls.registrations).toHaveLength(0);
});
