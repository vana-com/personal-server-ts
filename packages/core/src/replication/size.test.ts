import { expect, it } from "vitest";
import { encryptWithPassword } from "@opendatalabs/vana-sdk/browser";
import { replicaOpenPgpCiphertextByteLength } from "./dpv2.js";
import { replicaDigest } from "./transport.js";
import {
  encodeReplicaPayload,
  fragmentReplicaStream,
  replicaPayloadOperationCrossings,
  replicaStreamCiphertextByteLength,
} from "./stream.js";
import { identity, upsert } from "./fixtures.js";
import type { ReplicaEnvelope } from "./envelope.js";

it("A5c exact OpenPGP sizing matches SDK ciphertext at both packet-length boundaries", async () => {
  for (const n of [
    0, 1, 143, 144, 185, 186, 8327, 8334, 8377, 8378, 8384, 65536, 1048579,
  ]) {
    const ciphertext = await encryptWithPassword(
      new Uint8Array(n).fill(37),
      "size-oracle",
    );
    expect(replicaOpenPgpCiphertextByteLength(n), `plaintext bytes=${n}`).toBe(
      ciphertext.length,
    );
  }
});

it("A5c grouped stream sizing matches real framing across index and offset digit boundaries", async () => {
  for (const count of [1, 9, 10, 99, 100, 999, 1000, 1001]) {
    const bytes = new Uint8Array(count * 7 - 1).fill(39);
    const input = {
      owner: identity.owner,
      writer: "a".repeat(32),
      batch: "b".repeat(32),
      sequence: 1,
      previous: null,
      collectedAt: "2026-10-20T00:00:00.000Z",
      digest: replicaDigest(bytes),
      totalBytes: bytes.length,
      targetChunkBytes: 7,
    };
    let actual = 0;
    for await (const part of fragmentReplicaStream({
      ...input,
      bytes: async function* () {
        yield bytes;
      },
      encrypt: async (_scope, plaintext) =>
        new Uint8Array(plaintext.length + 28),
    }))
      actual += part.encrypted.length;
    let probes = 0;
    const predicted = replicaStreamCiphertextByteLength(input, (length) => {
      probes++;
      return length + 28;
    });
    expect(predicted, `fragment count=${count}`).toBe(actual);
    expect(probes).toBeLessThanOrEqual(12);
  }
});

it("A5c greedy byte accounting agrees with canonical encodes, including Unicode and blobs shared by refused ops", async () => {
  const blob = new Uint8Array(81).fill(41);
  const descriptor = {
    blobId: replicaDigest(blob),
    sha256: replicaDigest(blob),
    sizeBytes: blob.length,
    mimeType: "application/octet-stream",
  };
  const operations = Array.from({ length: 80 }, (_, i) => ({
    ...upsert(String(i), i + 1, "é".repeat((i * 71) % 1000)),
    blobs: i % 3 ? [descriptor] : [],
  }));
  const envelope: ReplicaEnvelope = {
    format: "vana-pdpp-replica",
    version: 1,
    owner: identity.owner,
    batchId: "b".repeat(32),
    operations,
  };
  const cap = 12_345;
  const accepted: typeof operations = [],
    expected: number[] = [];
  for (const [index, operation] of operations.entries()) {
    let size = 0;
    for await (const bytes of encodeReplicaPayload(
      { ...envelope, operations: [...accepted, operation] },
      async function* () {
        yield blob;
      },
    ))
      size += bytes.length;
    if (size > cap) expected.push(index);
    else accepted.push(operation);
  }
  expect(expected.length).toBeGreaterThan(1);
  expect(
    replicaPayloadOperationCrossings(envelope, (bytes) => bytes > cap),
  ).toEqual(expected);
});
