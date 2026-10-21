import { expect, it } from "vitest";
import { canonicalJson, type ReplicaEnvelope } from "./envelope.js";
import { binding, identity, upsert } from "./fixtures.js";
import {
  encodeReplicaPayload,
  hashReplicaBytes,
  fragmentReplicaStream,
  assembleReplicaStream,
  inspectReplicaPayload,
} from "./stream.js";
import {
  replicaDigest,
  fragmentReplicaPayload,
  decodeReplicaFragment,
} from "./transport.js";

it("streams the existing canonical wire bytes and fragments, including metadata above the Lite envelope limit", async () => {
  for (const size of [0, 1, 2, 3, 65537]) {
    const blob = new Uint8Array(size).fill(31);
    const descriptor = {
      blobId: replicaDigest(blob),
      sha256: replicaDigest(blob),
      sizeBytes: size,
      mimeType: "application/octet-stream",
    };
    const operation = {
      ...upsert("binary", 2, size === 65537 ? "é".repeat(100000) : "small"),
      blobs: [descriptor],
    };
    const envelope: ReplicaEnvelope = {
      format: "vana-pdpp-replica",
      version: 1,
      owner: identity.owner,
      batchId: "b".repeat(32),
      operations: [operation],
    };
    const source = () =>
      encodeReplicaPayload(envelope, async function* () {
        for (let offset = 0; offset < blob.length; offset += 4097)
          yield blob.subarray(offset, offset + 4097);
      });
    const expectedBytes = new TextEncoder().encode(
      canonicalJson({
        envelope,
        blobs: [
          {
            blobId: descriptor.blobId,
            bytes: Buffer.from(blob).toString("base64"),
          },
        ],
      }),
    );
    const encoded: Uint8Array[] = [];
    for await (const bytes of source()) encoded.push(bytes);
    expect(Buffer.concat(encoded)).toEqual(Buffer.from(expectedBytes));
    const hash = await hashReplicaBytes(source);
    expect(hash).toEqual({
      totalBytes: expectedBytes.length,
      digest: replicaDigest(expectedBytes),
    });
    const input = {
      owner: identity.owner,
      writer: "a".repeat(32),
      batch: envelope.batchId,
      sequence: 1,
      previous: null,
      collectedAt: "2026-10-20T00:00:00.000Z",
      encrypt: async (_scope: string, bytes: Uint8Array) => bytes,
      maxBlobBytes: 8 * 1024 * 1024,
      targetChunkBytes: 17000,
    };
    const buffered = await fragmentReplicaPayload({
      ...input,
      bytes: expectedBytes,
    });
    const streamed = [];
    for await (const part of fragmentReplicaStream({
      ...input,
      ...hash,
      bytes: source,
    }))
      streamed.push(part);
    expect(streamed).toEqual(buffered);
    const assembled = () =>
      assembleReplicaStream(async function* () {
        for (const part of streamed)
          yield decodeReplicaFragment(
            part.plaintext,
            part.scope,
            identity.owner,
          );
      });
    const staged: Uint8Array[] = [];
    const inspected = await inspectReplicaPayload(
      assembled,
      {
        owner: identity.owner,
        declarations: [{ sourceId: identity.sourceId, binding }],
      },
      (_id, bytes) => {
        staged.push(bytes);
      },
    );
    expect(inspected.envelope).toEqual(envelope);
    expect(Buffer.concat(staged)).toEqual(Buffer.from(blob));
    if (size === 3) {
      // Buffered Node import accepted an initial UTF-8 BOM and duplicate equal entries.
      const entry = {
        blobId: descriptor.blobId,
        bytes: Buffer.from(blob).toString("base64"),
      };
      const duplicateBytes = new TextEncoder().encode(
        "\uFEFF" + canonicalJson({ envelope, blobs: [entry, entry] }),
      );
      const indices: number[] = [];
      const duplicate = await inspectReplicaPayload(
        async function* () {
          yield duplicateBytes;
        },
        {
          owner: identity.owner,
          declarations: [{ sourceId: identity.sourceId, binding }],
        },
        (_id, _bytes, index) => {
          indices.push(index);
        },
      );
      expect(duplicate.blobs).toHaveLength(2);
      expect(indices).toEqual([0, 1]);
      await expect(
        inspectReplicaPayload(
          async function* () {
            yield duplicateBytes.subarray(0, duplicateBytes.length - 1);
          },
          {
            owner: identity.owner,
            declarations: [{ sourceId: identity.sourceId, binding }],
          },
        ),
      ).rejects.toThrow();
    }
  }
}, 30000);
