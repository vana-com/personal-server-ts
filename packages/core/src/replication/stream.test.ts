import { expect, it, vi } from "vitest";
import { canonicalJson, type ReplicaEnvelope } from "./envelope.js";
import { binding, identity, registration, upsert } from "./fixtures.js";
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
import { DEFAULT_REPLICA_STREAMED_LIMITS } from "./stream.js";
import { ReplicaByteBudget, admit } from "./limits.js";

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

it("caps assembled payload bytes at the admitted amount", async () => {
  const plaintext = new TextEncoder().encode("small-payload");
  const fragments = await fragmentReplicaPayload({
    owner: identity.owner,
    writer: "a".repeat(32),
    batch: "b".repeat(32),
    sequence: 1,
    previous: null,
    bytes: plaintext,
    collectedAt: "2026-10-20T00:00:00.000Z",
    encrypt: async (_scope, bytes) => bytes,
    targetChunkBytes: 4,
  });
  const stream = () =>
    assembleReplicaStream(
      async function* () {
        for (const part of fragments)
          yield decodeReplicaFragment(
            part.plaintext,
            part.scope,
            identity.owner,
          );
      },
      { maxBytes: plaintext.length - 1 },
    );

  await expect(async () => {
    for await (const _chunk of stream()) void _chunk;
  }).rejects.toMatchObject({ code: "payload_invalid" });
});

it("T4 rejects missing, duplicate, overlapping, altered and inconsistent fragments", async () => {
  const bytes = new TextEncoder().encode(
    "payload whose fragment edges must stay exact".repeat(80),
  );
  const parts = await fragmentReplicaPayload({
    owner: identity.owner,
    writer: "a".repeat(32),
    batch: "b".repeat(32),
    sequence: 1,
    previous: null,
    bytes,
    collectedAt: "2026-10-20T00:00:00.000Z",
    encrypt: async (_scope, input) => input,
    targetChunkBytes: 70,
  });
  const fragments = parts.map((part) =>
    decodeReplicaFragment(part.plaintext, part.scope, identity.owner),
  );
  const refused = async (value: typeof fragments) => {
    await expect(async () => {
      for await (const _chunk of assembleReplicaStream(async function* () {
        yield* value;
      }))
        void _chunk;
    }).rejects.toMatchObject({ code: "payload_invalid" });
  };

  await refused(fragments.slice(0, -1));
  await refused([fragments[0]!, fragments[0]!, ...fragments.slice(2)]);
  await refused([
    fragments[0]!,
    { ...fragments[1]!, offset: fragments[1]!.offset - 1 },
    ...fragments.slice(2),
  ]);
  await refused([
    fragments[0]!,
    {
      ...fragments[1]!,
      content: `${fragments[1]!.content[0] === "A" ? "B" : "A"}${fragments[1]!.content.slice(1)}`,
    },
    ...fragments.slice(2),
  ]);
  await refused([
    fragments[0]!,
    { ...fragments[1]!, totalBytes: fragments[1]!.totalBytes - 1 },
    ...fragments.slice(2),
  ]);
});

it("E2 aborts on the first byte beyond the declaration and releases admission", async () => {
  const plaintext = new TextEncoder().encode("actual payload");
  const parts = await fragmentReplicaPayload({
    owner: identity.owner,
    writer: "a".repeat(32),
    batch: "b".repeat(32),
    sequence: 1,
    previous: null,
    bytes: plaintext,
    collectedAt: "2026-10-20T00:00:00.000Z",
    encrypt: async (_scope, bytes) => bytes,
  });
  const fragment = decodeReplicaFragment(
    parts[0]!.plaintext,
    parts[0]!.scope,
    identity.owner,
  );
  const declaredBytes = plaintext.length - 1;
  const budget = new ReplicaByteBudget(100_000);
  const admission = admit(
    {
      totalBytes: declaredBytes,
      fragments: [{ bytes: parts[0]!.encrypted.length }],
    },
    budget,
    {
      repositoryId: "repo",
      owner: identity.owner,
      manifestDigest: "sha256:batch",
    },
  );
  if ("kind" in admission) throw new Error("expected admission");
  const reservation = admission.reserveObject(parts[0]!.encrypted.length);
  if (typeof reservation !== "function")
    throw new Error("expected fragment reservation");

  try {
    await expect(async () => {
      for await (const _chunk of assembleReplicaStream(
        async function* () {
          yield { ...fragment, totalBytes: declaredBytes };
        },
        { maxBytes: admission.payloadBytes },
      ))
        void _chunk;
    }).rejects.toMatchObject({ code: "payload_invalid" });
  } finally {
    reservation();
  }
  expect(budget.reserved).toBe(0);
});

it("enforces streamed operation and blob limits before staging excess bytes", async () => {
  const blob = new Uint8Array([1, 2, 3, 4]);
  const descriptor = {
    blobId: replicaDigest(blob),
    sha256: replicaDigest(blob),
    sizeBytes: blob.length,
    mimeType: "application/octet-stream",
  };
  const operation = { ...upsert("limited", 2), blobs: [descriptor] };
  const envelope: ReplicaEnvelope = {
    format: "vana-pdpp-replica",
    version: 1,
    owner: identity.owner,
    batchId: "c".repeat(32),
    operations: [operation, { ...registration }],
  };
  const source = () =>
    encodeReplicaPayload(envelope, async function* () {
      yield blob;
    });
  const stage = vi.fn();
  await expect(
    inspectReplicaPayload(source, undefined, stage, {
      limits: {
        ...DEFAULT_REPLICA_STREAMED_LIMITS,
        maxOperations: 1,
      },
    }),
  ).rejects.toMatchObject({
    code: "replica_resource_limit_exceeded",
    limit: "operation_count",
  });

  const blobStage = vi.fn();
  await expect(
    inspectReplicaPayload(source, undefined, blobStage, {
      limits: {
        ...DEFAULT_REPLICA_STREAMED_LIMITS,
        maxSingleBlobBytes: 2,
      },
    }),
  ).rejects.toMatchObject({
    code: "replica_resource_limit_exceeded",
    limit: "single_blob_bytes",
  });
  expect(blobStage).toHaveBeenCalledTimes(0);
});
