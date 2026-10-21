import { expect, it } from "vitest";
import { canonicalJson, type ReplicaEnvelope } from "./envelope.js";
import { binding, identity, upsert } from "./fixtures.js";
import { replicaDigest, toBase64 } from "./transport.js";
import {
  encodeReplicaPayload,
  hashReplicaBytes,
  replicaPayloadByteLength,
} from "./stream.js";

const envelope: ReplicaEnvelope = {
  format: "vana-pdpp-replica",
  version: 1,
  owner: identity.owner,
  batchId: "batch",
  operations: [upsert("a", 2)],
};
const expected = {
  owner: identity.owner,
  declarations: [{ sourceId: identity.sourceId, binding }],
};
async function collect<T>(source: AsyncIterable<T>): Promise<T[]> {
  const result: T[] = [];
  for await (const item of source) result.push(item);
  return result;
}
async function bytes(source: AsyncIterable<Uint8Array>): Promise<Uint8Array> {
  const chunks = await collect(source);
  const result = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}
function source(value: Uint8Array, size = 7): () => AsyncIterable<Uint8Array> {
  return async function* () {
    for (let i = 0; i < value.length; i += size)
      yield value.subarray(i, i + size);
  };
}
it("encodes exact canonical Node payload bytes and incremental digest across base64 boundaries", async () => {
  const value = new Uint8Array([0, 255, 1, 2, 3, 4, 128]);
  const blob = {
    blobId: "sha256:blob",
    sha256: replicaDigest(value),
    sizeBytes: value.length,
    mimeType: "application/octet-stream",
  };
  const operation = { ...upsert("a", 2), blobs: [blob, blob] };
  const env = { ...envelope, operations: [operation] };
  const factory = () => encodeReplicaPayload(env, () => source(value, 1)());
  const result = await bytes(factory());
  expect(replicaPayloadByteLength(env)).toBe(result.length);
  expect(new TextDecoder().decode(result)).toBe(
    canonicalJson({
      envelope: env,
      blobs: [{ blobId: blob.blobId, bytes: toBase64(value) }],
    }),
  );
  expect(await hashReplicaBytes(factory)).toEqual({
    digest: replicaDigest(result),
    totalBytes: result.length,
  });
});

it("shares the fragment codec in both directions and rejects damaged or incomplete streams", async () => {
  const { fragmentReplicaStream, assembleReplicaStream } =
    await import("./stream.js");
  const {
    fragmentReplicaPayload,
    assembleReplicaPayload,
    decodeReplicaFragment,
  } = await import("./transport.js");
  const value = new TextEncoder().encode("😺".repeat(20000));
  const params = {
    owner: identity.owner,
    writer: "a".repeat(32),
    batch: "b".repeat(32),
    sequence: 1,
    previous: null,
    collectedAt: "2026-10-20T00:00:00Z",
    encrypt: async (_s: string, b: Uint8Array) => b,
    targetChunkBytes: 32768,
  };
  const summary = await hashReplicaBytes(source(value));
  const streamed = await collect(
    fragmentReplicaStream({ ...params, ...summary, bytes: source(value, 113) }),
  );
  const old = await fragmentReplicaPayload({ ...params, bytes: value });
  expect(streamed).toEqual(old);
  const fragments = old.map((p) =>
    decodeReplicaFragment(p.plaintext, p.scope, identity.owner),
  );
  const factory = (f = fragments) =>
    async function* () {
      yield* f;
    };
  expect(assembleReplicaPayload(fragments)).toEqual(value);
  expect(await bytes(assembleReplicaStream(factory()))).toEqual(value);
  for (const f of [
    fragments.slice(1),
    fragments.slice(0, -1),
    [fragments[0]!, ...fragments],
    [...fragments].reverse(),
    [{ ...fragments[0]!, offset: 1 }, ...fragments.slice(1)],
    [{ ...fragments[0]!, content: "YQ==" }, ...fragments.slice(1)],
    fragments.map((f) => ({ ...f, digest: `sha256:${"0".repeat(64)}` })),
    [{ ...fragments[0]!, owner: "wrong" }, ...fragments.slice(1)],
  ])
    await expect(bytes(assembleReplicaStream(factory(f)))).rejects.toThrow();
  await expect(
    collect(
      fragmentReplicaStream({
        ...params,
        ...summary,
        bytes: source(value),
        maxBlobBytes: 1,
      }),
    ),
  ).rejects.toThrow(RangeError);
  await expect(
    collect(
      fragmentReplicaStream({
        ...params,
        ...summary,
        totalBytes: value.length - 1,
        bytes: source(value),
      }),
    ),
  ).rejects.toThrow();
});

it("inspects canonical payloads and reads selected binary through the same bounded parser", async () => {
  const { inspectReplicaPayload, readReplicaPayloadBlob } =
    await import("./stream.js");
  const value = new Uint8Array([0, 255, 1, 2, 3, 4, 128]);
  const blob = {
    blobId: 'escaped"😺\\id',
    sha256: replicaDigest(value),
    sizeBytes: value.length,
    mimeType: "binary",
  };
  const env = {
    ...envelope,
    operations: [{ ...upsert("a", 2), blobs: [blob] }],
  };
  const encoded = new TextEncoder().encode(
    canonicalJson({
      envelope: env,
      blobs: [{ blobId: blob.blobId, bytes: toBase64(value) }],
    }),
  );
  const factory = source(encoded, 1);
  expect(await inspectReplicaPayload(factory, expected)).toEqual({
    envelope: env,
    blobs: [
      { blobId: blob.blobId, sha256: blob.sha256, sizeBytes: value.length },
    ],
  });
  expect(await bytes(readReplicaPayloadBlob(factory, blob.blobId))).toEqual(
    value,
  );
  expect(
    await inspectReplicaPayload(
      source(
        new TextEncoder().encode(canonicalJson({ envelope: env, blobs: [] })),
      ),
      expected,
    ),
  ).toEqual({ envelope: env, blobs: [] });
  for (const payload of [
    { envelope: env, blobs: [{ blobId: "extra", bytes: "AA==" }] },
    { envelope: env, blobs: [{ blobId: blob.blobId, bytes: "AB==" }] },
    { envelope: env, blobs: [{ blobId: blob.blobId, bytes: "AAAA" }] },
    {
      envelope: env,
      blobs: [
        { blobId: blob.blobId, bytes: toBase64(value) },
        { blobId: blob.blobId, bytes: toBase64(value) },
      ],
    },
  ])
    await expect(
      inspectReplicaPayload(
        source(new TextEncoder().encode(canonicalJson(payload)), 3),
        expected,
      ),
    ).rejects.toThrow();
  for (const text of [
    new TextDecoder().decode(encoded) + " ",
    new TextDecoder().decode(encoded).replace('{"blobs":', '{ "blobs":'),
    new TextDecoder().decode(encoded).replace('"bytes":"', '"bytes":"\\u0041'),
    '{"blobs":[],"envelope":' + canonicalJson(env) + ',"extra":1}',
    new TextDecoder().decode(encoded).slice(0, -1),
  ])
    await expect(
      inspectReplicaPayload(
        source(new TextEncoder().encode(text), 5),
        expected,
      ),
    ).rejects.toThrow();
  await expect(
    inspectReplicaPayload(factory, { ...expected, owner: "wrong" }),
  ).rejects.toThrow();
});

it("bounds frames on a multi-MiB streaming blob through encode, fragment, assemble, inspect and second-pass read", async () => {
  const {
    fragmentReplicaStream,
    assembleReplicaStream,
    inspectReplicaPayload,
    readReplicaPayloadBlob,
  } = await import("./stream.js");
  const { decodeReplicaFragment } = await import("./transport.js");
  const raw = async function* () {
    for (let i = 0; i < 193; i++) {
      const chunk = new Uint8Array(16387);
      chunk.fill(i);
      yield chunk;
    }
  };
  const summary = await hashReplicaBytes(raw);
  const descriptor = {
    blobId: summary.digest,
    sha256: summary.digest,
    sizeBytes: summary.totalBytes,
    mimeType: "binary",
  };
  const env = {
    ...envelope,
    operations: [{ ...upsert("big", 3), blobs: [descriptor] }],
  };
  let encodedMax = 0;
  let encryptedMax = 0;
  let fragmentCount = 0;
  const payload = async function* () {
    for await (const frame of encodeReplicaPayload(env, () => raw())) {
      encodedMax = Math.max(encodedMax, frame.length);
      yield frame;
    }
  };
  const payloadSummary = await hashReplicaBytes(payload);
  const fragmentFactory = async function* () {
    for await (const part of fragmentReplicaStream({
      owner: identity.owner,
      writer: "a".repeat(32),
      batch: "b".repeat(32),
      sequence: 1,
      previous: null,
      collectedAt: "2026-10-20T00:00:00Z",
      ...payloadSummary,
      bytes: payload,
      encrypt: async (_scope, plaintext) =>
        new Uint8Array(plaintext.length + 100),
    })) {
      fragmentCount++;
      encryptedMax = Math.max(encryptedMax, part.encrypted.length);
      yield decodeReplicaFragment(part.plaintext, part.scope, identity.owner);
    }
  };
  const reassembled = () => assembleReplicaStream(fragmentFactory);
  expect(await inspectReplicaPayload(reassembled, expected)).toEqual({
    envelope: env,
    blobs: [
      {
        blobId: descriptor.blobId,
        sha256: summary.digest,
        sizeBytes: summary.totalBytes,
      },
    ],
  });
  let binaryMax = 0;
  const selected = async function* () {
    for await (const frame of readReplicaPayloadBlob(
      payload,
      descriptor.blobId,
    )) {
      binaryMax = Math.max(binaryMax, frame.length);
      yield frame;
    }
  };
  expect(await hashReplicaBytes(selected)).toEqual(summary);
  expect(fragmentCount).toBeGreaterThan(100);
  expect(encodedMax).toBeLessThanOrEqual(128 * 1024);
  expect(encryptedMax).toBeLessThanOrEqual(128 * 1024);
  expect(binaryMax).toBeLessThanOrEqual(64 * 1024);
}, 30000);

it("refuses oversized envelope, blob identifiers and metadata tables", async () => {
  const { inspectReplicaPayload } = await import("./stream.js");
  const large = {
    ...envelope,
    operations: [
      { ...upsert("big", 3), data: { text: "a".repeat(192 * 1024) } },
    ],
  };
  await expect(
    bytes(encodeReplicaPayload(large, () => source(new Uint8Array())())),
  ).rejects.toThrow(RangeError);
  await expect(
    inspectReplicaPayload(
      source(
        new TextEncoder().encode(canonicalJson({ envelope: large, blobs: [] })),
      ),
      expected,
    ),
  ).rejects.toThrow(RangeError);
  const empty = replicaDigest(new Uint8Array());
  const blob = {
    blobId: "a".repeat(257),
    sha256: empty,
    sizeBytes: 0,
    mimeType: "binary",
  };
  const env = {
    ...envelope,
    operations: [{ ...upsert("id", 2), blobs: [blob] }],
  };
  await expect(
    bytes(encodeReplicaPayload(env, () => source(new Uint8Array())())),
  ).rejects.toThrow();
  await expect(
    inspectReplicaPayload(
      source(
        new TextEncoder().encode(
          canonicalJson({
            envelope: env,
            blobs: [{ blobId: blob.blobId, bytes: "" }],
          }),
        ),
      ),
      expected,
    ),
  ).rejects.toThrow();
  const many = {
    ...envelope,
    operations: [
      {
        ...upsert("many", 2),
        blobs: Array.from({ length: 1001 }, (_, index) => ({
          ...blob,
          blobId: String(index),
        })),
      },
    ],
  };
  const iterator = encodeReplicaPayload(many, () => source(new Uint8Array())())[
    Symbol.asyncIterator
  ]();
  await expect(iterator.next()).rejects.toThrow(RangeError);
  const text = canonicalJson({
    blobs: Array.from({ length: 1001 }, (_, i) => ({
      blobId: String(i),
      bytes: "",
    })),
    envelope,
  });
  await expect(
    inspectReplicaPayload(
      source(new TextEncoder().encode(text), 32768),
      expected,
    ),
  ).rejects.toThrow(RangeError);
});

it("accepts the exact envelope limit and rejects noncanonical JSON, invalid UTF-8 and untrusted declarations", async () => {
  const { inspectReplicaPayload, readReplicaPayloadBlob } =
    await import("./stream.js");
  const base = {
    ...envelope,
    operations: [{ ...upsert("limit", 3), data: { text: "" } }],
  };
  const remaining =
    192 * 1024 - new TextEncoder().encode(canonicalJson(base)).length;
  const exact = {
    ...base,
    operations: [
      { ...base.operations[0]!, data: { text: "x".repeat(remaining) } },
    ],
  };
  const frames = await collect(
    encodeReplicaPayload(exact, () => source(new Uint8Array())()),
  );
  expect(frames.every((frame) => frame.length <= 128 * 1024)).toBe(true);
  const factory = async function* () {
    yield* frames;
  };
  expect((await inspectReplicaPayload(factory, expected)).envelope).toEqual(
    exact,
  );
  await expect(
    inspectReplicaPayload(factory, { ...expected, declarations: [] }),
  ).rejects.toThrow();
  await expect(
    bytes(readReplicaPayloadBlob(factory, "missing")),
  ).rejects.toThrow();
  const env = {
    ...envelope,
    operations: [
      {
        ...upsert("empty", 2),
        blobs: [
          {
            blobId: "a",
            sha256: replicaDigest(new Uint8Array()),
            sizeBytes: 0,
            mimeType: "binary",
          },
        ],
      },
    ],
  };
  const text = canonicalJson({
    envelope: env,
    blobs: [{ blobId: "a", bytes: "" }],
  });
  expect(
    await bytes(
      readReplicaPayloadBlob(source(new TextEncoder().encode(text), 1), "a"),
    ),
  ).toEqual(new Uint8Array());
  for (const invalid of [
    text.replace('"blobId":"a"', '"blobId":"\\u0061"'),
    text.replace('"bytes":""', '"bytes":"AA==AA=="'),
    text.replace('"bytes":""', '"bytes":"AA== "'),
    text.replace('"blobId":"a","bytes":""', '"bytes":"","blobId":"a"'),
    text.replace('"batchId":"batch"', '"batchId":"batch","batchId":"batch"'),
    "\ufeff" + text,
  ])
    await expect(
      inspectReplicaPayload(
        source(new TextEncoder().encode(invalid), 1),
        expected,
      ),
    ).rejects.toThrow();
  await expect(
    inspectReplicaPayload(source(new Uint8Array([123, 34, 0xff])), expected),
  ).rejects.toThrow();
});

it("verifies bytes before completing export and preserves first appearance across claim/upsert descriptors", async () => {
  const { inspectReplicaPayload } = await import("./stream.js");
  const a = new Uint8Array([1, 2]);
  const b = new Uint8Array([3, 4, 5]);
  const descriptor = (blobId: string, value: Uint8Array) => ({
    blobId,
    sha256: replicaDigest(value),
    sizeBytes: value.length,
    mimeType: "binary",
  });
  const first = descriptor("first", a);
  const second = descriptor("second", b);
  const env = {
    ...envelope,
    operations: [
      { ...upsert("first", 2), blobs: [first, second] },
      {
        ...identity,
        kind: "blob-claim" as const,
        revision: { counter: 3, writerId: "device-a", operationId: "claim" },
        blob: first,
      },
    ],
  };
  const read = (id: string) => source(id === "first" ? a : b, 1)();
  expect(
    new TextDecoder().decode(await bytes(encodeReplicaPayload(env, read))),
  ).toBe(
    canonicalJson({
      envelope: env,
      blobs: [
        { blobId: "first", bytes: toBase64(a) },
        { blobId: "second", bytes: toBase64(b) },
      ],
    }),
  );
  await expect(
    bytes(encodeReplicaPayload(env, () => source(new Uint8Array([9]))())),
  ).rejects.toThrow();
  const payload = canonicalJson({
    envelope: env,
    blobs: [{ blobId: "first", bytes: toBase64(a) }],
  });
  expect(
    (
      await inspectReplicaPayload(
        source(new TextEncoder().encode(payload)),
        expected,
      )
    ).blobs,
  ).toHaveLength(1);
});

it("yields one fragment at a time and checks the actual encrypted size without changing offsets", async () => {
  const { fragmentReplicaStream } = await import("./stream.js");
  const { decodeReplicaFragment } = await import("./transport.js");
  const value = new Uint8Array(65537);
  value.fill(7);
  let reads = 0;
  const factory = async function* () {
    for (let offset = 0; offset < value.length; offset += 32768) {
      reads++;
      yield value.subarray(offset, offset + 32768);
    }
  };
  const params = {
    owner: identity.owner,
    writer: "a".repeat(32),
    batch: "b".repeat(32),
    sequence: 1,
    previous: null,
    collectedAt: "2026-10-20T00:00:00Z",
    digest: replicaDigest(value),
    totalBytes: value.length,
    bytes: factory,
    encrypt: async (_scope: string, plaintext: Uint8Array) =>
      new Uint8Array(plaintext.length + 17),
  };
  const iterator = fragmentReplicaStream(params)[Symbol.asyncIterator]();
  const first = await iterator.next();
  expect(reads).toBe(1);
  expect(first.done).toBe(false);
  const one = decodeReplicaFragment(
    first.value!.plaintext,
    first.value!.scope,
    identity.owner,
  );
  expect({ index: one.index, offset: one.offset, count: one.count }).toEqual({
    index: 0,
    offset: 0,
    count: 3,
  });
  await iterator.return?.();
  expect(reads).toBe(1);
  await expect(
    collect(
      fragmentReplicaStream({
        ...params,
        encrypt: async () => new Uint8Array(128 * 1024 + 1),
      }),
    ),
  ).rejects.toThrow(RangeError);
  await expect(
    collect(
      fragmentReplicaStream({ ...params, digest: `sha256:${"0".repeat(64)}` }),
    ),
  ).rejects.toThrow();
});
