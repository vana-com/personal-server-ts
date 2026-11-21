import { describe, expect, it } from "vitest";
import vector from "./__fixtures__/envelope-v3.json";
import { binding, identity, registration, upsert } from "./fixtures.js";
import {
  canonicalJson,
  decodeReplicaEnvelope,
  encodeReplicaEnvelope,
  replicaEnvelopeSchema,
} from "./envelope.js";

const expected = {
  owner: identity.owner,
  declarations: [{ sourceId: identity.sourceId, binding }],
};
const envelope = replicaEnvelopeSchema.parse({
  format: "vana-pdpp-replica",
  version: 3,
  owner: identity.owner,
  batchId: "batch-default",
  frontier: {},
  operations: [registration, upsert("a", 2, "hello")],
});

describe("replica wire contract", () => {
  it("roundtrips canonical observations, HLCs, account identity and declaration rules", () => {
    const encoded = encodeReplicaEnvelope(envelope, expected);
    expect(encoded).toBe(vector.encoded);
    expect(envelope).toEqual(vector.envelope);
    expect(decodeReplicaEnvelope(encoded, expected)).toEqual(envelope);
    expect(canonicalJson({ z: 1, a: { z: 2, a: [null, true, "é"] } })).toBe(
      '{"a":{"a":[null,true,"é"],"z":2},"z":1}',
    );
  });
  it("roundtrips logical counters beyond JavaScript's safe integer range exactly", () => {
    const wide = {
      ...upsert("wide-counter", 2),
      revision: {
        ...upsert("wide-counter", 2).revision,
        logical: "9007199254740993",
      },
    };
    const wideEnvelope = replicaEnvelopeSchema.parse({
      ...envelope,
      operations: [registration, wide],
    });
    const encoded = encodeReplicaEnvelope(wideEnvelope, expected);
    expect(encoded).toContain('"logical":"9007199254740993"');
    expect(
      decodeReplicaEnvelope(encoded, expected).operations[1].revision.logical,
    ).toBe("9007199254740993");
    expect(() =>
      replicaEnvelopeSchema.parse({
        ...wideEnvelope,
        operations: [
          registration,
          {
            ...wide,
            revision: {
              ...wide.revision,
              logical: "18446744073709551616",
            },
          },
        ],
      }),
    ).toThrow();
  });
  it.each([
    ["unknown version", { ...envelope, version: 2 }],
    ["altered outer owner", { ...envelope, owner: "other" }],
    [
      "altered operation owner",
      {
        ...envelope,
        operations: [{ ...envelope.operations[0], owner: "other" }],
      },
    ],
    ["unknown auth state", { ...envelope, grants: [] }],
    ["empty operations", { ...envelope, operations: [] }],
  ])("rejects %s", (_name, value) =>
    expect(() =>
      decodeReplicaEnvelope(canonicalJson(value), expected),
    ).toThrow(),
  );
  it("keeps connector principal and source-version admission in the host planner", () => {
    const renamed = {
      ...upsert("renamed", 2),
      upstreamAccount: identity.upstreamAccount,
    };
    expect(
      decodeReplicaEnvelope(
        encodeReplicaEnvelope(
          { ...envelope, operations: [registration, renamed] },
          expected,
        ),
        expected,
      ).operations,
    ).toHaveLength(2);
    expect(() =>
      decodeReplicaEnvelope(
        encodeReplicaEnvelope(
          {
            ...envelope,
            operations: [
              {
                ...registration,
                upstreamAccount: {
                  issuer: "https://github.com",
                  subject: "gh:other",
                },
              },
              renamed,
            ],
          },
          expected,
        ),
        expected,
      ),
    ).not.toThrow();
    expect(() =>
      replicaEnvelopeSchema.parse({
        ...envelope,
        operations: [
          {
            ...upsert("unbound", 2),
            sourceVersion: { domain: "d", incarnation: "1", value: "2" },
          },
        ],
      }),
    ).not.toThrow();
  });
  it("rejects noncanonical bytes and invalid HLC revisions", () => {
    expect(() =>
      decodeReplicaEnvelope(
        ` ${encodeReplicaEnvelope(envelope, expected)}`,
        expected,
      ),
    ).toThrow();
    for (const revision of [
      { wallMs: -1, logical: 0, writerId: "a", operationId: "a" },
      { wallMs: 1, logical: -1, writerId: "a", operationId: "a" },
      { wallMs: 1, logical: 0, writerId: "a", operationId: "a", counter: 1 },
    ])
      expect(() =>
        replicaEnvelopeSchema.parse({
          ...envelope,
          operations: [{ ...upsert("invalid", 2), revision }],
        }),
      ).toThrow();
  });
  it("roundtrips source and owner lifecycle operations", () => {
    const {
      data: _deleteData,
      blobs: _deleteBlobs,
      ...observation
    } = upsert("delete", 3);
    const sourceDelete = {
      ...observation,
      kind: "source-delete" as const,
      origin: "source-event" as const,
    };
    const {
      emittedAt: _emittedAt,
      contentHash: _contentHash,
      data: _data,
      blobs: _blobs,
      ...owner
    } = upsert("hide", 4);
    const hide = { ...owner, kind: "owner-hide" as const, parents: [] };
    const payload = {
      ...envelope,
      operations: [registration, sourceDelete, hide],
    };
    expect(
      decodeReplicaEnvelope(encodeReplicaEnvelope(payload, expected), expected),
    ).toEqual(payload);
  });
});

import v1Vector from "../__fixtures__/envelope-v1.json";
import {
  canonicalJson as v1CanonicalJson,
  replicaEnvelopeSchema as v1Schema,
} from "../envelope.js";
import { replicaOperationSchema } from "./envelope.js";

describe("version coexistence and immutable bytes", () => {
  it("never reinterprets a v1 envelope or rewrites its canonical bytes", () => {
    expect(v1CanonicalJson(v1Schema.parse(v1Vector.envelope))).toBe(
      v1Vector.encoded,
    );
    expect(canonicalJson(v1Vector.envelope)).toBe(v1Vector.encoded);
    expect(() => replicaEnvelopeSchema.parse(v1Vector.envelope)).toThrow();
    expect(() => v1Schema.parse(envelope)).toThrow();
  });
  it("preserves exact own payload keys and rejects sparse/non-JSON payloads", () => {
    const payload = JSON.parse(
      '{"id":"same-key","__proto__":{"retained":true},"constructor":"value"}',
    );
    const parsed = replicaOperationSchema.parse({
      ...upsert("own-keys", 1),
      data: payload,
    });
    expect(parsed.kind).toBe("upsert");
    if (parsed.kind === "upsert")
      expect(canonicalJson(parsed.data)).toBe(v1CanonicalJson(payload));
    expect(() =>
      replicaOperationSchema.parse({
        ...upsert("hole", 1),
        data: { hole: new Array(1) },
      }),
    ).toThrow();
    expect(() =>
      replicaOperationSchema.parse({
        ...upsert("undefined", 1),
        data: { value: undefined },
      }),
    ).toThrow();
  });
  it("binds one authenticated writer and rejects a self-received frontier", () => {
    expect(() =>
      decodeReplicaEnvelope(vector.encoded, {
        ...expected,
        writerId: "other-writer",
      }),
    ).toThrow("wrong operation writer");
    const wrong = {
      ...envelope,
      operations: [registration, upsert("other", 1, "x", "other-writer")],
    };
    expect(() => encodeReplicaEnvelope(wrong, expected)).toThrow(
      "wrong operation writer",
    );
    const frontier = {
      [registration.revision.writerId]: { wallMs: 1, logical: 0 },
    };
    expect(() =>
      encodeReplicaEnvelope(
        {
          ...envelope,
          frontier,
          operations: envelope.operations.map((operation) => ({
            ...operation,
            frontier,
          })),
        },
        expected,
      ),
    ).toThrow("self writer frontier");
  });
  it("retains blob claims, stream invalidation and completion dependency digests", () => {
    const blob = {
      blobId: "blob",
      sha256: `sha256:${"c".repeat(64)}`,
      mimeType: "text/plain",
      sizeBytes: 1,
    };
    const dependency = {
      writerId: "writer",
      operationId: "operation",
      digest: `sha256:${"d".repeat(64)}`,
    };
    const base = { ...identity, revision: registration.revision };
    const operations = [
      { ...base, kind: "blob-claim", blob },
      { ...base, kind: "stream-invalidate", declaration: binding },
      {
        ...base,
        kind: "stream-complete",
        declaration: binding,
        sourceCollectedAt: "2026-10-21T00:00:00.000Z",
        liveCount: 1,
        snapshotSha256: blob.sha256,
        proof: {
          kind: "native",
          snapshotSha256: blob.sha256,
          collectionTimeBasis: "host_run_finished",
        },
        dependencies: [dependency],
      },
    ].map((operation) => replicaOperationSchema.parse(operation));
    expect(
      replicaEnvelopeSchema.parse({ ...envelope, operations }).operations,
    ).toEqual(operations);
    expect(operations[2]).toHaveProperty("dependencies", [dependency]);
  });
});
