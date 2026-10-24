import { describe, expect, it } from "vitest";
import vector from "./__fixtures__/envelope-v1.json";
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
  version: 1,
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
