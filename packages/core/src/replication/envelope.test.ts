import { describe, expect, it } from "vitest";
import vector from "./__fixtures__/envelope-v1.json";
import {
  binding,
  identity,
  mutableVectors,
  registration,
  upsert,
} from "./fixtures.js";
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
describe("profile v1 golden wire vectors", () => {
  it("encodes exact pinned bytes and decodes the independently pinned JSON", () => {
    const envelope = replicaEnvelopeSchema.parse(vector.envelope);
    expect(encodeReplicaEnvelope(envelope, expected)).toBe(vector.encoded);
    expect(decodeReplicaEnvelope(vector.encoded, expected)).toEqual(
      vector.envelope,
    );
    expect(canonicalJson({ z: 1, a: { z: 2, a: [null, true, "é"] } })).toBe(
      '{"a":{"a":[null,true,"é"],"z":2},"z":1}',
    );
  });
  it.each([
    ["unknown version", { ...vector.envelope, version: 2 }],
    ["altered outer owner", { ...vector.envelope, owner: "other" }],
    [
      "altered operation owner",
      {
        ...vector.envelope,
        operations: [{ ...vector.envelope.operations[0], owner: "other" }],
      },
    ],
    ["unknown auth state", { ...vector.envelope, grants: [] }],
    ["empty operations", { ...vector.envelope, operations: [] }],
  ])("rejects %s", (_name, value) => {
    expect(() =>
      decodeReplicaEnvelope(canonicalJson(value), expected),
    ).toThrow();
  });
  it.each([
    "digest",
    "version",
    "stream",
    "semantics",
    "primaryKey",
    "schemaDigest",
  ])("rejects changed declaration %s", (field) => {
    const changed = {
      ...binding,
      [field]:
        field === "primaryKey"
          ? ["other"]
          : field === "semantics"
            ? "append_only"
            : field === "digest" || field === "schemaDigest"
              ? `sha256:${"c".repeat(64)}`
              : "other",
    };
    const operation = { ...upsert("altered", 2), declaration: changed };
    expect(() =>
      decodeReplicaEnvelope(
        canonicalJson({ ...vector.envelope, operations: [operation] }),
        expected,
      ),
    ).toThrow("binding");
  });
  it("rejects producer substitution even when declaration content matches", () => {
    expect(() =>
      decodeReplicaEnvelope(
        canonicalJson({
          ...vector.envelope,
          operations: [{ ...upsert("wrong-source", 2), sourceId: "other" }],
        }),
        expected,
      ),
    ).toThrow("binding");
  });
  it.each([0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1])(
    "rejects invalid persisted counter %s",
    (counter) => {
      const operation = {
        ...upsert("a", 2),
        revision: { counter, writerId: "a", operationId: "a" },
      };
      expect(() =>
        decodeReplicaEnvelope(
          canonicalJson({ ...vector.envelope, operations: [operation] }),
          expected,
        ),
      ).toThrow();
    },
  );
  it("roundtrips tombstones, lifecycle and referenced byte descriptors", () => {
    const blob = {
      blobId: "blob-a",
      sha256: `sha256:${"c".repeat(64)}`,
      mimeType: "text/plain",
      sizeBytes: 5,
    };
    const envelope = replicaEnvelopeSchema.parse({
      ...vector.envelope,
      operations: [
        registration,
        { ...upsert("blob", 2), blobs: [blob] },
        mutableVectors[2],
        {
          ...identity,
          kind: "connection-reset",
          generation: 2,
          previousGeneration: 1,
          revision: { counter: 4, writerId: "a", operationId: "reset" },
        },
        {
          ...identity,
          kind: "connection-delete",
          revision: { counter: 5, writerId: "a", operationId: "delete" },
        },
      ],
    });
    expect(
      decodeReplicaEnvelope(
        encodeReplicaEnvelope(envelope, expected),
        expected,
      ),
    ).toEqual(envelope);
    expect(() =>
      encodeReplicaEnvelope({ ...envelope, version: 2 } as never, expected),
    ).toThrow();
  });
  it("preserves top-level and nested own __proto__ keys when decoding peer JSON", () => {
    const encoded = vector.encoded.replace(
      '"data":{"id":"same-key","text":"hello"}',
      '"data":{"__proto__":{"nested":{"__proto__":{"value":2}}},"id":"same-key","text":"hello"}',
    );

    const decoded = decodeReplicaEnvelope(encoded, expected);
    const operation = decoded.operations.find((item) => item.kind === "upsert");
    expect(operation?.kind).toBe("upsert");
    if (operation?.kind !== "upsert") throw new Error("missing upsert");
    expect(Object.hasOwn(operation.data, "__proto__")).toBe(true);
    expect(Object.hasOwn(operation.data["__proto__"], "nested")).toBe(true);
    expect(Object.hasOwn(operation.data["__proto__"].nested, "__proto__")).toBe(
      true,
    );
    expect(operation.data["__proto__"].nested["__proto__"]).toEqual({
      value: 2,
    });
  });
  it("rejects malformed JSON and non-JSON data rather than silently coercing bytes", () => {
    expect(() => decodeReplicaEnvelope("{", expected)).toThrow();
    for (const data of [{ id: undefined }, { id: NaN }, { id: BigInt(1) }]) {
      expect(() =>
        encodeReplicaEnvelope(
          {
            ...vector.envelope,
            operations: [{ ...upsert("a", 2), data }],
          } as never,
          expected,
        ),
      ).toThrow();
    }
  });
});

it("rejects duplicate-member wire ambiguity even when the last version is supported", () => {
  expect(() =>
    decodeReplicaEnvelope(
      vector.encoded.replace('"version":1}', '"version":2,"version":1}'),
      expected,
    ),
  ).toThrow();
});
