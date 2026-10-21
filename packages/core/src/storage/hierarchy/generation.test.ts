import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { envelopeGeneration } from "./generation.js";

describe("envelopeGeneration", () => {
  const envelope = {
    version: "1.0",
    scope: "a.b",
    collectedAt: "2026-01-01T00:00:00Z",
    data: { b: 1, a: [1, { d: 2, c: 3 }] },
  };

  it("is the SHA-256 of the envelope with object keys sorted", () => {
    const sorted =
      '{"collectedAt":"2026-01-01T00:00:00Z","data":{"a":[1,{"c":3,"d":2}],"b":1},"scope":"a.b","version":"1.0"}';
    expect(envelopeGeneration(envelope)).toBe(
      "88e42af4d4aaeb54ecc5df5fea552ccb4f543c354659b1413d98438a9c12ea04",
    );
    expect(envelopeGeneration(envelope)).toBe(
      createHash("sha256").update(sorted).digest("hex"),
    );
  });

  it("does not depend on key order, and changes with any value", () => {
    expect(
      envelopeGeneration({
        data: { a: [1, { c: 3, d: 2 }], b: 1 },
        collectedAt: "2026-01-01T00:00:00Z",
        scope: "a.b",
        version: "1.0",
      }),
    ).toBe(envelopeGeneration(envelope));
    expect(
      envelopeGeneration({ ...envelope, data: { ...envelope.data, b: 2 } }),
    ).not.toBe(envelopeGeneration(envelope));
  });
});
