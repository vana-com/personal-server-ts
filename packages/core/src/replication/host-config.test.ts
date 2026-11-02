import { describe, expect, it } from "vitest";
import type { DeclarationSnapshot } from "../pdpp/types.js";
import {
  replicaDeclarationBindings,
  replicaDeclarationContext,
  replicaEnvironmentForChain,
  replicaPartitionOwner,
} from "./host-config.js";

const hex = (c: string) => c.repeat(64);

function snapshot(
  sourceId: string,
  streams: DeclarationSnapshot["streams"],
  digest = hex("a"),
): DeclarationSnapshot {
  return {
    source_id: sourceId,
    source_kind: "connector" as DeclarationSnapshot["source_kind"],
    version: "1.0.0",
    digest,
    streams,
  };
}

const stream = (
  name: string,
  extra: Partial<DeclarationSnapshot["streams"][number]> = {},
): DeclarationSnapshot["streams"][number] => ({
  name,
  fields: ["id", "text"],
  required_fields: ["id"],
  primary_key: ["id"],
  ...extra,
});

describe("replicaEnvironmentForChain", () => {
  it("maps Vana mainnet to prod and Moksha to dev, and nothing else", () => {
    expect(replicaEnvironmentForChain(1480)).toBe("prod");
    expect(replicaEnvironmentForChain(14800)).toBe("dev");
    expect(replicaEnvironmentForChain(1)).toBeUndefined();
    expect(replicaEnvironmentForChain(31337)).toBeUndefined();
  });
});

describe("replicaPartitionOwner", () => {
  it("lowercases a checksummed address and rejects anything else", () => {
    expect(
      replicaPartitionOwner("0xAbCdEf0123456789aBcDeF0123456789AbCdEf01"),
    ).toBe("0xabcdef0123456789abcdef0123456789abcdef01");
    for (const bad of ["", "0x123", "abcdef0123456789abcdef0123456789abcdef01"])
      expect(() => replicaPartitionOwner(bad)).toThrow(TypeError);
  });
});

describe("replicaDeclarationBindings", () => {
  const schema = {
    type: "object",
    properties: { id: { type: "string" }, text: { type: "string" } },
    required: ["id"],
  };

  it("binds every stream to the document digest, version, semantics, key and schema digest", () => {
    const bindings = replicaDeclarationBindings([
      snapshot("zeta", [stream("events", { semantics: "append_only" })]),
      snapshot("alpha", [stream("messages", { schema })], hex("b")),
    ]);
    expect(bindings.map((b) => [b.sourceId, b.binding.stream])).toEqual([
      ["alpha", "messages"],
      ["zeta", "events"],
    ]);
    expect(bindings[0]!.binding).toMatchObject({
      digest: `sha256:${hex("b")}`,
      version: "1.0.0",
      semantics: "mutable_state",
      primaryKey: ["id"],
    });
    expect(bindings[1]!.binding.semantics).toBe("append_only");
    expect(bindings[0]!.binding.schemaDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("is deterministic and independent of schema key order", () => {
    const reordered = {
      required: ["id"],
      properties: { text: { type: "string" }, id: { type: "string" } },
      type: "object",
    };
    const a = replicaDeclarationBindings([
      snapshot("s", [stream("m", { schema })]),
    ]);
    const b = replicaDeclarationBindings([
      snapshot("s", [stream("m", { schema: reordered })]),
    ]);
    expect(a).toEqual(b);
  });

  it("a schema change, a schemaless stream and a new version give new bindings", () => {
    const base = replicaDeclarationBindings([
      snapshot("s", [stream("m", { schema })]),
    ])[0]!.binding;
    const changed = replicaDeclarationBindings([
      snapshot("s", [
        stream("m", { schema: { ...schema, required: ["id", "text"] } }),
      ]),
    ])[0]!.binding;
    const none = replicaDeclarationBindings([snapshot("s", [stream("m")])])[0]!
      .binding;
    expect(changed.schemaDigest).not.toBe(base.schemaDigest);
    expect(none.schemaDigest).not.toBe(base.schemaDigest);
    expect(new Set([base.digest, changed.digest, none.digest]).size).toBe(1);
  });

  it("throws for a stream that cannot be bound", () => {
    expect(() =>
      replicaDeclarationBindings([
        snapshot("s", [stream("m", { primary_key: [] })]),
      ]),
    ).toThrow();
    expect(() =>
      replicaDeclarationBindings([snapshot("s", [stream("m")], "not-hex")]),
    ).toThrow();
  });
});

describe("replicaDeclarationContext", () => {
  it("validates data with the stream's own schema, and accepts any shape without one", () => {
    const context = replicaDeclarationContext("0xowner", [
      snapshot("s", [
        stream("typed", {
          schema: {
            type: "object",
            properties: { id: { type: "string" } },
            required: ["id"],
          },
        }),
        stream("free"),
      ]),
    ]);
    expect(context.expected.owner).toBe("0xowner");
    expect(context.expected.declarations).toHaveLength(2);
    const typed = context.declarations.find(
      (d) => d.binding.stream === "typed",
    )!;
    const free = context.declarations.find((d) => d.binding.stream === "free")!;
    expect(typed.validateData({ id: "a" })).toBe(true);
    expect(typed.validateData({ id: 1 })).toBe(false);
    expect(typed.validateData({})).toBe(false);
    expect(free.validateData({ anything: 1 })).toBe(true);
  });
});
