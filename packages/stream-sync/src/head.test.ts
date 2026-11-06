import { describe, expect, it } from "vitest";
import { utf8 } from "./bytes.js";
import { InvalidArgumentError } from "./errors.js";
import {
  chooseBase,
  decodeHead,
  digestHead,
  encodeHead,
  isHeadLive,
  verifyHead,
  writerCompatibility,
  type Head,
} from "./head.js";
import { int, keccak256, pick, rng } from "./test-support/ports.js";

const head: Head = {
  complete: true,
  connector: "c",
  format: 1,
  generation: 2,
  keyCheck: "0123456789abcdef",
  ns: "fedcba9876543210",
  observedAt: 1,
  parts: [{ bytes: 10, count: 1, hash: "a".repeat(64), prefix: "" }],
  primaryKey: ["id"],
  profile: { key: null, version: "1.0.0" },
  recordCount: 1,
  stream: "s",
};

function randomHead(random: () => number): Head {
  const parts = [];
  const depth = int(random, 5);
  let total = 0;
  for (let b = 0; b < 2 ** depth; b += 1) {
    if (random() < 0.3) continue;
    const count = 1 + int(random, 1000);
    total += count;
    parts.push({
      bytes: 1 + int(random, 1 << 20),
      count,
      hash: [...Array(64)]
        .map(() => pick(random, [..."0123456789abcdef"]))
        .join(""),
      prefix: depth === 0 ? "" : b.toString(2).padStart(depth, "0"),
    });
  }
  return {
    ...head,
    complete: random() < 0.5,
    generation: 1 + int(random, 1e9),
    ns: random() < 0.3 ? "" : head.ns,
    observedAt: int(random, 2 ** 45),
    parts,
    primaryKey: random() < 0.5 ? ["id"] : ["a", "é"],
    profile: { key: random() < 0.5 ? null : "pk ✓", version: "2.0.0-beta.1" },
    recordCount: total,
    stream: pick(random, ["s", "a.b", "é"]),
  };
}

describe("head", () => {
  it("round-trips canonical bytes (property)", () => {
    const random = rng(21);
    for (let i = 0; i < 300; i += 1) {
      const h = randomHead(random);
      const bytes = encodeHead(h);
      const decoded = decodeHead(bytes);
      expect(decoded).toEqual({ kind: "ok", head: h });
      if (decoded.kind === "ok")
        expect(encodeHead(decoded.head)).toEqual(bytes);
    }
  });

  it("verifies hash, names and key check", async () => {
    const bytes = encodeHead(head);
    const { dataHash, blobName } = await digestHead(keccak256, bytes);
    expect(blobName).toBe(`h-${dataHash.slice(2)}`);
    const expected = {
      dataHash,
      connector: "c",
      ns: head.ns,
      stream: "s",
      keyCheck: head.keyCheck,
    };
    expect((await verifyHead(keccak256, bytes, expected)).kind).toBe("ok");
    expect(
      (
        await verifyHead(keccak256, bytes, {
          ...expected,
          dataHash: dataHash.toUpperCase().replace("0X", "0x"),
        })
      ).kind,
    ).toBe("ok");
    expect(
      (
        await verifyHead(keccak256, bytes, {
          ...expected,
          keyCheck: "f".repeat(16),
        })
      ).kind,
    ).toBe("key_mismatch");
    const tampered = bytes.slice();
    tampered[3] = tampered[3]! ^ 1;
    expect((await verifyHead(keccak256, tampered, expected)).kind).toBe(
      "hash_mismatch",
    );
  });

  it("refuses to write a head readers would reject", () => {
    expect(() => encodeHead({ ...head, generation: 0 })).toThrow(
      InvalidArgumentError,
    );
    expect(() => encodeHead({ ...head, recordCount: 2 })).toThrow(
      InvalidArgumentError,
    );
    expect(() => encodeHead({ ...head, format: 2 as 1 })).toThrow(
      InvalidArgumentError,
    );
  });

  it("rejects a head over 1 MiB", () => {
    const big = utf8(`{"format":1,"x":"${"a".repeat(1024 * 1024)}"}`);
    expect(decodeHead(big).kind).toBe("malformed");
  });

  it("is live only at the control generation", () => {
    expect(isHeadLive({ kind: "active", generation: 2 }, "present", 2)).toBe(
      true,
    );
    expect(isHeadLive({ kind: "active", generation: 3 }, "present", 2)).toBe(
      false,
    );
  });

  it("chooses an empty base for another generation", () => {
    expect(chooseBase("present", head, 2)).toBe(head);
    expect(chooseBase("present", head, 3)).toBeNull();
    expect(chooseBase("tombstoned", head, 2)).toBeNull();
  });

  it("applies the compatible-writer rule", () => {
    expect(writerCompatibility(head, ["id", "t"], "higher")).toEqual({
      kind: "empty_base",
    });
    expect(writerCompatibility(head, ["id", "t"], "lower")).toEqual({
      kind: "connector_update_required",
    });
  });
});
