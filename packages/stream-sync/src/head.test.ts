import { describe, expect, it } from "vitest";
import { utf8 } from "./bytes.js";
import { InvalidArgumentError } from "./errors.js";
import {
  chooseBase,
  decodeHead,
  digestHead,
  encodeHead,
  framesCarryFirstSeen,
  HEAD_FORMAT,
  isHeadLive,
  omissionCutoff,
  verifyHead,
  writerCompatibility,
  type Head,
} from "./head.js";
import { int, keccak256, pick, rng } from "./test-support/ports.js";

const head: Head = {
  complete: true,
  connector: "c",
  format: HEAD_FORMAT,
  lastDeleteVersion: 0,
  generation: 2,
  keyCheck: "0123456789abcdef",
  ns: "fedcba9876543210",
  observedAt: 1,
  parts: [{ bytes: 10, count: 1, hash: "a".repeat(64), prefix: "" }],
  primaryKey: ["id"],
  profile: { key: null, version: "1.0.0" },
  recordCount: 1,
  replacedAt: 1,
  stream: "s",
};

function randomHead(random: () => number): Head {
  const observedAt = int(random, 2 ** 45);
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
    observedAt,
    replacedAt: int(random, 2 ** 45),
    parts,
    primaryKey: random() < 0.5 ? ["id"] : ["a", "é"],
    profile: { key: random() < 0.5 ? null : "pk ✓", version: "2.0.0-beta.1" },
    recordCount: total,
    stream: pick(random, ["s", "a.b", "é"]),
  };
}

describe("head", () => {
  it("head-format-5-emitted-and-1-to-5-accepted", () => {
    expect(HEAD_FORMAT).toBe(5);
    const encoded = encodeHead(head);
    expect(JSON.parse(new TextDecoder().decode(encoded)).format).toBe(5);

    // Build legacy wire fixtures without the writer, which emits format 5.
    const legacy = { ...head };
    delete legacy.lastDeleteVersion;
    delete legacy.replacedAt;
    for (const format of [1, 2, 3, 4, 5] as const) {
      const expected: Head = {
        ...legacy,
        format,
        ...(format >= 3 ? { lastDeleteVersion: 7 } : {}),
        ...(format >= 5 ? { replacedAt: 1 } : {}),
      };
      const wire = JSON.stringify({
        complete: expected.complete,
        connector: expected.connector,
        format,
        generation: String(expected.generation),
        keyCheck: expected.keyCheck,
        ...(format >= 3 ? { lastDeleteVersion: 7 } : {}),
        ns: expected.ns,
        observedAt: expected.observedAt,
        parts: expected.parts,
        primaryKey: expected.primaryKey,
        profile: expected.profile,
        recordCount: expected.recordCount,
        ...(format >= 5 ? { replacedAt: 1 } : {}),
        stream: expected.stream,
      });
      expect(decodeHead(utf8(wire))).toEqual({ kind: "ok", head: expected });
      // Each format round-trips byte for byte; format 3 is the frozen v1 form.
      expect(encodeHead(expected)).toEqual(utf8(wire));
    }
    expect(() => encodeHead({ ...head, format: 6 as never })).toThrow(
      InvalidArgumentError,
    );
    expect(decodeHead(utf8('{"format":6}'))).toEqual({
      kind: "unsupported_format",
      format: 6,
    });
  });

  it("replacedAt is a format 5 field: required there, refused earlier, independent of observedAt", () => {
    const { replacedAt: _drop, ...without } = head;
    expect(() => encodeHead(without)).toThrow(InvalidArgumentError);
    // Either order of the two times round-trips: a later partial run puts
    // observedAt after replacedAt, a clock that is behind puts it before.
    for (const times of [
      { observedAt: 5, replacedAt: 6 },
      { observedAt: 6, replacedAt: 5 },
    ]) {
      const h = { ...head, ...times };
      expect(decodeHead(encodeHead(h))).toEqual({ kind: "ok", head: h });
    }
    expect(() => encodeHead({ ...head, replacedAt: -1 })).toThrow(
      InvalidArgumentError,
    );
    const four = decodeHead(
      utf8(
        JSON.stringify({
          complete: true,
          connector: "c",
          format: 4,
          generation: "2",
          keyCheck: head.keyCheck,
          lastDeleteVersion: 0,
          ns: head.ns,
          observedAt: 9,
          parts: head.parts,
          primaryKey: ["id"],
          profile: head.profile,
          recordCount: 1,
          replacedAt: 9,
          stream: "s",
        }),
      ),
    );
    expect(four.kind).toBe("malformed");
  });

  it("omissionCutoff is the replacing run's time, or observedAt on an older head", () => {
    expect(
      omissionCutoff({ ...head, observedAt: 4000, replacedAt: 2000 }),
    ).toBe(2000);
    const { replacedAt: _drop, ...older } = head;
    expect(omissionCutoff({ ...older, format: 4, observedAt: 4000 })).toBe(
      4000,
    );
  });

  it("framesCarryFirstSeen(format) is true only for format 4 and more", () => {
    for (const format of [-1, 0, 1, 2, 3]) {
      expect(framesCarryFirstSeen(format)).toBe(false);
    }
    for (const format of [4, 5, 6, Number.MAX_SAFE_INTEGER]) {
      expect(framesCarryFirstSeen(format)).toBe(true);
    }
  });

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
    expect(() => encodeHead({ ...head, format: 6 as 5 })).toThrow(
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

  // A control that is not active has no generation to match, so no head is
  // live under it, including a head that records no generation (null).
  it("is not live under a deleted control, even for a head with no generation", () => {
    expect(isHeadLive({ kind: "deleted", version: 2 }, "present", null)).toBe(
      false,
    );
    expect(isHeadLive({ kind: "deleted", version: 2 }, "present", 2)).toBe(
      false,
    );
  });

  it("is not live when there is no control, even for a head with no generation", () => {
    expect(isHeadLive({ kind: "absent" }, "present", null)).toBe(false);
    expect(isHeadLive({ kind: "absent" }, "present", 1)).toBe(false);
  });

  it("is not live under an active control at a different generation", () => {
    expect(isHeadLive({ kind: "active", generation: 2 }, "present", 1)).toBe(
      false,
    );
    expect(isHeadLive({ kind: "active", generation: 2 }, "present", null)).toBe(
      false,
    );
  });

  it("chooses the base by generation, with stale_generation (F1)", () => {
    // head.generation is 2
    expect(chooseBase("present", head, 2)).toEqual({ kind: "base", head });
    expect(chooseBase("present", head, 3)).toEqual({ kind: "empty" });
    expect(chooseBase("present", head, 1)).toEqual({
      kind: "stale_generation",
    });
    expect(chooseBase("tombstoned", head, 2)).toEqual({ kind: "empty" });
    expect(chooseBase("absent", null, 1)).toEqual({ kind: "empty" });
    expect(() => chooseBase("present", null, 1)).toThrow(/verified head/);
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
