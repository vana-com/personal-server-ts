import { describe, expect, it } from "vitest";
import { InvalidArgumentError } from "./errors.js";
import {
  canonicalBytes32,
  keccakHex,
  sha256Hex,
  toHex,
  utf8,
  utf8Length,
} from "./bytes.js";
import {
  canonicalJson,
  canonicalJsonChunks,
  JSON_CHUNK_UNITS,
} from "./json.js";

const digits = "0123456789abcdefABCDEF".repeat(3).slice(0, 64);
const lower = `0x${digits.toLowerCase()}`;

describe("canonicalBytes32", () => {
  it.each([
    lower,
    `0x${digits.toUpperCase()}`,
    `0X${digits}`,
    `0X${digits.toUpperCase()}`,
    digits,
    digits.toUpperCase(),
  ])("returns lowercase 0x for %s", (input) => {
    expect(canonicalBytes32(input)).toBe(lower);
  });
  it.each([
    "",
    "0x",
    "wrong",
    `0x${digits.slice(1)}`,
    `0x${digits}0`,
    `0x${"g".repeat(64)}`,
    ` ${lower}`,
    `${lower}\n`,
    `0x0x${digits}`,
  ])("rejects %j", (input) => {
    expect(() => canonicalBytes32(input)).toThrow(InvalidArgumentError);
  });
});

describe("utf8", () => {
  it("preserves byte-order mark, combining form and an embedded NUL", () => {
    expect(Array.from(utf8("\uFEFFe\u0301\u0000"))).toEqual([
      0xef, 0xbb, 0xbf, 0x65, 0xcc, 0x81, 0,
    ]);
  });

  it("replaces unpaired UTF-16 units without losing the adjacent pair or text", () => {
    const sample = "\uD800\uD83D\uDC1F\uDC00X";
    expect(Array.from(utf8(sample))).toEqual([
      0xef, 0xbf, 0xbd, 0xf0, 0x9f, 0x90, 0x9f, 0xef, 0xbf, 0xbd, 0x58,
    ]);
    expect(utf8Length(sample)).toBe(11);
  });
});

describe("utf8Length", () => {
  it("counts the bytes the encoder would write", () => {
    const samples = [
      "",
      "plain ascii",
      "café ünïcödé",
      "emoji 🐟 and 𝄞 surrogate pairs",
      "lone \uD800 surrogate",
      "x".repeat(70_000),
    ];
    for (const text of samples) {
      expect(utf8Length(text)).toBe(utf8(text).length);
    }
  });

  it("counts exactly at the one-, two-, three-, and four-byte boundaries", () => {
    const cases = [
      [0x7f, 1],
      [0x80, 2],
      [0x7ff, 2],
      [0x800, 3],
      [0xffff, 3],
      [0x10000, 4],
      [0x10ffff, 4],
    ] as const;
    for (const [point, width] of cases) {
      expect(utf8Length(String.fromCodePoint(point))).toBe(width);
    }
    expect(
      utf8Length(String.fromCodePoint(...cases.map(([point]) => point))),
    ).toBe(19);
  });
});

describe("toHex", () => {
  it("writes lowercase two-digit pairs for every byte", () => {
    const bytes = Uint8Array.from({ length: 256 }, (_, i) => i);
    expect(toHex(bytes)).toBe(Buffer.from(bytes).toString("hex"));
    expect(toHex(new Uint8Array())).toBe("");
  });

  it("formats only a subview, leaving its neighboring bytes unchanged", () => {
    const backing = Uint8Array.of(0xf1, 0, 0xab, 0xff, 0xf2);
    expect(toHex(backing.subarray(1, 4))).toBe("00abff");
    expect(toHex(backing.subarray(2, 2))).toBe("");
    expect(Array.from(backing)).toEqual([0xf1, 0, 0xab, 0xff, 0xf2]);
  });
});

describe("hash port output formatting", () => {
  it("forwards a sliced byte view to SHA-256 and emits lowercase text without a prefix", async () => {
    const bytes = Uint8Array.of(99, 1, 2, 88).subarray(1, 3);
    const result = await sha256Hex(async (seen) => {
      expect(seen).toBe(bytes);
      return Uint8Array.from({ length: 32 }, () => 0xab);
    }, bytes);

    expect(result).toBe("ab".repeat(32));
  });

  it("formats only the returned Keccak digest view as a prefixed registry hash", async () => {
    const backing = Uint8Array.of(
      0xfe,
      0,
      ...Uint8Array.from({ length: 31 }, () => 0xcd),
      0xff,
    );
    const result = await keccakHex(async (seen) => {
      expect(seen).toEqual(new Uint8Array());
      return backing.subarray(1, 33);
    }, new Uint8Array());

    expect(result).toBe("0x00" + "cd".repeat(31));
  });

  it("preserves the exact rejection from the SHA-256 callback", async () => {
    const failure = new Error("synthetic digest unavailable");
    await expect(
      sha256Hex(() => Promise.reject(failure), new Uint8Array()),
    ).rejects.toBe(failure);
  });

  it("allows a fresh Keccak callback attempt after a rejected one", async () => {
    let attempts = 0;
    const failure = new Error("synthetic retry");
    const adapter = async () => {
      if (++attempts === 1) throw failure;
      return new Uint8Array(32);
    };
    const bytes = Uint8Array.of(42);

    await expect(keccakHex(adapter, bytes)).rejects.toBe(failure);
    await expect(keccakHex(adapter, bytes)).resolves.toBe(
      `0x${"00".repeat(32)}`,
    );
    expect(attempts).toBe(2);
  });
});

describe("encoding JSON as bytes", () => {
  it("refuses a Date object rather than silently encoding it as text", () => {
    const value = "2026-06-01T00:00:00.000Z";
    expect(() => utf8(canonicalJson({ label: new Date(value) }))).toThrow(
      expect.objectContaining({
        code: "non-canonical-value",
        message: "only plain objects are allowed",
      }),
    );
    expect(
      new TextDecoder().decode(utf8(canonicalJson({ label: value }))),
    ).toBe('{"label":"2026-06-01T00:00:00.000Z"}');
  });

  it("terminates a partial text iterator when a later value cannot be serialized", () => {
    const chunks = canonicalJsonChunks([
      "a".repeat(JSON_CHUNK_UNITS),
      undefined,
    ]);
    const first = chunks.next();
    if (first.done) throw new Error("expected an initial text chunk");
    expect(first.value.startsWith('["a')).toBe(true);
    expect(() => chunks.next()).toThrow(
      expect.objectContaining({
        code: "non-canonical-value",
        message: "unsupported value of type undefined",
      }),
    );
    expect(chunks.next().done).toBe(true);
  });
});
