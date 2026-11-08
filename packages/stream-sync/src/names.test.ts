import { describe, expect, it } from "vitest";
import { InvalidNameError } from "./errors.js";
import {
  controlScope,
  headBlobName,
  parseBlobName,
  parseScope,
  partBlobName,
  streamScope,
} from "./names.js";
import { int, pick, rng } from "./test-support/ports.js";

const ALPHABET = ["a", "z", "0", ".", "_", "-", "~", "é", "😀", "A"];

function word(random: () => number, min: number, allowTilde: boolean): string {
  let out = "";
  const len = min + int(random, 12);
  while (out.length < len) {
    const c = pick(random, ALPHABET);
    if ((c === "~" || c === ".") && !allowTilde) continue;
    out += c;
  }
  return out;
}

describe("scope names", () => {
  it("round-trips every buildable stream and control scope (property)", () => {
    const random = rng(1);
    for (let i = 0; i < 2000; i += 1) {
      const connector = word(random, 1, false);
      const ns =
        random() < 0.3
          ? ""
          : [...Array(16)]
              .map(() => pick(random, [..."0123456789abcdef"]))
              .join("");
      const stream = word(random, 1, true);
      expect(parseScope(streamScope(connector, ns, stream))).toEqual({
        kind: "stream",
        connector,
        ns,
        stream,
      });
      expect(parseScope(controlScope(connector, ns))).toEqual({
        kind: "control",
        connector,
        ns,
      });
    }
  });

  it("never parses an old raw name", () => {
    const random = rng(2);
    for (let i = 0; i < 500; i += 1) {
      const name = `pdpp.${word(random, 1, false)}.${word(random, 1, false)}`;
      expect(parseScope(name)).toBeNull();
    }
  });

  it("counts the 256-byte limit in UTF-8 bytes", () => {
    const fits = "é".repeat(124); // 248 bytes + "pdpp.c~." (8) = 256
    expect(streamScope("c", "", fits)).toBe(`pdpp.c~.${fits}`);
    expect(() => streamScope("c", "", `${fits}x`)).toThrow(InvalidNameError);
    expect(parseScope(`pdpp.c~.${fits}x`)).toBeNull();
  });

  it("builds and parses blob names", () => {
    const hash = "ab".repeat(32);
    expect(headBlobName(`0x${hash}`)).toBe(`h-${hash}`);
    expect(parseBlobName(partBlobName(7, hash))).toEqual({
      kind: "part",
      generation: 7,
      sha256: hash,
    });
    expect(() => partBlobName(0, hash)).toThrow(InvalidNameError);
    expect(() => partBlobName(1.5, hash)).toThrow(InvalidNameError);
    expect(() => headBlobName("xyz")).toThrow(InvalidNameError);
    expect(parseBlobName(`g${"9".repeat(20)}-p-${hash}`)).toBeNull();
  });
});
