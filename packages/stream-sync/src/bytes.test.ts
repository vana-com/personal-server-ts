import { describe, expect, it } from "vitest";
import { InvalidArgumentError } from "./errors.js";
import { canonicalBytes32 } from "./bytes.js";

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
