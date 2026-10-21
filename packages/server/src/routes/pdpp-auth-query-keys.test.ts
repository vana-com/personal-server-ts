import { describe, expect, it } from "vitest";
import { readNamedQueryValues } from "./pdpp-auth-query-keys.js";

const axes = [
  "approve",
  "decline",
  "field",
  "instance",
  "since",
  "until",
] as const;

describe("PDPP consent bracket query keys", () => {
  it.each(["\n", "\r", "\u2028", "\u2029"])(
    "preserves a name containing %s",
    (lineBreak) => {
      const name = `before${lineBreak}after`;
      const params = new URLSearchParams();
      for (const axis of axes) params.append(`${axis}[${name}]`, "value");

      for (const axis of axes) {
        expect(readNamedQueryValues(params, axis)).toEqual(
          new Map([[name, ["value"]]]),
        );
      }
    },
  );

  it.each(["__proto__", "constructor", "toString"])(
    "collects %s as an ordinary name",
    (name) => {
      const params = new URLSearchParams();
      for (const axis of axes) {
        params.append(`${axis}[${name}]`, "first");
        params.append(`${axis}[${name}]`, "second");
      }

      for (const axis of axes) {
        expect(readNamedQueryValues(params, axis)).toEqual(
          new Map([[name, ["first", "second"]]]),
        );
      }
    },
  );

  it.each(["a]b", "a[b]", "x][y"])(
    "uses the final closing bracket for the name %s",
    (name) => {
      const params = new URLSearchParams();
      params.append(`field[${name}]`, "value");

      expect(readNamedQueryValues(params, "field")).toEqual(
        new Map([[name, ["value"]]]),
      );
    },
  );

  it("rejects an empty bracket name like Account's reader", () => {
    const params = new URLSearchParams();
    params.append("field[]", "value");

    expect(readNamedQueryValues(params, "field")).toEqual(new Map());
  });
});
