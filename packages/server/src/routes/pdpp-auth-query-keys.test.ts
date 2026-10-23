import { describe, expect, it } from "vitest";
import {
  hasMalformedNamedQuery,
  readNamedQueryValues,
} from "./pdpp-auth-query-keys.js";

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

describe("names are collected as data", () => {
  it.each([
    "hasOwnProperty",
    "valueOf",
    "emoji \u{1F600}",
    "math \u{1D4B3}",
    "line\u2028separator",
  ])("collects %s with its values in order", (name) => {
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
  });

  it("does not change Object.prototype while collecting", () => {
    const before = Object.getOwnPropertyNames(Object.prototype).sort();
    const params = new URLSearchParams();
    for (const axis of axes) params.append(`${axis}[__proto__]`, "value");
    for (const axis of axes) readNamedQueryValues(params, axis);

    expect(Object.getOwnPropertyNames(Object.prototype).sort()).toEqual(before);
    for (const axis of axes) expect(Reflect.get({}, axis)).toBeUndefined();
  });
});

describe("hasMalformedNamedQuery", () => {
  it.each(axes)("flags an invalid UTF-8 sequence in a %s key", (axis) => {
    expect(hasMalformedNamedQuery(`?${axis}[%ED%A0%80]=x`)).toBe(true);
  });

  it("flags an invalid UTF-8 sequence in a value of a named key", () => {
    expect(hasMalformedNamedQuery("?field[a]=%ED%B0%80")).toBe(true);
    expect(hasMalformedNamedQuery("?field[a]=%C0%AF")).toBe(true);
  });

  it("accepts every well-formed spelling of a name", () => {
    expect(hasMalformedNamedQuery("?field[a%EF%BF%BDb]=x")).toBe(false);
    expect(hasMalformedNamedQuery("?field[%F0%9F%98%80]=%F0%9F%98%80")).toBe(
      false,
    );
    expect(hasMalformedNamedQuery("?field%5Ba+b%5D=x&since[a%0Ab]=y")).toBe(
      false,
    );
    expect(hasMalformedNamedQuery("")).toBe(false);
  });

  it("does not mistake a key that starts with ? for a named axis", () => {
    // The second pair's key is the text `?field[a]`, which is not `field[a]`.
    expect(hasMalformedNamedQuery("?x=1&?field[a]=%ED%A0%80")).toBe(false);
    // Encoded, the same bytes spell the key `?field[a]` as well; still not an axis.
    expect(hasMalformedNamedQuery("?x=1&%3Ffield%5Ba%5D=%ED%A0%80")).toBe(
      false,
    );
    // A real axis key is still examined, whatever precedes it.
    expect(hasMalformedNamedQuery("?x=1&field[a]=%ED%A0%80")).toBe(true);
    expect(hasMalformedNamedQuery("?field%5Ba%5D=%ED%A0%80")).toBe(true);
  });

  it("ignores a malformed parameter that is not a named axis", () => {
    expect(hasMalformedNamedQuery("?other=%ED%A0%80&field[a]=x")).toBe(false);
  });
});
