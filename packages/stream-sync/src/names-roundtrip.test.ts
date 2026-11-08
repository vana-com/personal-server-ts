import { describe, expect, it } from "vitest";
import * as names from "./names.js";
import { InvalidNameError } from "./errors.js";

describe("one stream-sync name codec", () => {
  it("round-trips generated connectors and dotted streams through logical names", () => {
    const alphabet = "azAZ09_-";
    let state = 0x13579bdf;
    const word = () => {
      let value = "";
      for (let j = 0; j < 12; j += 1) {
        state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
        value += alphabet[(state >>> 16) % alphabet.length];
      }
      return value;
    };
    for (let i = 0; i < 1000; i += 1) {
      const connector = word();
      const stream = `${word()}.${word()}.0`;
      const physical = names.parseScope(
        names.streamScope(connector, "", stream),
      );
      expect(physical?.kind).toBe("stream");
      if (physical?.kind !== "stream") throw new Error("expected stream");
      const logical = names.logicalStreamScope(
        physical.connector,
        physical.stream,
      );
      expect(names.parseLogicalStreamScope(logical)).toEqual({
        connector,
        stream,
      });
    }
  });

  it("refuses dotted connector keys in every builder", () => {
    for (const connector of ["a.b", ".a", "a.", "."]) {
      expect(() => names.streamScope(connector, "", "s")).toThrow(
        InvalidNameError,
      );
      expect(() => names.controlScope(connector, "")).toThrow(InvalidNameError);
      expect(() => names.logicalStreamScope(connector, "s")).toThrow(
        InvalidNameError,
      );
    }
  });

  it("parses a physical dotted connector as v1 vectors define it, and never maps it to a logical name", () => {
    // vectors/v1.json: pdpp.a.b~ parses as control connector "a.b".
    expect(names.parseScope("pdpp.a.b~")).toEqual({
      kind: "control",
      connector: "a.b",
      ns: "",
    });
    expect(names.parseScope("pdpp.a.b~.s")).toEqual({
      kind: "stream",
      connector: "a.b",
      ns: "",
      stream: "s",
    });
    expect(names.isPhysicalScope("pdpp.a.b~.s")).toBe(true);
    expect(names.parseLogicalStreamScope("pdpp.a.b.s")).toEqual({
      connector: "a",
      stream: "b.s",
    });
  });

  it("keeps dotted streams, namespaces and physical-only stream characters", () => {
    expect(
      names.parseLogicalStreamScope(names.logicalStreamScope("a-_09", "b.s")),
    ).toEqual({ connector: "a-_09", stream: "b.s" });
    expect(
      names.parseScope(names.streamScope("é😀", "0123456789abcdef", "b.~s")),
    ).toEqual({
      kind: "stream",
      connector: "é😀",
      ns: "0123456789abcdef",
      stream: "b.~s",
    });
    expect(names.parseLogicalStreamScope("pdpp.a.b~s")).toBeNull();
    expect(() => names.logicalStreamScope("a", "b~s")).toThrow(
      InvalidNameError,
    );
    for (const name of ["pdpp..s", "pdpp.a.", "pdpp.a", "other.a.s"]) {
      expect(names.parseLogicalStreamScope(name)).toBeNull();
    }
  });
});
