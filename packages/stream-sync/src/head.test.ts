import { describe, expect, it } from "vitest";
import {
  buildHead,
  decodeHead,
  encodeHead,
  FORMAT_VERSION,
  parseHead,
} from "./head.js";
import { MalformedHeadError, UnsupportedFormatVersionError } from "./errors.js";
import { split } from "./parts.js";
import { nodeSha256, stamped } from "./test-support/index.js";

describe("head", () => {
  it("starts at format version 1", () => {
    expect(FORMAT_VERSION).toBe(1);
  });

  it("records version, stream, connection, ordered parts with lengths, count and base version", async () => {
    const { parts } = await split(
      stamped([{ id: 1 }, { id: 2 }], 1),
      nodeSha256,
      45,
    );
    const head = buildHead({
      stream: "s",
      connectionId: "c",
      parts,
      recordCount: 2,
      baseVersion: "4",
    });
    expect(head).toEqual({
      format: 1,
      stream: "s",
      connectionId: "c",
      parts: parts.map((p) => ({ hash: p.hash, bytes: p.bytes.length })),
      recordCount: 2,
      baseVersion: "4",
    });
    expect(decodeHead(encodeHead(head))).toEqual(head);
  });

  it("encodes to canonical bytes", () => {
    const bytes = encodeHead(
      buildHead({
        stream: "s",
        connectionId: "c",
        parts: [],
        recordCount: 0,
        baseVersion: null,
      }),
    );
    expect(new TextDecoder().decode(bytes)).toBe(
      '{"baseVersion":null,"connectionId":"c","format":1,"parts":[],"recordCount":0,"stream":"s"}',
    );
  });

  const valid = {
    format: 1,
    stream: "s",
    connectionId: "c",
    parts: [{ hash: "a".repeat(64), bytes: 10 }],
    recordCount: 1,
    baseVersion: null,
  };

  it.each([
    ["format 2", { ...valid, format: 2 }],
    ["format 1000", { ...valid, format: 1000 }],
  ])("rejects an unknown future version: %s", (_n, head) => {
    expect(() => parseHead(head)).toThrow(UnsupportedFormatVersionError);
  });

  it("reports a future version even when the rest of the head has another shape", () => {
    expect(() => parseHead({ format: 2, somethingNew: true })).toThrow(
      UnsupportedFormatVersionError,
    );
  });

  it.each([
    ["format 0", { ...valid, format: 0 }],
    ["format as string", { ...valid, format: "1" }],
    ["fractional format", { ...valid, format: 1.5 }],
    ["missing field", { ...valid, baseVersion: undefined }],
    ["extra field", { ...valid, extra: 1 }],
    ["empty stream", { ...valid, stream: "" }],
    [
      "upper-case hash",
      { ...valid, parts: [{ hash: "A".repeat(64), bytes: 1 }] },
    ],
    ["short hash", { ...valid, parts: [{ hash: "a", bytes: 1 }] }],
    [
      "negative bytes",
      { ...valid, parts: [{ hash: "a".repeat(64), bytes: -1 }] },
    ],
    [
      "part with extra field",
      { ...valid, parts: [{ hash: "a".repeat(64), bytes: 1, x: 1 }] },
    ],
    ["numeric base version", { ...valid, baseVersion: 3 }],
    ["parts for zero records", { ...valid, recordCount: 0 }],
    ["negative count", { ...valid, recordCount: -1 }],
    ["array", []],
    ["null", null],
  ])("fails closed on %s", (_n, head) => {
    expect(() => parseHead(head)).toThrow(MalformedHeadError);
  });

  it("fails closed on bytes that are not UTF-8 or not JSON", () => {
    expect(() => decodeHead(new Uint8Array([0xff, 0xfe]))).toThrow(
      MalformedHeadError,
    );
    expect(() => decodeHead("{")).toThrow(MalformedHeadError);
  });
});
