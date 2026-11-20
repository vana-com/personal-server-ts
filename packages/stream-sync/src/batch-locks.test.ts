import { describe, expect, it } from "vitest";
import { countFencedLogScopes, fencingLogScope } from "./batch-locks.js";

const stream = "pdpp.fixture~.items";
const log = "pdpp.fixture~.~log";
const tombstone = { dataHash: "dead", metadataHash: "dead" };
const row = (
  scope: string,
  hashes = { dataHash: "head", metadataHash: "meta" },
) => ({ scope, ...hashes });
const isTombstone = (r: ReturnType<typeof row>) =>
  r.dataHash === tombstone.dataHash &&
  r.metadataHash === tombstone.metadataHash;

describe("the registry's connection-log lock count", () => {
  it.each([
    [stream, log],
    [
      "pdpp.fixture~0123456789abcdef.items",
      "pdpp.fixture~0123456789abcdef.~log",
    ],
    [log, null],
    ["pdpp.fixture~", null],
    ["pdpp.fixture.items", null],
    ["pdpp.dotted.connector~.items", null],
    ["pdpp.fixture~ABCDEF0123456789.items", null],
  ])("%s fences %s", (scope, expected) => {
    expect(fencingLogScope(scope!)).toBe(expected);
  });

  it("counts distinct connections, not streams, and ignores log rows written in either order", () => {
    const streams = [
      row(stream),
      row("pdpp.fixture~.other"),
      row("pdpp.other~.items"),
    ];
    expect(countFencedLogScopes(streams, isTombstone)).toBe(2);
    expect(countFencedLogScopes([row(log), ...streams], isTombstone)).toBe(1);
    expect(countFencedLogScopes([...streams, row(log)], isTombstone)).toBe(1);
  });

  it("exempts the tombstone hash pair, but fences a delete head with different metadata", () => {
    expect(countFencedLogScopes([row(stream, tombstone)], isTombstone)).toBe(0);
    expect(
      countFencedLogScopes(
        [row(stream, { ...tombstone, metadataHash: "delete" })],
        isTombstone,
      ),
    ).toBe(1);
  });
});
