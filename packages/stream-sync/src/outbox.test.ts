import { describe, expect, it } from "vitest";
import { InvalidArgumentError } from "./errors.js";
import { createOutboxEntry, streamRunResult } from "./outbox.js";

const base = {
  runId: "run-1",
  connector: "c",
  start: { "0123456789abcdef": { kind: "active", generation: 2 } } as const,
  userConnect: false,
  full: false,
  observedAt: 1700000000000,
  spoolRef: "spool/run-1",
  checkpointCandidate: { cursor: "x" },
  needsFull: [],
};

describe("outbox entry", () => {
  it("is plain JSON and copies the start snapshot", () => {
    const entry = createOutboxEntry(base);
    expect(JSON.parse(JSON.stringify(entry))).toEqual(entry);
    expect(entry.start).not.toBe(base.start);
    expect(entry.ns).toBeNull();
  });

  it("refuses an incremental run while the connector needs a full run", () => {
    const needsFull = [{ connector: "c", ns: "", stream: "s" }];
    expect(() => createOutboxEntry({ ...base, needsFull })).toThrow(
      InvalidArgumentError,
    );
    expect(createOutboxEntry({ ...base, full: true, needsFull }).full).toBe(
      true,
    );
    expect(
      createOutboxEntry({ ...base, connector: "other", needsFull }).full,
    ).toBe(false);
  });

  it("maps stream states to checkpoint inputs", () => {
    expect(
      streamRunResult({ state: "committed", generation: 2, complete: true }),
    ).toEqual({
      state: "committed",
      generation: 2,
      complete: true,
    });
    expect(streamRunResult({ state: "request_persisted" })).toEqual({
      state: "pending",
    });
    expect(
      streamRunResult({ state: "planned", problem: "key_mismatch" }),
    ).toEqual({ state: "pending" });
    expect(streamRunResult({ state: "discarded" })).toEqual({
      state: "discarded",
    });
    expect(() => streamRunResult({ state: "noop" })).toThrow(
      InvalidArgumentError,
    );
  });
});
