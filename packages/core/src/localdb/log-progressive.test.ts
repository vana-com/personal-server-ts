import { describe, expect, it } from "vitest";
import type {
  LogOmitted,
  LogOperation,
  LogStreamMeta,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { heldKeys, planLogLoad, type PlannedBatch } from "./log-progressive.js";

const meta = (stream: string, complete = true): LogStreamMeta => ({
  stream,
  primaryKey: ["id"],
  profile: { key: null, version: "1" },
  complete,
});
const stamp = { o: 1, r: "a" };
const upsert = (stream: string, pkHash: string): LogOperation => ({
  kind: "upsert",
  stream,
  pkHash,
  stamp,
  firstSeen: 1,
  value: { id: pkHash },
});
const remove = (stream: string, pkHash: string): LogOperation => ({
  kind: "delete",
  stream,
  pkHash,
  key: [pkHash],
  stamp,
});
const omit = (stream: string, pkHash: string): LogOmitted => ({
  kind: "omitted",
  stream,
  pkHash,
  key: [pkHash],
  stamp,
});
const batch = (
  streams: LogStreamMeta[],
  operations: (LogOperation | LogOmitted)[] = [],
): PlannedBatch => ({ streams, operations });

describe("planLogLoad", () => {
  it("loads a stream progressively when two batches name it and its last meta is complete", () => {
    const plans = planLogLoad(
      [batch([meta("a", false)]), batch([meta("b")]), batch([meta("a")])],
      new Set(),
    );
    expect([...plans.keys()]).toEqual(["a"]);
    expect(plans.get("a")).toMatchObject({ total: 2, first: 0, last: 2 });
  });

  it("does not load progressively a stream whose last meta says it is incomplete: it never ends", () => {
    const plans = planLogLoad(
      [batch([meta("a")]), batch([meta("a", false)])],
      new Set(),
    );
    expect(plans.size).toBe(0);
  });

  it("does not load progressively a stream one batch names, or one that already reads as complete", () => {
    const plans = planLogLoad(
      [batch([meta("a"), meta("b")]), batch([meta("b")])],
      new Set(["b"]),
    );
    expect(plans.size).toBe(0);
  });

  it("records the last batch that deletes or omits a key, and holds a key only until it is written after that", () => {
    const plans = planLogLoad(
      [
        batch([meta("a")], [upsert("a", "k1"), upsert("a", "k2")]),
        batch([meta("a")], [remove("a", "k1"), omit("a", "k2")]),
        batch([meta("a")], [upsert("a", "k1")]),
        batch([meta("a")], [remove("a", "k1")]),
      ],
      new Set(),
    );
    const plan = plans.get("a")!;
    expect(plan.removedAt.get("k1")).toBe(3);
    expect(plan.removedAt.get("k2")).toBe(1);
    expect(heldKeys(plan, 0, [upsert("a", "k1"), upsert("a", "k2")])).toEqual([
      "k1",
      "k2",
    ]);
    // k1 is written again at 2 and removed again at 3: held there too. k2 is
    // not written again.
    expect(heldKeys(plan, 2, [upsert("a", "k1")])).toEqual(["k1"]);
    expect(heldKeys(plan, 3, [upsert("a", "k1")])).toEqual([]);
  });

  it("holds the keys a later completion omits", () => {
    const plans = planLogLoad(
      [
        batch([meta("a")], [upsert("a", "k1"), upsert("a", "k2")]),
        batch(
          [meta("a")],
          [
            {
              kind: "complete",
              stream: "a",
              cutoff: stamp,
              omitted: [{ pkHash: "k2", key: ["k2"] }],
            },
          ],
        ),
      ],
      new Set(),
    );
    expect(
      heldKeys(plans.get("a")!, 0, [upsert("a", "k1"), upsert("a", "k2")]),
    ).toEqual(["k2"]);
  });
});
