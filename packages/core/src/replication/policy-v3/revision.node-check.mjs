import test from "node:test";
import assert from "node:assert/strict";
import {
  nextHlc,
  receiveHlc,
  observeRemoteClocks,
  recordRawReceipt,
  compareRevisions,
} from "./revision.ts";
import {
  compareRevisions as oldCompare,
  nextLamportCounter,
} from "../revision.ts";
const local = { wallMs: 10, logical: 1, writerId: "local", operationId: "l" };
const remote = {
  wallMs: 1000000,
  logical: 4,
  writerId: "remote",
  operationId: "r",
};
test("v1 original identity tie ordering remains intact", () => {
  assert.equal(
    oldCompare(
      {
        counter: 4,
        writerId: "z",
        operationId: "x",
        origin: { writerId: "a", operationId: "a" },
      },
      { counter: 4, writerId: "b", operationId: "b" },
    ),
    -1,
  );
  assert.equal(nextLamportCounter(2, [4]), 5);
});
test("v1 behavioral negative control: large counter dominates regardless of observation", () => {
  assert.equal(
    oldCompare(
      { counter: 10000, writerId: "A", operationId: "old", wallMs: 1 },
      { counter: 5, writerId: "B", operationId: "new", wallMs: 1000000 },
    ),
    1,
  );
});
test("next HLC guards raw remote without trusting caller pre-clamping", () => {
  assert.deepEqual(nextHlc(local, [remote], 10), {
    wallMs: 300010,
    logical: 1,
  });
});
test("raw remote receipt remains separate from capped local clock", () => {
  const result = observeRemoteClocks(local, {}, [remote], 10);
  assert.deepEqual(result.clock, { wallMs: 300010, logical: 1 });
  assert.deepEqual(result.rawFrontier, {
    remote: { wallMs: 1000000, logical: 4 },
  });
  assert.deepEqual(result.clockWarnings, ["remote"]);
});
test("replay and older receipts cannot reduce raw frontier", () => {
  const a = recordRawReceipt({}, remote);
  assert.deepEqual(recordRawReceipt(a, { ...remote, wallMs: 2 }), a);
  assert.deepEqual(recordRawReceipt(a, remote), a);
});
test("raw frontier retains __proto__ writer as an own key", () => {
  const a = recordRawReceipt({}, { ...remote, writerId: "__proto__" });
  assert.ok(Object.hasOwn(a, "__proto__"));
  assert.deepEqual(a.__proto__, { wallMs: 1000000, logical: 4 });
  assert.equal(Object.getPrototypeOf(a), Object.prototype);
});
test("HLC exact wide counter survives increment", () => {
  assert.deepEqual(
    nextHlc({ ...local, logical: Number.MAX_SAFE_INTEGER }, [], 10),
    { wallMs: 10, logical: "9007199254740992" },
  );
});
test("HLC exhaustion fails closed", () => {
  assert.throws(
    () => nextHlc({ ...local, logical: "18446744073709551615" }, [], 10),
    /exhausted/,
  );
});
test("HLC received bound and warning inclusive edge", () => {
  assert.equal(
    receiveHlc({ ...remote, wallMs: 300010 }, 10, 300000).clockAhead,
    false,
  );
  assert.equal(
    receiveHlc({ ...remote, wallMs: 300011 }, 10, 300000).clockAhead,
    true,
  );
});
test("HLC exact logical writer op tie break ignores wall only at final tie stage", () => {
  assert.equal(compareRevisions(local, { ...local, wallMs: 10000 }), 0);
  assert.equal(compareRevisions(local, { ...local, logical: 2 }), -1);
  assert.equal(compareRevisions(local, { ...local, writerId: "z" }), -1);
});
test("invalid clocks are rejected", () => {
  for (const logical of [-1, 1.5, Infinity, "01", "18446744073709551616"]) {
    assert.throws(() => nextHlc({ ...local, logical }, [], 10));
  }
  assert.throws(() => receiveHlc(remote, Number.MAX_SAFE_INTEGER, 300000));
});
test("local writer is not a remote frontier entry", () => {
  assert.deepEqual(
    observeRemoteClocks(local, {}, [{ ...local, logical: 2 }], 10).rawFrontier,
    {},
  );
});
