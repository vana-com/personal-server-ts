import assert from "node:assert/strict";
import { it } from "vitest";
import {
  perform,
  ReplicaAsyncEffectError,
  runEffectAsync,
  runEffectSync,
  type ReplicaEffect,
} from "./effects.js";

type Log = { log: string[]; fail?: string };

/** One computation: two reads, a caught failure, a final write. */
function* program(): ReplicaEffect<string, Log> {
  const a = yield* perform<string, Log>((c) => (c.log.push("a"), "A"));
  let b: string;
  try {
    b = yield* perform<string, Log>((c) => {
      if (c.fail === "b") throw new Error("b failed");
      return "B";
    });
  } catch {
    b = "recovered";
  }
  yield* perform<void, Log>((c) => void c.log.push(`${a}${b}`));
  return `${a}+${b}`;
}

it("the same effect runs synchronously and asynchronously with the same result", async () => {
  const sync: Log = { log: [] };
  assert.equal(runEffectSync(program(), sync), "A+B");
  const asyncLog: Log = { log: [] };
  const lifted = (op: (c: Log) => unknown) => async (c: Log) => op(c);
  // An async host answers every operation with a promise.
  function* liftedProgram(): ReplicaEffect<string, Log> {
    const gen = program();
    let step = gen.next();
    while (!step.done) {
      try {
        step = gen.next(yield lifted(step.value));
      } catch (error) {
        step = gen.throw(error);
      }
    }
    return step.value;
  }
  assert.equal(await runEffectAsync(liftedProgram(), asyncLog), "A+B");
  assert.deepEqual(sync.log, asyncLog.log);
});

it("an operation's error reaches the effect's own catch on both runners", async () => {
  assert.equal(runEffectSync(program(), { log: [], fail: "b" }), "A+recovered");
  assert.equal(
    await runEffectAsync(program(), { log: [], fail: "b" }),
    "A+recovered",
  );
});

it("an uncaught operation error rejects the run", async () => {
  function* failing(): ReplicaEffect<void, Log> {
    yield* perform<void, Log>(() => {
      throw new Error("boom");
    });
  }
  assert.throws(() => runEffectSync(failing(), { log: [] }), /boom/);
  await assert.rejects(runEffectAsync(failing(), { log: [] }), /boom/);
});

it("the synchronous runner refuses a promise and the effect sees the refusal", () => {
  function* asyncOp(): ReplicaEffect<unknown, Log> {
    return yield* perform<unknown, Log>(async () => "late");
  }
  assert.throws(
    () => runEffectSync(asyncOp(), { log: [] }),
    ReplicaAsyncEffectError,
  );
});
