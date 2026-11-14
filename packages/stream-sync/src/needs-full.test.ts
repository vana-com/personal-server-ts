import { describe, expect, it } from "vitest";
import { afterCommit, runMustBeFull, type NeedsFull } from "./needs-full.js";
import { pick, rng } from "./test-support/ports.js";

describe("needsFull (property)", () => {
  it("an entry exists iff the last commit for it was incomplete and no full complete commit followed", () => {
    const random = rng(13);
    for (let i = 0; i < 200; i += 1) {
      let set: NeedsFull = [];
      const model = new Map<string, boolean>();
      for (let j = 0; j < 30; j += 1) {
        const commit = {
          connector: pick(random, ["c1", "c2"]),
          ns: pick(random, ["", "0123456789abcdef"]),
          stream: pick(random, ["a", "b", "c"]),
          complete: random() < 0.6,
          runFull: random() < 0.5,
        };
        const effect = afterCommit(set, commit);
        set = effect.needsFull;
        const key = `${commit.connector}\u0000${commit.ns}\u0000${commit.stream}`;
        if (!commit.complete) model.set(key, true);
        else if (commit.runFull) model.delete(key);
        expect(effect.clearCheckpoint).toBe(!commit.complete);
        expect(
          set.map((k) => `${k.connector}\u0000${k.ns}\u0000${k.stream}`),
        ).toEqual([...model.keys()].sort());
        for (const c of ["c1", "c2"]) {
          expect(runMustBeFull(set, c)).toBe(
            [...model.keys()].some((k) => k.startsWith(`${c}\u0000`)),
          );
        }
      }
    }
  });
});
