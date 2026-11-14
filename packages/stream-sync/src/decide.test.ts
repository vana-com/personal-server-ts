import { describe, expect, it } from "vitest";
import { admitStart } from "./admission.js";
import type { ControlState } from "./control.js";
import {
  checkpointDecision,
  decide,
  startState,
  targetFor,
  type DecidePhase,
  type StartState,
  type StreamRunResult,
} from "./decide.js";
import { int, pick, rng } from "./test-support/ports.js";

const STARTS: StartState[] = [{ kind: "unknown" }, { kind: "absent" }];
const CURRENTS: ControlState[] = [{ kind: "absent" }];
for (let n = 1; n <= 5; n += 1) {
  STARTS.push(
    { kind: "active", generation: n },
    { kind: "deleted", version: n },
    { kind: "foreign", version: n },
  );
  CURRENTS.push(
    { kind: "active", generation: n },
    { kind: "deleted", version: n },
    { kind: "foreign", version: n },
  );
}
const PHASES: DecidePhase[] = ["first", "reread", "after_write"];

function* everyInput() {
  for (const start of STARTS)
    for (const current of CURRENTS)
      for (const userConnect of [false, true])
        for (const full of [false, true])
          for (const phase of PHASES)
            yield { start, current, userConnect, full, phase };
}

describe("decide invariants (exhaustive over small states)", () => {
  it("publishes only at the start snapshot's target, and only when C = active(T)", () => {
    for (const input of everyInput()) {
      const d = decide(input);
      if (d.kind === "publish") {
        expect(d.target).toBe(targetFor(input.start));
        expect(input.current).toEqual({ kind: "active", generation: d.target });
      }
    }
  });

  it("writes control only as the table allows", () => {
    for (const input of everyInput()) {
      const d = decide(input);
      if (d.kind === "create") {
        expect(input.start.kind).toBe("absent");
        expect(input.current.kind).toBe("absent");
        expect(input.phase).not.toBe("after_write");
      }
      if (d.kind === "reconnect") {
        expect(input.userConnect && input.full).toBe(true);
        expect(input.start).toEqual(input.current);
        expect(d.target).toBe(targetFor(input.start));
      }
    }
  });

  it("after a write, only publish or discard", () => {
    for (const input of everyInput()) {
      if (input.phase !== "after_write") continue;
      expect(["publish", "discard"]).toContain(decide(input).kind);
    }
  });

  it("never publishes with an unknown start or a foreign current row", () => {
    for (const input of everyInput()) {
      if (input.start.kind === "unknown" || input.current.kind === "foreign") {
        expect(decide(input).kind).not.toBe("publish");
      }
    }
  });

  it("waits on an active start whose connection is absent or at a lower generation", () => {
    for (const input of everyInput()) {
      const { start, current, phase } = input;
      if (start.kind !== "active" || phase === "after_write") continue;
      const lower =
        current.kind === "absent" ||
        (current.kind === "active" && current.generation < start.generation);
      if (!lower) continue;
      expect(decide(input)).toEqual(
        phase === "reread"
          ? { kind: "keep_pending", reason: "registry_inconsistent" }
          : { kind: "reread" },
      );
    }
  });

  it("a deleted start: a full connect reconnects at a same delete, publishes at the next generation, and nothing else publishes", () => {
    for (let v0 = 1; v0 <= 5; v0 += 1) {
      const start: StartState = { kind: "deleted", version: v0 };
      for (const current of CURRENTS) {
        const got = decide({
          start,
          current,
          userConnect: true,
          full: true,
          phase: "first",
        });
        if (current.kind === "foreign") {
          expect(got).toEqual({ kind: "keep_pending", reason: "key_mismatch" });
        } else if (current.kind === "deleted" && current.version === v0) {
          expect(got).toEqual({ kind: "reconnect", target: v0 + 1 });
        } else if (current.kind === "active" && current.generation === v0 + 1) {
          expect(got).toEqual({ kind: "publish", target: v0 + 1 });
        } else {
          expect(got).toMatchObject({ kind: "discard", restartFull: false });
        }
      }
    }
  });

  it("a deleted start that is not a full connect never writes or publishes, and restarts full only at its deletion or reconnect", () => {
    for (let v0 = 1; v0 <= 5; v0 += 1) {
      const start: StartState = { kind: "deleted", version: v0 };
      for (const current of CURRENTS) {
        if (current.kind === "foreign") continue;
        const atDelete = current.kind === "deleted" && current.version === v0;
        const atReconnect =
          current.kind === "active" && current.generation === v0 + 1;
        const notConnect = decide({
          start,
          current,
          userConnect: false,
          full: true,
          phase: "first",
        });
        expect(notConnect).toMatchObject({
          kind: "discard",
          restartFull: false,
        });
        const notFull = decide({
          start,
          current,
          userConnect: true,
          full: false,
          phase: "first",
        });
        expect(notFull).toMatchObject({
          kind: "discard",
          restartFull: atDelete || atReconnect,
        });
      }
    }
  });

  it("the rule never admits an unknown or foreign start, and decide never writes or publishes one", () => {
    const unadmitted: StartState[] = [
      { kind: "unknown" },
      { kind: "foreign", version: 1 },
    ];
    for (const start of unadmitted) {
      for (const current of CURRENTS) {
        for (const userConnect of [false, true]) {
          for (const full of [false, true]) {
            expect(admitStart(start, current, { userConnect, full })).toBe(
              "discard",
            );
            const got = decide({
              start,
              current,
              userConnect,
              full,
              phase: "first",
            });
            // A foreign current row holds every run pending, whatever its start.
            expect(got.kind).toBe(
              current.kind === "foreign" ? "keep_pending" : "discard",
            );
          }
        }
      }
    }
  });

  it("decodes a missing start snapshot, null or absent, as unknown", () => {
    expect(startState(null, "")).toEqual({ kind: "unknown" });
    expect(startState(undefined, "")).toEqual({ kind: "unknown" });
  });

  it("reads the start snapshot by ns", () => {
    expect(startState(null, "x")).toEqual({ kind: "unknown" });
    expect(startState({}, "x")).toEqual({ kind: "absent" });
    expect(
      startState({ toString: { kind: "absent" } } as never, "constructor"),
    ).toEqual({
      kind: "absent",
    });
  });
});

/**
 * Random runs against a one-row registry with other devices acting between
 * any two steps. Checks the split-run property: a run commits every stream
 * at one generation, the start snapshot's target, and saves a checkpoint
 * only when all streams committed there and control is still active(T).
 */
describe("run simulation (property)", () => {
  function external(random: () => number, c: ControlState): ControlState {
    switch (c.kind) {
      case "absent":
        return random() < 0.8
          ? { kind: "active", generation: 1 }
          : { kind: "foreign", version: 1 };
      case "active":
        return { kind: "deleted", version: c.generation + 1 };
      case "foreign":
        return { kind: "deleted", version: c.version + 1 };
      case "deleted":
        return random() < 0.8
          ? { kind: "active", generation: c.version + 1 }
          : { kind: "foreign", version: c.version + 1 };
    }
  }

  it("never commits one run at two generations or checkpoints across them", () => {
    let saved = 0;
    let discarded = 0;
    for (let seed = 1; seed <= 4000; seed += 1) {
      const random = rng(seed);
      let control: ControlState = { kind: "absent" };
      for (let i = int(random, 5); i > 0; i -= 1)
        control = external(random, control);
      const listed = random() < 0.9;
      // The listing may be stale: other devices act after it.
      const start = startState(listed ? { n: control } : null, "n");
      for (let i = int(random, 3); i > 0; i -= 1)
        control = external(random, control);
      const userConnect = random() < 0.5;
      const full = random() < 0.6;
      const maybe = () => {
        if (random() < 0.25) control = external(random, control);
      };

      const streams: Record<string, StreamRunResult> = {};
      let runDiscarded = false;
      for (const s of ["s1", "s2", "s3"].slice(0, 1 + int(random, 3))) {
        let phase: DecidePhase = "first";
        streams[s] = { state: "pending" };
        for (let step = 0; step < 10 && !runDiscarded; step += 1) {
          maybe();
          const d = decide({
            start,
            current: control,
            userConnect,
            full,
            phase,
          });
          if (d.kind === "publish") {
            maybe();
            streams[s] = {
              state: "committed",
              generation: d.target,
              complete: full,
            };
            break;
          }
          if (d.kind === "create" || d.kind === "reconnect") {
            const ok =
              d.kind === "create"
                ? control.kind === "absent"
                : control.kind === "deleted" &&
                  control.version + 1 === d.target;
            if (ok) control = { kind: "active", generation: d.target };
            maybe();
            phase = ok ? "after_write" : "first"; // 409 → re-plan from read control
            continue;
          }
          if (d.kind === "reread") {
            phase = "reread";
            continue;
          }
          if (d.kind === "discard") runDiscarded = true;
          break;
        }
        if (runDiscarded) break;
      }
      const commits = Object.values(streams).filter(
        (r) => r.state === "committed",
      );
      const target = targetFor(start);
      for (const c of commits) {
        expect(c.state === "committed" && c.generation).toBe(target);
      }
      if (runDiscarded) discarded += 1;
      maybe();
      const result = checkpointDecision({
        target: target ?? 0,
        streams: runDiscarded
          ? { ...streams, discarded: { state: "discarded" } }
          : streams,
        control,
        seedReceiptsPending: false,
      });
      if (result.kind === "save") {
        saved += 1;
        expect(runDiscarded).toBe(false);
        expect(control).toEqual({ kind: "active", generation: target });
        for (const r of Object.values(streams)) {
          expect(r).toMatchObject({ state: "committed", generation: target });
        }
      }
    }
    // The simulation must reach both outcomes to mean anything.
    expect(saved).toBeGreaterThan(100);
    expect(discarded).toBeGreaterThan(100);
  });
});

describe("checkpointDecision", () => {
  it("ignores stream order", () => {
    const random = rng(4);
    const choices: StreamRunResult[] = [
      { state: "committed", generation: 2, complete: true },
      { state: "noop", generation: 2, complete: true },
      { state: "committed", generation: 2, complete: false },
      { state: "pending" },
    ];
    for (let i = 0; i < 200; i += 1) {
      const entries = Array.from({ length: 1 + int(random, 4) }, (_, j) => [
        `s${j}`,
        pick(random, choices),
      ]);
      const forward = Object.fromEntries(entries);
      const backward = Object.fromEntries([...entries].reverse());
      const base = {
        target: 2,
        control: { kind: "active", generation: 2 } as const,
        seedReceiptsPending: false,
      };
      expect(checkpointDecision({ ...base, streams: forward })).toEqual(
        checkpointDecision({ ...base, streams: backward }),
      );
    }
  });
});
