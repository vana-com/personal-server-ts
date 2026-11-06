import { describe, expect, it } from "vitest";
import type { ControlState } from "./control.js";
import {
  eligible,
  isReady,
  selectConnection,
  type ConnectionView,
} from "./eligible.js";
import { InvalidArgumentError } from "./errors.js";
import { int, pick, rng } from "./test-support/ports.js";

const CONTROLS: ControlState[] = [
  { kind: "active", generation: 1 },
  { kind: "active", generation: 2 },
  { kind: "deleted", version: 2 },
  { kind: "foreign", version: 1 },
];

function randomInput(random: () => number) {
  const connections: ConnectionView[] = [];
  for (let i = int(random, 4); i > 0; i -= 1) {
    const streams: Record<string, { live: boolean; complete: boolean }> = {};
    for (const s of ["a", "b"]) {
      if (random() < 0.7)
        streams[s] = { live: random() < 0.7, complete: random() < 0.6 };
    }
    connections.push({
      ns: `${i}`.padStart(16, "0"),
      control: pick(random, CONTROLS),
      latestHeadRegistration: random() < 0.2 ? null : int(random, 5),
      streams,
    });
  }
  const streams = random() < 0.5 ? ["a"] : ["a", "b"];
  return {
    connections,
    target: { kind: "logical" as const, streams },
    legacyFile: random() < 0.5,
  };
}

describe("eligible (property)", () => {
  it("readiness matches reads; legacy never beats a complete view or a deletion", () => {
    const random = rng(8);
    for (let i = 0; i < 3000; i += 1) {
      const input = randomInput(random);
      const result = eligible(input);
      expect(isReady(input)).toBe(result.kind !== "unavailable");
      const selected = selectConnection(input.connections);
      const viewComplete =
        selected !== null &&
        input.target.streams.every(
          (s) => selected.streams[s]?.live && selected.streams[s]?.complete,
        );
      if (viewComplete)
        expect(result).toEqual({ kind: "view", ns: selected!.ns });
      if (result.kind === "legacy") {
        expect(input.legacyFile).toBe(true);
        expect(
          input.connections.some((c) => c.control.kind === "deleted"),
        ).toBe(false);
      }
      if (result.kind === "view") {
        const chosen = input.connections.find((c) => c.ns === result.ns)!;
        expect(chosen.control.kind).toBe("active");
      }
    }
  });

  it("requires at least one stream", () => {
    expect(() =>
      eligible({
        connections: [],
        target: { kind: "logical", streams: [] },
        legacyFile: true,
      }),
    ).toThrow(InvalidArgumentError);
  });
});
