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

// Legacy fallback converse: a newer legacy file survives while any required
// head is missing, incomplete or non-live, but never defeats a complete view.
describe("eligible legacy fallback converse", () => {
  const ns = "0000000000000001";
  const active = { kind: "active" as const, generation: 1 };
  const cases: {
    label: string;
    control: ControlState;
    streams: ConnectionView["streams"];
  }[] = [
    { label: "absent head", control: active, streams: {} },
    {
      label: "live incomplete head",
      control: active,
      streams: { a: { live: true, complete: false } },
    },
    {
      label: "complete non-live head",
      control: active,
      streams: { a: { live: false, complete: true } },
    },
    {
      label: "foreign control",
      control: { kind: "foreign" as const, version: 1 },
      streams: { a: { live: true, complete: true } },
    },
  ];
  it.each(cases)("falls back to legacy for $label", ({ control, streams }) => {
    expect(
      eligible({
        connections: [{ ns, control, streams, latestHeadRegistration: 1 }],
        target: { kind: "logical", streams: ["a"] },
        legacyFile: true,
      }),
    ).toEqual({ kind: "legacy" });
  });

  it("keeps a deleted control unavailable rather than falling back", () => {
    expect(
      eligible({
        connections: [
          {
            ns,
            control: { kind: "deleted", version: 2 },
            streams: { a: { live: true, complete: true } },
            latestHeadRegistration: 1,
          },
        ],
        target: { kind: "logical", streams: ["a"] },
        legacyFile: true,
      }),
    ).toEqual({ kind: "unavailable", reason: "deleted" });
  });

  it("returns a view only if EVERY required head is live and complete", () => {
    const heads = [
      undefined,
      { live: false, complete: false },
      { live: false, complete: true },
      { live: true, complete: false },
      { live: true, complete: true },
    ];
    const controls: ControlState[] = [
      active,
      { kind: "foreign", version: 1 },
      { kind: "deleted", version: 2 },
    ];
    for (const control of controls)
      for (const a of heads)
        for (const b of heads) {
          const streams = { ...(a ? { a } : {}), ...(b ? { b } : {}) };
          const result = eligible({
            connections: [{ ns, control, streams, latestHeadRegistration: 1 }],
            target: { kind: "logical", streams: ["a", "b"] },
            legacyFile: true,
          });
          const allRequired =
            control.kind === "active" &&
            !!a?.live &&
            !!a.complete &&
            !!b?.live &&
            !!b.complete;
          expect(result).toEqual(
            allRequired
              ? { kind: "view", ns }
              : control.kind === "deleted"
                ? { kind: "unavailable", reason: "deleted" }
                : { kind: "legacy" },
          );
          if (result.kind === "view") {
            expect(control.kind).toBe("active");
            expect([a, b].every((head) => head?.live && head.complete)).toBe(
              true,
            );
          }
        }
  });
});
