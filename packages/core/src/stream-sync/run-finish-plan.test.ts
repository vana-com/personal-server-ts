import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { StreamObservation } from "./intake.js";
import {
  blockUpward,
  parseEndRequest,
  planRunFinish,
  pruneDownward,
  type RunFinishInput,
  type RunFinishPlan,
  type RunFinishStream,
} from "./run-finish-plan.js";

interface Capture {
  readonly records?: Record<string, { key: unknown; op?: string }[]>;
  readonly skips?: { stream?: string; retryable: boolean }[];
  readonly detailGaps?: { stream: string; retryable: boolean }[];
  readonly detailCoverage?: Record<string, StreamObservation["detailCoverage"]>;
  readonly invalidDetailCoverage?: string[];
  readonly preflightExclusions?: string[];
  readonly failedInDone?: string[];
}

const fixture = JSON.parse(
  readFileSync(
    new URL("../../contracts/run-finish-plan.json", import.meta.url),
    "utf8",
  ),
) as {
  cases: {
    id: string;
    declared: Record<string, RunFinishStream>;
    capture: Capture;
    input: RunFinishInput;
    expect: RunFinishPlan;
  }[];
};

/** The mapping every host makes from what its connector emitted. */
function observe(capture: Capture, stream: string): StreamObservation {
  const records = capture.records?.[stream] ?? [];
  const live = new Map<string, boolean>();
  for (const record of records)
    live.set(JSON.stringify(record.key), record.op !== "delete");
  const skips = (capture.skips ?? []).filter(
    (skip) => skip.stream === undefined || skip.stream === stream,
  );
  const gaps = (capture.detailGaps ?? []).filter((g) => g.stream === stream);
  const report = capture.detailCoverage?.[stream];
  return {
    liveRecord: [...live.values()].some(Boolean),
    explicitDelete: records.some((record) => record.op === "delete"),
    retryableSkip: skips.some((skip) => skip.retryable),
    otherSkip: skips.some((skip) => !skip.retryable),
    preflightExclusion: (capture.preflightExclusions ?? []).includes(stream),
    detailGap:
      gaps.length === 0
        ? "none"
        : gaps.some((gap) => gap.retryable)
          ? "retryable"
          : "fatal",
    invalidDetailCoverage: (capture.invalidDetailCoverage ?? []).includes(
      stream,
    ),
    failedInDone: (capture.failedInDone ?? []).includes(stream),
    ...(report === undefined ? {} : { detailCoverage: report }),
  };
}

describe("run-finish-plan.json", () => {
  it("has unique case ids", () => {
    const ids = fixture.cases.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it.each(fixture.cases)("$id: the observation is the capture's", (c) => {
    for (const [stream, observation] of Object.entries(c.input.streams))
      expect(observation).toEqual(observe(c.capture, stream));
  });

  it.each(fixture.cases)("$id", (c) => {
    expect(planRunFinish(c.input, c.declared)).toEqual(c.expect);
  });
});

describe("blockUpward", () => {
  it("blocks every ancestor whatever the edge order", () => {
    const blocked = new Set(["c"]);
    blockUpward(blocked, [
      ["p", ["g"]],
      ["c", ["p"]],
    ]);
    expect([...blocked].sort()).toEqual(["c", "g", "p"]);
  });
});

describe("pruneDownward", () => {
  it("drops descendants of a missing parent, never other parents", () => {
    const eligible = new Set(["q", "c", "d"]);
    pruneDownward(eligible, [
      ["d", ["c"]],
      ["c", ["p", "q"]],
    ]);
    expect([...eligible]).toEqual(["q"]);
  });
});

describe("parseEndRequest", () => {
  const observation: StreamObservation = {
    liveRecord: true,
    explicitDelete: false,
    retryableSkip: false,
    otherSkip: false,
    preflightExclusion: false,
    detailGap: "none",
    invalidDetailCoverage: false,
    failedInDone: false,
  };
  const body = {
    finish: "completed",
    streams: { items: observation },
    checkpoints: {},
    lastBatch: 0,
  };

  it("accepts an observation body", () => {
    expect(parseEndRequest(body, ["items"])).toBe(body);
  });

  it.each([
    [
      "the old outcome body",
      { outcome: "succeeded", coveredStreams: [], lastBatch: 0 },
    ],
    ["an unknown finish", { ...body, finish: "retry_pending" }],
    ["an undeclared stream", { ...body, streams: { other: observation } }],
    [
      "a missing flag",
      {
        ...body,
        streams: { items: { ...observation, failedInDone: undefined } },
      },
    ],
    [
      "an unknown gap",
      { ...body, streams: { items: { ...observation, detailGap: "some" } } },
    ],
    ["checkpoints as a list", { ...body, checkpoints: [] }],
    ["no lastBatch", { ...body, lastBatch: undefined }],
    ["proven streams not strings", { ...body, provenFullStreams: [1] }],
  ])("refuses %s", (_, bad) => {
    expect(() => parseEndRequest(bad, ["items"])).toThrow(
      expect.objectContaining({ code: "invalid_request" }),
    );
  });
});

describe("partial retry", () => {
  it("covers a finished stream while another remains retryable", () => {
    const finished = observe({ records: { a: [{ key: "one" }] } }, "a");
    const retrying = observe(
      { skips: [{ stream: "b", retryable: true }] },
      "b",
    );
    const plan = planRunFinish(
      {
        finish: "completed",
        streams: { a: finished, b: retrying },
        checkpoints: {},
      },
      { a: { mode: "incremental" }, b: { mode: "incremental" } },
    );
    expect(plan.outcome).toBe("partial");
    expect(plan.covered).toEqual(["a"]);
  });
});
