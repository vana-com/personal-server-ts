import { describe, expect, it } from "vitest";
import { normalizeRawEnd } from "./normalize-raw-end.js";
import type { RawEndV1 } from "./raw-end.js";
import type { DurableRecordEvidence } from "./normalize-raw-end.js";

const empty: DurableRecordEvidence = {
  liveCount: 0,
  deletedCount: 0,
  everDeleted: false,
  upsertEvents: 0,
  deleteEvents: 0,
};
const live: DurableRecordEvidence = {
  ...empty,
  liveCount: 1,
  upsertEvents: 1,
};
const raw = (patch: Partial<RawEndV1> = {}): RawEndV1 => ({
  wireDialect: "connector-end-evidence/1",
  lastBatch: -1,
  selectedStreams: ["A", "B"],
  done: { status: "succeeded" },
  errors: [],
  checkpoints: {},
  preflightExcludedStreams: [],
  detailCoverage: {},
  invalidDetailCoverageStreams: [],
  wholeStreamEvidence: [],
  ...patch,
});
const begin = {
  selectedStreams: ["A", "B"],
  streams: {
    A: {
      mode: "full_refresh" as const,
      coverageStrategy: "full_inventory" as const,
      fullRead: true,
    },
    B: { mode: "incremental" as const },
  },
};
describe("normalizeRawEnd", () => {
  it("keeps completion separate from whole proof and folds delete history", () => {
    const evidence = { ...live, everDeleted: true, deleteEvents: 1 };
    const end = normalizeRawEnd(raw({ covered: ["A"] }), begin, {
      A: evidence,
    });
    expect(end.streams.A).toMatchObject({
      liveRecord: true,
      explicitDelete: true,
      sourceAnswered: true,
    });
    expect(end.streams.B).toMatchObject({
      sourceAnswered: false,
      preflightExclusion: false,
    });
    expect(end.provenFullStreams).toEqual([]);
  });
  it("fans scope-less errors out and preserves both skip classifications", () => {
    const end = normalizeRawEnd(
      raw({
        errors: [
          {
            kind: "skip_result",
            code: "unknown",
            recoveryHint: { retryable: true },
          },
          {
            kind: "skip_result",
            scope: { kind: "run" },
            code: "timeout",
            recoveryHint: { retryable: false, action: "retry_by_runtime" },
          },
        ],
      } as unknown as Partial<RawEndV1>),
      begin,
      {},
    );
    for (const o of Object.values(end.streams))
      expect(o).toMatchObject({ retryableSkip: true, otherSkip: true });
  });
  it("defaults unknown errors to hold and missing detail-gap hints to retry", () => {
    const end = normalizeRawEnd(
      raw({
        errors: [
          {
            kind: "error",
            scope: { kind: "stream", stream: "A" },
            code: "unknown",
          },
          {
            kind: "detail_gap",
            scope: { kind: "stream", stream: "B" },
            code: "detail_missing",
          },
        ],
      }),
      begin,
      {},
    );
    expect(end.streams.A?.otherSkip).toBe(true);
    expect(end.streams.B?.detailGap).toBe("retryable");
  });
  it("rejects selection mismatch and unselected durable records", () => {
    expect(() =>
      normalizeRawEnd(raw({ selectedStreams: ["A"] }), begin, {}),
    ).toThrow(/selection/);
    expect(() => normalizeRawEnd(raw(), begin, { C: live })).toThrow(
      /unselected/,
    );
    expect(
      normalizeRawEnd(raw(), begin, { A: live }).streams.A?.liveRecord,
    ).toBe(true);
    expect(() =>
      normalizeRawEnd({ ...raw(), records: { A: live } }, begin, {}),
    ).toThrow(/derived/);
  });
  it("validates explicit whole-inventory enumeration against durable final key count", () => {
    const proof = {
      stream: "A",
      report: { considered: 1, covered: 1, gap_keys: [] },
    };
    expect(
      normalizeRawEnd(raw({ wholeStreamEvidence: [proof] }), begin, { A: live })
        .provenFullStreams,
    ).toEqual(["A"]);
    for (const report of [
      { considered: 1, covered: 0 },
      { considered: 1, covered: 1, gap_keys: [["one"]] },
      { considered: 2, covered: 2 },
      { keys: [["one"]], considered: 1, covered: 1 },
    ]) {
      const end = normalizeRawEnd(
        raw({
          wholeStreamEvidence: [{ stream: "A", report }],
        }),
        begin,
        { A: live },
      );
      expect(end.provenFullStreams).toEqual([]);
      expect(end.streams.A?.invalidDetailCoverage).toBe(true);
    }
    expect(
      normalizeRawEnd(
        raw({
          wholeStreamEvidence: [
            { stream: "A", report: { considered: 0, covered: 0 } },
          ],
        }),
        begin,
        {},
      ).provenFullStreams,
    ).toEqual(["A"]);
  });
  it("downgrades failed-DONE without selected failure certification", () => {
    expect(
      normalizeRawEnd(
        raw({
          done: {
            status: "failed",
            error: { code: "stream_collection_failed" },
          },
        }),
        begin,
        {},
      ).finish,
    ).toBe("failed_done_upsert_only");
  });
});

it("refuses a host-certified finish claim instead of trusting failedStreams", () => {
  expect(() =>
    normalizeRawEnd(
      {
        ...raw(),
        finish: { kind: "certified_failed_done", failedStreams: ["B"] },
      },
      begin,
      { A: live },
    ),
  ).toThrow();
});
it("certifies raw failed DONE only from attributable collection-failure skips", () => {
  const base = raw();
  const body = {
    ...base,
    done: { status: "failed", error: { code: "stream_collection_failed" } },
    errors: [
      {
        kind: "skip_result",
        code: "stream_collection_failed",
        scope: { kind: "stream", stream: "B" },
      },
    ],
  };
  expect(normalizeRawEnd(body, begin, {}).finish).toBe("certified_failed_done");
  expect(normalizeRawEnd({ ...body, errors: [] }, begin, {}).finish).toBe(
    "failed_done_upsert_only",
  );
  expect(
    normalizeRawEnd(
      { ...body, errors: [{ ...body.errors[0], scope: { kind: "run" } }] },
      begin,
      {},
    ).finish,
  ).toBe("failed_done_upsert_only");
  expect(() =>
    normalizeRawEnd({ ...body, done: undefined }, begin, {}),
  ).toThrow();
  expect(() =>
    normalizeRawEnd({ ...body, done: { status: "cancelled" } }, begin, {}),
  ).toThrow();
  expect(() =>
    normalizeRawEnd(
      {
        ...body,
        done: {
          status: "succeeded",
          error: { code: "stream_collection_failed" },
        },
      },
      begin,
      {},
    ),
  ).toThrow();
});

it("holds incomplete detail reports even when no separate gap event arrived", () => {
  const end = normalizeRawEnd(
    raw({
      covered: ["A"],
      detailCoverage: { A: { considered: 1, covered: 0, gap_keys: [["one"]] } },
      wholeStreamEvidence: [
        { stream: "A", report: { considered: 1, covered: 1 } },
      ],
    }),
    begin,
    { A: live },
  );
  expect(end.streams.A?.detailGap).toBe("retryable");
  expect(end.provenFullStreams).toEqual([]);
});

it.each(["__proto__", "constructor", "toString"])(
  "treats prototype-named stream %s as an ordinary selected stream",
  (name) => {
    const begin = {
      selectedStreams: [name],
      streams: Object.fromEntries([[name, { mode: "incremental" as const }]]),
    };
    const end = normalizeRawEnd(raw({ selectedStreams: [name] }), begin, {});
    expect(end.streams[name]).toMatchObject({
      liveRecord: false,
      detailGap: "none",
      invalidDetailCoverage: false,
    });
    expect(end.streams[name]?.sourceAnswered).toBeUndefined();
  },
);

it("preserves native gap retryability, recovered frames and string recovery hints", () => {
  const end = normalizeRawEnd(
    {
      ...raw(),
      errors: [
        {
          kind: "detail_gap",
          scope: { kind: "stream", stream: "A" },
          reason: "source_unrepresentable",
          retryable: false,
          status: "pending",
          raw: {
            record_key: "one",
            detail_locator: { kind: "api" },
            reference_only: true,
          },
        },
        {
          kind: "detail_gap_recovered",
          scope: { kind: "stream", stream: "A" },
          raw: { gap_id: "gap-1", reference_only: true },
        },
        {
          kind: "skip_result",
          scope: { kind: "stream", stream: "B" },
          reason: "temporary_unavailable",
          recoveryHint: "retry_by_runtime",
        },
      ],
    },
    begin,
    {},
  );
  expect(end.streams.A?.detailGap).toBe("fatal");
  expect(end.streams.B?.retryableSkip).toBe(true);
});

it("classifies stream-scoped structured retry hints independently on succeeded DONE", () => {
  const end = normalizeRawEnd(
    raw({
      errors: [
        {
          kind: "skip_result",
          scope: { kind: "stream", stream: "A" },
          recoveryHint: { retryable: true },
        },
        {
          kind: "skip_result",
          scope: { kind: "stream", stream: "B" },
          recoveryHint: { retryable: false },
        },
      ],
    }),
    begin,
    {},
  );
  expect(end.streams.A).toMatchObject({
    retryableSkip: true,
    otherSkip: false,
  });
  expect(end.streams.B).toMatchObject({
    retryableSkip: false,
    otherSkip: true,
  });
  expect(end.finish).toBe("completed");
});

it.each([
  {
    required_keys: [["one"], ["one"]],
    hydrated_keys: [["one"]],
    gap: "none",
    invalid: false,
  },
  {
    required_keys: [{ b: 2, a: 1 }],
    hydrated_keys: [{ a: 1, b: 2 }],
    gap: "none",
    invalid: false,
  },
  {
    required_keys: [null, 1, "key"],
    hydrated_keys: [1, null, "key", "key"],
    gap: "none",
    invalid: false,
  },
  {
    required_keys: [["missing"]],
    hydrated_keys: [["one"], ["one"]],
    gap: "retryable",
    invalid: false,
  },
  { required_keys: "malformed", hydrated_keys: [], gap: "none", invalid: true },
  { required_keys: [], hydrated_keys: null, gap: "none", invalid: true },
])(
  "preserves gap membership and malformed report handling: %j",
  ({ gap, invalid, ...keys }) => {
    const result = normalizeRawEnd(
      raw({ detailCoverage: { A: { considered: 1, covered: 1, ...keys } } }),
      begin,
      {},
    );
    expect(result.streams.A).toMatchObject({
      detailGap: gap,
      invalidDetailCoverage: invalid,
    });
  },
);
