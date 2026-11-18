import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { normalizeRawEnd } from "./normalize-raw-end.js";
import { parseEndRequest, planRunFinish } from "./run-finish-plan.js";
const vectors = JSON.parse(
  readFileSync(
    new URL("../../contracts/raw-end.json", import.meta.url),
    "utf8",
  ),
);
describe("V1 raw end acceptance", () => {
  for (const c of vectors.finish)
    it(c.id, () => {
      if (c.reject) {
        expect(() => normalizeRawEnd(c.raw, c.begin, c.durable)).toThrowError(
          expect.objectContaining({ code: c.reject }),
        );
        return;
      }
      const end = normalizeRawEnd(c.raw, c.begin, c.durable);
      expect(planRunFinish(end, c.begin.streams, "raw-v1")).toEqual(c.expect);
      if (c.expectObservation)
        expect(end.streams).toMatchObject(c.expectObservation);
    });
  it("validates optional sourceAnswered and never turns silent full-refresh into whole coverage", () => {
    const c = vectors.finish[0];
    const end = normalizeRawEnd(c.raw, c.begin, c.durable);
    const no = {
      ...end,
      streams: { A: { ...end.streams.A!, sourceAnswered: false } },
    };
    expect(planRunFinish(no, { A: { mode: "incremental" } }).covered).toEqual(
      [],
    );
    const yes = {
      ...end,
      streams: { A: { ...end.streams.A!, sourceAnswered: true } },
    };
    expect(planRunFinish(yes, { A: { mode: "full_refresh" } }).covered).toEqual(
      [],
    );
    expect(() =>
      parseEndRequest(
        { ...yes, streams: { A: { ...yes.streams.A, sourceAnswered: "yes" } } },
        ["A"],
      ),
    ).toThrow();
  });
});
