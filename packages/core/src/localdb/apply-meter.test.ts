import { expect, it } from "vitest";
import { createApplyMeter } from "./apply-meter.js";

it("reports nothing for a job that waited on nothing", () => {
  expect(createApplyMeter().report(5)).toBeNull();
});

it("tells fetches that ran together from fetches that ran one after another", async () => {
  let now = 0;
  const meter = createApplyMeter(() => now);
  const wait = (ms: number) => async () => {
    now += ms;
  };
  await meter.time("fetch", wait(10));
  await meter.time("fetch", wait(10));
  expect(meter.report(20)).toEqual({
    wallMs: 20,
    fetch: { n: 2, ms: 20, peak: 1 },
  });
  const together = createApplyMeter(() => now);
  await Promise.all([
    together.time("fetch", wait(10)),
    together.time("fetch", wait(10)),
  ]);
  expect(together.report(10)).toMatchObject({ fetch: { n: 2, peak: 2 } });
});
