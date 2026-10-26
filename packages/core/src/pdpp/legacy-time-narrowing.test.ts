/**
 * One legacy time-bound interpretation from AS validation through narrowing
 * to RS enforcement, whatever the host time zone (#441 review F1).
 */
import { afterEach, expect, it } from "vitest";
import { resolveSelection } from "./resolve.js";
import { validateSelectionRequest } from "./selection.js";
import { withinTimeConstraint } from "../ports/pdpp-auth.js";
import {
  PDPP_DATA_ACCESS_TYPE_V02,
  type DeclarationSnapshot,
  type SelectionRequest,
  type TimeRange,
} from "./types.js";

const snapshot: DeclarationSnapshot = {
  source_id: "https://data.example.com/finance",
  source_kind: "provider_native",
  version: "2026-09-01",
  digest: "f".repeat(64),
  streams: [
    {
      name: "transactions",
      fields: ["date", "amount"],
      consent_time_field: "date",
      primary_key: ["date"],
    },
  ],
};

const request = (
  time_range: TimeRange,
  minimum?: TimeRange,
): SelectionRequest => ({
  type: PDPP_DATA_ACCESS_TYPE_V02,
  source: { id: snapshot.source_id },
  purpose_code: "https://apps.example.com/purposes/budget",
  access_mode: "single_use",
  streams: [
    {
      name: "transactions",
      necessity: "required",
      fields: ["date", "amount"],
      time_range,
      ...(minimum && { minimum: { time_range: minimum } }),
    },
  ],
});

const zones = ["UTC", "America/Los_Angeles", "Asia/Tokyo"];
const previous = process.env.TZ;
afterEach(() => {
  if (previous === undefined) delete process.env.TZ;
  else process.env.TZ = previous;
});

it.each(zones)(
  "never discloses time the owner narrowed away from an offset-less request bound (TZ=%s)",
  (zone) => {
    process.env.TZ = zone;
    const result = resolveSelection(
      request({ since: "2026-01-01T12:00:00", until: "2026-01-31T12:00:00" }),
      snapshot,
      { eligibleFor: () => ["account_example"] },
      {
        time_ranges: {
          transactions: {
            since: "2026-01-01T16:00:00Z",
            until: "2026-01-31T08:00:00Z",
          },
        },
      },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const constraint = result.streams[0]!.time_constraint;
    const disclosed = (at: string) => withinTimeConstraint(at, constraint);
    expect(disclosed("2026-01-01T14:00:00Z")).toBe(false);
    expect(disclosed("2026-01-01T17:00:00Z")).toBe(true);
    expect(disclosed("2026-01-31T07:00:00Z")).toBe(true);
    expect(disclosed("2026-01-31T10:00:00Z")).toBe(false);
  },
);

it("validates offset-less request bounds and minima the same in every time zone", () => {
  const outcomes = zones.map((zone) => {
    process.env.TZ = zone;
    return [
      // Valid in UTC; Date.parse in a western zone puts since after until.
      validateSelectionRequest(
        request({
          since: "2026-01-01T12:00:00",
          until: "2026-01-01T15:00:00Z",
        }),
        snapshot,
      ).ok,
      // The minimum sits inside the UTC ceiling.
      validateSelectionRequest(
        request(
          { since: "2026-01-01T00:00:00", until: "2026-02-01T00:00:00" },
          { since: "2026-01-01T00:00:00Z", until: "2026-01-02T00:00:00Z" },
        ),
        snapshot,
      ).ok,
    ];
  });
  expect(outcomes).toEqual(zones.map(() => [true, true]));
});
