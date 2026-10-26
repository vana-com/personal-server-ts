import { describe, expect, it } from "vitest";
import {
  isOuraTakeoverSelection,
  ouraTakeoverSelectionSince,
} from "./history-policy.js";

const unrestricted = {
  streams: [{ name: "sleep" }, { name: "readiness" }, { name: "activity" }],
};

const cases: [string, unknown, { since: string | null } | null][] = [
  ["exactly the three unrestricted streams", unrestricted, { since: null }],
  [
    "exactly the three prefixed streams with a common valid since",
    {
      streams: [
        { name: "oura.sleep", time_range: { since: "2026-01-03" } },
        { name: "oura.readiness", time_range: { since: "2026-01-03" } },
        { name: "oura.activity", time_range: { since: "2026-01-03" } },
      ],
    },
    { since: "2026-01-03" },
  ],
  [
    "three common since values without prefixes",
    {
      streams: [
        { name: "sleep", time_range: { since: "2026-01-03" } },
        { name: "readiness", time_range: { since: "2026-01-03" } },
        { name: "activity", time_range: { since: "2026-01-03" } },
      ],
    },
    { since: "2026-01-03" },
  ],
  [
    "an unknown stream",
    {
      streams: [
        { name: "sleep" },
        { name: "readiness" },
        { name: "heart_rate" },
      ],
    },
    null,
  ],
  [
    "a non-string stream name",
    { streams: [{ name: "sleep" }, { name: "readiness" }, { name: 42 }] },
    null,
  ],
  ["a null selection", null, null],
  ["an array selection", [], null],
  ["a selection without streams", {}, null],
  ["a selection with an extra key", { ...unrestricted, source: "oura" }, null],
  [
    "a selection with a missing stream",
    { streams: unrestricted.streams.slice(0, 2) },
    null,
  ],
  [
    "a selection with an extra stream",
    { streams: [...unrestricted.streams, { name: "sleep" }] },
    null,
  ],
  [
    "duplicate unprefixed streams",
    { streams: [{ name: "sleep" }, { name: "sleep" }, { name: "activity" }] },
    null,
  ],
  [
    "duplicate prefixed and unprefixed aliases",
    {
      streams: [
        { name: "oura.sleep" },
        { name: "sleep" },
        { name: "activity" },
      ],
    },
    null,
  ],
  [
    "a mixed restricted and unrestricted selection",
    {
      streams: [
        { name: "sleep", time_range: { since: "2026-01-03" } },
        { name: "readiness" },
        { name: "activity", time_range: { since: "2026-01-03" } },
      ],
    },
    null,
  ],
  [
    "different since days",
    {
      streams: [
        { name: "sleep", time_range: { since: "2026-01-03" } },
        { name: "readiness", time_range: { since: "2026-01-04" } },
        { name: "activity", time_range: { since: "2026-01-03" } },
      ],
    },
    null,
  ],
  ...["2026-02-30", "2026-04-31", "2026-1-03", "2026-01-03T00:00:00Z"].map(
    (day): [string, unknown, null] => [
      `invalid, nonexistent, or reformatted since day ${day}`,
      {
        streams: unrestricted.streams.map((stream) => ({
          name: stream.name,
          time_range: { since: day },
        })),
      },
      null,
    ],
  ),
  [
    "a stream entry that is not an object",
    { streams: [{ name: "sleep" }, null, { name: "activity" }] },
    null,
  ],
  [
    "a stream with an extra key",
    {
      streams: [
        { name: "sleep", extra: true },
        { name: "readiness" },
        { name: "activity" },
      ],
    },
    null,
  ],
  [
    "until at stream level",
    {
      streams: [
        { name: "sleep", until: "2026-02-01" },
        { name: "readiness" },
        { name: "activity" },
      ],
    },
    null,
  ],
  [
    "until in the time range",
    {
      streams: unrestricted.streams.map((stream) => ({
        name: stream.name,
        time_range: { since: "2026-01-03", until: "2026-02-01" },
      })),
    },
    null,
  ],
  [
    "an extra time range key",
    {
      streams: unrestricted.streams.map((stream) => ({
        name: stream.name,
        time_range: { since: "2026-01-03", zone: "UTC" },
      })),
    },
    null,
  ],
  [
    "an empty time range",
    {
      streams: unrestricted.streams.map((stream) => ({
        name: stream.name,
        time_range: {},
      })),
    },
    null,
  ],
];

describe("Oura takeover selection policy", () => {
  it.each(cases)("classifies %s", (_name, value, expected) => {
    expect(ouraTakeoverSelectionSince(value)).toEqual(expected);
    expect(isOuraTakeoverSelection(value)).toBe(expected !== null);
  });
});
