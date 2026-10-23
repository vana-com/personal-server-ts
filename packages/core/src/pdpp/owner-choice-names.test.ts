/**
 * Stream and field names are data, not property names.
 *
 * The PDPP spec gives no character grammar for stream or field names, so a
 * source may declare a stream called `constructor`, `__proto__` or
 * `hasOwnProperty`, or one containing a line break or an astral character.
 * Owner choices reach Core as plain JSON objects keyed by those names, so a
 * lookup that also reads inherited properties finds a built-in function where
 * the owner made no choice.
 */

import { describe, expect, it } from "vitest";
import { resolveSelection, type InstanceInventory } from "./resolve.js";
import {
  PDPP_DATA_ACCESS_TYPE_V02,
  type DeclarationSnapshot,
  type SelectionRequest,
} from "./types.js";

const NAMES = [
  "__proto__",
  "constructor",
  "toString",
  "hasOwnProperty",
  "valueOf",
  "line\nbreak",
  "carriage\rreturn",
  "line\u2028separator",
  "paragraph\u2029separator",
  "astral \u{1F600} \u{1D4B3}",
];
const SINCE = "2025-06-01T00:00:00Z";
const YEAR = { since: "2025-01-01T00:00:00Z", until: "2026-01-01T00:00:00Z" };

const inventory: InstanceInventory = { eligibleFor: () => ["account_a"] };

function declaring(name: string): DeclarationSnapshot {
  return {
    source_id: "https://data.example.com/names",
    source_kind: "provider_native",
    version: "2026-09-01",
    digest: "e".repeat(64),
    streams: [
      {
        name,
        fields: ["date", "amount"],
        required_fields: [],
        consent_time_field: "date",
        primary_key: ["date"],
      },
      {
        name: "profile",
        fields: ["id", "display_name"],
        required_fields: [],
        primary_key: ["id"],
      },
    ],
  };
}

function requesting(name: string): SelectionRequest {
  return {
    type: PDPP_DATA_ACCESS_TYPE_V02,
    source: { id: "https://data.example.com/names" },
    purpose_code: "https://apps.example.com/purposes/budget",
    access_mode: "single_use",
    streams: [
      {
        name,
        necessity: "optional",
        fields: ["date", "amount"],
        time_range: YEAR,
      },
      { name: "profile", necessity: "optional", fields: ["id"] },
    ],
  };
}

/** A computed key is an own property even for `__proto__`, as JSON.parse makes. */
function own<T>(name: string, value: T): Record<string, T> {
  return { [name]: value };
}

function shapeOf(result: ReturnType<typeof resolveSelection>, name: string) {
  if (!result.ok)
    throw new Error(`expected resolution: ${result.failure.message}`);
  const stream = result.streams.find((s) => s.name === name);
  if (!stream) throw new Error(`stream ${JSON.stringify(name)} not resolved`);
  return stream;
}

describe.each(NAMES)("stream named %j", (name) => {
  it("keeps the ceiling when the owner narrowed only another stream", () => {
    const result = resolveSelection(
      requesting(name),
      declaring(name),
      inventory,
      {
        fields: own("profile", ["id"]),
        time_ranges: own("profile", { since: SINCE }),
      },
    );
    const stream = shapeOf(result, name);
    expect(stream.name).toBe(name);
    expect(stream.fields).toEqual(["date", "amount"]);
    expect(stream.time_range ?? stream.time_constraint).toMatchObject(YEAR);
  });

  it("applies the owner's field and window choice to that exact name", () => {
    const result = resolveSelection(
      requesting(name),
      declaring(name),
      inventory,
      {
        fields: own(name, ["date"]),
        time_ranges: own(name, { since: SINCE }),
      },
    );
    const stream = shapeOf(result, name);
    expect(stream.fields).toEqual(["date"]);
    expect(stream.time_range ?? stream.time_constraint).toMatchObject({
      since: SINCE,
      until: YEAR.until,
    });
  });
});

it("leaves Object.prototype unchanged", () => {
  const before = Object.getOwnPropertyNames(Object.prototype).sort();
  for (const name of NAMES) {
    resolveSelection(requesting(name), declaring(name), inventory, {
      fields: own(name, ["date"]),
      time_ranges: own(name, { since: SINCE }),
    });
  }
  expect(Object.getOwnPropertyNames(Object.prototype).sort()).toEqual(before);
  expect(Reflect.get({}, "since")).toBeUndefined();
  expect(Reflect.get({}, "date")).toBeUndefined();
});
