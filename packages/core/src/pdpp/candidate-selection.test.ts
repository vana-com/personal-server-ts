import { expect, it } from "vitest";
import type { OwnerChoices } from "./resolve.js";
import { resolveSelection } from "./resolve.js";
import type { DeclarationSnapshot, SelectionRequest } from "./types.js";

// Explicit opt-in profile: current v0.1 and private v0.2 keep their contracts.
export const candidateType = "https://pdpp.dev/data-access/candidate-0.1.0";
const snapshot: DeclarationSnapshot = {
  source_id: "s",
  source_kind: "connector",
  version: "1",
  digest: "d",
  streams: [
    {
      name: "required",
      fields: ["id"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
    {
      name: "optional",
      fields: ["id"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
};
it("candidate omits optional streams without affirmative owner choice", () => {
  const request = {
    type: candidateType,
    source: { id: "s" },
    purpose_code: "https://pdpp.dev/purpose/analytics",
    access_mode: "continuous",
    streams: [
      { name: "required", necessity: "required", fields: ["id"] },
      { name: "optional", necessity: "optional", fields: ["id"] },
    ],
  } as SelectionRequest;
  const resolved = resolveSelection(request, snapshot, {
    eligibleFor: () => ["i"],
  });
  expect(resolved.ok).toBe(true);
  if (resolved.ok)
    expect(resolved.streams.map((s) => s.name)).toEqual(["required"]);
});

import { validateSelectionRequest } from "./selection.js";
const base = {
  type: candidateType,
  source: { id: "s" },
  purpose_code: "https://pdpp.dev/purpose/analytics",
  access_mode: "continuous",
} as const;
it("candidate requires explicit selectors for named, wildcard and preset streams", () => {
  for (const streams of [
    [{ name: "required" }],
    [{ name: "*" }],
    [{ name: "*", fields: ["*", "id"] }],
    [{ name: "*", fields: [] }],
    [{ name: "*", fields: ["unknown"] }],
  ]) {
    expect(
      validateSelectionRequest(
        { ...base, streams } as SelectionRequest,
        snapshot,
      ).ok,
    ).toBe(false);
  }
  expect(
    validateSelectionRequest(
      {
        ...base,
        streams: [{ name: "required", fields: ["*"] }],
      } as SelectionRequest,
      snapshot,
    ).ok,
  ).toBe(true);
  expect(
    validateSelectionRequest(
      { ...base, streams: [{ name: "*", fields: ["*"] }] } as SelectionRequest,
      snapshot,
    ).ok,
  ).toBe(true);
  expect(
    validateSelectionRequest(
      { ...base, selection_preset: "p" } as SelectionRequest,
      {
        ...snapshot,
        selection_presets: [{ name: "p", streams: [{ name: "required" }] }],
      },
    ).ok,
  ).toBe(false);
});
it("candidate defaults optional, accepts affirmative choices, and refuses empty or required declines", () => {
  const request = {
    ...base,
    streams: [{ name: "required", fields: ["*"] }],
  } as SelectionRequest;
  expect(
    resolveSelection(request, snapshot, { eligibleFor: () => ["i"] }).ok,
  ).toBe(false);
  const approved = resolveSelection(
    request,
    snapshot,
    { eligibleFor: () => ["i"] },
    { approved_streams: ["required"] },
  );
  expect(approved.ok && approved.streams[0].fields).toEqual(["id"]);
  expect(
    resolveSelection(
      {
        ...request,
        streams: [{ name: "required", fields: ["id"], necessity: "required" }],
      },
      snapshot,
      { eligibleFor: () => ["i"] },
      { declined_streams: ["required"] },
    ).ok,
  ).toBe(false);
});
it("candidate freezes declared date format and validates bound type", () => {
  const declared = {
    ...snapshot,
    streams: [
      {
        ...snapshot.streams[0],
        consent_time_field: "at",
        fields: ["id", "at"],
        schema: {
          type: "object",
          properties: {
            id: { type: "string" },
            at: { type: "string", format: "date" },
          },
        },
      },
    ],
  };
  const request = {
    ...base,
    streams: [
      {
        name: "required",
        necessity: "required",
        fields: ["id"],
        time_range: { since: "2026-01-01", until: "2026-01-02" },
      },
    ],
  } as SelectionRequest;
  expect(validateSelectionRequest(request, declared).ok).toBe(true);
  const result = resolveSelection(request, declared, {
    eligibleFor: () => ["i"],
  });
  expect(result.ok && result.streams[0].time_constraint).toEqual({
    field: "at",
    type: "date",
    since: "2026-01-01",
    until: "2026-01-02",
  });
  expect(
    validateSelectionRequest(
      {
        ...request,
        streams: [
          {
            ...request.streams![0],
            time_range: { since: "2026-01-01T00:00:00Z" },
          },
        ],
      },
      declared,
    ).ok,
  ).toBe(false);
});
it("candidate preserves exact precision when intersecting owner time windows", () => {
  const declared = {
    ...snapshot,
    streams: [
      {
        ...snapshot.streams[0],
        consent_time_field: "at",
        fields: ["id", "at"],
        schema: { properties: { at: { type: "string", format: "date-time" } } },
      },
    ],
  };
  const request = {
    ...base,
    streams: [
      {
        name: "required",
        necessity: "required",
        fields: ["id"],
        time_range: { since: "2026-01-01T00:00:00.0001Z" },
      },
    ],
  } as SelectionRequest;
  const result = resolveSelection(
    request,
    declared,
    { eligibleFor: () => ["i"] },
    { time_ranges: { required: { since: "2026-01-01T00:00:00.0002Z" } } },
  );
  expect(result.ok && result.streams[0].time_constraint?.since).toBe(
    "2026-01-01T00:00:00.0002Z",
  );
});
it("candidate expands wildcard presets through the same selector resolution", () => {
  const declared = {
    ...snapshot,
    selection_presets: [
      {
        name: "p",
        streams: [{ name: "*", fields: ["*"], necessity: "required" as const }],
      },
    ],
  };
  const request = { ...base, selection_preset: "p" } as SelectionRequest;
  expect(validateSelectionRequest(request, declared).ok).toBe(true);
  const result = resolveSelection(request, declared, {
    eligibleFor: () => ["i"],
  });
  expect(result.ok && result.streams.map((s) => s.name)).toEqual([
    "required",
    "optional",
  ]);
});
it("candidate refuses declaration with non-temporal consent field even without requested bounds", () => {
  const declared = {
    ...snapshot,
    streams: [
      {
        ...snapshot.streams[0],
        consent_time_field: "id",
        schema: { properties: { id: { type: "string" } } },
      },
    ],
  };
  expect(
    validateSelectionRequest(
      { ...base, streams: [{ name: "required", fields: ["id"] }] },
      declared,
    ).ok,
  ).toBe(false);
});

it.each(["required", 42, { includes: true }, [42]])(
  "candidate rejects malformed affirmative choice %j without throwing",
  (approved) => {
    const request = {
      ...base,
      streams: [{ name: "required", fields: ["id"] }],
    } as SelectionRequest;
    expect(
      resolveSelection(
        request,
        snapshot,
        { eligibleFor: () => ["i"] },
        { approved_streams: approved as string[] },
      ).ok,
    ).toBe(false);
  },
);

it("freezes schema-required fields into candidate authority before any read", () => {
  const source = {
    ...snapshot,
    streams: [
      {
        name: "required",
        fields: ["id", "value"],
        required_fields: ["id"],
        primary_key: ["id"],
      },
    ],
  };
  const request = {
    type: candidateType,
    source: { id: "s" },
    purpose_code: "https://pdpp.dev/purpose/analytics",
    access_mode: "continuous",
    streams: [{ name: "required", necessity: "required", fields: ["value"] }],
  } as SelectionRequest;
  const result = resolveSelection(
    request,
    source,
    { eligibleFor: () => ["i"] },
    { fields: { required: ["value"] } },
  );
  expect(result.ok && result.streams[0].fields).toEqual(["value", "id"]);
});

it("rejects invalid owner bounds before intersecting them with a valid ceiling", () => {
  const source: DeclarationSnapshot = {
    ...snapshot,
    streams: [
      {
        name: "required",
        fields: ["id", "at"],
        required_fields: ["id"],
        primary_key: ["id"],
        consent_time_field: "at",
        schema: {
          type: "object",
          properties: { at: { type: "string", format: "date" } },
        },
      },
    ],
  };
  const request = {
    type: candidateType,
    source: { id: "s" },
    purpose_code: "https://pdpp.dev/purpose/analytics",
    access_mode: "continuous",
    streams: [
      {
        name: "required",
        necessity: "required",
        fields: ["id"],
        time_range: { since: "2026-01-01", until: "2026-02-01" },
      },
    ],
  } as SelectionRequest;
  const result = resolveSelection(
    request,
    source,
    { eligibleFor: () => ["i"] },
    { time_ranges: { required: { since: "January 1, 2026" } } },
  );
  expect(result.ok).toBe(false);
});
it("candidate rejects private-v0.2 minimum even on wildcard", () => {
  for (const name of ["required", "*"])
    expect(
      validateSelectionRequest(
        {
          ...base,
          streams: [{ name, fields: ["*"], minimum: { fields: ["id"] } }],
        },
        snapshot,
      ).ok,
    ).toBe(false);
});
it("candidate wildcard does not permit view shorthand", () => {
  expect(
    validateSelectionRequest(
      { ...base, streams: [{ name: "*", view: "v" }] },
      { ...snapshot, views: [{ name: "v", fields: ["id"] }] },
    ).ok,
  ).toBe(false);
});
it.each([
  { fields: { required: 42 } },
  { fields: { required: "id" } },
  { declined_streams: 42 },
  { time_ranges: { required: 42 } },
])("candidate malformed owner choices fail without throwing %j", (choices) => {
  const result = resolveSelection(
    {
      ...base,
      streams: [{ name: "required", necessity: "required", fields: ["id"] }],
    },
    snapshot,
    { eligibleFor: () => ["i"] },
    choices as OwnerChoices,
  );
  expect(result.ok).toBe(false);
});
it.each([
  { approved_streams: ["unknown"] },
  { declined_streams: ["optional"] },
  { approved_streams: ["required"], declined_streams: ["required"] },
  { fields: { unknown: ["id"] } },
  { time_ranges: { unknown: { since: "2026-01-01" } } },
])("candidate rejects choices outside request and overlap %j", (choices) => {
  expect(
    resolveSelection(
      {
        ...base,
        streams: [{ name: "required", necessity: "required", fields: ["id"] }],
      },
      snapshot,
      { eligibleFor: () => ["i"] },
      choices,
    ).ok,
  ).toBe(false);
});
