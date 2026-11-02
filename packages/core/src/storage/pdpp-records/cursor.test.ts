import { expect, it } from "vitest";
import { encodeCursor, validateCursor } from "./cursor.js";

it("expires enabled-mode cursors with no saved visibility epoch", () => {
  const cursor = encodeCursor({
    kind: "list",
    order: "asc",
    sortValue: "2026-01-01T00:00:00.000Z",
    recordKey: "a",
  });

  expect(validateCursor(cursor, { visibilityEpoch: "epoch-1" })).toEqual({
    kind: "expired",
  });
});

it("expires an epoch-bound cursor when the projection epoch has moved", () => {
  const cursor = encodeCursor({
    kind: "list",
    order: "asc",
    sortValue: null,
    recordKey: "a",
    visibilityEpoch: "epoch-1",
  });

  expect(validateCursor(cursor, { visibilityEpoch: "epoch-2" })).toEqual({
    kind: "expired",
  });
});

it("keeps the legacy flag-off cursor bytes unchanged", () => {
  expect(
    encodeCursor({
      kind: "list",
      order: "asc",
      sortValue: "2026-01-01T00:00:00.000Z",
      recordKey: "a",
    }),
  ).toBe(
    "eyJraW5kIjoibGlzdCIsIm9yZGVyIjoiYXNjIiwic29ydFZhbHVlIjoiMjAyNi0wMS0wMVQwMDowMDowMC4wMDBaIiwicmVjb3JkS2V5IjoiYSJ9",
  );
});
