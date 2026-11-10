import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  decideReplace,
  replaceMayApply,
  type ReplaceInput,
} from "./replace.js";

const bytes = readFileSync(
  new URL("./replace-conformance.json", import.meta.url),
);
const fixture = JSON.parse(bytes.toString()) as {
  cases: {
    id: string;
    input: ReplaceInput;
    replace: boolean;
    source: { commit: string; path: string };
  }[];
};
const SHA256 =
  "4b0a9b5c1fe647e2437811c893f9b0a47de125d2863ad25515a31e028ed7e180";

it("pins all 18 historical producer cases and #560 cases 1-5", () => {
  expect(createHash("sha256").update(bytes).digest("hex")).toBe(SHA256);
  expect(fixture.cases.filter((c) => c.id.startsWith("2208-"))).toHaveLength(
    18,
  );
  expect(fixture.cases.filter((c) => c.id.startsWith("560-"))).toHaveLength(5);
  expect(new Set(fixture.cases.map((c) => c.id)).size).toBe(23);
  expect(
    fixture.cases.every((c) => /^[a-f0-9]{40}$/.test(c.source.commit)),
  ).toBe(true);
  expect(fixture.cases.every((c) => /\.(?:ts|json)$/.test(c.source.path))).toBe(
    true,
  );
});

describe("decideReplace sourced conformance", () => {
  it.each(fixture.cases)("$id", (c) =>
    expect(decideReplace(c.input)).toBe(c.replace),
  );
});

it.each(["failed", "cancelled", "retry_pending"] as const)(
  "%s never replaces even if the caller lists proof",
  (outcome) => {
    expect(
      decideReplace({
        stream: "items",
        outcome,
        collectionMode: "full_refresh",
        coveredStreams: ["items"],
        provenFullStreams: ["items"],
      }),
    ).toBe(false);
  },
);

it("requires the same stream in both coverage and this run's proof", () => {
  const input: ReplaceInput = {
    stream: "items",
    outcome: "partial",
    collectionMode: "full_refresh",
    coveredStreams: ["items"],
    provenFullStreams: ["other"],
  };
  expect(decideReplace(input)).toBe(false);
  expect(
    decideReplace({
      ...input,
      coveredStreams: ["other"],
      provenFullStreams: ["items"],
    }),
  ).toBe(false);
});

it("never treats an unknown or changed basis as the recorded basis", () => {
  expect(
    replaceMayApply(
      { basisVersion: null, basisDataHash: null, basisKnown: true },
      null,
    ),
  ).toBe(true);
  expect(
    replaceMayApply(
      { basisVersion: null, basisDataHash: null },
      { version: 1, dataHash: "0xaa" },
    ),
  ).toBe(false);
  expect(
    replaceMayApply({ basisVersion: 1, basisDataHash: "0xaa" }, null),
  ).toBe(false);
  expect(
    replaceMayApply(
      { basisVersion: 1, basisDataHash: "0xaa" },
      { version: 2, dataHash: "0xaa" },
    ),
  ).toBe(false);
  expect(
    replaceMayApply(
      { basisVersion: 1, basisDataHash: "0xaa" },
      { version: 1, dataHash: "0xbb" },
    ),
  ).toBe(false);
});

it("a missing basis is not a recorded absent head", () => {
  expect(
    replaceMayApply({ basisVersion: null, basisDataHash: null }, null),
  ).toBe(false);
});
