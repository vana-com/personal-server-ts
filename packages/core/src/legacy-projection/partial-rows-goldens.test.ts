import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { projectPdppRecordsToLegacyPayload } from "./index.js";
import type { PdppRecord } from "./types.js";

// Rows the source reports short of detail (records_partial) keep a legacy
// file from being taken over. These are the only scopes that report them.
// Their parity goldens show which inputs do and which do not.
interface Golden {
  case?: string;
  fetchedStreams?: string[];
  streams?: Record<string, Record<string, unknown>[]>;
  profileKey?: string;
  cases?: Golden[];
}

function partialReasons(scope: string): Record<string, string[]> {
  const golden = JSON.parse(
    readFileSync(
      new URL(`./__fixtures__/parity/${scope}.json`, import.meta.url),
      "utf8",
    ),
  ) as Golden;
  return Object.fromEntries(
    [golden, ...(golden.cases ?? [])].map((entry) => {
      const records: PdppRecord[] = Object.entries(entry.streams ?? {}).flatMap(
        ([stream, rows]) => rows.map((data) => ({ stream, data })),
      );
      const result = projectPdppRecordsToLegacyPayload(scope, records, {
        fetchedStreams: entry.fetchedStreams ?? golden.fetchedStreams ?? [],
        now: "2026-10-01T00:00:00.000Z",
        ...(entry.profileKey ? { profileKey: entry.profileKey } : {}),
      });
      if (!result.ok) throw new Error(`${scope} ${entry.case}: rejected`);
      return [
        entry.case ?? "normal",
        (result.diagnostics ?? []).flatMap((diagnostic) =>
          diagnostic.kind === "records_partial" ? diagnostic.reasons : [],
        ),
      ];
    }),
  );
}

describe("parity goldens that would keep a legacy file", () => {
  it.each([
    ["claude.conversations", { normal: [] }],
    [
      "heb.orders",
      {
        normal: [],
        empty: [],
        "dirty-row": ["projection_order_unit_count_mismatch"],
      },
    ],
    [
      "wholefoods.orders",
      {
        normal: [],
        empty: [],
        "dirty-row": ["projection_order_item_count_mismatch"],
      },
    ],
  ])("%s", (scope, expected) => {
    expect(partialReasons(scope)).toEqual(expected);
  });
});
