/**
 * Oracles for v0.2 request resolution under owner choices.
 *
 * Anchors: PR vana-com/pdpp#1 spec-core.md "Limits and owner choices",
 * "Explicit authorization minima", and the
 * `authorization-disclosure-contract` requirement "Request resolution SHALL
 * preserve explicit limits and owner choices".
 *
 * The property under test: the request is the ceiling, the minimum is the
 * floor, and the owner moves freely between them. Three failure directions
 * each get their own outcome, and conflating any two of them is the bug this
 * file exists to catch:
 *
 *   - owner narrows *above* the floor  -> issue the narrowed grant
 *   - owner narrows *below* a required floor -> refuse issuance entirely
 *   - owner narrows *below* an optional floor -> drop that whole stream
 *   - owner tries to widen past the ceiling -> the ceiling holds, silently
 */

import { describe, expect, it } from "vitest";
import { resolveSelection, type InstanceInventory } from "./resolve.js";
import {
  PDPP_DATA_ACCESS_TYPE,
  PDPP_DATA_ACCESS_TYPE_V02,
  type DeclarationSnapshot,
  type SelectionRequest,
  type StreamRequest,
} from "./types.js";

const snapshot: DeclarationSnapshot = {
  source_id: "https://data.example.com/finance",
  source_kind: "provider_native",
  version: "2026-09-01",
  digest: "f".repeat(64),
  streams: [
    {
      name: "transactions",
      fields: ["date", "amount", "merchant", "private_note"],
      // A schema floor under v0.1. v0.2 revokes its consent effect, and
      // several tests below assert exactly that.
      required_fields: ["date", "private_note"],
      consent_time_field: "date",
      primary_key: ["date"],
    },
    {
      name: "profile",
      fields: ["id", "display_name", "country"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
};

const singleInstance: InstanceInventory = {
  eligibleFor: () => ["account_example"],
};

const YEAR = { since: "2025-01-01T00:00:00Z", until: "2026-01-01T00:00:00Z" };
const Q4 = { since: "2025-10-01T00:00:00Z", until: "2026-01-01T00:00:00Z" };
const DECEMBER = {
  since: "2025-12-01T00:00:00Z",
  until: "2026-01-01T00:00:00Z",
};

function v02(streams: StreamRequest[]): SelectionRequest {
  return {
    type: PDPP_DATA_ACCESS_TYPE_V02,
    source: { id: snapshot.source_id },
    purpose_code: "https://apps.example.com/purposes/budget",
    access_mode: "single_use",
    streams,
  };
}

/** PR #1's examples.md request: twelve-month ceiling, three-month floor. */
function transactions(overrides: Partial<StreamRequest> = {}): StreamRequest {
  return {
    name: "transactions",
    necessity: "required",
    fields: ["date", "amount", "merchant"],
    time_range: YEAR,
    minimum: { fields: ["date", "amount"], time_range: Q4 },
    ...overrides,
  };
}

function resolve(
  request: SelectionRequest,
  choices?: Parameters<typeof resolveSelection>[3],
) {
  return resolveSelection(request, snapshot, singleInstance, choices);
}

describe("v0.2 schema-required fields are no longer a consent floor", () => {
  it("omits a schema-required field the request did not ask for", () => {
    // PR #1 scenario "Schema-required field is withheld". `private_note` is
    // in the stream's `required_fields`; under v0.1 resolution it was unioned
    // in unconditionally. v0.2 makes the schema describe a complete record,
    // not the owner's permission to disclose a field.
    const result = resolve(v02([transactions()]));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams[0].fields).toEqual(["date", "amount", "merchant"]);
    expect(result.streams[0].fields).not.toContain("private_note");
  });

  it("does not union a primary-key or consent-time field into the grant", () => {
    // PR #1 scenario "No implicit key or time-field data union".
    const result = resolve(
      v02([{ name: "transactions", fields: ["merchant"] }]),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams[0].fields).toEqual(["merchant"]);
  });

  it("keeps the v0.1 consent floor for a v0.1 request", () => {
    // The revisions coexist. The same body under the v0.1 type must resolve
    // exactly as it did before, floor included.
    const result = resolveSelection(
      {
        type: PDPP_DATA_ACCESS_TYPE,
        source: { id: snapshot.source_id },
        purpose_code: "https://pdpp.dev/purpose/portability",
        access_mode: "single_use",
        streams: [{ name: "transactions", fields: ["amount"] }],
      },
      snapshot,
      singleInstance,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams[0].fields).toEqual(["amount", "date", "private_note"]);
  });
});

describe("owner narrowing within the request limits", () => {
  it("narrows fields down to the minimum", () => {
    const result = resolve(v02([transactions()]), {
      fields: { transactions: ["date", "amount"] },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams[0].fields).toEqual(["date", "amount"]);
  });

  it("narrows the time window down to the minimum window", () => {
    const result = resolve(v02([transactions()]), {
      time_ranges: { transactions: Q4 },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams[0].time_constraint).toEqual({
      field: "date",
      ...Q4,
    });
  });

  it("retains a narrowed required stream rather than treating it as removed", () => {
    // PR #1 scenario "Required stream remains required": narrowing is not
    // refusal while the explicit minimum still holds.
    const result = resolve(v02([transactions()]), {
      fields: { transactions: ["date", "amount"] },
      time_ranges: { transactions: Q4 },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams.map((s) => s.name)).toEqual(["transactions"]);
  });

  it("cannot widen fields past the requested upper limit", () => {
    // The request is the ceiling. A choice naming `private_note` -- declared
    // by the schema but not requested -- resolves to the intersection, so an
    // owner choice can never become an escalation path.
    const result = resolve(v02([transactions()]), {
      fields: { transactions: ["date", "amount", "private_note"] },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams[0].fields).toEqual(["date", "amount"]);
  });

  it("cannot widen the time window past the requested upper limit", () => {
    const result = resolve(v02([transactions()]), {
      time_ranges: {
        transactions: { since: "2020-01-01T00:00:00Z", until: YEAR.until },
      },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams[0].time_constraint).toEqual({
      field: "date",
      ...YEAR,
    });
  });

  it("applies an owner window to a stream the request left unbounded", () => {
    const result = resolve(
      v02([{ name: "transactions", fields: ["date", "amount"] }]),
      { time_ranges: { transactions: Q4 } },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams[0].time_constraint).toEqual({ field: "date", ...Q4 });
  });
});

describe("required-stream minima refuse issuance", () => {
  it("refuses when a required stream cannot meet its field minimum", () => {
    // PR #1 scenario "Required field minimum is denied": refuse, and do not
    // issue a weaker grant for that stream.
    const result = resolve(v02([transactions()]), {
      fields: { transactions: ["date"] },
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("minimum_not_met");
    expect(result.failure.stream).toBe("transactions");
  });

  it("refuses when a required stream's window is narrower than its minimum", () => {
    // PR #1 scenario "Minimum window is not satisfied": requests
    // January-December, requires October-December, owner approves December.
    const result = resolve(v02([transactions()]), {
      time_ranges: { transactions: DECEMBER },
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("minimum_not_met");
  });

  it("accepts a window strictly containing the minimum window", () => {
    const result = resolve(v02([transactions()]), {
      time_ranges: {
        transactions: { since: "2025-09-01T00:00:00Z", until: YEAR.until },
      },
    });
    expect(result.ok).toBe(true);
  });

  it("treats an absent resolved bound as infinite, satisfying any floor", () => {
    // A stream whose request carries no window and whose owner narrows only
    // fields resolves to an unbounded window, which contains every floor.
    const result = resolve(
      v02([
        {
          name: "transactions",
          fields: ["date", "amount"],
          minimum: { time_range: Q4 },
        },
      ]),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams[0].time_constraint).toBeUndefined();
  });

  it("refuses a declined required stream", () => {
    const result = resolve(v02([transactions()]), {
      declined_streams: ["transactions"],
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("required_stream_declined");
  });

  it("treats an unmarked stream as required", () => {
    // `necessity` defaults to `required`, so an unmarked stream cannot be
    // declined either.
    const result = resolve(
      v02([{ name: "transactions", fields: ["date", "amount"] }]),
      { declined_streams: ["transactions"] },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("required_stream_declined");
  });
});

describe("optional-stream minima drop the stream", () => {
  const withOptional = () =>
    v02([
      transactions(),
      {
        name: "profile",
        necessity: "optional",
        fields: ["id", "display_name", "country"],
        minimum: { fields: ["id", "display_name"] },
      },
    ]);

  it("drops an optional stream the owner declined", () => {
    const result = resolve(withOptional(), {
      declined_streams: ["profile"],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams.map((s) => s.name)).toEqual(["transactions"]);
    expect(result.omittedStreams).toEqual(["profile"]);
  });

  it("drops the whole optional stream rather than retain a weaker projection", () => {
    // PR #1 scenario "Optional field minimum is omitted with its stream".
    const result = resolve(withOptional(), {
      fields: { profile: ["id"] },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams.map((s) => s.name)).toEqual(["transactions"]);
    expect(result.omittedStreams).toEqual(["profile"]);
  });

  it("retains an optional stream whose minimum is met", () => {
    const result = resolve(withOptional(), {
      fields: { profile: ["id", "display_name"] },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams.map((s) => s.name)).toEqual([
      "transactions",
      "profile",
    ]);
    expect(result.streams[1].fields).toEqual(["id", "display_name"]);
    expect(result.omittedStreams).toBeUndefined();
  });

  it("refuses issuance when the owner approves no streams", () => {
    // PR #1 scenario "All optional streams are declined" and the "MUST refuse
    // issuance when the owner approves no streams" rule: no empty grant, and
    // no compensating stream added in place of the refused selection.
    const result = resolve(
      v02([
        { name: "transactions", necessity: "optional", fields: ["amount"] },
        { name: "profile", necessity: "optional", fields: ["id"] },
      ]),
      { declined_streams: ["transactions", "profile"] },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("no_streams_approved");
  });

  it("refuses when narrowing empties the last remaining stream", () => {
    const result = resolve(
      v02([
        {
          name: "profile",
          necessity: "optional",
          fields: ["id", "display_name"],
          minimum: { fields: ["display_name"] },
        },
      ]),
      { fields: { profile: ["id"] } },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("no_streams_approved");
  });

  it("refuses when an owner narrows a stream to no fields at all", () => {
    // The resolved selection must contain at least one field per retained
    // stream. A no-field choice on the only stream is a refusal, not an
    // all-fields default -- treating an explicit empty choice as "everything"
    // would invert the owner's decision.
    const result = resolve(
      v02([{ name: "profile", fields: ["id", "display_name"] }]),
      { fields: { profile: [] } },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("empty_field_set");
  });
});

describe("resolution ignores owner choices under v0.1", () => {
  it("does not let a v0.1 request be narrowed by owner choices", () => {
    // v0.1 has no narrowing step, so passing choices alongside a v0.1 request
    // must not quietly change what that revision resolves. A v0.1 client's
    // grant is the same one it has always received.
    const result = resolveSelection(
      {
        type: PDPP_DATA_ACCESS_TYPE,
        source: { id: snapshot.source_id },
        purpose_code: "https://pdpp.dev/purpose/portability",
        access_mode: "single_use",
        streams: [{ name: "profile", fields: ["id", "display_name"] }],
      },
      snapshot,
      singleInstance,
      { fields: { profile: ["id"] }, declined_streams: ["profile"] },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams[0].fields).toEqual(["id", "display_name"]);
  });
});
