/**
 * The independent review's finding 2 repro, and the rule it forced.
 *
 * The finding: `{"name": "*", "time_range": {...}}` was accepted by validation
 * without checking the streams it expands to, and resolution then set
 * `time_range: undefined` for every stream with no `consent_time_field`. On a
 * mixed-capability source the client asked for a bounded window and the owner
 * was shown, and issued, an *unbounded* grant on the untimed streams. The
 * request's own words said less than the grant it produced.
 *
 * §6 already states the rule for a named stream: "the declaration's
 * consent_time_field is the authoritative signal that a stream is
 * time-range-capable. No field, no time_range." A wildcard is a shorthand for
 * naming every declared stream, so it cannot mean something weaker than
 * naming them — the same request written out longhand is rejected. That is
 * the reading this file pins, with the same error code the longhand form
 * already returns, so a client sees one rule rather than two.
 *
 * The alternative — an explicit per-stream wildcard rule under which a
 * time-incapable stream is silently exempt — is not available to us: it is
 * not in the contract, and inventing it here would be the AS deciding on the
 * owner's behalf that unbounded access to those streams is what was meant.
 */

import { describe, expect, it } from "vitest";
import { validateSelectionRequest } from "./selection.js";
import { resolveSelection, type InstanceInventory } from "./resolve.js";
import {
  PDPP_DATA_ACCESS_TYPE,
  PDPP_DATA_ACCESS_TYPE_V02,
  type DeclarationSnapshot,
  type SelectionRequest,
  type StreamRequest,
} from "./types.js";

/** One timed stream and one untimed stream — the reviewer's exact shape. */
const mixed: DeclarationSnapshot = {
  source_id: "https://data.example.com/finance",
  source_kind: "provider_native",
  version: "2026-09-01",
  digest: "a".repeat(64),
  streams: [
    {
      name: "transactions",
      fields: ["date", "amount", "merchant"],
      required_fields: ["date"],
      consent_time_field: "date",
      primary_key: ["date"],
    },
    {
      // No consent_time_field: cannot carry a time window at all.
      name: "profile",
      fields: ["id", "display_name"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
};

/** Every declared stream is time-range-capable. */
const allTimed: DeclarationSnapshot = {
  ...mixed,
  streams: [
    mixed.streams[0],
    {
      name: "play_events",
      fields: ["track_id", "played_at"],
      required_fields: ["track_id"],
      consent_time_field: "played_at",
      primary_key: ["track_id"],
    },
  ],
};

const window = {
  since: "2025-01-01T00:00:00Z",
  until: "2026-01-01T00:00:00Z",
};

function request(
  streams: StreamRequest[],
  type: string = PDPP_DATA_ACCESS_TYPE_V02,
  source: DeclarationSnapshot = mixed,
): SelectionRequest {
  return {
    type,
    source: { id: source.source_id },
    purpose_code: "https://apps.example.com/purposes/budget",
    access_mode: "single_use",
    streams,
  } as SelectionRequest;
}

const inventory: InstanceInventory = {
  eligibleFor: () => ["inst_1"],
};

describe("review finding 2 — a wildcard time_range is validated per expanded stream", () => {
  it("rejects a wildcard time_range when any expanded stream cannot carry one", () => {
    const result = validateSelectionRequest(
      request([{ name: "*", time_range: window }]),
      mixed,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    // The same code the longhand `{"name":"profile", time_range}` returns:
    // one rule for the client, not two.
    expect(result.failure.code).toBe("unsupported_selection_parameter");
    // The message names the stream that cannot carry it, so the client can
    // fix the request without guessing which of the expanded streams failed.
    expect(result.failure.message).toContain("profile");
  });

  it("rejects it identically under v0.1, which has the same §6 rule", () => {
    const result = validateSelectionRequest(
      request([{ name: "*", time_range: window }], PDPP_DATA_ACCESS_TYPE),
      mixed,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("unsupported_selection_parameter");
  });

  it("still accepts a wildcard time_range when every expanded stream can carry one", () => {
    const result = validateSelectionRequest(
      request(
        [{ name: "*", time_range: window }],
        PDPP_DATA_ACCESS_TYPE_V02,
        allTimed,
      ),
      allTimed,
    );
    expect(result.ok).toBe(true);
  });

  it("still accepts a wildcard carrying no time_range against a mixed source", () => {
    // The wildcard itself is not what is being rejected. This is the case the
    // fix must leave alone.
    const result = validateSelectionRequest(request([{ name: "*" }]), mixed);
    expect(result.ok).toBe(true);
  });

  it("never issues an unbounded grant on a stream the wildcard's window named", () => {
    // The disclosure half of the same finding, asserted where the harm is:
    // whatever survives validation, no resolved stream may end up with no
    // time constraint while the request carried a window.
    const req = request([{ name: "*", time_range: window }]);
    if (validateSelectionRequest(req, mixed).ok) {
      const resolution = resolveSelection(req, mixed, inventory);
      if (resolution.ok) {
        for (const stream of resolution.streams) {
          expect(stream.time_constraint).toBeDefined();
        }
      }
    }
    // And, as this implementation resolves it, validation refuses first.
    expect(validateSelectionRequest(req, mixed).ok).toBe(false);
  });

  // Found while fixing the above, and the same defect class: the wildcard
  // path returned before any of the named path's bound checks, so a window
  // the longhand form rejects outright was accepted as a wildcard.
  it.each([
    ["unparseable bounds", { since: "not-a-date", until: "also-not" }],
    [
      "inverted bounds",
      { since: "2026-01-01T00:00:00Z", until: "2025-01-01T00:00:00Z" },
    ],
    ["an empty window", {}],
    ["non-string bounds", { since: 1735689600, until: 1767225600 }],
  ])("rejects a wildcard time_range with %s", (_label, time_range) => {
    const result = validateSelectionRequest(
      request(
        [{ name: "*", time_range } as StreamRequest],
        PDPP_DATA_ACCESS_TYPE_V02,
        allTimed,
      ),
      allTimed,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_request");
  });

  it("leaves an every-stream-timed wildcard resolving with its window intact", () => {
    const req = request(
      [{ name: "*", time_range: window }],
      PDPP_DATA_ACCESS_TYPE_V02,
      allTimed,
    );
    const resolution = resolveSelection(req, allTimed, inventory);
    expect(resolution.ok).toBe(true);
    if (!resolution.ok) return;
    expect(resolution.streams).toHaveLength(2);
    for (const stream of resolution.streams) {
      expect(stream.time_constraint?.since).toBe(window.since);
      expect(stream.time_constraint?.until).toBe(window.until);
    }
  });
});
