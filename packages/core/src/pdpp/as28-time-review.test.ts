/**
 * AS item 28 (spec-core L2544, §5 L877-L887): the review payload of a
 * time-bounded stream carries `time_constraint.type`, the field's declared
 * meaning (`time_constraint.meaning`, chosen in the review's language), and
 * the stream's `consent_time_content_may_exceed`. The meaning is also a
 * declaration display value shown on final review, so it is listed in
 * `display_values` and bound into the review digest (AS item 34).
 *
 * Also AS item 27's declaration half: a non-boolean
 * `consent_time_content_may_exceed` and a `display.fields` key that names no
 * declared field are rejected at acceptance.
 */

import { describe, expect, it } from "vitest";
import { parseDeclaration } from "./declaration.js";
import { resolveSelection } from "./resolve.js";
import { buildConsentReview, type RequesterIdentity } from "./review.js";
import {
  PDPP_DATA_ACCESS_TYPE,
  type DeclarationSnapshot,
  type SelectionRequest,
} from "./types.js";

const SOURCE = "https://registry.pdpp.dev/connectors/ynab";

function declaration(
  overrides: {
    mayExceed?: unknown;
    fieldsDisplay?: unknown;
    transactionsMeaning?: unknown;
  } = {},
): string {
  return JSON.stringify({
    protocol_version: "0.1.0",
    source: { kind: "connector", id: SOURCE },
    declaration_version: "v1",
    display: { name: "YNAB", default_language: "en" },
    streams: [
      {
        name: "transactions",
        semantics: "append_only",
        primary_key: ["id"],
        consent_time_field: "booked_at",
        display: {
          label: "Transactions",
          fields:
            overrides.fieldsDisplay !== undefined
              ? overrides.fieldsDisplay
              : {
                  booked_at: {
                    meaning: overrides.transactionsMeaning ?? {
                      en: "When the bank booked the payment",
                      es: "Cuando el banco registró el pago",
                    },
                  },
                },
        },
        schema: {
          type: "object",
          properties: {
            id: { type: "string" },
            booked_at: { type: "string", format: "date-time" },
            amount: { type: "number" },
          },
          required: ["id"],
        },
      },
      {
        name: "months",
        semantics: "mutable_state",
        primary_key: ["month"],
        consent_time_field: "month",
        ...(overrides.mayExceed !== undefined
          ? { consent_time_content_may_exceed: overrides.mayExceed }
          : { consent_time_content_may_exceed: true }),
        schema: {
          type: "object",
          properties: {
            month: { type: "string", format: "date" },
            budgeted: { type: "number" },
          },
          required: ["month"],
        },
      },
      {
        name: "accounts",
        semantics: "mutable_state",
        primary_key: ["id"],
        schema: {
          type: "object",
          properties: { id: { type: "string" } },
          required: ["id"],
        },
      },
    ],
  });
}

function snapshotOf(body: string): DeclarationSnapshot {
  const result = parseDeclaration(body, SOURCE);
  if (!result.ok) throw new Error(result.failure.message);
  return result.snapshot;
}

const requester: RequesterIdentity = {
  client_id: "client-a",
  display_name: "Budget Coach",
  app_approved: false,
};

function request(): SelectionRequest {
  return {
    type: PDPP_DATA_ACCESS_TYPE,
    source: { id: SOURCE },
    purpose_code: "https://pdpp.dev/purpose/personalization",
    access_mode: "continuous",
    streams: [
      {
        name: "transactions",
        fields: ["*"],
        time_range: { since: "2026-01-01T00:00:00Z" },
      },
      {
        name: "months",
        fields: ["*"],
        time_range: { since: "2026-01-01", until: "2026-07-01" },
      },
      { name: "accounts", fields: ["*"] },
    ],
  };
}

function review(snapshot: DeclarationSnapshot, languagePriority: string[]) {
  const req = request();
  const resolved = resolveSelection(req, snapshot, {
    eligibleFor: () => ["i1"],
  });
  if (!resolved.ok) throw new Error(resolved.failure.message);
  return buildConsentReview({
    subjectId: "s",
    request: req,
    snapshot,
    resolvedStreams: resolved.streams,
    requester,
    languagePriority,
  });
}

describe("AS item 28 — time-bounded review payload", () => {
  it("sends type, the localized declared meaning and may_exceed per time-bounded stream", () => {
    const r = review(snapshotOf(declaration()), ["es-MX"]);
    // Through a JSON round-trip, exactly as the broker reads it.
    const wire = JSON.parse(JSON.stringify(r)) as {
      data: { streams: Array<Record<string, unknown>> };
      display_values: Array<Record<string, unknown>>;
    };
    const byName = Object.fromEntries(
      wire.data.streams.map((s) => [s.name as string, s]),
    );
    expect(byName.transactions.time_constraint).toEqual({
      field: "booked_at",
      type: "date-time",
      since: "2026-01-01T00:00:00Z",
      meaning: "Cuando el banco registró el pago",
    });
    expect(byName.transactions.consent_time_content_may_exceed).toBe(false);
    expect(byName.months.time_constraint).toEqual({
      field: "month",
      type: "date",
      since: "2026-01-01",
      until: "2026-07-01",
    });
    expect(byName.months.consent_time_content_may_exceed).toBe(true);
    // A stream with no time bound carries neither member.
    expect(byName.accounts.time_constraint).toBeUndefined();
    expect("consent_time_content_may_exceed" in byName.accounts).toBe(false);
    expect(wire.display_values).toContainEqual({
      id: "streams[transactions].display.fields.booked_at.meaning",
      value: "Cuando el banco registró el pago",
      language: "es",
    });
  });

  it("uses the default-language meaning when no preference matches", () => {
    const r = review(snapshotOf(declaration()), []);
    expect(r.data.streams[0].time_constraint?.meaning).toBe(
      "When the bank booked the payment",
    );
  });

  it("binds the meaning into the digest (AS item 34)", () => {
    const en = review(snapshotOf(declaration()), ["en"]);
    const es = review(snapshotOf(declaration()), ["es"]);
    expect(en.review_digest).not.toBe(es.review_digest);
    const other = review(
      snapshotOf(declaration({ transactionsMeaning: "Booking date" })),
      ["en"],
    );
    expect(other.review_digest).not.toBe(en.review_digest);
  });

  it("omits meaning when the declaration states none, leaving the surface's own words", () => {
    const r = review(snapshotOf(declaration({ fieldsDisplay: {} })), ["en"]);
    expect(r.data.streams[0].time_constraint?.meaning).toBeUndefined();
    expect(
      r.display_values?.some((v) => v.id.includes("display.fields")),
    ).toBe(false);
  });

  it("defaults consent_time_content_may_exceed to false when undeclared", () => {
    const body = JSON.parse(declaration()) as {
      streams: Array<Record<string, unknown>>;
    };
    delete body.streams[1].consent_time_content_may_exceed;
    const r = review(snapshotOf(JSON.stringify(body)), ["en"]);
    expect(r.data.streams[1].consent_time_content_may_exceed).toBe(false);
  });
});

describe("AS item 27 — declaration acceptance of the new members", () => {
  it.each([["true"], [1], [null]])(
    "rejects a non-boolean consent_time_content_may_exceed (%s)",
    (value) => {
      const result = parseDeclaration(
        declaration({ mayExceed: value }),
        SOURCE,
      );
      expect(result.ok).toBe(false);
    },
  );

  it("rejects a display.fields key that names no declared field", () => {
    const result = parseDeclaration(
      declaration({ fieldsDisplay: { posted_at: { meaning: "x" } } }),
      SOURCE,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.message).toMatch(/posted_at/);
  });

  it("rejects a display.fields entry that is not an object", () => {
    const result = parseDeclaration(
      declaration({ fieldsDisplay: { booked_at: "When booked" } }),
      SOURCE,
    );
    expect(result.ok).toBe(false);
  });
});
