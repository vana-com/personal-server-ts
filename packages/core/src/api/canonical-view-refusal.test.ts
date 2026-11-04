import { describe, expect, it } from "vitest";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "./index.js";
import type {
  LegacyScopeLatest,
  LegacyScopeRefusal,
} from "../storage/legacy-scope-view.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";

const scope = "chatgpt.conversations";
const refusals = [
  { status: "unavailable", reason: "no_connection", candidates: 0 },
  { status: "unavailable", reason: "ambiguous_connection", candidates: 2 },
  {
    status: "unavailable",
    reason: "connection_unavailable",
    detail: "method_not_configured",
  },
  {
    status: "incomplete",
    reason: "canonical_view_incomplete",
    confirmation: "confirmed",
    diagnostics: [{ stream: "messages", kind: "omitted", detail: "one row" }],
  },
  {
    status: "incomplete",
    reason: "canonical_view_incomplete",
    confirmation: "unconfirmed",
    diagnostics: [],
  },
  {
    status: "unavailable",
    reason: "store_inconsistent_read",
    detail: "indexed legacy head could not be read",
  },
  {
    status: "unavailable",
    reason: "unbound_scope",
    lookup: { kind: "unknown_scope", scope },
  },
  { status: "unavailable", reason: "scope_source_mismatch", scope },
  { status: "unavailable", reason: "no_synced_data" },
  {
    status: "unavailable",
    reason: "stream_completion_unknown",
    streams: ["messages"],
  },
  { status: "unavailable", reason: "invalid_collected_at" },
  {
    status: "unavailable",
    reason: "blob_backed_records_unsupported",
    stream: "messages",
    recordCount: 1,
    blocker: "byte reader unavailable",
  },
  {
    status: "unavailable",
    reason: "blob_read_budget_exceeded",
    requiredBytes: 2,
    maxBytes: 1,
  },
  {
    status: "unavailable",
    reason: "blob_backed_record_invalid",
    detail: "source bytes invalid",
  },
  { status: "unavailable", reason: "missing_raw_blob", recordCount: 1 },
  {
    status: "incomplete",
    reason: "projection_rejected",
    error: { kind: "empty_singleton", scope },
    sourceRowCounts: { messages: 1 },
  },
  {
    status: "incomplete",
    reason: "all_rows_rejected",
    stream: "messages",
    sourceRows: 1,
    dropped: 1,
    reasons: ["invalid source"],
    sourceRowCounts: { messages: 1 },
  },
] as const satisfies readonly LegacyScopeRefusal[];

async function request(latest: LegacyScopeLatest, paid = false) {
  const deps: PersonalServerDataApiDeps = {
    storage: createMemoryDataStorage(),
    legacyScopeView: {
      readLatest: async () => latest,
      legacyFileReadRefusal: () => null,
      listingFor: () => ({ kind: "refused" }),
      listCanonicalScopes: () => [],
      ownsScope: () => true,
      verdictFor: () => [],
      resetTakeover: () => {},
      isReset: () => false,
    },
    auth: {
      authorizeOwner: async () => {},
      authorizeBuilderList: async () => {},
      authorizeBuilderRead: async () => ({
        builder: "0x1111111111111111111111111111111111111111",
        grantId: "synthetic-grant",
      }),
    },
    accessLogWriter: { write: async () => {} },
    logger: { debug: () => {} },
    ...(paid
      ? {
          paymentEnabled: true,
          gateway: {} as NonNullable<PersonalServerDataApiDeps["gateway"]>,
          gatewayConfig: {} as NonNullable<
            PersonalServerDataApiDeps["gatewayConfig"]
          >,
          gatewayUrl: "https://gateway.test",
        }
      : {}),
  };
  return handlePersonalServerDataRequest(
    new Request(`https://ps.test/v1/data/${scope}`),
    deps,
    { basePath: "/v1/data" },
  );
}

function envelope(reason: string, status: string, retryable: boolean) {
  return {
    error: "CANONICAL_VIEW_UNAVAILABLE",
    retryable,
    message: `The latest data for scope "${scope}" cannot be served from the owner's connector records (${reason}).`,
    status,
    reason,
  };
}

describe("canonical refusal envelopes", () => {
  it.each(refusals)(
    "$reason ($status): explicit retryability",
    async (refusal) => {
      const response = await request({ kind: "refused", refusal });
      expect(response.status).toBe(
        refusal.reason === "ambiguous_connection" ? 409 : 503,
      );
      expect(await response.json()).toEqual({
        ...envelope(
          refusal.reason,
          refusal.status,
          refusal.reason === "canonical_view_incomplete" &&
            refusal.confirmation === "unconfirmed",
        ),
        ...("detail" in refusal ? { detail: refusal.detail } : {}),
        ...("streams" in refusal ? { streams: refusal.streams } : {}),
        ...("stream" in refusal ? { stream: refusal.stream } : {}),
        ...("candidates" in refusal ? { candidates: refusal.candidates } : {}),
      });
    },
  );

  it("paid_read_unsupported: explicit final refusal", async () => {
    const response = await request(
      {
        kind: "canonical",
        revision: "synthetic",
        envelope: {
          version: "1.0",
          scope,
          collectedAt: "2026-11-04T00:00:00.000Z",
          data: {},
        },
      },
      true,
    );
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual(
      envelope("paid_read_unsupported", "unavailable", false),
    );
  });
});

// A client retries a 503 carrying retryable:true. With retryable:false it
// treats that scope as a final failure, including canonical_view_incomplete.
// This bounded consumer records those outcomes using the public response.
it.each([
  { confirmation: "unconfirmed", attempts: 2, outcome: "retry" },
  { confirmation: "confirmed", attempts: 1, outcome: "scope_failed" },
] as const)(
  "client $outcome for $confirmation incomplete data",
  async ({ confirmation, attempts, outcome }) => {
    let calls = 0;
    let actual: "retry" | "scope_failed" = "scope_failed";
    for (let attempt = 0; attempt < 2; attempt++) {
      const response = await request({
        kind: "refused",
        refusal: {
          status: "incomplete",
          reason: "canonical_view_incomplete",
          confirmation,
          diagnostics: [],
        },
      });
      calls++;
      const body = await response.json();
      if (response.status === 503 && body.retryable === true) {
        actual = "retry";
        continue;
      }
      actual = "scope_failed";
      break;
    }
    expect(calls).toBe(attempts);
    expect(actual).toBe(outcome);
  },
);
