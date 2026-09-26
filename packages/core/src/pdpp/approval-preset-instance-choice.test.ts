/**
 * The independent review's finding 3 repro.
 *
 * The finding: `pendingInstanceChoices` read only `session.request.streams`,
 * which a `selection_preset` request leaves `undefined`. So the owner was
 * never offered the instance-choice step; `resolveSelection` expanded the
 * preset itself, found a stream with two eligible instances, and returned
 * `instance_choice_required`, which `fetchReview` maps to an invalid request.
 * A valid preset was therefore unapprovable on any source with two connected
 * instances — a dead end the owner could do nothing about.
 *
 * The rule under test is the one the implementation already states for a
 * named stream and for a wildcard: **omission is not fan-in, the owner
 * picks.** A preset is a third way of naming streams, so it must reach the
 * same step. The whole point of the choice surface is that an unresolvable
 * instance is a consent question, not an error.
 *
 * These tests drive `fetchReview` rather than `pendingInstanceChoices`
 * directly: the defect was only observable at the boundary, where "needs a
 * choice" turned into "invalid request".
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuthorizationSessionStore, fetchReview } from "./approval.js";
import { openPdppAuthStore, type PdppAuthStore } from "./store.js";
import { PdppTokenService } from "./tokens.js";
import type { InstanceInventory } from "./resolve.js";
import type { RequesterIdentity } from "./review.js";
import {
  PDPP_DATA_ACCESS_TYPE,
  type DeclarationSnapshot,
  type SelectionRequest,
} from "./types.js";

const OWNER = "user_abc123";

const snapshot: DeclarationSnapshot = {
  source_id: "https://registry.pdpp.dev/connectors/spotify",
  source_kind: "connector",
  version: "2026-08-11",
  digest: "d".repeat(64),
  streams: [
    {
      name: "top_artists",
      fields: ["id", "name", "genres"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
    {
      name: "profile",
      fields: ["id", "display_name"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
  selection_presets: [
    {
      name: "social_summary",
      streams: [{ name: "top_artists" }, { name: "profile" }],
    },
    {
      // A preset that names its handles is already a decision, so it must NOT
      // produce a choice step even on a two-instance source.
      name: "pinned_account",
      streams: [{ name: "top_artists", instance_ids: ["account-a"] }],
    },
  ],
};

const requester: RequesterIdentity = {
  client_id: "music_recommendations",
  display_name: "Concert Finder",
  app_approved: false,
};

/** Two eligible instances on every stream: the reviewer's exact condition. */
const twoInstances: InstanceInventory = {
  eligibleFor: () => ["account-a", "account-b"],
};

function presetRequest(name: string): SelectionRequest {
  return {
    type: PDPP_DATA_ACCESS_TYPE,
    source: { id: snapshot.source_id },
    purpose_code: "https://pdpp.dev/purpose/personalization",
    access_mode: "single_use",
    selection_preset: name,
  };
}

let dir: string;
let store: PdppAuthStore;
let tokens: PdppTokenService;
let sessions: AuthorizationSessionStore;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "pdpp-preset-choice-"));
  store = openPdppAuthStore(join(dir, "auth.db"));
  tokens = new PdppTokenService(store);
  sessions = new AuthorizationSessionStore();
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

function review(
  request: SelectionRequest,
  instanceChoices?: Record<string, string[]>,
) {
  const session = sessions.create({
    subjectId: OWNER,
    request,
    snapshot,
    requester,
    redirectUri: "https://app.example.com/callback",
  });
  return fetchReview({
    sessions,
    tokens,
    sessionId: session.session_id,
    ownerToken: tokens.issueOwnerToken({ subjectId: OWNER }).access_token,
    inventory: twoInstances,
    instanceChoices,
  });
}

describe("review finding 3 — a preset reaches the instance-choice step", () => {
  it("offers the choice rather than failing the request", () => {
    const result = review(presetRequest("social_summary"));
    // The defect surfaced here as ok:false — a valid preset reported as an
    // invalid request, with nothing the owner could do about it.
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.result.review).toBeUndefined();
    // Every stream the preset expands to, not just the first: a surface that
    // asked about one at a time would make the owner approve a moving target.
    expect(result.result.instance_choice_required).toEqual([
      { stream: "top_artists", candidates: ["account-a", "account-b"] },
      { stream: "profile", candidates: ["account-a", "account-b"] },
    ]);
  });

  it("returns a reviewable decision once the owner picks for every stream", () => {
    const result = review(presetRequest("social_summary"), {
      top_artists: ["account-b"],
      profile: ["account-a"],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.result.instance_choice_required).toBeUndefined();
    const streams = result.result.review?.data.streams ?? [];
    expect(streams.find((s) => s.name === "top_artists")?.instance_ids).toEqual(
      ["account-b"],
    );
    expect(streams.find((s) => s.name === "profile")?.instance_ids).toEqual([
      "account-a",
    ]);
  });

  it("still asks about the streams the owner has not yet decided", () => {
    // A partial pick must not be read as consent to fan in on the rest.
    const result = review(presetRequest("social_summary"), {
      top_artists: ["account-b"],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.result.instance_choice_required).toEqual([
      { stream: "profile", candidates: ["account-a", "account-b"] },
    ]);
  });

  it("asks nothing when the preset already names its handles", () => {
    // An explicitly named handle set is a decision the preset author made;
    // the choice step exists for omission, not for confirmation.
    const result = review(presetRequest("pinned_account"));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.result.instance_choice_required).toBeUndefined();
    expect(result.result.review?.data.streams[0].instance_ids).toEqual([
      "account-a",
    ]);
  });
});
