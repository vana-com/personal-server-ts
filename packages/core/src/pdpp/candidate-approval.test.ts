import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { expect, it } from "vitest";
import {
  AuthorizationSessionStore,
  fetchReview,
  approveAuthorization,
} from "./approval.js";
import { openPdppAuthStore } from "./store.js";
import { PdppTokenService } from "./tokens.js";
import {
  PDPP_DATA_ACCESS_TYPE_CANDIDATE,
  PDPP_GRANT_VERSION_CANDIDATE,
} from "./types.js";
it.each([undefined, ["a", "b"]])(
  "reviews and issues candidate grant ignoring inventory and fan-in of unapproved optional streams (%j)",
  (optionalInstances) => {
    const dir = mkdtempSync(join(tmpdir(), "candidate-approval-"));
    const store = openPdppAuthStore(join(dir, "auth.db"));
    try {
      const tokens = new PdppTokenService(store);
      const sessions = new AuthorizationSessionStore();
      const session = sessions.create({
        subjectId: "owner",
        request: {
          type: PDPP_DATA_ACCESS_TYPE_CANDIDATE,
          source: { id: "s" },
          purpose_code: "https://pdpp.dev/purpose/analytics",
          access_mode: "continuous",
          streams: [
            { name: "required", necessity: "required", fields: ["id"] },
            {
              name: "optional",
              fields: ["id"],
              instance_ids: optionalInstances,
            },
          ],
        },
        snapshot: {
          source_id: "s",
          source_kind: "connector",
          version: "1",
          digest: "d",
          streams: ["required", "optional"].map((name) => ({
            name,
            fields: ["id"],
            required_fields: ["id"],
            primary_key: ["id"],
          })),
        },
        requester: { client_id: "c", display_name: "App", app_approved: false },
        redirectUri: "https://app.example/callback",
      });
      const ownerToken = tokens.issueOwnerToken({
        subjectId: "owner",
      }).access_token;
      const inventory = {
        eligibleFor: (name: string) =>
          name === "required" ? ["i"] : ["a", "b"],
      };
      const input = {
        sessions,
        tokens,
        sessionId: session.session_id,
        ownerToken,
        inventory,
      };
      const reviewed = fetchReview(input);
      expect(reviewed.ok && reviewed.result.review).toBeTruthy();
      if (!reviewed.ok || !reviewed.result.review)
        throw Error("review missing");
      const result = approveAuthorization({
        ...input,
        reviewDigest: reviewed.result.review.review_digest,
      });
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.grant.version).toBe(PDPP_GRANT_VERSION_CANDIDATE);
        expect(result.grant.streams.map((s) => s.name)).toEqual(["required"]);
      }
    } finally {
      store.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

it("reviews an all-optional candidate request before any choice and issues only an affirmatively selected stream", () => {
  const dir = mkdtempSync(join(tmpdir(), "candidate-approval-"));
  const store = openPdppAuthStore(join(dir, "auth.db"));
  try {
    const tokens = new PdppTokenService(store);
    const sessions = new AuthorizationSessionStore();
    const session = sessions.create({
      subjectId: "owner",
      request: {
        type: PDPP_DATA_ACCESS_TYPE_CANDIDATE,
        source: { id: "s" },
        purpose_code: "https://pdpp.dev/purpose/analytics",
        access_mode: "continuous",
        // Necessity omitted: optional under the candidate.
        streams: [{ name: "transactions", fields: ["date"] }],
      },
      snapshot: {
        source_id: "s",
        source_kind: "connector",
        version: "1",
        digest: "d",
        streams: [
          {
            name: "transactions",
            fields: ["date"],
            required_fields: ["date"],
            primary_key: ["date"],
          },
        ],
      },
      requester: { client_id: "c", display_name: "App", app_approved: false },
      redirectUri: "https://app.example/callback",
    });
    const input = {
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken: tokens.issueOwnerToken({ subjectId: "owner" }).access_token,
      inventory: { eligibleFor: () => ["i"] },
    };

    // Initial review: the stream is shown unselected; nothing is refused yet.
    const initial = fetchReview(input);
    expect(initial.ok).toBe(true);
    if (!initial.ok || !initial.result.review) throw Error("review missing");
    expect(initial.result.review.data.streams).toEqual([]);
    expect(initial.result.review.data.omitted_streams).toEqual([
      "transactions",
    ]);
    // An empty grant is still never issued.
    const empty = approveAuthorization({
      ...input,
      reviewDigest: initial.result.review.review_digest,
    });
    expect(empty.ok).toBe(false);
    if (!empty.ok) expect(empty.failure.code).toBe("selection_refused");

    // All declined: still reviewable, still not issuable.
    const declined = { declined_streams: ["transactions"] };
    const declinedReview = fetchReview({ ...input, ownerChoices: declined });
    expect(declinedReview.ok).toBe(true);
    if (!declinedReview.ok || !declinedReview.result.review)
      throw Error("review missing");
    const refused = approveAuthorization({
      ...input,
      ownerChoices: declined,
      reviewDigest: declinedReview.result.review.review_digest,
    });
    expect(refused.ok).toBe(false);
    if (!refused.ok) expect(refused.failure.code).toBe("selection_refused");

    // Affirmative choice: the refreshed review and the grant carry the stream.
    const chosen = { approved_streams: ["transactions"] };
    const refreshed = fetchReview({ ...input, ownerChoices: chosen });
    if (!refreshed.ok || !refreshed.result.review)
      throw Error("review missing");
    expect(refreshed.result.review.data.streams.map((s) => s.name)).toEqual([
      "transactions",
    ]);
    const approved = approveAuthorization({
      ...input,
      ownerChoices: chosen,
      reviewDigest: refreshed.result.review.review_digest,
    });
    expect(approved.ok).toBe(true);
    if (approved.ok)
      expect(approved.grant.streams.map((s) => s.name)).toEqual([
        "transactions",
      ]);
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
