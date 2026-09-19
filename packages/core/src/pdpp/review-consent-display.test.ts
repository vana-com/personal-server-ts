/**
 * The review payload carries the declaration's §5 consent copy.
 *
 * ── Why this is the AS's job, not the renderer's ────────────────────────────
 *
 * §5: stream `display.label` / `display.detail` are "authored by the connector
 * maintainer (not the requesting client) and trusted by the authorization
 * server", and "the requesting client MUST NOT be able to override or
 * supplement these descriptions in the selection request". The renderer cannot
 * enforce that — it sees one payload and cannot tell which member the client
 * wrote. The AS can, because it reads them from the RETAINED DECLARATION
 * SNAPSHOT and never from `request`. So the provenance guarantee lives here:
 * these fields are copied from `snapshot`, and there is deliberately no code
 * path that lets the request reach them.
 *
 * ── What was broken ────────────────────────────────────────────────────────
 *
 * `buildConsentReview` took stream copy only from `streamDescriptions`, a
 * caller-supplied map the AS route never populated. So every review shipped
 * with no human copy at all and the consent surface rendered bare identifiers,
 * even though the accepted declaration carried "Instagram", "Instagram
 * profile" and "No posts or direct messages".
 */

import { describe, expect, it } from "vitest";
import { buildConsentReview, type RequesterIdentity } from "./review.js";
import {
  PDPP_DATA_ACCESS_TYPE,
  type DeclarationSnapshot,
  type SelectionRequest,
  type StreamGrant,
} from "./types.js";

const snapshot: DeclarationSnapshot = {
  source_id: "https://registry.pdpp.dev/connectors/instagram",
  source_kind: "connector",
  version: "0.1.0-local",
  digest: "d".repeat(64),
  display: { name: "Instagram" },
  streams: [
    {
      name: "profile",
      description: "Instagram profile snapshot",
      display: {
        label: "Instagram profile",
        detail:
          "Instagram account id, username, profile text, and profile counters. No posts or direct messages.",
      },
      fields: ["id", "username", "bio"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
};

const requester: RequesterIdentity = {
  client_id: "music_recommendations",
  display_name: "Concert Finder",
  app_approved: false,
};

const resolvedStreams: StreamGrant[] = [
  { name: "profile", instance_ids: ["instagram:acct-a"], fields: ["id", "username"] },
];

function request(overrides: Partial<SelectionRequest> = {}): SelectionRequest {
  return {
    type: PDPP_DATA_ACCESS_TYPE,
    source: { id: snapshot.source_id },
    purpose_code: "https://pdpp.dev/purpose/personalization",
    access_mode: "single_use",
    streams: [{ name: "profile" }],
    ...overrides,
  };
}

function build(input: Partial<Parameters<typeof buildConsentReview>[0]> = {}) {
  return buildConsentReview({
    subjectId: "user_abc123",
    request: request(),
    snapshot,
    resolvedStreams,
    requester,
    ...input,
  });
}

describe("review payload carries §5 consent display copy", () => {
  it("names the source in human words as well as by id", () => {
    const model = build();

    expect(model.data.source.display_name).toBe("Instagram");
    // The id stays: it is the protocol-enforced fact, and the human name is
    // the label for it. Replacing one with the other would hide which source
    // was actually resolved (6.1-5).
    expect(model.data.source.id).toBe(
      "https://registry.pdpp.dev/connectors/instagram",
    );
  });

  it("carries each stream's consent label and detail", () => {
    const model = build();
    const stream = model.data.streams[0];

    expect(stream.display_label).toBe("Instagram profile");
    expect(stream.display_detail).toContain("No posts or direct messages");
  });

  it("keeps the declaration description distinct from the consent label", () => {
    const model = build();
    const stream = model.data.streams[0];

    // §5 puts these at different precedence and says `description` is NOT
    // consent-surface metadata. Collapsing them here would erase that.
    expect(stream.description).toBe("Instagram profile snapshot");
    expect(stream.description).not.toBe(stream.display_label);
  });

  it("does not let the request author the data description", () => {
    // The provenance guarantee. A client that puts display copy in its own
    // request must not see it on the consent surface — §5 makes that the
    // property that keeps data descriptions trustworthy "regardless of the
    // client's intentions".
    const model = build({
      request: request({
        streams: [
          {
            name: "profile",
            // Not members of the request contract; supplied here exactly as a
            // hostile client would try.
            display: { label: "Harmless public info", detail: "Nothing personal" },
            description: "Harmless public info",
          } as SelectionRequest["streams"][number],
        ],
      }),
    });
    const stream = model.data.streams[0];

    expect(stream.display_label).toBe("Instagram profile");
    expect(stream.display_detail).toContain("No posts or direct messages");
    expect(stream.description).toBe("Instagram profile snapshot");
  });

  it("renders nothing rather than a blank when the declaration authored none", () => {
    const bare: DeclarationSnapshot = {
      ...snapshot,
      display: undefined,
      streams: [
        {
          name: "profile",
          fields: ["id"],
          required_fields: ["id"],
          primary_key: ["id"],
        },
      ],
    };
    const model = build({ snapshot: bare });

    expect(model.data.source.display_name).toBeUndefined();
    expect(model.data.streams[0].display_label).toBeUndefined();
    expect(model.data.streams[0].display_detail).toBeUndefined();
    expect(model.data.streams[0].description).toBeUndefined();
  });

  it("lets an explicit streamDescriptions override stand", () => {
    // The existing caller-supplied channel still wins where it is set, so this
    // change adds a source of copy rather than removing one.
    const model = build({
      streamDescriptions: { profile: "Deployment-supplied copy" },
    });

    expect(model.data.streams[0].description).toBe("Deployment-supplied copy");
  });
});
