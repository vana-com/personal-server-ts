/**
 * §5 consent-surface display metadata survives declaration parsing.
 *
 * ── The conformance gap this closes ─────────────────────────────────────────
 *
 * §5 "Stream display metadata" defines `display.label` and `display.detail` as
 * consent-surface metadata "authored by the connector maintainer (not the
 * requesting client) and trusted by the authorization server", and §5 defines
 * a top-level `display.name` as the "human-readable name for display in
 * consent UIs". The requesting client MUST NOT be able to override or
 * supplement them — that is what makes them the ONLY data description on the
 * consent surface a hostile client cannot author.
 *
 * `parseDeclaration` was dropping all three on the floor. The snapshot kept
 * `fields`, `required_fields`, `schema` and `selection` and discarded
 * `display` and `description`, so the review payload had nothing human to
 * render and the consent surface fell back to raw identifiers: the owner saw
 * `https://registry.pdpp.dev/connectors/instagram` and a bare `profile`,
 * while the accepted declaration said "Instagram" and "Instagram profile —
 * Instagram account id, username, profile text, and profile counters. No
 * posts or direct messages."
 *
 * The fixtures are the ACTUAL producer documents already in `__fixtures__`,
 * not hand-written substitutes: they prove the metadata is really there in
 * the documents this AS accepts today, so the missing copy was a parser
 * omission and not an absent input.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseDeclaration } from "./declaration.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "__fixtures__");

function parseFixture(connector: string, sourceId: string) {
  const body = readFileSync(
    join(FIXTURES, `${connector}.source-declaration.json`),
    "utf-8",
  );
  const parsed = parseDeclaration(body, sourceId);
  if (!parsed.ok) throw new Error(parsed.failure.message);
  return parsed.snapshot;
}

describe("§5 declaration display metadata reaches the snapshot", () => {
  it("keeps the source's human display name", () => {
    const snapshot = parseFixture(
      "instagram",
      "https://registry.pdpp.dev/connectors/instagram",
    );

    // Without this the consent surface can only name the source by its
    // registry URL, which is what the owner actually saw.
    expect(snapshot.display?.name).toBe("Instagram");
  });

  it("keeps each stream's consent label and detail", () => {
    const snapshot = parseFixture(
      "instagram",
      "https://registry.pdpp.dev/connectors/instagram",
    );
    const profile = snapshot.streams.find((s) => s.name === "profile");

    expect(profile?.display?.label).toBe("Instagram profile");
    // The detail says what is EXCLUDED as well as included. That exclusion is
    // the part an owner cannot reconstruct from a field list, and the part a
    // client must not be able to author.
    expect(profile?.display?.detail).toContain(
      "No posts or direct messages",
    );
  });

  it("keeps the stream description as a distinct, lower-precedence field", () => {
    const snapshot = parseFixture(
      "instagram",
      "https://registry.pdpp.dev/connectors/instagram",
    );
    const profile = snapshot.streams.find((s) => s.name === "profile");

    // §5 is explicit that `description` is NOT consent-surface metadata and
    // that `display` is. They are kept apart rather than coalesced here so the
    // AS can apply that precedence rather than guess at render time.
    expect(profile?.description).toBe("Instagram profile snapshot");
    expect(profile?.description).not.toBe(profile?.display?.label);
  });

  it("carries display metadata for every producer declaration, not just one", () => {
    for (const [connector, sourceId, name] of [
      ["github", "https://registry.pdpp.dev/connectors/github", "GitHub"],
      ["youtube", "https://registry.pdpp.dev/connectors/youtube", "YouTube"],
    ] as const) {
      const snapshot = parseFixture(connector, sourceId);
      expect(snapshot.display?.name).toBe(name);
      // Every stream in these documents declares a consent label.
      for (const stream of snapshot.streams) {
        expect(stream.display?.label).toBeTruthy();
      }
    }
  });

  it("leaves display absent when the declaration omits it", () => {
    // A minimal internal-shape declaration. Absence must stay absence: an
    // empty `display: {}` would make a renderer print a blank label where it
    // should fall back to the stream name.
    const body = JSON.stringify({
      source_id: "urn:test:source",
      source_kind: "connector",
      version: "1.0.0",
      streams: [
        {
          name: "plain",
          fields: ["id"],
          required_fields: ["id"],
          primary_key: ["id"],
        },
      ],
    });
    const parsed = parseDeclaration(body, "urn:test:source");
    if (!parsed.ok) throw new Error(parsed.failure.message);

    expect(parsed.snapshot.display).toBeUndefined();
    expect(parsed.snapshot.streams[0].display).toBeUndefined();
    expect(parsed.snapshot.streams[0].description).toBeUndefined();
  });
});
